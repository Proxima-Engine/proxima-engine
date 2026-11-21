#!/usr/bin/env bash
set -euo pipefail

: "${ELASTICSEARCH_URL:?Set ELASTICSEARCH_URL to a disposable HTTPS Elasticsearch cluster}"
: "${ELASTICSEARCH_ADMIN_USER:?Set ELASTICSEARCH_ADMIN_USER to a disposable cluster administrator}"
: "${ELASTICSEARCH_ADMIN_PASSWORD:?Set ELASTICSEARCH_ADMIN_PASSWORD}"
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

BASE="${ELASTICSEARCH_URL%/}"
TMP="$(mktemp -d)"
NETRC="$TMP/curl.conf"
KEY_A_ID=""
KEY_B_ID=""
INDEX_A="tenant-proxima-a-acceptance"
INDEX_B="tenant-proxima-b-acceptance"
cleanup() {
  if [[ -n "$KEY_A_ID" || -n "$KEY_B_ID" ]]; then
    jq -n --arg a "$KEY_A_ID" --arg b "$KEY_B_ID" '{ids:([$a,$b] | map(select(length>0)))}' |
      curl --silent --show-error --config "$NETRC" -X POST "$BASE/_security/api_key/_invalidate" \
        -H 'content-type: application/json' --data-binary @- >/dev/null || true
  fi
  curl --silent --show-error --config "$NETRC" -X DELETE "$BASE/$INDEX_A,$INDEX_B" >/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

# Keep administrator credentials in a mode-0600 curl config, not in command-line arguments.
chmod 700 "$TMP"
printf 'user = "%s:%s"\n' "$ELASTICSEARCH_ADMIN_USER" "$ELASTICSEARCH_ADMIN_PASSWORD" > "$NETRC"
chmod 600 "$NETRC"

request() {
  curl --silent --show-error --config "$NETRC" "$@"
}
status_request() {
  local expected="$1"; shift
  local code
  code="$(curl --silent --show-error --config "$NETRC" -o "$TMP/response.json" -w '%{http_code}' "$@" || true)"
  if [[ "$code" != "$expected" ]]; then
    echo "Expected HTTP $expected, received $code" >&2
    cat "$TMP/response.json" >&2 || true
    exit 1
  fi
}
api_key_request() {
  local key="$1"; shift
  curl --silent --show-error -H "Authorization: ApiKey $key" "$@"
}
api_key_status() {
  local key="$1" expected="$2"; shift 2
  local code
  code="$(curl --silent --show-error -H "Authorization: ApiKey $key" -o "$TMP/response.json" -w '%{http_code}' "$@" || true)"
  if [[ "$code" != "$expected" ]]; then
    echo "Tenant API key expected HTTP $expected, received $code" >&2
    cat "$TMP/response.json" >&2 || true
    exit 1
  fi
}

# Create two independent indices and canary documents using the administrator.
for index in "$INDEX_A" "$INDEX_B"; do
  request -fsS -X PUT "$BASE/$index" -H 'content-type: application/json' \
    -d '{"mappings":{"properties":{"tenant_id":{"type":"keyword"},"public_field":{"type":"keyword"},"secret_field":{"type":"keyword"}}}}' >/dev/null
done
request -fsS -X PUT "$BASE/$INDEX_A/_doc/a1?refresh=true" -H 'content-type: application/json' \
  -d '{"tenant_id":"tenant-a","public_field":"alpha","secret_field":"must-not-leak"}' >/dev/null
request -fsS -X PUT "$BASE/$INDEX_B/_doc/b1?refresh=true" -H 'content-type: application/json' \
  -d '{"tenant_id":"tenant-b","public_field":"bravo","secret_field":"must-not-leak"}' >/dev/null
# A shared index can contain multiple tenants; DLS must filter the other tenant's row.
request -fsS -X PUT "$BASE/$INDEX_A/_doc/a2?refresh=true" -H 'content-type: application/json' \
  -d '{"tenant_id":"tenant-b","public_field":"cross-tenant-canary","secret_field":"must-not-leak"}' >/dev/null

create_key() {
  local tenant="$1" pattern="$2" out="$3"
  jq -n --arg tenant "$tenant" --arg pattern "$pattern" '{
    name:("proxima-acceptance-"+$tenant),
    role_descriptors:{
      tenant_role:{
        cluster:[],
        indices:[{
          names:[$pattern],
          privileges:["read"],
          query:({term:{tenant_id:$tenant}}|tojson),
          field_security:{grant:["tenant_id","public_field"]}
        }],
        applications:[],
        run_as:[],
        metadata:{managed_by:"proxima-engine",tenant_id:$tenant}
      }
    }
  }' > "$TMP/key.json"
  request -fsS -X POST "$BASE/_security/api_key" -H 'content-type: application/json' \
    --data-binary @"$TMP/key.json" > "$out"
}

create_key "tenant-a" "tenant-proxima-a-*" "$TMP/key-a.json"
create_key "tenant-b" "tenant-proxima-b-*" "$TMP/key-b.json"
KEY_A_ID="$(jq -r '.id' "$TMP/key-a.json")"
KEY_B_ID="$(jq -r '.id' "$TMP/key-b.json")"
KEY_A="$(jq -r '.id + ":" + .api_key' "$TMP/key-a.json" | base64 | tr -d '\n')"
KEY_B="$(jq -r '.id + ":" + .api_key' "$TMP/key-b.json" | base64 | tr -d '\n')"
[[ -n "$KEY_A_ID" && -n "$KEY_B_ID" && -n "$KEY_A" && -n "$KEY_B" ]]

# Tenant A can read its own document; DLS and FLS must filter the response.
api_key_request "$KEY_A" -fsS "$BASE/$INDEX_A/_search" > "$TMP/a-own.json"
jq -e '.hits.total.value == 1 and .hits.hits[0]._source.tenant_id == "tenant-a" and .hits.hits[0]._source.public_field == "alpha" and (.hits.hits[0]._source | has("secret_field") | not)' "$TMP/a-own.json" >/dev/null

# DLS denies an otherwise valid query for Tenant B's document in Tenant A's index.
api_key_request "$KEY_A" -fsS -X POST "$BASE/$INDEX_A/_search" -H 'content-type: application/json' \
  -d '{"query":{"term":{"tenant_id":"tenant-b"}}}' > "$TMP/a-dls.json"
jq -e '.hits.total.value == 0' "$TMP/a-dls.json" >/dev/null

# Index namespace and cluster privilege boundaries must independently deny access.
api_key_status "$KEY_A" 403 "$BASE/$INDEX_B/_search"
api_key_status "$KEY_A" 403 "$BASE/_cluster/health"
api_key_request "$KEY_B" -fsS "$BASE/$INDEX_B/_search" > "$TMP/b-own.json"
jq -e '.hits.total.value == 1 and .hits.hits[0]._source.tenant_id == "tenant-b" and (.hits.hits[0]._source | has("secret_field") | not)' "$TMP/b-own.json" >/dev/null
api_key_status "$KEY_B" 403 "$BASE/$INDEX_A/_search"
api_key_status "$KEY_B" 403 "$BASE/_cluster/health"

echo "PASS: Elasticsearch two-tenant index, DLS, FLS and cluster-privilege isolation"
