#!/usr/bin/env bash
set -euo pipefail

: "${OPENSEARCH_URL:?Set OPENSEARCH_URL to a disposable HTTPS OpenSearch cluster}"
: "${OPENSEARCH_ADMIN_USER:?Set OPENSEARCH_ADMIN_USER}"
: "${OPENSEARCH_ADMIN_PASSWORD:?Set OPENSEARCH_ADMIN_PASSWORD}"
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

BASE="${OPENSEARCH_URL%/}"
TMP="$(mktemp -d)"
chmod 700 "$TMP"
ADMIN="$TMP/admin.conf"
A_AUTH="$TMP/tenant-a.conf"
B_AUTH="$TMP/tenant-b.conf"
ROLE_A="proxima_acceptance_tenant_a"
ROLE_B="proxima_acceptance_tenant_b"
USER_A="proxima_acceptance_a"
USER_B="proxima_acceptance_b"
BACKEND_A="proxima_acceptance_backend_a"
BACKEND_B="proxima_acceptance_backend_b"
INDEX_A="tenant-proxima-a-acceptance"
INDEX_B="tenant-proxima-b-acceptance"
PASS_A="$(openssl rand -hex 24)"
PASS_B="$(openssl rand -hex 24)"

printf 'user = "%s:%s"\n' "$OPENSEARCH_ADMIN_USER" "$OPENSEARCH_ADMIN_PASSWORD" > "$ADMIN"
printf 'user = "%s:%s"\n' "$USER_A" "$PASS_A" > "$A_AUTH"
printf 'user = "%s:%s"\n' "$USER_B" "$PASS_B" > "$B_AUTH"
chmod 600 "$ADMIN" "$A_AUTH" "$B_AUTH"

admin() { curl --silent --show-error --config "$ADMIN" "$@"; }
tenant_a() { curl --silent --show-error --config "$A_AUTH" "$@"; }
tenant_b() { curl --silent --show-error --config "$B_AUTH" "$@"; }
expect_status() {
  local expected="$1"; shift
  local code
  code="$(curl --silent --show-error "$@" -o "$TMP/response.json" -w '%{http_code}' || true)"
  if [[ "$code" != "$expected" ]]; then
    echo "Expected HTTP $expected, received $code" >&2
    cat "$TMP/response.json" >&2 || true
    exit 1
  fi
}
cleanup() {
  admin -X DELETE "$BASE/$INDEX_A,$INDEX_B" >/dev/null 2>&1 || true
  for user in "$USER_A" "$USER_B"; do admin -X DELETE "$BASE/_plugins/_security/api/internalusers/$user" >/dev/null 2>&1 || true; done
  for role in "$ROLE_A" "$ROLE_B"; do
    admin -X DELETE "$BASE/_plugins/_security/api/rolesmapping/$role" >/dev/null 2>&1 || true
    admin -X DELETE "$BASE/_plugins/_security/api/roles/$role" >/dev/null 2>&1 || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

create_role() {
  local role="$1" tenant="$2" pattern="$3"
  jq -n --arg tenant "$tenant" --arg pattern "$pattern" '{
    cluster_permissions:[],
    index_permissions:[{
      index_patterns:[$pattern],
      allowed_actions:[
        "indices:data/read/search",
        "indices:data/read/get"
      ],
      dls:({term:{tenant_id:$tenant}}|tojson),
      fls:["tenant_id","public_field"]
    }],
    tenant_permissions:[],
    description:("Proxima acceptance role for "+$tenant)
  }' > "$TMP/role.json"
  admin -fsS -X PUT "$BASE/_plugins/_security/api/roles/$role" \
    -H 'content-type: application/json' --data-binary @"$TMP/role.json" >/dev/null
}
create_user() {
  local user="$1" password="$2" backend="$3"
  jq -n --arg password "$password" --arg backend "$backend" \
    '{password:$password,backend_roles:[$backend]}' > "$TMP/user.json"
  admin -fsS -X PUT "$BASE/_plugins/_security/api/internalusers/$user" \
    -H 'content-type: application/json' --data-binary @"$TMP/user.json" >/dev/null
}
map_role() {
  local role="$1" backend="$2"
  jq -n --arg backend "$backend" '{backend_roles:[$backend],users:[],hosts:[]}' > "$TMP/mapping.json"
  admin -fsS -X PUT "$BASE/_plugins/_security/api/rolesmapping/$role" \
    -H 'content-type: application/json' --data-binary @"$TMP/mapping.json" >/dev/null
}

for index in "$INDEX_A" "$INDEX_B"; do
  admin -fsS -X PUT "$BASE/$index" -H 'content-type: application/json' \
    -d '{"mappings":{"properties":{"tenant_id":{"type":"keyword"},"public_field":{"type":"keyword"},"secret_field":{"type":"keyword"}}}}' >/dev/null
done
admin -fsS -X PUT "$BASE/$INDEX_A/_doc/a1?refresh=true" -H 'content-type: application/json' \
  -d '{"tenant_id":"tenant-a","public_field":"alpha","secret_field":"must-not-leak"}' >/dev/null
admin -fsS -X PUT "$BASE/$INDEX_A/_doc/a2?refresh=true" -H 'content-type: application/json' \
  -d '{"tenant_id":"tenant-b","public_field":"cross-tenant-canary","secret_field":"must-not-leak"}' >/dev/null
admin -fsS -X PUT "$BASE/$INDEX_B/_doc/b1?refresh=true" -H 'content-type: application/json' \
  -d '{"tenant_id":"tenant-b","public_field":"bravo","secret_field":"must-not-leak"}' >/dev/null

create_role "$ROLE_A" "tenant-a" "tenant-proxima-a-*"
create_role "$ROLE_B" "tenant-b" "tenant-proxima-b-*"
create_user "$USER_A" "$PASS_A" "$BACKEND_A"
create_user "$USER_B" "$PASS_B" "$BACKEND_B"
map_role "$ROLE_A" "$BACKEND_A"
map_role "$ROLE_B" "$BACKEND_B"

tenant_a -fsS "$BASE/$INDEX_A/_search" > "$TMP/a-own.json"
jq -e '.hits.total.value == 1 and .hits.hits[0]._source.tenant_id == "tenant-a" and .hits.hits[0]._source.public_field == "alpha" and (.hits.hits[0]._source | has("secret_field") | not)' "$TMP/a-own.json" >/dev/null
tenant_a -fsS -X POST "$BASE/$INDEX_A/_search" -H 'content-type: application/json' \
  -d '{"query":{"term":{"tenant_id":"tenant-b"}}}' > "$TMP/a-dls.json"
jq -e '.hits.total.value == 0' "$TMP/a-dls.json" >/dev/null
expect_status 403 --config "$A_AUTH" "$BASE/$INDEX_B/_search"
expect_status 403 --config "$A_AUTH" "$BASE/_cluster/health"

tenant_b -fsS "$BASE/$INDEX_B/_search" > "$TMP/b-own.json"
jq -e '.hits.total.value == 1 and .hits.hits[0]._source.tenant_id == "tenant-b" and (.hits.hits[0]._source | has("secret_field") | not)' "$TMP/b-own.json" >/dev/null
expect_status 403 --config "$B_AUTH" "$BASE/$INDEX_A/_search"
expect_status 403 --config "$B_AUTH" "$BASE/_cluster/health"

echo "PASS: OpenSearch two-tenant index, DLS, FLS and cluster-privilege isolation"
