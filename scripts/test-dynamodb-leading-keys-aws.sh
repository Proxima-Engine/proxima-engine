#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:?Set AWS_REGION}"
: "${AWS_PROFILE_TENANT_A:?Set AWS_PROFILE_TENANT_A to a least-privilege tenant A role}"
: "${AWS_PROFILE_TENANT_B:?Set AWS_PROFILE_TENANT_B to a least-privilege tenant B role}"
: "${DYNAMODB_TEST_TABLE:?Set DYNAMODB_TEST_TABLE to a disposable test table}"
: "${DYNAMODB_PARTITION_KEY:=tenant_id}"
: "${DYNAMODB_SORT_KEY:?Set DYNAMODB_SORT_KEY to the table range-key attribute; a composite key is required for safe canary cleanup}"

command -v aws >/dev/null || { echo "AWS CLI v2 is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

A_IDENTITY="$(aws sts get-caller-identity --profile "$AWS_PROFILE_TENANT_A" --output json)"
B_IDENTITY="$(aws sts get-caller-identity --profile "$AWS_PROFILE_TENANT_B" --output json)"
A_ACCOUNT="$(jq -r '.Account' <<<"$A_IDENTITY")"
B_ACCOUNT="$(jq -r '.Account' <<<"$B_IDENTITY")"
A_ARN="$(jq -r '.Arn' <<<"$A_IDENTITY")"
B_ARN="$(jq -r '.Arn' <<<"$B_IDENTITY")"
[[ "$A_ACCOUNT" == "$B_ACCOUNT" ]] || { echo "Tenant roles must be in the same dedicated test account" >&2; exit 1; }
[[ "$A_ARN" != "$B_ARN" ]] || { echo "Tenant A and B must use distinct IAM principals" >&2; exit 1; }

TABLE="$(aws dynamodb describe-table --profile "$AWS_PROFILE_TENANT_A" --table-name "$DYNAMODB_TEST_TABLE" --output json)"
TABLE_ARN="$(jq -r '.Table.TableArn' <<<"$TABLE")"
PARTITION_KEY_TYPE="$(jq -r --arg name "$DYNAMODB_PARTITION_KEY" '.Table.KeySchema[] | select(.KeyType=="HASH") | .AttributeName' <<<"$TABLE")"
[[ "$PARTITION_KEY_TYPE" == "$DYNAMODB_PARTITION_KEY" ]] || { echo "Table partition key must be $DYNAMODB_PARTITION_KEY" >&2; exit 1; }
SORT_KEY_TYPE="$(jq -r '.Table.KeySchema[] | select(.KeyType=="RANGE") | .AttributeName' <<<"$TABLE")"
[[ "$SORT_KEY_TYPE" == "$DYNAMODB_SORT_KEY" ]] || { echo "Configured sort key does not match the table" >&2; exit 1; }

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
TENANT_A="proxima-tenant-a"
TENANT_B="proxima-tenant-b"
RECORD_A="acceptance-$RUN_ID-a"
RECORD_B="acceptance-$RUN_ID-b"
TMP="$(mktemp -d)"
cleanup() {
  local key_a key_b
  if [[ -n "$DYNAMODB_SORT_KEY" ]]; then
    key_a="$(jq -cn --arg pk "$TENANT_A" --arg sk "$RECORD_A" --arg p "$DYNAMODB_PARTITION_KEY" --arg s "$DYNAMODB_SORT_KEY" '{($p):{S:$pk},($s):{S:$sk}}')"
    key_b="$(jq -cn --arg pk "$TENANT_B" --arg sk "$RECORD_B" --arg p "$DYNAMODB_PARTITION_KEY" --arg s "$DYNAMODB_SORT_KEY" '{($p):{S:$pk},($s):{S:$sk}}')"
  else
    key_a="$(jq -cn --arg pk "$TENANT_A" --arg p "$DYNAMODB_PARTITION_KEY" '{($p):{S:$pk}}')"
    key_b="$(jq -cn --arg pk "$TENANT_B" --arg p "$DYNAMODB_PARTITION_KEY" '{($p):{S:$pk}}')"
  fi
  aws dynamodb delete-item --profile "$AWS_PROFILE_TENANT_A" --region "$AWS_REGION" --table-name "$DYNAMODB_TEST_TABLE" --key "$key_a" >/dev/null 2>&1 || true
  aws dynamodb delete-item --profile "$AWS_PROFILE_TENANT_B" --region "$AWS_REGION" --table-name "$DYNAMODB_TEST_TABLE" --key "$key_b" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

make_item() {
  local tenant="$1" record="$2"
  if [[ -n "$DYNAMODB_SORT_KEY" ]]; then
    jq -cn --arg p "$DYNAMODB_PARTITION_KEY" --arg s "$DYNAMODB_SORT_KEY" --arg t "$tenant" --arg r "$record" \
      '{($p):{S:$t},($s):{S:$r},payload:{S:"proxima-iam-acceptance"}}'
  else
    jq -cn --arg p "$DYNAMODB_PARTITION_KEY" --arg t "$tenant" --arg r "$record" \
      '{($p):{S:$t},payload:{S:$r}}'
  fi
}
make_key() {
  local tenant="$1" record="$2"
  if [[ -n "$DYNAMODB_SORT_KEY" ]]; then
    jq -cn --arg p "$DYNAMODB_PARTITION_KEY" --arg s "$DYNAMODB_SORT_KEY" --arg t "$tenant" --arg r "$record" \
      '{($p):{S:$t},($s):{S:$r}}'
  else
    jq -cn --arg p "$DYNAMODB_PARTITION_KEY" --arg t "$tenant" '{($p):{S:$t}}'
  fi
}
expect_denied() {
  local label="$1"; shift
  if "$@" >"$TMP/denied.out" 2>"$TMP/denied.err"; then
    echo "FAIL: $label unexpectedly succeeded" >&2
    exit 1
  fi
  if ! grep -Eqi 'AccessDenied|AccessDeniedException|not authorized|UnauthorizedOperation' "$TMP/denied.err"; then
    echo "FAIL: $label failed for a reason other than IAM authorization" >&2
    cat "$TMP/denied.err" >&2
    exit 1
  fi
}

ITEM_A="$(make_item "$TENANT_A" "$RECORD_A")"
ITEM_B="$(make_item "$TENANT_B" "$RECORD_B")"
KEY_A="$(make_key "$TENANT_A" "$RECORD_A")"
KEY_B="$(make_key "$TENANT_B" "$RECORD_B")"

aws dynamodb put-item --profile "$AWS_PROFILE_TENANT_A" --region "$AWS_REGION" --table-name "$DYNAMODB_TEST_TABLE" --item "$ITEM_A" >/dev/null
aws dynamodb put-item --profile "$AWS_PROFILE_TENANT_B" --region "$AWS_REGION" --table-name "$DYNAMODB_TEST_TABLE" --item "$ITEM_B" >/dev/null
aws dynamodb get-item --profile "$AWS_PROFILE_TENANT_A" --region "$AWS_REGION" --table-name "$DYNAMODB_TEST_TABLE" --key "$KEY_A" --consistent-read --output json | jq -e '.Item.payload.S == "proxima-iam-acceptance"' >/dev/null
aws dynamodb get-item --profile "$AWS_PROFILE_TENANT_B" --region "$AWS_REGION" --table-name "$DYNAMODB_TEST_TABLE" --key "$KEY_B" --consistent-read --output json | jq -e '.Item.payload.S == "proxima-iam-acceptance"' >/dev/null

expect_denied "Tenant A GetItem for Tenant B partition" aws dynamodb get-item --profile "$AWS_PROFILE_TENANT_A" --region "$AWS_REGION" --table-name "$DYNAMODB_TEST_TABLE" --key "$KEY_B"
expect_denied "Tenant B GetItem for Tenant A partition" aws dynamodb get-item --profile "$AWS_PROFILE_TENANT_B" --region "$AWS_REGION" --table-name "$DYNAMODB_TEST_TABLE" --key "$KEY_A"
expect_denied "Tenant A Query for Tenant B partition" aws dynamodb query --profile "$AWS_PROFILE_TENANT_A" --region "$AWS_REGION" --table-name "$DYNAMODB_TEST_TABLE" --key-condition-expression "#pk = :pk" --expression-attribute-names "{\"#pk\":\"$DYNAMODB_PARTITION_KEY\"}" --expression-attribute-values "{\":pk\":{\"S\":\"$TENANT_B\"}}"
expect_denied "Tenant B Query for Tenant A partition" aws dynamodb query --profile "$AWS_PROFILE_TENANT_B" --region "$AWS_REGION" --table-name "$DYNAMODB_TEST_TABLE" --key-condition-expression "#pk = :pk" --expression-attribute-names "{\"#pk\":\"$DYNAMODB_PARTITION_KEY\"}" --expression-attribute-values "{\":pk\":{\"S\":\"$TENANT_A\"}}"
expect_denied "Tenant A Scan" aws dynamodb scan --profile "$AWS_PROFILE_TENANT_A" --region "$AWS_REGION" --table-name "$DYNAMODB_TEST_TABLE"
expect_denied "Tenant B Scan" aws dynamodb scan --profile "$AWS_PROFILE_TENANT_B" --region "$AWS_REGION" --table-name "$DYNAMODB_TEST_TABLE"

echo "PASS: DynamoDB IAM LeadingKeys tenant isolation"
echo "Table ARN: $TABLE_ARN"
echo "Tenant A principal: $A_ARN"
echo "Tenant B principal: $B_ARN"
