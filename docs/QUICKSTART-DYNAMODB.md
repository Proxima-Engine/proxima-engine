# Amazon DynamoDB quickstart

Proxima generates tenant-scoped IAM policy for an exact table ARN. AWS enforces tenant partition access through `dynamodb:LeadingKeys`; the partition key must contain the authenticated tenant ID.

## 1. Clone and build

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --locked --release -p proxima-engine
```

## 2. Generate the policy

```rust
use proxima_engine::dynamodb_tenant::DynamoTenant;

let tenant = DynamoTenant::new(
    "tenant-a",
    "arn:aws:dynamodb:us-east-1:123456789012:table/proxima-records",
)?;
let policy = tenant.iam_policy();
```

Attach the policy to the tenant-specific IAM role. Restrict it to the exact table ARN; do not attach a broad role or wildcard table policy.

## 3. Verify with real IAM

Use a dedicated disposable AWS account, two tenant roles and a test table with `tenant_id` as its partition key:

```bash
export AWS_REGION=us-east-1
export AWS_PROFILE_TENANT_A=proxima-tenant-a
export AWS_PROFILE_TENANT_B=proxima-tenant-b
export DYNAMODB_TEST_TABLE=proxima-tenant-acceptance
export DYNAMODB_PARTITION_KEY=tenant_id
export DYNAMODB_SORT_KEY=record_id
bash scripts/test-dynamodb-leading-keys-aws.sh
```

The acceptance script checks own-tenant reads/writes and cross-tenant denial and removes only its uniquely named canary records. Never point it at production data.

**Next:** [Complete DynamoDB guide](DYNAMODB_TENANCY.md) · [Security](SECURITY.md)
