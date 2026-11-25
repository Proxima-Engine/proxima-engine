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


## 2A. Create the disposable AWS test resources

Use a dedicated AWS test account, not a production account. Create a disposable table with a string partition key named `tenant_id` and a sort key named `record_id`. Create two separate IAM roles, one for Tenant A and one for Tenant B. Configure each role's trust relationship so only the trusted application backend or its test principal can assume it.

## 2B. Review and attach the generated policy

The generated policy is scoped to the exact table ARN and tenant partition key. Review the JSON before attaching it to the corresponding tenant role. Do not add broad DynamoDB permissions, wildcard table resources, Scan, PartiQL, stream or table-administration actions to the application role. Check role trust policies, permissions boundaries, resource policies and organization SCPs for alternate paths that could bypass the condition.

The application must derive the tenant ID from authenticated membership and use credentials for that tenant's role. The partition-key value must be the authenticated tenant ID; a value supplied by an untrusted client is not an authorization decision.

## 2C. Verify both tenant roles

Configure the two AWS CLI profiles to assume the separate roles and run the acceptance script. Confirm own-partition reads and writes succeed while cross-tenant GetItem/Query and Scan are denied. The script uses uniquely named canary records and removes only those records. Keep the test table disposable.

## 2D. Production checklist

- Use exact table ARNs and tenant-specific IAM roles.
- Verify the actual partition key and every access pattern.
- Review role trust, resource policies, permissions boundaries and SCPs.
- Keep administrative credentials outside application processes.
- Test cross-tenant denial with real AWS IAM; DynamoDB Local does not prove AWS IAM LeadingKeys enforcement.

See [DynamoDB tenant isolation](DYNAMODB_TENANCY.md) for policy scope, test-account requirements and the security boundary.
