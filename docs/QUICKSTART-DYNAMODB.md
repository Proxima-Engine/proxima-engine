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


## Windows PowerShell: clone and build

Open PowerShell in the folder where you keep source repositories. Install Git, the stable Rust toolchain and Cargo first. For gateway providers, Docker Desktop is also required for the disposable database service used by the acceptance test.

```powershell
git clone https://github.com/Proxima-Engine/proxima-engine.git
Set-Location .\proxima-engine
cargo build --locked --release -p proxima-engine
if ($LASTEXITCODE -ne 0) { throw "Proxima build failed" }
```

Run the command from the repository root. If you already cloned the repository, use `Set-Location` to enter the extracted `proxima-engine` directory instead of cloning a second copy. Keep generated credentials, certificates and local environment files outside Git.

## Configuration review before starting

Before launching this provider, verify all of the following against the full provider guide:

1. The provider endpoint, port and distribution/version identify the intended disposable or customer database.
2. Tenant IDs are resolved by the trusted application backend and are not accepted as authorization claims from a browser.
3. Each tenant has its own database/schema/keyspace/index namespace or IAM identity, as applicable to this provider.
4. Provisioning credentials are separate from tenant application credentials and are not stored in the client registry as plaintext.
5. Certificate authorities, server names and client certificates are configured for every network TLS leg.
6. Listener exposure is limited to the application network. Keep local tests on loopback.
7. Registry files and private keys have restrictive permissions and are excluded from source control.

## Runtime diagnostics

Start the provider process in a dedicated terminal and keep its logs visible while connecting a test client. Confirm the process is listening on the configured address before running application queries. If the client cannot connect, check the process output, port binding, upstream reachability and the database service's readiness before changing tenant policy.

If authentication fails, compare the client principal and tenant mapping with the registry or native provider identity. If a certificate error occurs, validate the configured CA and server name; do not disable certificate verification to make the connection succeed. If a cross-tenant test succeeds unexpectedly, stop the test and review the provider-native grants, namespace mapping and trusted tenant-resolution path before continuing.

## Production handover checklist

- Repeat the acceptance suite against a disposable instance matching the intended provider version.
- Record the exact provider version, Engine release, configuration revision and test result.
- Test allowed tenant operations and denied cross-tenant reads and writes.
- Verify backup/restore and credential rotation for the provider's isolation model.
- Move secrets into the deployment secret manager and enable verified TLS.
- Restrict network access to the Engine and database endpoints.
- Monitor Engine health, provider errors, rejected sessions and credential lifecycle.
- Use the linked complete provider guide for deployment-specific settings and operational procedures.
