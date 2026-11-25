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


## Use the shared Agata Proxima SDK and CLI

The SDK and `agata` CLI are shared across all twelve database providers. You do not install a separate SDK or CLI for dynamodb. Download the integration starter kit from the public developer downloads page and extract it.

Linux/macOS:

```bash
curl -fL https://agataproxima.com/downloads/agata-proxima-integration-starter-kit.zip -o agata-proxima-integration-starter-kit.zip
unzip agata-proxima-integration-starter-kit.zip -d agata-proxima-integration-starter-kit
cd agata-proxima-integration-starter-kit
npm ci
npm run check
npm link
agata --help
```

Windows PowerShell:

```powershell
Invoke-WebRequest "https://agataproxima.com/downloads/agata-proxima-integration-starter-kit.zip" -OutFile ".\agata-proxima-integration-starter-kit.zip"
Expand-Archive ".\agata-proxima-integration-starter-kit.zip" -DestinationPath ".\agata-proxima-integration-starter-kit" -Force
Set-Location ".\agata-proxima-integration-starter-kit"
npm ci
npm run check
npm link
agata --help
```

Set the Cloud API origin and organization-scoped API key in the trusted backend environment or secret manager. Do not put the key in a browser bundle, source control, command-line argument or application log.

```bash
export AGATA_API_BASE_URL=https://api.agataproxima.com
export AGATA_API_KEY=aga_your_organization_key
agata health
agata whoami
agata databases providers
agata databases targets
agata nodes list
agata deployments list
agata verification list
```

For PowerShell, use `$env:AGATA_API_BASE_URL` and `$env:AGATA_API_KEY` instead of Bash `export`. Create a provider target using a reviewed private `target.json`, then use `agata databases targets create target.json`. Assign the target with `agata databases targets assign TARGET_ID NODE_ID`, create a tenant binding with `agata databases bindings create binding.json`, and inspect the resulting deployment and verification records. The full provider guide defines the exact target and runtime configuration fields for this database.

The same JavaScript SDK can be used from a trusted Node.js service:

```js
import { AgataClient, createProviderRuntimeConfig } from "./node/agata-client.mjs";

const agata = new AgataClient();
const [health, providers, targets] = await Promise.all([
  agata.health(),
  agata.listDatabaseProviders(),
  agata.listDatabaseTargets(),
]);

const runtimeConfig = createProviderRuntimeConfig("dynamodb", {
  host: "replace-with-your-provider-host",
});
console.log({ health, providers, targets, runtimeConfig });
```

Replace the host and add any provider-specific fields required by the complete guide (for example a DynamoDB table ARN, Cassandra datacenter, Elasticsearch distribution, or local SQLite storage settings). The SDK prepares the provider runtime configuration; the Engine and provider-side checks remain responsible for applying and verifying it.

## End-to-end Cloud workflow

1. Register the existing database as a target under **Dashboard → Databases** or with the shared SDK/CLI.
2. Enroll the customer-hosted Proxima Engine node and confirm its heartbeat.
3. Assign the database target to a node that advertises the matching provider runtime.
4. Create one tenant/database binding for each tenant and retain the one-time application credentials in your secret manager.
5. Deploy the desired configuration and wait for the Engine's applied revision and provider evidence.
6. Connect the application using its existing native database driver or client and the tenant-specific connection identity.
7. Run the positive and cross-tenant negative checks in this quickstart before routing production traffic.

Useful links: [Shared SDK and CLI downloads](https://agataproxima.com/developers/downloads) · [Cloud API reference](https://agataproxima.com/developers/api-reference) · [Engine provider runtime reference](PROVIDER_RUNTIME_REFERENCE.md).
