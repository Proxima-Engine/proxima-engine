# Elasticsearch and OpenSearch quickstart

The Engine uses native security APIs to create tenant identities and index-scoped permissions. Run the two distributions' checks independently.

## 1. Clone and build

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --locked --release -p proxima-engine
```

## 2. Prepare tenant roles

Use a disposable HTTPS cluster for the selected distribution. Create a dedicated tenant role and index namespace per tenant. Keep cluster/security administration outside application identities. Apply DLS/FLS only where supported by the selected distribution, version and license. Keep certificate verification enabled.

## 3. Verify Elasticsearch

```bash
bash scripts/test-elasticsearch-tenant-isolation.sh
```

## 4. Verify OpenSearch

```bash
bash scripts/test-opensearch-tenant-isolation.sh
```

Both scripts require disposable HTTPS clusters and administrator credentials. They check tenant-local access, cross-index denial, document/field controls where supported and cluster privilege denial.

**Next:** [Complete Elasticsearch/OpenSearch guide](ELASTICSEARCH_TENANCY.md) · [Security](SECURITY.md)


## 2A. Prepare the HTTPS cluster

Use a disposable Elasticsearch or OpenSearch HTTPS cluster. Record the exact distribution, version, endpoint, CA certificate and administrator credential location. Keep TLS certificate verification enabled. Do not use a public unauthenticated endpoint or production cluster for the first acceptance run.

## 2B. Create tenant namespaces and roles

Create a distinct index namespace and tenant role for each tenant. Scope index permissions to only that tenant's namespace. Keep cluster administration, snapshot/restore, index administration and security administration outside tenant application roles.

Document-level security (DLS) and field-level security (FLS) depend on the selected distribution, version and license. Apply them only when supported and verify the effective role descriptor on the actual service. Index-level separation remains the primary boundary in this quickstart.

## 2C. Configure the trusted application

The trusted backend authenticates the user, resolves tenant membership and selects the matching tenant credential. Do not expose administrator credentials, API keys or tenant role secrets in browser code. Configure the application's existing Elasticsearch or OpenSearch client to use the tenant-scoped endpoint/credential and verify the server certificate.

## 2D. Acceptance checklist

- Tenant A can read and write only its assigned indices.
- Tenant B can read and write only its assigned indices.
- Cross-tenant index requests are denied.
- DLS/FLS behavior is verified only where supported by the chosen distribution.
- Cluster and security administration are denied to tenant application roles.
- TLS verification and credential rotation are tested.

Run both distribution-specific scripts against their own disposable clusters. See [Elasticsearch / OpenSearch tenant isolation](ELASTICSEARCH_TENANCY.md) for the role model and deployment workflow.


## Windows PowerShell: clone and build

Install Git, stable Rust/Cargo and the Elasticsearch or OpenSearch client tools. Use a disposable HTTPS cluster for acceptance.

```powershell
git clone https://github.com/Proxima-Engine/proxima-engine.git
Set-Location .\proxima-engine
cargo build --locked --release -p proxima-engine
if ($LASTEXITCODE -ne 0) { throw "Proxima build failed" }
```

If the repository is already extracted, enter its root folder rather than cloning another copy. Keep cluster administrator credentials and CA files outside source control.

## Configure the distribution explicitly

Do not assume Elasticsearch and OpenSearch have identical security APIs. Record which distribution and version you are testing, its HTTPS endpoint, CA certificate and administrator credential source. Create a separate tenant index namespace and role for each tenant. Keep the cluster administrator identity out of application configuration.

## Runtime diagnostics

Before running the acceptance script, verify that the cluster responds over HTTPS and that the configured CA validates the endpoint certificate. A TLS error is a trust-chain or server-name issue; do not disable verification. An authorization failure should be investigated by inspecting the effective tenant role and index permissions, not by granting broad cluster privileges.

## Production handover checklist

- Run the Elasticsearch and OpenSearch acceptance scripts independently against their matching distributions.
- Verify tenant-local access and cross-index denial for both tenants.
- Verify DLS/FLS only where supported by the selected distribution, version and license.
- Confirm tenant roles cannot administer clusters, security settings, snapshots or unrelated indices.
- Keep administrator credentials in a secret manager and rotate tenant credentials through the approved lifecycle.
- Record provider version, Engine release, role descriptors, test results and configuration revision.
- Monitor rejected requests, TLS errors, credential rotation and index permission changes.

See [Elasticsearch / OpenSearch tenant isolation](ELASTICSEARCH_TENANCY.md) for distribution-specific security API behavior and cloud assignment.


## Use the shared Agata Proxima SDK and CLI

The SDK and `agata` CLI are shared across all twelve database providers. You do not install a separate SDK or CLI for Elasticsearch or OpenSearch. Download the integration starter kit from the public developer downloads page and extract it.

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

Set the Cloud API origin and organization-scoped API key in the trusted backend environment or secret manager. Never expose the key in browser code, source control, command-line arguments or logs.

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

For PowerShell, set `$env:AGATA_API_BASE_URL` and `$env:AGATA_API_KEY`. Create a reviewed private `target.json` for the selected distribution and use `agata databases targets create target.json`. Assign it with `agata databases targets assign TARGET_ID NODE_ID`, create a tenant binding with `agata databases bindings create binding.json`, and inspect deployment and verification records. Use the full guide for the exact Elasticsearch/OpenSearch distribution and role fields.

The same JavaScript SDK is available to trusted Node.js services:

```js
import { AgataClient, createProviderRuntimeConfig } from "./node/agata-client.mjs";

const agata = new AgataClient();
const [health, providers, targets] = await Promise.all([
  agata.health(),
  agata.listDatabaseProviders(),
  agata.listDatabaseTargets(),
]);
const runtimeConfig = createProviderRuntimeConfig("elasticsearch", {
  host: "search.example.internal",
  distribution: "elasticsearch",
});
console.log({ health, providers, targets, runtimeConfig });
```

## End-to-end Cloud workflow

1. Register the HTTPS search cluster and selected distribution as a database target.
2. Enroll the customer-hosted Engine node and confirm its signed heartbeat.
3. Assign the target to a node advertising the native search runtime.
4. Create one tenant binding per tenant with a distinct index namespace and identity.
5. Deploy the desired configuration and wait for applied revision and provider evidence.
6. Connect the application using its existing Elasticsearch or OpenSearch client with the tenant-specific credentials.
7. Run the matching distribution-specific positive and cross-tenant negative acceptance script before production.

Useful links: [Shared SDK and CLI downloads](https://agataproxima.com/developers/downloads) · [Cloud API reference](https://agataproxima.com/developers/api-reference) · [Engine provider runtime reference](PROVIDER_RUNTIME_REFERENCE.md).
