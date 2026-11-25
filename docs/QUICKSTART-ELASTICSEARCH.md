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
