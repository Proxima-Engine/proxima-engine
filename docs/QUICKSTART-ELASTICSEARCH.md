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
