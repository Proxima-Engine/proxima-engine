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
