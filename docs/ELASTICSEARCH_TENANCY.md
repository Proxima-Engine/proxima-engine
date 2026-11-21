# Elasticsearch and OpenSearch tenant isolation

## Security model

Elasticsearch and OpenSearch do not provide SQL row-level security. Tenant isolation must use native security controls and index design. Proxima does not claim to add transparent SQL-style RLS.

The first implementation target is Elasticsearch native roles: each tenant receives a dedicated role and API key restricted to a tenant-specific index namespace. Where the exact distribution, version, and license support document-level security (DLS) and field-level security (FLS), apply a tenant filter and explicit field allowlist. DLS is defense in depth and does not replace index-level separation.

OpenSearch has a related but non-identical Security plugin API and feature matrix. The Engine now has a separate OpenSearch role-descriptor helper using `index_permissions`, explicit action names, DLS and FLS. It is not an API client or provisioning executor: a trusted control-plane integration must create the role and bind it to a tenant-specific backend role or API key. Never send Elasticsearch role descriptors to OpenSearch or assume feature/license parity. The Cloud catalog groups the family for discovery only; it does not mean both distributions are released.

## Required controls

- Use separate tenant index namespaces; never grant wildcard access to shared application indices.
- Create one least-privilege role and API key per tenant; never distribute administrator credentials to applications.
- Deny cluster administration, index lifecycle administration, snapshots, restore, cross-cluster search, scripts, and unrestricted aliases unless explicitly reviewed.
- Apply DLS to shared multi-tenant indices and FLS to sensitive fields only where supported by the deployed distribution/version/license.
- Validate aliases, data streams, rollover, reindex, update-by-query, bulk operations, ingest pipelines, search templates, aggregations, and cross-cluster features for bypasses.
- Bind authenticated tenant identity to server-side API-key selection. A client-supplied tenant ID is not authorization.
- Rotate and revoke tenant API keys independently. Keep administrator credentials in a secret manager.
- Require TLS with certificate verification.

## Release status

The Engine helper validates tenant identifiers and constructs a narrowly scoped Elasticsearch role descriptor. It is not a cluster client, provisioning executor, API-key issuer, runtime gateway, or OpenSearch adapter. Cloud remains catalog-only until exact distribution/version support, feature entitlements, role provisioning, API-key lifecycle, packaging, and real two-tenant acceptance are complete.

## Real-cluster acceptance script

Run the Elasticsearch-specific suite against a disposable HTTPS cluster with Security enabled and DLS/FLS features available in the deployed license. The script uses an administrator credential only to create temporary indices and two tenant API keys, then verifies index-level denial, shared-index DLS filtering, FLS redaction and denial of cluster privileges. It invalidates the API keys and deletes its test indices on exit.

```bash
export ELASTICSEARCH_URL='https://127.0.0.1:9200'
export ELASTICSEARCH_ADMIN_USER='elastic'
export ELASTICSEARCH_ADMIN_PASSWORD='<disposable-cluster-password>'
bash scripts/test-elasticsearch-tenant-isolation.sh
```

The script requires `curl` and `jq`; TLS certificate verification remains enabled. Use a disposable cluster only. It does not verify OpenSearch, which has a separate Security-plugin API and must be accepted independently.

## Acceptance matrix

For each supported distribution and exact version:

1. Create two tenants and independent role/API-key pairs.
2. Prove tenant A can read/write only its own index namespace.
3. Prove tenant A cannot read, aggregate, update, delete, reindex, or infer tenant B documents through aliases, data streams, bulk APIs, scripts, or alternate endpoints.
4. Verify field restrictions for search hits, aggregations, stored fields, doc values, and supported query surfaces.
5. Verify tenant credentials cannot administer cluster, indices, snapshots, users, roles, API keys, or security configuration.
6. Test key rotation, revocation, expired credentials, TLS validation, restart, and signed evidence.
7. Run the complete suite independently against Elasticsearch and OpenSearch. A pass on one is not evidence for the other.
