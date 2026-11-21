# Elasticsearch and OpenSearch tenant isolation

## Security model

Elasticsearch and OpenSearch do not provide SQL row-level security. Tenant isolation must use native security controls and index design. Proxima does not claim to add transparent SQL-style RLS.

The first implementation target is Elasticsearch native roles: each tenant receives a dedicated role and API key restricted to a tenant-specific index namespace. Where the exact distribution, version, and license support document-level security (DLS) and field-level security (FLS), apply a tenant filter and explicit field allowlist. DLS is defense in depth and does not replace index-level separation.

OpenSearch has a related but non-identical Security plugin API and feature matrix. It requires a separately reviewed role-mapping/backend-role adapter. Never send Elasticsearch role descriptors to OpenSearch or assume feature/license parity. The Cloud catalog groups the family for discovery only; it does not mean both distributions are released.

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

## Acceptance matrix

For each supported distribution and exact version:

1. Create two tenants and independent role/API-key pairs.
2. Prove tenant A can read/write only its own index namespace.
3. Prove tenant A cannot read, aggregate, update, delete, reindex, or infer tenant B documents through aliases, data streams, bulk APIs, scripts, or alternate endpoints.
4. Verify field restrictions for search hits, aggregations, stored fields, doc values, and supported query surfaces.
5. Verify tenant credentials cannot administer cluster, indices, snapshots, users, roles, API keys, or security configuration.
6. Test key rotation, revocation, expired credentials, TLS validation, restart, and signed evidence.
7. Run the complete suite independently against Elasticsearch and OpenSearch. A pass on one is not evidence for the other.
