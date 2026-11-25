# Elasticsearch and OpenSearch tenant isolation

## Integration model

Proxima Engine manages tenant identities and index permissions through the native security APIs of Elasticsearch and OpenSearch. The Cloud assignment selects the distribution, and the Engine uses the corresponding REST client and role descriptor.

Each tenant receives a dedicated identity and index namespace. Apply document-level security (DLS) and field-level security (FLS) where supported by the deployed distribution, version and license. Keep index-level separation as the primary boundary for tenant data.

## Clone, build and run

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --release -p proxima-engine
bash scripts/test-elasticsearch-tenant-isolation.sh
bash scripts/test-opensearch-tenant-isolation.sh
```

The two acceptance scripts exercise their respective security APIs independently. Each requires a disposable HTTPS cluster, administrator credentials, `curl`, `jq` and TLS certificate verification.

## Cloud assignment

1. Register the Elasticsearch or OpenSearch endpoint in **Dashboard → Databases**.
2. Select the distribution in the provider runtime configuration.
3. Supply the service administrator identity through the encrypted target credential record.
4. Assign the target to an enrolled Engine node.
5. Create one tenant binding per tenant, using the tenant-specific index namespace and identity reference.
6. Deploy the assignment. Engine creates or verifies tenant roles and credentials, checks the index permissions and reports the applied revision and binding evidence.

## Tenant security controls

- Use a separate tenant index namespace and a dedicated tenant role or API credential.
- Scope index permissions to the tenant's own indices.
- Apply DLS and FLS to shared-index patterns where the selected distribution supports them.
- Keep cluster administration, index administration, snapshots, restore and security administration outside application identities.
- Bind the selected tenant identity on the trusted server side.
- Require HTTPS with certificate verification for the Engine-to-cluster connection.
- Rotate and revoke tenant credentials through the Cloud assignment lifecycle.

## Verification

Run both acceptance scripts against disposable clusters. The Elasticsearch suite checks tenant-local access, cross-index denial, DLS filtering, FLS redaction and cluster privilege denial. The OpenSearch suite checks its Security-plugin role, backend-role mapping, tenant-local access, cross-index denial, DLS filtering, FLS redaction and cluster privilege denial.

## Application connection

Applications continue using the Elasticsearch or OpenSearch client. Resolve the authenticated tenant on the trusted backend and select the corresponding tenant credential. Keep administrator credentials in a secret manager and never expose them to browser clients.
