# Apache Cassandra tenant isolation

## Support model

Proxima uses keyspace-per-tenant isolation with a dedicated Cassandra login role for each tenant. Applications connect through the Cassandra driver using tenant-specific credentials; Cassandra enforces the role and keyspace permissions.

A trusted provisioning identity creates one keyspace and one login role per tenant. The role receives SELECT and MODIFY only on its own keyspace. It receives no AUTHORIZE permission or schema-administration grants. Applications connect with tenant-specific credentials and never receive the provisioning identity.

## Rust provisioning profile

The implementation is proxima_engine::cassandra_tenant::CassandraTenant. It validates tenant identifiers and strong passwords, derives a tenant-specific keyspace and role, escapes password quotes, and generates NetworkTopologyStrategy keyspace DDL plus restricted grants.

Example:

    use proxima_engine::cassandra_tenant::CassandraTenant;
    let tenant = CassandraTenant::new("customer_01", &generated_secret)?;
    let statements = tenant.provisioning_cql("datacenter1", 3)?;
    // Execute only through a trusted Cassandra provisioning session.

Set the replication factor to the actual replica count in each configured datacenter. Use RF=1 for a single-node development cluster. Set the production replication factor to the actual replica count in each datacenter.

## Operational boundary

Enable Cassandra PasswordAuthenticator and CassandraAuthorizer (or an approved enterprise identity integration). Keep tenant roles out of privileged groups, do not grant cross-keyspace permissions, and do not expose provisioning credentials to application processes. Restrict network access and require TLS in production.

A keyspace is a logical isolation boundary inside a cluster, not a separate cluster, encryption key or independent failure domain. Higher-assurance workloads may require separate clusters.

## Verification

Unit tests cover tenant-specific keyspace and role generation, password escaping, identifier injection rejection and least-privilege grants. The real Cassandra acceptance test provisions two tenant roles, verifies tenant-local CRUD and verifies cross-keyspace reads are denied. For production, run the same acceptance flow against the deployment's multi-node topology and verify TLS, backup/restore and operational procedures.

## Clone, build and verify

Clone the Engine repository and enter its root:

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --release -p proxima-engine
bash scripts/test-cassandra-tenant-isolation-ci.sh
```

## Cloud assignment

In **Agata Proxima Cloud → Dashboard → Databases**, register the existing Apache Cassandra service, enroll an Engine node, assign the target to that node, configure its datacenter and replication factor, create the tenant binding and deploy the configuration. The Engine provisions or verifies the tenant keyspace and role, then reports the applied revision and tenant evidence to the workspace.
