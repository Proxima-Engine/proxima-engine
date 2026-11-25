# Apache Cassandra quickstart

Proxima creates a keyspace and restricted Cassandra login role per tenant. Cassandra enforces access to each tenant's own keyspace.

## 1. Clone and build

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --locked --release -p proxima-engine
```

## 2. Generate tenant provisioning CQL

```rust
use proxima_engine::cassandra_tenant::CassandraTenant;

let tenant = CassandraTenant::new("customer_01", &generated_secret)?;
let statements = tenant.provisioning_cql("datacenter1", 1)?;
```

Execute statements only through a trusted provisioning session. RF=1 is for a single-node development cluster; set production replication to the actual replica count in each datacenter. Give tenant roles SELECT and MODIFY only on their own keyspace.

## 3. Verify

```bash
bash scripts/test-cassandra-tenant-isolation-ci.sh
```

The acceptance test provisions two tenant roles, checks tenant-local CRUD and confirms cross-keyspace reads are denied. Repeat against the actual production topology and validate TLS, replication and backup/restore.

**Next:** [Complete Cassandra guide](CASSANDRA_TENANCY.md) · [Operations](OPERATIONS.md)


## 2A. Prepare the Cassandra service

Use a disposable Cassandra cluster for the first run. Confirm that the cluster is reachable from the machine running the provisioning client and note the datacenter name returned by `nodetool status` or the cluster metadata. The example uses `datacenter1`; replace it with the actual datacenter name.

Before generating tenant CQL, enable Cassandra authentication and authorization (PasswordAuthenticator and CassandraAuthorizer, or an approved enterprise identity integration). The provisioning session must be an administrative identity held outside application configuration.

## 2B. Review the generated tenant grants

The generated CQL creates a tenant-specific keyspace and login role. Execute it only through the trusted provisioning session. Inspect the statements before applying them. Each application role must have SELECT and MODIFY on its own keyspace only; it must not receive AUTHORIZE, CREATE, ALTER, DROP or cluster administration privileges.

For a multi-node cluster, use the real replica count for every datacenter in the NetworkTopologyStrategy configuration. RF=1 is only suitable for a single-node local test. A keyspace is a logical boundary within a cluster, not a separate cluster or failure domain.

## 2C. Connect the application

Configure the Cassandra driver with the tenant-specific login, password, contact points and TLS trust configuration. Resolve the tenant on the trusted application backend and select that tenant's credentials there. Do not let a browser or untrusted request select arbitrary keyspaces or supply provisioning credentials.

## 2D. Acceptance checklist

- Tenant A can create, read, update and delete records in its own keyspace.
- Tenant B can perform the same operations in its own keyspace.
- Tenant A cannot read or modify Tenant B's keyspace.
- Tenant application roles cannot grant permissions or administer schemas.
- TLS, replication, backup and restore are verified for the target topology.

For the complete Rust module behavior, generated CQL and operational constraints, see [Cassandra tenant isolation](CASSANDRA_TENANCY.md).
