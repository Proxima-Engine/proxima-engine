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
