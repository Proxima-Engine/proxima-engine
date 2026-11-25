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


## Windows PowerShell: clone and build

Open PowerShell in the folder where you keep source repositories. Install Git, the stable Rust toolchain and Cargo first. For gateway providers, Docker Desktop is also required for the disposable database service used by the acceptance test.

```powershell
git clone https://github.com/Proxima-Engine/proxima-engine.git
Set-Location .\proxima-engine
cargo build --locked --release -p proxima-engine
if ($LASTEXITCODE -ne 0) { throw "Proxima build failed" }
```

Run the command from the repository root. If you already cloned the repository, use `Set-Location` to enter the extracted `proxima-engine` directory instead of cloning a second copy. Keep generated credentials, certificates and local environment files outside Git.

## Configuration review before starting

Before launching this provider, verify all of the following against the full provider guide:

1. The provider endpoint, port and distribution/version identify the intended disposable or customer database.
2. Tenant IDs are resolved by the trusted application backend and are not accepted as authorization claims from a browser.
3. Each tenant has its own database/schema/keyspace/index namespace or IAM identity, as applicable to this provider.
4. Provisioning credentials are separate from tenant application credentials and are not stored in the client registry as plaintext.
5. Certificate authorities, server names and client certificates are configured for every network TLS leg.
6. Listener exposure is limited to the application network. Keep local tests on loopback.
7. Registry files and private keys have restrictive permissions and are excluded from source control.

## Runtime diagnostics

Start the provider process in a dedicated terminal and keep its logs visible while connecting a test client. Confirm the process is listening on the configured address before running application queries. If the client cannot connect, check the process output, port binding, upstream reachability and the database service's readiness before changing tenant policy.

If authentication fails, compare the client principal and tenant mapping with the registry or native provider identity. If a certificate error occurs, validate the configured CA and server name; do not disable certificate verification to make the connection succeed. If a cross-tenant test succeeds unexpectedly, stop the test and review the provider-native grants, namespace mapping and trusted tenant-resolution path before continuing.

## Production handover checklist

- Repeat the acceptance suite against a disposable instance matching the intended provider version.
- Record the exact provider version, Engine release, configuration revision and test result.
- Test allowed tenant operations and denied cross-tenant reads and writes.
- Verify backup/restore and credential rotation for the provider's isolation model.
- Move secrets into the deployment secret manager and enable verified TLS.
- Restrict network access to the Engine and database endpoints.
- Monitor Engine health, provider errors, rejected sessions and credential lifecycle.
- Use the linked complete provider guide for deployment-specific settings and operational procedures.
