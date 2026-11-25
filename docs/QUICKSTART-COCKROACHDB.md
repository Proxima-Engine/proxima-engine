# CockroachDB quickstart

CockroachDB uses the Engine's PostgreSQL wire listener. Your application keeps its PostgreSQL-compatible driver.

## 1. Clone and build

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --locked --release -p proxima-engine --bin proxima-engine
```

## 2. Configure the CockroachDB endpoint

```dotenv
PROXIMA_LISTEN_ADDR=127.0.0.1:6432
PROXIMA_UPSTREAM_ADDR=cockroach.example:26257
PROXIMA_TENANT_ROLE_PREFIX=proxima_tenant_
PROXIMA_UPSTREAM_TLS_MODE=verify-full
PROXIMA_UPSTREAM_TLS_CA_FILE=/etc/proxima/tls/cockroach-ca.pem
PROXIMA_UPSTREAM_TLS_SERVER_NAME=cockroach.example
```

Create non-admin tenant roles and forced row-level-security policies as described in [CockroachDB guide](COCKROACHDB_COMPATIBILITY.md). Do not use root or cluster-admin credentials for tenant traffic.

## 3. Run and verify

```bash
RUST_LOG=info cargo run --release -p proxima-engine
bash scripts/test-cockroachdb-tenant-isolation-ci.sh
```

The acceptance script provisions a disposable CockroachDB 25.2 node and verifies tenant-local operations, cross-tenant filtering/write rejection and invalid-token rejection. Connect clients to `127.0.0.1:6432` with the signed tenant startup parameter described in the guide.

**Next:** [Complete CockroachDB guide](COCKROACHDB_COMPATIBILITY.md) · [Tenant isolation](TENANT_ISOLATION.md)


## 2A. Provision database-side tenant roles

Create one non-admin role per tenant using the `PROXIMA_TENANT_ROLE_PREFIX` naming convention and the normalized tenant identifier. Do not use `root`, cluster-admin, table-owner or any role that bypasses row-level security for application traffic.

For every tenant-bearing shared table, enable and force row-level security. Add tenant-specific `USING` and `WITH CHECK` policies, grant only required schema/table privileges and ensure views, functions, join targets and related tables do not expose cross-tenant data.

## 2B. Configure signed tenant context

The trusted backend issues a short-lived signed Proxima tenant token for the authenticated tenant and supplies it through the documented PostgreSQL startup parameter `proxima_tenant_token` (or the supported PGOPTIONS form). Do not accept an unsigned tenant label from the browser. Configure the upstream CA and certificate server name so CockroachDB TLS is verified.

## 2C. Application connection

Keep the existing PostgreSQL-compatible driver. Point it at the Proxima PostgreSQL listener, not directly at the CockroachDB SQL endpoint. The application must follow CockroachDB's transaction retry protocol for SQLSTATE `40001`; do not blindly replay arbitrary transactions in the proxy.

## 2D. Acceptance checklist

- Tenant A and Tenant B can access their own rows.
- Cross-tenant reads are filtered and cross-tenant writes are rejected.
- Missing, expired and invalid tenant tokens are rejected.
- Tenant roles cannot bypass RLS or administer the cluster.
- Upstream TLS validates the CockroachDB certificate.
- Transaction retry behavior is tested by the application.

See [CockroachDB compatibility guide](COCKROACHDB_COMPATIBILITY.md) for policy examples, transaction semantics and the complete real-service acceptance workflow.


## Windows PowerShell: clone and build

Open PowerShell in the folder where you keep source repositories. Install Git, the stable Rust toolchain and Cargo first. For gateway providers, Docker Desktop is also required for the disposable database service used by the acceptance test.

```powershell
git clone https://github.com/Proxima-Engine/proxima-engine.git
Set-Location .\proxima-engine
cargo build --locked --release -p proxima-engine --bin proxima-engine
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
