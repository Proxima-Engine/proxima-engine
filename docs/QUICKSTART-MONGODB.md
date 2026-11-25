# MongoDB quickstart

The MongoDB gateway binds each authenticated SCRAM-SHA-256 principal to one tenant database.

## 1. Clone and build

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --locked --release -p proxima-engine --bin proxima-mongodb-gateway
```

## 2. Prepare tenant identities

Start a disposable MongoDB standalone service. Create one database and least-privilege user per tenant. Create `secrets/mongodb-identities.json` using the registry schema in [MongoDB guide](MONGODB_TENANT_ISOLATION.md). Prepare the gateway certificate/key and upstream CA files.

## 3. Configure and start

```bash
export PROXIMA_MONGODB_LISTEN_ADDR=127.0.0.1:27018
export PROXIMA_MONGODB_UPSTREAM_ADDR=127.0.0.1:27017
export PROXIMA_MONGODB_IDENTITY_REGISTRY=./secrets/mongodb-identities.json
export PROXIMA_MONGODB_TLS_CERT_FILE=./secrets/gateway-cert.pem
export PROXIMA_MONGODB_TLS_KEY_FILE=./secrets/gateway-key.pem
export PROXIMA_MONGODB_UPSTREAM_TLS=true
export PROXIMA_MONGODB_UPSTREAM_TLS_CA_FILE=./secrets/mongodb-ca.pem
./target/release/proxima-mongodb-gateway
```

Use the configured TLS server name and verify the upstream certificate. The customer Compose `mongodb` profile is also documented in the full guide.

## 4. Verify

Connect with a MongoDB driver using TLS and `directConnection=true`. Run `bash scripts/test-mongodb-tenant-isolation-ci.sh` against the disposable service to verify authentication, database binding, cross-database denial and rejected unsupported commands.

**Next:** [Complete MongoDB guide](MONGODB_TENANT_ISOLATION.md) · [Deployment](DEPLOYMENT.md)


## 2A. Create tenant database users

Create one MongoDB database and one upstream user per tenant. Assign each user a role scoped to its own database. Do not grant `root`, `readWriteAnyDatabase`, `dbAdminAnyDatabase` or cluster-wide privileges. The gateway identity registry contains the client username, tenant ID, database and auth source; it does not store upstream passwords.

A tenant maps to exactly one database, and one database cannot be assigned to multiple tenant IDs. Review the registry before starting the gateway.

## 2B. Configure TLS and Compose

Client-to-gateway TLS is mandatory. Mount the gateway certificate and private key, and configure the upstream CA file and certificate server name. The optional customer Compose `mongodb` profile is available for deployments that use the repository's customer Compose file. Create all referenced secret files before starting that profile.

## 2C. Application connection

Use the application's existing MongoDB driver pointed at the gateway. Enable TLS and `directConnection=true`; use the assigned tenant username and its upstream password. Resolve tenant membership on the trusted backend and select the matching credential. Do not expose tenant credentials or registry contents to browser clients.

## 2D. Acceptance checklist

- SCRAM-SHA-256 succeeds for an assigned tenant principal.
- The authenticated principal is bound to its configured database.
- Cross-database commands are denied.
- Unsupported commands and topology information that could bypass the boundary are rejected or sanitized as specified in the full guide.
- Client TLS and verified upstream TLS both succeed.
- Upstream MongoDB roles are database-scoped and least-privilege.

See [MongoDB tenant isolation](MONGODB_TENANT_ISOLATION.md) for the registry schema, complete Compose secret list, supported command behavior and test details.


## Windows PowerShell: clone and build

Open PowerShell in the folder where you keep source repositories. Install Git, the stable Rust toolchain and Cargo first. For gateway providers, Docker Desktop is also required for the disposable database service used by the acceptance test.

```powershell
git clone https://github.com/Proxima-Engine/proxima-engine.git
Set-Location .\proxima-engine
cargo build --locked --release -p proxima-engine --bin proxima-mongodb-gateway
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
