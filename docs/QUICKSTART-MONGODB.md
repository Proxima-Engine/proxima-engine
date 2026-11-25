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
