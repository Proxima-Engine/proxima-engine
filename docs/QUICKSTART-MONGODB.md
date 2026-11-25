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
