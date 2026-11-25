# Redis quickstart

The RESP2 gateway authenticates each client principal, binds it to a tenant and rewrites supported keys into that tenant's namespace.

## 1. Clone and build

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --locked --release -p proxima-engine --bin proxima-redis-gateway
```

## 2. Prepare tenant ACLs and secrets

Start a disposable Redis 7.4 TLS service. Create one restricted upstream ACL user per tenant and limit each user to its own generated key namespace. Create `secrets/redis-identities.json`, gateway certificate/key and upstream CA files as shown in [Redis guide](REDIS_TENANT_GATEWAY.md).

## 3. Start the gateway

Set the upstream address, TLS server name, CA, gateway certificate/key and registry paths:

```bash
export PROXIMA_REDIS_UPSTREAM_ADDR=redis:6379
export PROXIMA_REDIS_UPSTREAM_TLS_SERVER_NAME=redis
export PROXIMA_REDIS_UPSTREAM_TLS_CA_FILE=/run/secrets/redis-upstream-ca.pem
export PROXIMA_REDIS_TLS_CERT_FILE=/run/secrets/redis-gateway-cert.pem
export PROXIMA_REDIS_TLS_KEY_FILE=/run/secrets/redis-gateway-key.pem
export PROXIMA_REDIS_IDENTITY_REGISTRY=/run/secrets/redis-identities.json
docker compose -f compose.customer.yaml --profile redis up -d redis-gateway
docker compose -f compose.customer.yaml logs -f redis-gateway
```

## 4. Verify

Connect each tenant's Redis client over TLS with its own credentials. Run `bash scripts/test-redis-tenant-gateway-ci.sh` against the disposable Redis fixture and verify cross-tenant key access and administrative commands are rejected.

**Next:** [Complete Redis guide](REDIS_TENANT_GATEWAY.md) · [Deployment](DEPLOYMENT.md)
