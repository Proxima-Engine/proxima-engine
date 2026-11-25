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


## 2A. Configure Redis ACLs

Create one Redis ACL user per tenant. Restrict each user to its generated tenant key namespace and only the commands required by the application. Do not use logical database numbers as the tenant security boundary. Do not give tenant users administrative commands, ACL management or access to another tenant's namespace.

The gateway registry maps each client principal to its tenant and upstream ACL identity. Keep the registry, gateway private key and upstream CA in protected secret storage; never commit them.

## 2B. Keep both TLS legs verified

Configure client-to-gateway TLS with the gateway certificate and key. Configure gateway-to-Redis TLS with the trusted CA and the upstream certificate's server name. Keep the gateway listener on a private interface reachable only by application services.

## 2C. Application connection

Use the application's existing Redis client and point it at the gateway. Authenticate with the tenant-specific gateway credential and enable TLS. The gateway enforces supported RESP2 commands and key namespace rewriting; do not assume unsupported commands or RESP3 behavior is automatically available.

## 2D. Acceptance checklist

- Tenant A keys are rewritten into Tenant A's assigned namespace.
- Tenant B keys are rewritten into Tenant B's assigned namespace.
- Cross-tenant key reads and writes are denied.
- Administrative and ACL commands are denied to tenant application identities.
- Both TLS legs validate their certificates.
- Credential rotation and revocation are tested.

See [Redis tenant gateway](REDIS_TENANT_GATEWAY.md) for the full ACL pattern, identity registry, Compose profile and command compatibility matrix.
