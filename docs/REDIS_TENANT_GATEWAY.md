# Redis tenant gateway

Proxima Engine provides a tenant-aware RESP2 gateway for Redis. Each client authenticates with a registry principal; the gateway binds the connection to that tenant, rewrites supported key arguments into the tenant namespace, and authenticates upstream using the tenant's Redis ACL identity. Client-to-gateway and gateway-to-Redis connections use TLS.

## Build

```powershell
cargo build --release -p proxima-engine --bin proxima-redis-gateway
```

## 1. Create the client identity registry

Create `secrets/redis-identities.json`:

```json
{
  "users": [
    {
      "username": "tenant_a_client",
      "tenant_id": "tenant-a",
      "client_password_sha256": "<sha256-of-client-password>",
      "upstream_username": "proxima_tenant_a",
      "upstream_password": "<tenant-a-redis-acl-secret>"
    }
  ]
}
```

Use a strong random client password and store only its SHA-256 verifier in the registry. Store the upstream ACL password in your secret manager. Give each tenant a unique username and upstream ACL identity.

The gateway accepts `AUTH password` (where the registry username is the default principal) or `AUTH username password`. Prefer the explicit username form.

## 2. Configure Redis ACLs

Create one upstream ACL user per tenant. Restrict its key pattern to that tenant's Proxima namespace and allow only the commands required by the application:

```text
ACL SETUSER proxima_tenant_a on >UPSTREAM_SECRET ~proxima:{TENANT_HASH}:* +get +set +del +exists +mget +mset +incr +expire +ttl +type
```

Use the exact namespace prefix generated for the tenant by the gateway. Do not grant administrative commands, `+@all`, keyspace-wide access, scripting or Pub/Sub. Logical database numbers are not an isolation boundary.

## 3. Set TLS and gateway configuration

Provide the following customer Compose secrets:

- `secrets/redis-gateway-cert.pem` — client-facing gateway certificate.
- `secrets/redis-gateway-key.pem` — matching private key.
- `secrets/redis-upstream-ca.pem` — CA bundle used to verify Redis upstream TLS.
- `secrets/redis-identities.json` — client identity and tenant ACL mapping.

Configure the upstream address and DNS name in the Engine environment:

```dotenv
PROXIMA_REDIS_UPSTREAM_ADDR=redis:6379
PROXIMA_REDIS_UPSTREAM_TLS_SERVER_NAME=redis
PROXIMA_REDIS_UPSTREAM_TLS_CA_FILE=/run/secrets/redis-upstream-ca.pem
PROXIMA_REDIS_TLS_CERT_FILE=/run/secrets/redis-gateway-cert.pem
PROXIMA_REDIS_TLS_KEY_FILE=/run/secrets/redis-gateway-key.pem
PROXIMA_REDIS_IDENTITY_REGISTRY=/run/secrets/redis-identities.json
```

The listener binds to loopback by default. Configure an externally reachable bind only behind the application's private network and explicit network controls.

## 4. Start the gateway

```bash
docker compose -f compose.customer.yaml --profile redis up -d redis-gateway
docker compose -f compose.customer.yaml logs -f redis-gateway
```

Connect your existing Redis client to the gateway's configured address with TLS and authenticate with its tenant principal. The gateway validates the principal and command key namespace before sending the operation upstream.

## Supported command surface

The gateway accepts RESP2 array/bulk-string requests, requires AUTH before data commands, and supports the explicit command allowlist in `src/redis_protocol.rs`. The allowlist covers selected string, hash, list, set, sorted-set, expiry, stream and multi-key operations.

RESP3, inline protocol, transactions, scripts/functions, Pub/Sub, blocking operations, arbitrary commands and administrative commands are not part of the gateway command surface. Check the source allowlist before selecting a Redis client feature.

## Credential rotation and revocation

Update the registry and secret-store entry, then restart the gateway to load the new client identity. Rotate the tenant's upstream Redis ACL password and update the registry as part of the same controlled change. To revoke access, disable/remove the upstream ACL user and remove the client identity binding; then restart the gateway and confirm the old principal is rejected.

## Verification

Run the Redis gateway integration script against a disposable Redis 7.4 TLS service:

```bash
cargo test -p proxima-engine redis
bash scripts/test-redis-tenant-gateway-ci.sh
```

The fixture verifies separate tenant key namespaces, multi-key rewriting, invalid client credentials and rejection of administrative commands.

## Clone, build and verify

Clone the Engine repository and enter its root:

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --release -p proxima-engine --bin proxima-redis-gateway
bash scripts/test-redis-tenant-gateway-ci.sh
```

## Cloud assignment

In **Agata Proxima Cloud → Dashboard → Databases**, register the existing Redis service, enroll an Engine node, assign the target to that node, create the tenant binding and deploy the configuration. The Engine activates the Redis runtime and reports the applied revision and tenant evidence to the workspace.
