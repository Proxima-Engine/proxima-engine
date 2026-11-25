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


## Windows PowerShell: clone and build

Open PowerShell in the folder where you keep source repositories. Install Git, the stable Rust toolchain and Cargo first. For gateway providers, Docker Desktop is also required for the disposable database service used by the acceptance test.

```powershell
git clone https://github.com/Proxima-Engine/proxima-engine.git
Set-Location .\proxima-engine
cargo build --locked --release -p proxima-engine --bin proxima-redis-gateway
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
