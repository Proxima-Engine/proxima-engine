# Security architecture and deployment requirements

Proxima Engine places verified tenant identity at the PostgreSQL connection boundary. It validates signed tenant context, maps each verified tenant to a PostgreSQL role, and establishes a tenant-bound upstream session. PostgreSQL grants and Row-Level Security (RLS) enforce the database permissions for that role.

This guide describes the Engine controls, their activation settings, and the operational configuration required to use them.

## Implemented security controls

- **Signed tenant context:** when `PROXIMA_TENANT_SIGNING_KEY` or `PROXIMA_TENANT_SIGNING_KEY_FILE` is configured, the Engine requires a valid, unexpired HMAC-SHA256 tenant token during PostgreSQL startup. Prefer the file setting with a mounted secret in customer deployments. Missing, malformed, expired, and incorrectly signed tokens are rejected.
- **Tenant-specific role routing:** the verified tenant ID is mapped through `PROXIMA_TENANT_ROLE_PREFIX` to the corresponding PostgreSQL login role. Each accepted Engine client session has its own upstream PostgreSQL session.
- **PostgreSQL authorization:** tenant roles operate under PostgreSQL grants and RLS policies. Use non-superuser roles without `BYPASSRLS`, and apply `FORCE ROW LEVEL SECURITY` where the schema requires it.
- **Client and upstream TLS:** configure the client certificate/key pair and set `PROXIMA_TLS_REQUIRE_CLIENT=true` to reject plaintext client connections. Configure upstream `verify-full` with a trusted CA and expected server name.
- **Resource controls:** connection limits, upstream connect timeouts, and TLS handshake timeouts are configurable and validated.
- **Violation breaker:** repeated protocol or tenant-security violations can block a peer for a configured cooldown. See [Configuration](CONFIGURATION.md).
- **Emergency access:** break-glass tokens are signed, short-lived (maximum 15 minutes), and protected against replay through a persistent nonce store.
- **Attestation:** configured records are written to a hash-linked local ledger and signed with the configured signing credential.
- **Observability:** local health/status endpoints and Prometheus metrics expose process and connection telemetry.

## Tenant-isolation and pooling verification

The repository includes PostgreSQL-backed integration tests for tenant authentication, tenant-specific reads, denied cross-tenant reads, denied cross-tenant writes, and invalid tenant-token rejection.

The dedicated [PgBouncer tenant-pool integration test](../scripts/test-pgbouncer-pooling.sh) starts the local Compose stack and verifies five sequential connections per tenant role. Each tenant reuses its own backend PID, while Tenant A and Tenant B use separate PostgreSQL roles and distinct backend PIDs. The test also checks cross-tenant read/write denial and missing/invalid token rejection. GitHub Actions runs this test on pushes to `main` and pull requests targeting `main`.

The Engine keeps each accepted client connection bound to its own upstream session. When PgBouncer is used, the tenant-specific PostgreSQL role is part of the pool identity, keeping the two tenant roles in separate pools.

## Required deployment configuration

- [ ] Pin and review the exact source commit or container image digest.
- [ ] Mount the tenant signing key as a secret file and set `PROXIMA_TENANT_SIGNING_KEY_FILE`; verify that tenant-token enforcement is active in the Engine status output.
- [ ] Issue short-lived tenant tokens only from a trusted backend after authenticating the user and authorizing tenant membership.
- [ ] Use non-superuser PostgreSQL tenant roles without `BYPASSRLS`.
- [ ] Apply and test RLS policies for every tenant-scoped table and relevant read/write operation.
- [ ] Remove alternate privileged database paths that bypass the intended tenant boundary.
- [ ] Configure client TLS and verified upstream TLS for the deployment's network trust model.
- [ ] Restrict PostgreSQL, Engine, status, and metrics listeners to their intended callers.
- [ ] Keep node identity files, signing keys, database passwords, and enrollment tokens in protected secret storage.
- [ ] Persist and protect node identity, replay state, and attestation ledger data.
- [ ] Test restarts, upstream outages, token expiry, connection exhaustion, secret rotation, and recovery.
- [ ] Run the procedures in [Verification](VERIFICATION.md) and [Deployment](DEPLOYMENT.md).

## Configuration facts operators must know

- Tenant-token enforcement activates when `PROXIMA_TENANT_SIGNING_KEY` is configured. Without that key, the Engine runs without requiring tenant tokens; enable it for tenant-aware traffic.
- PostgreSQL superusers and roles with `BYPASSRLS` can bypass ordinary RLS policies. Tenant roles must use least privilege.
- The embedded status page and metrics listener do not authenticate callers. Keep them on loopback or behind a separately authenticated private monitoring layer.
- The attestation latency value is operator-supplied; record benchmark measurements separately from Engine-generated evidence.
- The local attestation ledger is hash-linked and signed. Protect the ledger, signing key, host, and backups with appropriate access controls.
- CI reports the result of the configured automated tests for a commit. Deployment configuration, database policies, network controls, and operational procedures must be verified in the target environment.

## Report a vulnerability

Email **[support@agataproxima.com](mailto:support@agataproxima.com)** with the subject **Private Security Report — Proxima Engine**. Do not publish exploitable details in public issues or pull requests. Include the affected commit, impact, and safe reproduction steps; do not attach live credentials, signing keys, customer records, or unredacted tenant data.

See the repository [Security Policy](../SECURITY.md) for the reporting process.
