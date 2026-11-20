# Developer evaluation

Agata Proxima provides security infrastructure for multi-tenant PostgreSQL applications. Proxima Engine is the open-source Rust PostgreSQL-protocol gateway that verifies signed tenant context and routes each session to a tenant-specific database role.

## Evaluate the Engine

Start with the [Quickstart](QUICKSTART.md) to launch the local stack and execute a real SQL query through the Engine. Then follow the [Tenant isolation guide](TENANT_ISOLATION.md) to create two PostgreSQL roles, configure Row-Level Security, and verify tenant-specific access.

The repository's verification material includes:

- Successful Tenant A and Tenant B authentication through the Engine.
- Tenant-specific reads that return only the authorized tenant's row.
- Cross-tenant reads that return zero rows.
- Cross-tenant writes rejected by PostgreSQL RLS.
- Rejection of missing or invalid signed tenant context when enforcement is enabled.
- PgBouncer transaction-pooling evidence showing backend reuse within each tenant role and separate backend process identities across the two tenant roles.

Review the exact commands and observed results in [Tenant isolation](TENANT_ISOLATION.md), [Verification](VERIFICATION.md), and [PgBouncer evidence](../evidence/pgbouncer-transaction-pooling.txt).

## Explore the implementation

- [Architecture](ARCHITECTURE.md) — request flow, tenant context, role mapping, and source layout.
- [Configuration](CONFIGURATION.md) — runtime settings and secure defaults.
- [Driver integrations](INTEGRATIONS.md) — existing PostgreSQL drivers for Node.js, Python, Rust, and psql.
- [Deployment](DEPLOYMENT.md) — container deployment, TLS, networking, and persistence.
- [Security model](SECURITY.md) — implemented controls and operational configuration.

## Participate

[Star or follow the Engine](https://github.com/Proxima-Engine/proxima-engine) to track changes. Use [GitHub Issues](https://github.com/Proxima-Engine/proxima-engine/issues) for reproducible bugs, driver compatibility reports, and improvement requests. Read [Contributing](../CONTRIBUTING.md) before submitting a pull request. Report vulnerabilities privately through the repository [Security Policy](../SECURITY.md).

## Project resources

- Website: https://agataproxima.com
- Engine: https://github.com/Proxima-Engine/proxima-engine
- [Discord community](https://discord.gg/xsYSuDMzg)
