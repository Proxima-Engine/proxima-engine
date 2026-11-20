# Support and issue reporting

Use the route that matches the request.

## Technical documentation

- [Quickstart](QUICKSTART.md) — start the Engine and query PostgreSQL.
- [Configuration](CONFIGURATION.md) — environment variables and defaults.
- [Operations](OPERATIONS.md) — logs, health checks, and troubleshooting.
- [Tenant isolation](TENANT_ISOLATION.md) — tenant roles, signed context, and RLS verification.

## Public Engine issues

Use [GitHub Issues](https://github.com/Proxima-Engine/proxima-engine/issues) for reproducible Engine bugs, driver integration problems, documentation corrections, and feature requests.

Include:

- Engine version or exact commit SHA.
- Operating system, container runtime, and Rust version where relevant.
- Exact command or request, sanitized response, and expected behavior.
- Configuration variable names, without secret values.
- A minimal reproduction using synthetic data.

## Support, hosted account, and billing

For technical support, hosted account, organization, node-management, plan, and billing questions, email **[support@agataproxima.com](mailto:support@agataproxima.com)** or visit the official [Agata Proxima website](https://agataproxima.com).

The hosted product is separate from the public Engine issue tracker.

## Security reports

For a suspected vulnerability in the public Engine, email **[support@agataproxima.com](mailto:support@agataproxima.com)** with the subject **Private Security Report — Proxima Engine**. Do not publish exploitable details in public issues or pull requests. Include the affected commit, impact, and safe reproduction steps; do not attach live credentials, signing keys, customer records, or unredacted tenant data.

See the repository [Security Policy](../SECURITY.md).

## Information to keep private

Never include passwords, signing keys, access tokens, payment data, customer records, private keys, or unredacted tenant logs in a public support request or issue.

## First checks

1. Check the [health and status routes](API.md).
2. Confirm the upstream PostgreSQL host, port, database, and credentials.
3. Check DNS and connectivity from the Engine runtime.
4. Compare environment variable names with [Configuration](CONFIGURATION.md).
5. For tenant issues, run allowed and denied access tests using [Tenant isolation](TENANT_ISOLATION.md).
6. For suspected vulnerabilities, use the private email reporting route above.
