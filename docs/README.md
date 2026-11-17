# Proxima Engine documentation

This is the complete technical guide to the public Rust data plane. Choose a task below and go directly to the relevant guide.

## Start and evaluate

- **[Quickstart](QUICKSTART.md)** — launch PostgreSQL and Proxima Engine, run a real SQL query, and inspect health and metrics.
- **[Architecture](ARCHITECTURE.md)** — understand the request lifecycle, tenant identity, role routing, and system boundaries.
- **[Tenant isolation](TENANT_ISOLATION.md)** — configure tenant roles and RLS, issue signed context, and run positive and negative access tests.
- **[Engineering case study](ENGINEERING_CASE_STUDY.md)** — review executed PgBouncer, RLS, 1,000-identity, signed-token, and recovery validation.
- **[Developer security walkthrough](DEVELOPER_SECURITY_DEMO.md)** — reproduce the tenant-access scenarios and review the recorded PgBouncer evidence.
- **[Local developer mode](LOCAL_DEVELOPMENT.md)** — generate a local node identity and signed test tokens without a hosted account.
- **[Engine CLI](CLI.md)** — use the bootstrap, token, diagnostic, and status commands.

## Integrate and operate

- [Configuration reference](CONFIGURATION.md) — environment variables, defaults, and validation.
- [API, health, and metrics](API.md) — PostgreSQL endpoint, local HTTP routes, and Prometheus metrics.
- [Driver integration recipes](INTEGRATIONS.md) — psql, Node.js, Python, and Rust.
- [Node identity and enrollment](NODE_ENROLLMENT.md) — node identity persistence and the enrollment contract.
- [Container deployment](DEPLOYMENT.md) — image build, networking, TLS, persistence, and deployment checklist.
- [Operations and troubleshooting](OPERATIONS.md) — health checks, logs, monitoring, restart, and recovery.
- [Verification and test guide](VERIFICATION.md) — automated tests, PostgreSQL integration, CI, and signed evidence.
- [Engineering validation evidence](../evidence/engineering-validation-2026-11-09.md) — recorded outputs from the completed local validation runs.

## Security and hosted product

- [Security architecture and deployment requirements](SECURITY.md) — implemented controls and required runtime configuration.
- [Hosted Cloud control plane](CLOUD_CONTROL_PLANE.md) — hosted organization workflows and the Engine integration boundary.
- [Plans and billing](BILLING.md) — hosted plans, checkout, subscription, and account billing.
- [Support](SUPPORT.md) — contact routes, diagnostics, and issue reporting.

## Contribute and project policies

- [Contributing](../CONTRIBUTING.md) — development setup, test commands, and pull-request requirements.
- [Security policy](../SECURITY.md) — private vulnerability disclosure.
- [Code of Conduct](../CODE_OF_CONDUCT.md) — community expectations.
- [Copyright and brand](../COPYRIGHT.md) — source license, trademarks, and reserved artwork.
- [MIT License](../LICENSE) — terms for covered source and documentation.
- [Open-source scope](OPEN_SOURCE_SCOPE.md) — self-managed use, MIT license, and support boundaries.

## External project resources

- [Agata Proxima website](https://agataproxima.com)
- [GitHub repository](https://github.com/Agata-Proxima/proxima-engine)
- [GitHub Actions](https://github.com/Agata-Proxima/proxima-engine/actions)
- [GitHub issues](https://github.com/Agata-Proxima/proxima-engine/issues)
- [GitHub pull requests](https://github.com/Agata-Proxima/proxima-engine/pulls)
- [GitHub releases](https://github.com/Agata-Proxima/proxima-engine/releases)
- [Discord community](https://discord.gg/xsYSuDMzg)

## Product boundary

Proxima Engine is independently buildable and testable. A compatible control plane can issue node-enrollment credentials and receive optional signed evidence. The hosted Agata Proxima Cloud application is a separate product; its private management source and hosted account workflows are not part of this repository.

## Customer installation packages

- [Registered-node installation guide](NODE_ENROLLMENT.md) — Windows PowerShell and Linux Bash installer steps, required downloads, enrollment credentials, Docker networking, health verification, and lifecycle operations.
- [Customer deployment executor](CUSTOMER_DEPLOYMENT_EXECUTOR.md) — signed deployment webhooks, executor credentials, approved releases, rollback, and customer-managed deployment operations.
- [Windows customer installer](../install-customer.ps1) — PowerShell installer for Windows hosts running Docker Desktop/Linux containers.
- [Linux customer installer](../install-customer.sh) — Bash installer for Linux hosts running Docker Engine and Compose v2.
- [Customer Compose definition](../compose.customer.yaml) — the container deployment and mounted secret contract.
