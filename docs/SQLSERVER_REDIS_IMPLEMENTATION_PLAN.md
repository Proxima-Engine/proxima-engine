# SQL Server and Redis gateways

This guide records the current Proxima Engine integrations and replaces the earlier implementation-plan status.

## Microsoft SQL Server

Proxima Engine includes a TDS 7.4 gateway and a native tenant database runtime. A tenant is assigned to its own SQL Server database and least-privilege login. The gateway authenticates the client, resolves its immutable tenant assignment, and connects upstream using the configured SQL Server identity and TLS settings.

Use the [SQL Server tenant guide](SQLSERVER_NATIVE_TENANCY.md) for setup, configuration and acceptance.

Build the gateway:

    cargo build --release -p proxima-engine --bin proxima-sqlserver-tds-gateway

## Redis

Proxima Engine includes a TLS-enabled RESP2 gateway. It binds each authenticated client connection to one tenant, rewrites supported key arguments into that tenant's namespace, and connects upstream with the tenant's Redis ACL identity.

The gateway deliberately supports a documented command set. Review the [Redis tenant gateway guide](REDIS_TENANT_GATEWAY.md) before connecting an application; unsupported commands fail closed rather than bypassing tenant isolation.

Build the gateway:

    cargo build --release -p proxima-engine --bin proxima-redis-gateway

## Verification

The Engine CI workflow builds the gateway binaries and runs disposable-provider acceptance suites. These tests verify the implementation against controlled test services. Before production use, also run the documented checks against the customer's SQL Server and Redis versions, TLS certificates, network policy and workload command requirements.

Related references:
- [Provider runtime reference](PROVIDER_RUNTIME_REFERENCE.md)
- [Database production verification](DATABASE_PRODUCTION_VERIFICATION.md)
- [Engine operations](OPERATIONS.md)
- [Cloud-to-Engine runtime lifecycle](CLOUD_ENGINE_RUNTIME_LIFECYCLE.md)
