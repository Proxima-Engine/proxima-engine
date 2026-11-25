<p align="center">
  <img src="https://raw.githubusercontent.com/Proxima-Engine/proxima-engine/main/assets/agata-proxima-orbit.svg" alt="Agata Proxima" width="112" />
</p>

<h1 align="center">Proxima Engine</h1>

<p align="center"><strong>Open-source Rust engine for multi-database tenant isolation and security.</strong></p>

<p align="center">A customer-deployed data plane that works alongside existing applications and database services.</p>

<p align="center">
  <a href="https://github.com/Proxima-Engine/proxima-engine">Source code</a> ·
  <a href="https://agataproxima.com">Agata Proxima platform</a> ·
  <a href="https://agataproxima.com/developers/downloads">SDK and CLI downloads</a>
</p>

Proxima Engine connects applications to existing database services and enforces provider-aware tenant identity and isolation. It does not replace your database or require you to rewrite your existing application driver. The public Engine repository contains the customer-side data plane; the Agata Proxima management workspace is accessed separately through the platform website.

## Why Agata Proxima?

Applications serving multiple customers need a reliable way to keep each customer's data within its authorized boundary. Agata Proxima provides a dedicated tenant-isolation layer across existing database systems, combining trusted tenant identity, provider-specific access controls, and verification evidence. Teams can strengthen how tenant access is enforced while continuing to use the databases and application drivers they already operate.

## Supported database systems

| Database | Runtime integration | Tenant boundary |
|---|---|---|
| PostgreSQL | PostgreSQL wire gateway | Signed tenant context, tenant roles and row-level security |
| MySQL | MySQL protocol gateway | Tenant identity binding and least-privilege upstream accounts |
| MariaDB | MySQL-compatible protocol gateway | Tenant identity binding and MariaDB permissions |
| CockroachDB | PostgreSQL wire compatibility | Tenant roles and CockroachDB row-level security |
| MongoDB | OP_MSG gateway | SCRAM-SHA-256 identity and database-per-tenant mapping |
| Redis | RESP2 gateway | Tenant key namespace and Redis ACL identity |
| Microsoft SQL Server | TDS 7.4 gateway | LOGIN7 tenant/database assignment and SQL Server login permissions |
| SQLite | Native embedded provider | Database file per tenant with path and filesystem controls |
| Oracle Database | Native provider | Dedicated schema owner and least-privilege grants |
| Amazon DynamoDB | AWS-native provider integration | IAM policy using tenant partition-key conditions |
| Apache Cassandra | Native provider | Keyspace-per-tenant roles and grants |
| Elasticsearch / OpenSearch | Native provider integration | Tenant index namespaces and provider-native roles |

The integrations retain each provider's protocol and authorization model. Use the linked provider guide for its setup, configuration and operations.

## Architecture

- **Cloud control plane** — organization-scoped resources, provider catalogue, database targets, tenant assignments, signed configuration delivery, deployment orchestration and audit.
- **Proxima Engine** — node identity, runtime reconciliation, protocol gateways, native provider operations, tenant authentication and health reporting.
- **Provider security** — protocol-aware gateways for networked database protocols and native authorization integrations for embedded, cloud-native and service-native providers.
- **Verification and operations** — provider-specific test suites, runtime health, Prometheus metrics and signed acknowledgement/evidence workflows.

## Quickstart

### 1. Clone

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
```

### 2. Configure

Start from the example environment and customer Compose files:

```bash
cp .env.example .env
```

Set the database connection, tenant signing key, runtime paths and TLS secrets required by the provider profile you are running. Keep production credentials in a secret manager; do not commit `.env` files or private keys.

### 3. Build and test

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo build --workspace --bins --release
```

Run a provider's dedicated integration script against a disposable instance of that database before deploying it.

### 4. Run locally

For the PostgreSQL reference profile, use the repository's quickstart and customer Compose definition:

```bash
docker compose -f compose.customer.yaml up -d
```

Follow [PostgreSQL quickstart](docs/QUICKSTART.md) for the required services, environment variables, tenant setup and connection examples. For optional gateways, enable the corresponding Compose profile and provide its identity registry and TLS secrets.

### 5. Connect your application

Keep the database driver your application already uses. Point it at the matching Proxima listener or provider endpoint, configure TLS as documented, and provide tenant identity through the trusted server-side integration for that provider.

## Cloud-managed database onboarding

1. Sign in to Agata Proxima Cloud and select the organization and environment.
2. Open **Dashboard → Databases** and register the existing database target.
3. Enroll the customer-hosted Engine node and wait for its healthy signed heartbeat.
4. Assign the target to the node that advertises the matching provider runtime.
5. Create the tenant/database binding. Cloud generates the provider namespace, identity and tenant credentials, then adds the runtime entry to the encrypted target configuration.
6. Deploy the desired configuration and inspect the applied revision, gateway health and tenant evidence.
7. Point the application's existing database driver at the assigned Engine endpoint or provider-native connection path.

The Cloud workspace manages provider discovery, target inventory, encrypted credential delivery, assignment, tenant binding and runtime state. The Engine enforces the selected provider's database path in the customer environment.

## Provider guides

- [PostgreSQL](docs/POSTGRESQL.md) · [Quickstart](docs/QUICKSTART.md)
- [MySQL](docs/MYSQL.md) · [Quickstart](docs/QUICKSTART-MYSQL.md)
- [MariaDB](docs/MARIADB.md) · [Quickstart](docs/QUICKSTART-MARIADB.md)
- [CockroachDB](docs/COCKROACHDB_COMPATIBILITY.md) · [Quickstart](docs/QUICKSTART-COCKROACHDB.md)
- [MongoDB](docs/MONGODB_TENANT_ISOLATION.md) · [Quickstart](docs/QUICKSTART-MONGODB.md)
- [Redis](docs/REDIS_TENANT_GATEWAY.md) · [Quickstart](docs/QUICKSTART-REDIS.md)
- [Microsoft SQL Server TDS gateway](docs/SQLSERVER_NATIVE_TENANCY.md) · [Quickstart](docs/QUICKSTART-SQLSERVER.md)
- [SQLite](docs/SQLITE_TENANCY.md) · [Quickstart](docs/QUICKSTART-SQLITE.md)
- [Oracle Database](docs/ORACLE_TENANCY.md) · [Quickstart](docs/QUICKSTART-ORACLE.md)
- [Amazon DynamoDB](docs/DYNAMODB_TENANCY.md) · [Quickstart](docs/QUICKSTART-DYNAMODB.md)
- [Apache Cassandra](docs/CASSANDRA_TENANCY.md) · [Quickstart](docs/QUICKSTART-CASSANDRA.md)
- [Elasticsearch / OpenSearch](docs/ELASTICSEARCH_TENANCY.md) · [Quickstart](docs/QUICKSTART-ELASTICSEARCH.md)

## Configuration and deployment

- [Configuration reference](docs/CONFIGURATION.md)
- [Customer deployment](docs/DEPLOYMENT.md)
- [Windows and Linux node installers](docs/NODE_ENROLLMENT.md)
- [Kubernetes gateway deployment](deploy/kubernetes/helm/proxima-gateways/README.md)
- [Operations](docs/OPERATIONS.md)
- [Monitoring and metrics](docs/API.md)
- [Security architecture](docs/SECURITY.md)

## CLI and application integrations

The Engine repository includes a local operator CLI for node bootstrap and diagnostics. For application-to-Engine connectivity, use your database's existing driver. For Agata Proxima Cloud management, download the shared server-side JavaScript SDK and CLI from the [public developer downloads page](https://agataproxima.com/developers/downloads).

- [Engine CLI](docs/CLI.md)
- [Cloud API client and CLI](https://agataproxima.com/developers/downloads)
- [Integration examples](docs/INTEGRATIONS.md)
- [Database reference](docs/README.md)
- [Provider runtime and acceptance reference](docs/PROVIDER_RUNTIME_REFERENCE.md)

## License

See [LICENSE](LICENSE).
