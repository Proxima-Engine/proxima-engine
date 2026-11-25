# Cloud-to-Engine runtime lifecycle

Agata Proxima Cloud is the organization-scoped control plane. Proxima Engine is the customer-deployed data plane. Cloud manages configuration and lifecycle; Engine connects to the assigned database and enforces the provider-specific tenant boundary.

## Platform responsibilities

Cloud manages organizations, projects, environments, typed database targets, tenant records, tenant-to-database bindings, policy versions, Engine enrollment, identity, desired runtime configuration, protected credential references, deployments, reconciliation state, verification results, audit events and signed evidence.

Engine manages customer-side database connections, provider runtimes, protocol gateways, provider-native tenant boundaries, runtime supervision, desired-state reconciliation, health reporting and verification execution.

Cloud does not replace customer databases or require direct public access to customer database endpoints. Customers keep their existing database services and application data.

## Supported database systems

The platform catalogue covers twelve database systems:

1. PostgreSQL
2. MySQL
3. MariaDB
4. CockroachDB
5. MongoDB
6. Redis
7. Microsoft SQL Server
8. SQLite
9. Oracle Database
10. Amazon DynamoDB
11. Apache Cassandra
12. Elasticsearch / OpenSearch

Each provider has its own runtime and tenant-isolation model. A policy or verification result for one provider must not be represented as proof for another provider.

## Runtime lifecycle

1. An organization registers a database target and provider-specific connection settings.
2. An Engine node enrolls and advertises its runtime capabilities.
3. An authorized tenant binding associates the tenant, environment, target and Engine assignment.
4. Cloud delivers versioned desired state and protected credential references.
5. Engine reconciles the assignment and starts the required provider runtime or gateway.
6. Engine reports observed state and health.
7. Verification runs against the selected provider and records the result with its runtime and policy context.
8. Cloud retains deployment, audit and verification history.

Engine remains the enforcement authority for the customer data path. Cloud manages intent and lifecycle; it does not replace the Engine's tenant checks.

## Operator and developer references

- [Agata Proxima public documentation](https://agataproxima.com/docs)
- [Database integration catalogue](https://agataproxima.com/docs/database-integrations)
- [Developer API reference](https://agataproxima.com/developers/api-reference)
- [SDK and CLI downloads](https://agataproxima.com/developers/downloads)
- [Cloud-to-Engine runtime lifecycle](CLOUD_ENGINE_RUNTIME_LIFECYCLE.md)
- [Provider runtime reference](PROVIDER_RUNTIME_REFERENCE.md)
- [Node enrollment](NODE_ENROLLMENT.md)
- [Verification](VERIFICATION.md)
