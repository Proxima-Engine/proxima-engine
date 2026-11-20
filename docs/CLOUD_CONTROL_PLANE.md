# Database gateways in Agata Proxima Cloud

This document separates the current hosted Cloud contract from the multi-database architecture planned for Cloud management.

## Current implementation boundary

Agata Proxima Cloud currently exposes organization-scoped management workflows for tenants, policies, nodes, deployments, verification, audit and attestations. The published node-enrollment and signed-evidence contract is documented for the PostgreSQL Engine path.

The public Proxima Engine repository also contains a separate MySQL-compatible gateway executable. Its local configuration uses a MySQL identity registry and tenant-specific upstream URLs. The repository CI workflow provisions MySQL 8.0 and MariaDB 11.4 independently and runs separate integration suites.

**The current hosted Cloud workflow does not yet provision, configure, deploy or verify MySQL/MariaDB gateway instances.** A MySQL or MariaDB developer can build and run the Engine gateway locally using the database-specific guides, but must not assume that creating a generic Cloud node automatically configures the MySQL listener, stores its registry or manages its upstream secrets.

| Capability | PostgreSQL | MySQL | MariaDB |
|---|---|---|---|
| Public Engine gateway | Available | Available through the MySQL-compatible gateway | Available through the MySQL-compatible gateway |
| Database-specific setup guide | Available | Available | Available |
| Separate real-database integration suite in CI | Available | MySQL 8.0 | MariaDB 11.4 |
| Local gateway configuration | PostgreSQL Engine settings | MySQL identity registry and listener settings | MySQL identity registry and listener settings |
| Hosted Cloud database selection and provisioning | Existing documented path | Not implemented in Cloud | Not implemented in Cloud |
| Hosted Cloud-managed gateway deployment and database-specific verification | Existing PostgreSQL-oriented contract; validate each environment | Not implemented in Cloud | Not implemented in Cloud |

## Intended multi-database Cloud resource model

The Cloud control plane should manage database gateways as explicit runtime targets rather than treating every database as a PostgreSQL connection. The intended hierarchy is:

~~~mermaid
flowchart TD
  Org[Organization] --> Project[Project / application]
  Project --> Env[Environment: dev, staging, production]
  Env --> Db[Database target: engine + endpoint + version]
  Env --> Node[Gateway node / runtime deployment]
  Node --> Bind[Database binding]
  Bind --> Tenant[Tenant assignments]
  Tenant --> Policy[Versioned database policy]
  Policy --> Deploy[Deployment / rollout]
  Deploy --> Verify[Engine-specific verification]
  Verify --> Evidence[Signed evidence + audit history]
~~~

### Organization and environment

An organization owns projects, environments, members, API credentials, usage and audit scope. Each environment separates development, staging and production configuration. A database target belongs to one environment and declares its engine type.

### Database target

The database target records a typed engine identifier (postgresql, mysql, or mariadb), server compatibility version, network endpoint reference, TLS mode, and a secret-manager reference. The Cloud API must never return plaintext upstream passwords after creation. Credentials are injected into the gateway runtime through secret references and rotated independently.

### Gateway node

A node represents a running gateway runtime, not an individual tenant. The runtime advertises its gateway capability and version. The PostgreSQL listener and MySQL-compatible listener have separate protocol and configuration contracts. MySQL and MariaDB may use the same MySQL-compatible gateway binary, but their upstream target type and compatibility test remain distinct.

A future enrollment contract must include the gateway capability, protocol, supported target engine, configuration revision and secret references. It must not silently interpret a MySQL/MariaDB target as PostgreSQL.

### Tenant-to-database binding

A tenant is assigned to a database target and a database/schema boundary. The gateway resolves an authenticated tenant identity to an immutable binding and tenant-specific least-privilege upstream credential. The control plane must validate that the binding belongs to the same organization and environment as the node and database target.

For MySQL/MariaDB, the current gateway uses a local JSON identity registry with a client verifier, tenant ID, assigned database and tenant-specific upstream URL. Cloud integration must replace manual registry distribution with a versioned, encrypted secret/configuration delivery contract without weakening those checks.

### Database-specific policies

Policies must declare their target engine and policy capability set. PostgreSQL policies can include role attributes, grants and Row-Level Security. MySQL/MariaDB policies must use supported SQL admission rules, database grants, tenant-specific upstream users, selected database validation, prepared-statement handling and database-specific restrictions. A policy compiled for one engine must not be deployed to another engine without an explicit compatible policy compiler.

### Deployment and verification

A deployment record must identify the organization, environment, gateway node, database target, gateway build, configuration revision, policy version and secret references. Rollout steps should validate connectivity and health before switching traffic.

Verification must select an engine-specific acceptance suite. The result must record the database engine and version, gateway build, policy digest, test-suite identifier, timestamp, expected and observed outcomes, and signed evidence reference. A PostgreSQL RLS result must never be presented as proof of MySQL or MariaDB isolation.

### Cloud UI workflow

The intended operator journey is:

1. Create or select an organization and project.
2. Create an environment.
3. Register a database target and select PostgreSQL, MySQL or MariaDB.
4. Add a gateway node with a compatible runtime capability.
5. Bind tenant records to database targets and least-privilege credentials.
6. Create an engine-specific policy.
7. Deploy the matching gateway configuration.
8. Run the matching database acceptance suite.
9. Review verification, signed attestations and audit history.

The UI must show a database-engine compatibility state and must block deployment when the node capability, target engine, policy compiler or verification suite does not match.

## Implementation sequence for Cloud support

1. **Contract and schema:** add database-engine enums, database targets, environment bindings, capability declarations and secret references with organization-scoped foreign keys.
2. **API authorization:** enforce organization/environment ownership on target creation, credential changes, node binding, policy deployment and evidence ingestion.
3. **Node enrollment:** issue engine-capability-scoped enrollment configuration and deliver only secret references or short-lived encrypted material.
4. **Runtime configuration:** load versioned PostgreSQL or MySQL-compatible gateway profiles; validate configuration before applying it.
5. **Policy compiler:** maintain engine-specific policy schemas and reject unsupported or cross-engine policy fields.
6. **Deployment executor:** render and apply the correct gateway runtime profile, perform health checks, and support rollback.
7. **Verification orchestration:** run the correct real-database suite and preserve per-engine evidence.
8. **Dashboard:** expose database targets, gateway capabilities, tenant bindings, policies, deployment history and verification outcomes.
9. **Acceptance:** test organization isolation, tenant isolation, secret rotation, rollback, node loss, database outage and control-plane recovery for each engine independently.

## Related implementation guides

- [PostgreSQL quickstart](QUICKSTART.md)
- [PostgreSQL tenant isolation](TENANT_ISOLATION.md)
- [MySQL gateway](MYSQL.md)
- [MariaDB gateway](MARIADB.md)
- [MySQL protocol authentication](MYSQL_GATEWAY_AUTH.md)
- [Node enrollment](NODE_ENROLLMENT.md)
- [Deployment](DEPLOYMENT.md)
- [Verification](VERIFICATION.md)
