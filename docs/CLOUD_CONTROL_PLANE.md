# Engine and Cloud integration architecture

This document describes how Proxima Engine's database gateways connect to Agata Proxima Cloud and how database-specific runtime configuration, deployment and verification fit into the platform.

## Platform responsibilities

Agata Proxima uses two cooperating planes:

- **Proxima Engine — data plane.** Accepts application database connections, authenticates clients, binds sessions to tenant identities, applies protocol-aware enforcement and connects to the configured upstream database.
- **Agata Proxima Cloud — management plane.** Provides organization-scoped management for tenants, policies, Engine nodes, deployment workflows, verification records, signed evidence and audit history.

The Cloud management channel is separate from application SQL traffic. The customer-operated Engine remains in the application-to-database path. Cloud coordinates management and records state; it does not replace the Engine's runtime enforcement decision or become a database proxy.

## Engine database gateway capabilities

| Database | Engine protocol path | Runtime identity and enforcement |
|---|---|---|
| PostgreSQL | Native PostgreSQL wire-protocol listener | Signed tenant context, tenant-to-role routing, least-privilege PostgreSQL roles, grants and RLS |
| MySQL | MySQL-compatible listener | Authenticated client identity, immutable tenant session, assigned database validation, tenant-specific upstream account and grants |
| MariaDB | MySQL-compatible listener | Authenticated client identity, immutable tenant session, assigned database validation, tenant-specific upstream account and grants |

MySQL and MariaDB use the same client protocol gateway but remain distinct database targets. They have separate upstream configuration, server compatibility and real-database integration suites. A verification result for one database must never be represented as proof for another.

## Cloud management model

The management plane organizes Engine deployments around an organization and its environments. A useful resource hierarchy is:

~~~mermaid
flowchart TD
  Org[Organization] --> Project[Project / application]
  Project --> Env[Environment: dev, staging, production]
  Env --> Target[Database target: engine + endpoint + version]
  Env --> Node[Engine node / runtime deployment]
  Node --> Binding[Database and tenant binding]
  Binding --> Tenant[Tenant identity]
  Tenant --> Policy[Engine-specific policy]
  Policy --> Deployment[Deployment revision]
  Deployment --> Verify[Database-specific verification]
  Verify --> Evidence[Signed evidence + audit history]
~~~

### Organization and environment

An organization owns projects, environments, members, API credentials, usage and audit scope. Environments separate development, staging and production configuration. Resources and credentials must remain organization-scoped and environment-aware.

### Database target

A database target identifies the upstream database engine and compatibility version, network endpoint reference, TLS mode and secret-manager reference. The target type must be explicit (postgresql, mysql or mariadb) so the management plane never assumes that all database servers share one protocol or permission model.

Plaintext upstream passwords must not be returned by management APIs after creation. Credentials should be injected into the Engine runtime through protected secret references or short-lived encrypted configuration and rotated independently.

### Engine node and capability

A node represents a running Engine instance. It advertises its build, protocol listeners and supported gateway capabilities. PostgreSQL and MySQL-compatible listener configuration have distinct contracts. A MySQL-compatible node can serve MySQL and MariaDB targets only when the server version and configuration have been validated for the selected target.

Enrollment binds a node to its organization and establishes its identity. The configuration contract should include the gateway capability, protocol, supported target engine, configuration revision and protected secret references. A node must reject an incompatible target or policy rather than silently applying a different engine's settings.

### Tenant-to-database binding

A tenant is assigned to a database target and a database/schema boundary. The Engine resolves an authenticated tenant identity to an immutable binding and tenant-specific least-privilege upstream credential. The management plane validates that the binding belongs to the same organization and environment as the node and database target.

The MySQL-compatible gateway currently uses a local JSON identity registry with a client verifier, tenant ID, assigned database and tenant-specific upstream URL. A Cloud-delivered configuration must preserve those properties, use versioned revisions and protect credential material in transit and at rest.

### Engine-specific policies

Policies declare their target engine and supported capability set. PostgreSQL policies can include role attributes, grants and Row-Level Security. MySQL/MariaDB policies use the gateway's supported SQL admission rules, database grants, tenant-specific upstream users, selected-database validation, prepared-statement handling and database-specific restrictions.

A policy compiled for one engine must not be deployed to another engine unless an explicit compatibility rule and policy compiler establish that it is safe. Shared policy intent may be represented in the product model, but the compiled runtime configuration remains database-specific.

### Deployment and verification

A deployment revision identifies the organization, environment, Engine node, database target, Engine build, configuration revision, policy version and protected secret references. Rollout steps validate compatibility, connectivity and health before traffic is switched.

Verification selects the acceptance suite for the actual database engine and server version. The result records:

- Database engine and server version
- Engine build and runtime configuration revision
- Policy version or digest
- Test-suite identifier and timestamp
- Test identities and tenant fixtures
- Expected and observed outcomes
- Skipped checks, failures and signed evidence reference

A PostgreSQL RLS result is not evidence of MySQL or MariaDB isolation. A test is accepted only for the database path and environment it actually exercised.

## Operator workflow

1. Create or select an organization and project.
2. Create an environment.
3. Register the database target and select its exact engine and server version.
4. Enroll an Engine node with a compatible runtime capability.
5. Bind tenant identities to the database target and least-privilege credentials.
6. Create or select an engine-specific policy.
7. Validate the configuration and deploy the matching Engine revision.
8. Run the matching real-database acceptance suite.
9. Review node health, verification results, signed attestations and audit history.
10. Rotate credentials or roll back a deployment using the documented lifecycle.

The dashboard should show engine compatibility explicitly and prevent a deployment when the node capability, database target, policy compiler or verification suite does not match.

## Security and operational requirements

- Enforce organization and environment ownership on every resource operation.
- Keep upstream passwords and signing secrets out of browser code and API responses.
- Use short-lived enrollment credentials and persistent node identity after enrollment.
- Authenticate and authorize management requests independently from application database traffic.
- Reject stale or replayed signed node reports.
- Validate the database engine, version, protocol capability and policy compatibility before deployment.
- Keep database-specific verification results distinct and attributable to a specific Engine build and configuration.
- Make deployment rollback and credential rotation observable and auditable.
- Preserve Engine enforcement when the management plane is unavailable; a Cloud outage must never grant access or weaken tenant isolation.

## Related implementation guides

- [PostgreSQL quickstart](QUICKSTART.md)
- [PostgreSQL tenant isolation](TENANT_ISOLATION.md)
- [MySQL gateway](MYSQL.md)
- [MariaDB gateway](MARIADB.md)
- [MySQL protocol authentication](MYSQL_GATEWAY_AUTH.md)
- [Node enrollment](NODE_ENROLLMENT.md)
- [Deployment](DEPLOYMENT.md)
- [Verification](VERIFICATION.md)
