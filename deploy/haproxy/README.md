# HAProxy TCP ingress for Proxima Engine

This is a Layer-4 TCP ingress template for PostgreSQL-wire Engine nodes. It distributes new TCP sessions across up to 32 addresses returned for the orchestrator service name `engine`, using least-connections and TCP health checks.

## Deployment contract

- Run HAProxy and Engine nodes on the same private network.
- Publish only the HAProxy listener to application networks; keep Engine node listeners private.
- Give every Engine replica its own node ID, one-time enrollment token, persistent identity file and state volume. Never share node identity or identity storage between replicas.
- Configure the Engine's upstream target and tenant-signing material consistently through the customer's secret-management and deployment system.
- Set the replica count through the customer's orchestrator. The `server-template` capacity is 32 addresses; raise it deliberately if a larger node fleet is required.
- The TCP health check verifies that the Engine listener accepts TCP. It is not a complete provider-readiness check. The orchestrator must separately evaluate the Engine health/readiness endpoint and provider connectivity before adding a node to service.
- Drain a node before maintenance using HAProxy's runtime admin socket, stop routing new sessions to it, and wait for existing sessions to complete or reach the documented drain deadline.
- Set host/container file-descriptor and HAProxy `maxconn` limits from measured capacity. The sample `maxconn 100000` is a configurable ingress ceiling, not a performance claim.

## Important boundaries

This template routes new TCP sessions; it does not create tenant assignments, provision database credentials, or enroll nodes with Agata Proxima Cloud. Cloud node enrollment and desired/applied configuration reconciliation remain separate control-plane workflows. The customer's orchestrator and ingress must connect those workflows to actual routing, readiness and drain operations.

This file is PostgreSQL-wire specific. MySQL, MongoDB, Redis and SQL Server require protocol-compatible listeners and separate health/connection budgets. Do not send different database protocols to this PostgreSQL listener.
