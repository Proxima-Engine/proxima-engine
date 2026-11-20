# MongoDB tenant isolation

## Security model

The first supported enterprise isolation mode is **database per tenant**.
Each tenant receives a distinct MongoDB database and a distinct upstream
MongoDB user whose roles are scoped only to that database. The gateway must
bind the authenticated tenant to one immutable database identity, require
every command's `$db` to match that identity, and reject administrative
commands or cross-database aggregation.

MongoDB's own authorization is the second enforcement boundary. The command
policy is an additional boundary, not a replacement for MongoDB RBAC. A
compromised or misconfigured gateway identity should still be unable to read
another tenant's database.

## Command policy

The initial policy admits a narrow set of data-plane commands: find,
aggregate, insert, update, delete, count, distinct, findAndModify, getMore,
killCursors, listCollections, and listIndexes. Unknown commands fail closed.
Server administration, user management, database enumeration, mapReduce,
JavaScript execution operators, cross-database lookup/union, change streams,
and aggregation output stages are denied.

Aggregation pipelines are inspected recursively, including nested facet and
lookup pipelines. Upserts are denied until their insert semantics can be
proven tenant-safe. Cursor IDs are remapped to gateway-owned opaque IDs and
bound to tenant, database, and collection. Logical session IDs are bound to
one tenant and cannot be reused by another tenant.

The optional `_proxima_tenant_id` document marker can be stamped and filtered
by the policy layer for schemas that have completed the required migration.
It is not silently enabled for existing collections.

## Current implementation boundary

The policy module and cursor/session registries are the authorization core.
The real MongoDB RBAC integration test proves that distinct least-privilege
upstream users cannot read or write another tenant database or enumerate
server databases. This is not yet a transparent MongoDB wire-protocol server:
SCRAM-SHA-256 termination, OP_MSG/OP_COMPRESSED handling, cursor translation,
transaction pinning, and end-to-end TLS are required before advertising a
drop-in MongoDB gateway.
