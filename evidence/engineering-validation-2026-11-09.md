# Engineering validation evidence

**Project:** Agata Proxima / Proxima Engine  
**Run date:** 2026-11-09  
**Environment:** Local disposable Docker Compose and PostgreSQL test environments  
**Data:** Synthetic tenant identities and records

These are the observed results from the completed local validation runs. No private keys, signed tokens, passwords, or customer data are included.

## PgBouncer transaction pooling

```text
PASS: PgBouncer transaction pooling reused each tenant role's backend, kept tenant pools separate, denied cross-tenant reads/writes, and rejected invalid/missing tenant context.
Tenant A backend PID: 89
Tenant B backend PID: 104
```

Command: `bash scripts/test-pgbouncer-pooling.sh`

## RLS policy and role-attribute scenarios

```text
PASS: baseline RLS exposes only each tenant's own row.
DROP POLICY
PASS: removing Tenant A's policy failed closed (zero visible rows).
CREATE POLICY
EXPECTED EXPOSURE: permissive RLS policy let Tenant A read Tenant B's row and insert a row labelled tenant_b.
Observed rows before insert: A-secret,B-secret
DROP POLICY
CREATE POLICY
ALTER ROLE
EXPECTED EXPOSURE: Tenant A's mapped PostgreSQL role has BYPASSRLS and can see all rows despite FORCE ROW LEVEL SECURITY.
Observed role and rows: proxima_tenant_tenant_a|A-inserted-into-B,A-secret,B-secret
ALTER ROLE
PASS: restoring NOBYPASSRLS and the strict policy restored Tenant A's row boundary.
PASS: deliberate RLS misconfiguration scenarios reproduced in an isolated disposable database.
NOTE: Proxima verified Tenant A's signed identity and mapped it to Tenant A's PostgreSQL role; PostgreSQL RLS and role attributes determined row visibility.
```

## 100-tenant and 1,000-tenant validation

```text
Environment ready: 1,000 distinct tenant roles and 1,000 synthetic records.
Starting 100-tenant validation (25 workers), followed by 1,000-tenant validation (50 workers).

--- 100-tenant concurrency: 100 distinct tenants; at most 25 concurrent clients ---
Progress: 100/100; failures=0
Completed: 100; passed: 100; failed: 0
Elapsed: 19.99s; observed validation throughput: 5.00 tenant checks/s
Client-command latency: median=4.645s; p95=6.855s; max=7.463s
PASS: every tenant saw exactly its own role and exactly its own protected row.

--- 1,000-tenant concurrency: 1000 distinct tenants; at most 50 concurrent clients ---
Progress: 100/1000; failures=0
...
Progress: 1000/1000; failures=0
Completed: 1000; passed: 1000; failed: 0
Elapsed: 220.92s; observed validation throughput: 4.53 tenant checks/s
Client-command latency: median=10.932s; p95=14.762s; max=18.385s
PASS: every tenant saw exactly its own role and exactly its own protected row.

PASS: 1,000 distinct tenant identities validated with bounded concurrency.
SCOPE: 50 concurrent client processes maximum, not 1,000 simultaneous open connections.
```

Command: `bash scripts/test-concurrent-tenant-isolation.sh`

## Authentication and Engine recovery

```text
PASS: valid signed token authenticated as proxima_tenant_tenant_a.
PASS: missing tenant token was rejected.
PASS: malformed tenant token was rejected.
PASS: tampered tenant-token signature was rejected.
PASS: expired tenant token was rejected.
PASS: database connection failed while the Engine was stopped.
PASS: Engine recovered; the still-valid signed token authenticated after restart.
PASS: expired token remained rejected after Engine recovery.

PASS: authentication and recovery scenarios completed.
SCOPE: disposable local Compose environment, synthetic tenant, and local signing key.
```

Command: `bash scripts/test-auth-recovery.sh`

The authentication/recovery run connected directly to the Engine endpoint. The PgBouncer path is independently covered by the pooling run above.

## Related documentation

- [Engineering case study](../docs/ENGINEERING_CASE_STUDY.md)
- [Verification and test guide](../docs/VERIFICATION.md)
- [Recorded PgBouncer evidence](pgbouncer-transaction-pooling.txt)
