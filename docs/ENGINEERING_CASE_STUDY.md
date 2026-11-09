# Engineering case study: tenant isolation under real PostgreSQL conditions

**Agata Proxima · Proxima Engine · 9 November 2026**

Proxima Engine places tenant identity at the PostgreSQL connection boundary. It validates signed tenant context, maps the verified identity to a dedicated PostgreSQL role, and establishes the upstream session under that role. PostgreSQL grants, role attributes, and Row-Level Security (RLS) enforce row-level access.

This case study records the completed engineering validation using real PostgreSQL processes, real SQL statements, Docker Compose services, signed tenant tokens, PgBouncer transaction pooling, and synthetic tenant records.

## Results

| Test | Result |
|---|---|
| PgBouncer transaction pooling | Passed; tenant role pools remained separate and backend reuse was verified |
| RLS policy removal | Failed closed; zero visible rows |
| Permissive RLS policy | Exposure reproduced; Tenant A read Tenant B's row and inserted a row labelled tenant_b |
| PostgreSQL BYPASSRLS | Exposure reproduced; Tenant A's mapped role saw all rows despite FORCE ROW LEVEL SECURITY |
| Strict policy and NOBYPASSRLS restored | Passed; Tenant A's row boundary was restored |
| 100 distinct tenant identities | 100/100 passed; maximum 25 concurrent client processes |
| 1,000 distinct tenant identities | 1,000/1,000 passed; maximum 50 concurrent client processes |
| Signed-token checks | Valid accepted; missing, malformed, tampered, and expired tokens rejected |
| Engine recovery | Valid token authenticated after restart; expired token remained rejected |

## 1. PgBouncer transaction pooling

The dedicated test exercised the Engine-to-PgBouncer-to-PostgreSQL path with PgBouncer in transaction-pooling mode. It verified that sequential connections for each tenant reused that tenant role's PostgreSQL backend, that the two tenant roles used distinct backend processes and separate role-specific pools, that cross-tenant reads and writes were denied by RLS, and that missing or invalid tenant context was rejected.

```text
PASS: PgBouncer transaction pooling reused each tenant role's backend, kept tenant pools separate, denied cross-tenant reads/writes, and rejected invalid/missing tenant context.
Tenant A backend PID: 89
Tenant B backend PID: 104
```

Run: `bash scripts/test-pgbouncer-pooling.sh`

## 2. Deliberate RLS misconfiguration scenarios

The RLS tests ran against an isolated disposable database with synthetic rows.

- **Baseline:** the strict policy exposed only Tenant A's own row.
- **Policy removed:** access failed closed and returned zero visible rows.
- **Permissive policy:** Tenant A read Tenant B's row and inserted a row labelled `tenant_b`.
- **BYPASSRLS enabled:** Tenant A's mapped PostgreSQL role saw all rows despite `FORCE ROW LEVEL SECURITY`.
- **Configuration restored:** restoring `NOBYPASSRLS` and the strict policy restored Tenant A's row boundary.

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

These tests demonstrate the enforcement boundary: Proxima Engine verifies tenant identity and maps it to the tenant-specific PostgreSQL role; PostgreSQL's policies and role attributes determine row visibility. Least-privilege tenant roles, strict RLS policies, and controlled role administration are essential deployment controls.

## 3. 1,000 distinct tenant identities

The test provisioned 1,000 distinct least-privilege PostgreSQL tenant roles and 1,000 synthetic records. It ran 100 tenant checks with at most 25 concurrent client processes, followed by 1,000 tenant checks with at most 50 concurrent client processes. Each check verified the expected PostgreSQL role and exactly that tenant's protected row.

| Measure | 100 tenants | 1,000 tenants |
|---|---:|---:|
| Checks passed | 100/100 | 1,000/1,000 |
| Failed checks | 0 | 0 |
| Maximum concurrent client processes | 25 | 50 |
| Elapsed time | 19.99 s | 220.92 s |
| Observed validation throughput | 5.00 checks/s | 4.53 checks/s |
| Client-command latency, median | 4.645 s | 10.932 s |
| Client-command latency, p95 | 6.855 s | 14.762 s |
| Client-command latency, maximum | 7.463 s | 18.385 s |

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

Run: `bash scripts/test-concurrent-tenant-isolation.sh`

## 4. Signed-token authentication and Engine recovery

This test connected directly to the Engine endpoint in an isolated Compose environment. It verified valid, missing, malformed, tampered, and expired tenant tokens, stopped the Engine, then restarted it.

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

Run: `bash scripts/test-auth-recovery.sh`

The recovery test connected directly to the Engine endpoint. PgBouncer transaction-pooling behavior is covered by the separate pooling test.

## 5. What the results establish

The executed scenarios demonstrate that Proxima Engine validates signed tenant context before establishing a tenant-bound database session; maps the verified tenant to its dedicated PostgreSQL role; maintains role separation through PgBouncer transaction pooling; rejects missing, malformed, tampered, and expired context; and resumes valid authentication after an Engine restart. The tenant-role mapping and protected-row boundary held across 1,000 distinct tenant identities in the bounded-concurrency run.

The RLS scenarios also show why database configuration matters: permissive policies and `BYPASSRLS` expose rows. Production deployments use least-privilege tenant roles, strict tenant policies, and controlled role administration.

## 6. Reproduce

From the repository root:

```bash
bash scripts/test-pgbouncer-pooling.sh
bash scripts/test-concurrent-tenant-isolation.sh
bash scripts/test-auth-recovery.sh
```

The RLS policy and role-attribute scenarios were run against an isolated disposable database. All validation used synthetic tenant data and local test credentials.

See [Verification and test guide](VERIFICATION.md) for the wider test workflow. The collected run summaries are in [engineering validation evidence](../evidence/engineering-validation-2026-11-09.md).

---

**Agata Proxima · Proxima Engine**  
[Website](https://agataproxima.com) · [Repository](https://github.com/Proxima-Engine/proxima-engine) · [Demonstration video](https://github.com/user-attachments/assets/bca488eb-829c-4672-bbe9-b25878e5401c)
