# Proxima Engine: 60-second tenant-isolation demo

This recording uses the repository's disposable Docker Compose acceptance test. It does not use the Agata Proxima website, a hosted account, production credentials, or real customer data.

## Before recording

- Use a clean clone of this repository and a terminal window (PowerShell with Git Bash available, or Git Bash).
- Confirm Docker Desktop is running.
- Close unrelated windows and increase terminal font size so commands and output are readable.
- Do not display `.env`, `.proxima-dev/dev-config.json`, signing keys, passwords, or tenant tokens.
- The test creates synthetic Acme-style tenant data in an isolated Compose project and removes its containers and volume on exit.

## Run the demonstration

From the repository root:

```bash
bash scripts/test-pgbouncer-pooling.sh
```

The script builds and starts PostgreSQL, PgBouncer, and Proxima Engine, creates two least-privilege PostgreSQL tenant roles, applies tenant-specific RLS policies, mints short-lived signed tenant tokens, and verifies the access boundaries through the Engine.

A successful run ends with a `PASS` line describing:
- Tenant A and Tenant B each seeing only their own row.
- Tenant A and Tenant B using distinct PostgreSQL roles and separate PgBouncer backend pools.
- Repeated connections for each tenant reusing that tenant's backend.
- Cross-tenant reads returning no rows.
- Cross-tenant writes being rejected by PostgreSQL RLS.
- Invalid and missing tenant context being rejected.

The test is destructive only to its own isolated Compose project and volume named for this test. Do not modify it to point at a production database.

## 60-second recording sequence

| Time | Show | Narration / on-screen point |
|---|---|---|
| 0–6s | Repository root in a normal terminal | “This is Proxima Engine, a PostgreSQL connection-layer security gateway for multi-tenant applications.” |
| 6–14s | Run `bash scripts/test-pgbouncer-pooling.sh` | “We are starting an isolated PostgreSQL and PgBouncer environment with synthetic tenant data.” |
| 14–25s | Build/startup and test output | “Each tenant has a signed identity and its own least-privilege PostgreSQL role.” |
| 25–38s | Tenant isolation and denied-operation checks | “Tenant A can read its own row. A cross-tenant read returns no data, and a cross-tenant write is rejected by PostgreSQL row-level security.” |
| 38–49s | Invalid/missing token checks and backend PID output | “Invalid or missing tenant context is rejected. The pooling test also checks that backend reuse stays separated by tenant role.” |
| 49–60s | Final `PASS` output and repository URL | “Proxima complements PostgreSQL grants and RLS with signed tenant verification at the connection boundary. Inspect the code and run the test yourself.” |

## Recording rules

- Record the actual test output; do not fabricate terminal output or edit failures into successes.
- If the test fails, stop and investigate before publishing a recording.
- Keep the complete uncut test run as internal evidence. A short public edit may trim waiting time, but must preserve the real test sequence and final result.
- State clearly that this is a local, reproducible acceptance test, not proof of production deployment or third-party adoption.
- Do not claim that RLS is inherently unsafe or that Proxima replaces it. The demo shows Proxima's tenant-context and role binding working alongside PostgreSQL RLS.

## Suggested capture tools

On Windows, use Xbox Game Bar (`Win + Alt + R`) for a quick terminal-only capture, or OBS Studio if you want control over resolution, microphone, and cropping. Record the terminal only; the main Agata Proxima website and VS Code are not needed.
