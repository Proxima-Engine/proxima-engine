#!/usr/bin/env bash
set -euo pipefail
: "${PROXIMA_MONGODB_TEST_URI:?PROXIMA_MONGODB_TEST_URI is required}"
cargo test -p proxima-engine --test mongodb_tenant_isolation -- --ignored --test-threads=1
