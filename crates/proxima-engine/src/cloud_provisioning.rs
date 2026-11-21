//! Cloud-assignment provider provisioning and runtime reconciliation for Phase Two.

use std::{env, io, path::{Path, PathBuf}};

use serde_json::{json, Value};

use crate::{
    gateway_runtime,
    provider_provisioning::{
        self, CoreProvider, ProvisioningRequest, ProvisioningTarget, Secret, TenantBinding,
    },
    runtime_coordinator::RuntimeCoordinator,
    runtime_reconciliation::{self, RuntimeRecord},
};

pub struct AssignmentOutcome {
    pub status: &'static str,
    pub runtime_health_passed: bool,
    pub error_code: Option<&'static str>,
    pub provisioning_result: Option<Value>,
}

impl AssignmentOutcome {
    fn staged() -> Self {
        Self { status: "staged", runtime_health_passed: false, error_code: None, provisioning_result: None }
    }
    fn failed(code: &'static str) -> Self {
        Self { status: "failed", runtime_health_passed: false, error_code: Some(code), provisioning_result: None }
    }
    fn applied(result: Value) -> Self {
        Self { status: "applied", runtime_health_passed: true, error_code: None, provisioning_result: Some(result) }
    }
}

fn fail_state(path: &Path, state: &mut RuntimeRecord, code: &'static str) -> AssignmentOutcome {
    let _ = state.mark_failed(code);
    let _ = runtime_reconciliation::persist(path, state);
    AssignmentOutcome::failed(code)
}

/// Provision tenant identities on the customer database, verify every generated
/// login, then activate the provider runtime. Credentials are returned only as a
/// structured result for the caller to encrypt into the signed Cloud acknowledgement.
pub async fn reconcile_core_assignment(
    record: &Value,
    credentials: &Value,
    state_path: &Path,
    state: &mut RuntimeRecord,
    coordinator: &RuntimeCoordinator,
) -> AssignmentOutcome {
    let provider_key = match record.get("provider_key").and_then(Value::as_str) {
        Some(value) => value,
        None => return fail_state(state_path, state, "PROVIDER_KEY_MISSING"),
    };
    let provider = match CoreProvider::parse(provider_key) {
        Ok(value) => value,
        Err(_) => return AssignmentOutcome::staged(),
    };

    let bindings_json = match record.get("tenant_bindings").and_then(Value::as_array) {
        Some(value) => value,
        None => return fail_state(state_path, state, "TENANT_BINDINGS_INVALID"),
    };
    if bindings_json.is_empty() {
        return AssignmentOutcome::staged();
    }
    let mut bindings = Vec::with_capacity(bindings_json.len());
    for binding in bindings_json {
        let tenant_id = match binding.get("tenant_id").and_then(Value::as_str) {
            Some(value) => value.to_owned(),
            None => return fail_state(state_path, state, "TENANT_ID_MISSING"),
        };
        let namespace = match binding.get("namespace").and_then(Value::as_str) {
            Some(value) => value.to_owned(),
            None => return fail_state(state_path, state, "TENANT_NAMESPACE_MISSING"),
        };
        let binding_id = binding.get("binding_id").and_then(Value::as_str).map(str::to_owned);
        bindings.push(TenantBinding { binding_id, tenant_id, namespace });
    }

    let database_name = match record.get("database_name").and_then(Value::as_str) {
        Some(value) => value,
        None => return fail_state(state_path, state, "DATABASE_NAME_MISSING"),
    };
    let endpoint = match record.get("endpoint") {
        Some(value) => value,
        None => return fail_state(state_path, state, "DATABASE_ENDPOINT_MISSING"),
    };
    let host = match endpoint.get("host").and_then(Value::as_str) {
        Some(value) => value,
        None => return fail_state(state_path, state, "DATABASE_HOST_MISSING"),
    };
    let port = match endpoint.get("port").and_then(Value::as_u64).filter(|v| (1..=65535).contains(v)) {
        Some(value) => value as u16,
        None => return fail_state(state_path, state, "DATABASE_PORT_INVALID"),
    };
    let admin_username = match credentials.get("username").and_then(Value::as_str).filter(|v| !v.is_empty()) {
        Some(value) => value,
        None => return fail_state(state_path, state, "PROVISIONING_USERNAME_MISSING"),
    };
    let admin_password = match credentials.get("password").and_then(Value::as_str).filter(|v| !v.is_empty()) {
        Some(value) => Secret::new(value),
        None => return fail_state(state_path, state, "PROVISIONING_PASSWORD_MISSING"),
    };

    let plan = match provider_provisioning::build_provisioning_plan(ProvisioningRequest {
        provider_key,
        database_name,
        bindings: &bindings,
    }) {
        Ok(value) => value,
        Err(_) => return fail_state(state_path, state, "PROVIDER_PROVISIONING_PLAN_INVALID"),
    };

    let ca_path = env::var_os("PROXIMA_DATABASE_TLS_CA_FILE")
        .or_else(|| env::var_os("PROXIMA_UPSTREAM_TLS_CA_FILE"))
        .map(PathBuf::from)
        .unwrap_or_default();
    let target = ProvisioningTarget {
        host,
        port,
        database_name,
        admin_username,
        admin_password: &admin_password,
        tls_ca_file: &ca_path,
    };
    if provider_provisioning::apply_provisioning_plan(&plan, &target).await.is_err() {
        return fail_state(state_path, state, "PROVIDER_PROVISIONING_OR_HEALTH_FAILED");
    }

    match provider {
        CoreProvider::PostgreSql | CoreProvider::CockroachDb => {
            let expected_upstream = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            let configured_upstream = env::var("PROXIMA_UPSTREAM_ADDR").unwrap_or_default();
            let tls_mode = env::var("PROXIMA_UPSTREAM_TLS_MODE").unwrap_or_default();
            let ca_configured = env::var_os("PROXIMA_UPSTREAM_TLS_CA_FILE").is_some();
            if configured_upstream != expected_upstream || tls_mode != "verify-full" || !ca_configured {
                return fail_state(state_path, state, "ENGINE_UPSTREAM_TARGET_MISMATCH");
            }
            if state.begin_apply(state.desired_revision, state.credential_revision).is_err()
                || runtime_reconciliation::persist(state_path, state).is_err()
                || state.mark_applied(state.desired_revision, true).is_err()
                || runtime_reconciliation::persist(state_path, state).is_err()
            {
                return fail_state(state_path, state, "RUNTIME_STATE_TRANSITION_FAILED");
            }
        }
        CoreProvider::MySql | CoreProvider::MariaDb => {
            let executable = match env::current_exe() {
                Ok(value) => value,
                Err(_) => return fail_state(state_path, state, "ENGINE_EXECUTABLE_UNAVAILABLE"),
            };
            let executable_dir = match executable.parent() {
                Some(value) => value,
                None => return fail_state(state_path, state, "ENGINE_EXECUTABLE_UNAVAILABLE"),
            };
            let runtime_dir = env::var_os("PROXIMA_NODE_RUNTIME_STATE_DIR")
                .map(PathBuf::from)
                .or_else(|| state_path.parent().map(Path::to_path_buf))
                .unwrap_or_else(|| PathBuf::from("data/runtime-state"));
            let mut runtime = match provider_provisioning::mysql_gateway_runtime_config(
                provider, &plan.identities, host, port,
            ) {
                Ok(value) => value,
                Err(_) => return fail_state(state_path, state, "MYSQL_GATEWAY_REGISTRY_INVALID"),
            };
            let listen_addr = env::var("PROXIMA_MYSQL_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:3307".to_owned());
            runtime["listen_addr"] = json!(listen_addr);
            let prepared = match gateway_runtime::prepare_mysql_from_registry(
                record, &runtime, executable_dir, &runtime_dir,
            ) {
                Ok(value) => value,
                Err(_) => return fail_state(state_path, state, "MYSQL_GATEWAY_PREPARATION_FAILED"),
            };
            let health = || async move { prepared.verify_upstream().await };
            if coordinator.activate(state_path, state, prepared.spec, health).await.is_err() {
                return fail_state(state_path, state, "MYSQL_GATEWAY_ACTIVATION_FAILED");
            }
        }
    }

    match provider_provisioning::provisioning_result_payload(&plan) {
        Ok(result) => AssignmentOutcome::applied(result),
        Err(_) => fail_state(state_path, state, "PROVISIONING_RESULT_SERIALIZATION_FAILED"),
    }
}
