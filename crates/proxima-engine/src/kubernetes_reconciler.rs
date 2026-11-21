//! Kubernetes workload reconciler for authenticated Engine desired state.
//! Applies only gateway Deployments/Services carrying this controller's ownership labels.
use reqwest::{header, Client, Method, StatusCode};
use serde_json::{json, Value};
use std::{collections::HashSet, env, fs, path::PathBuf, time::Duration};
use tokio::time::interval;
use tracing::{error, info, warn};

const MANAGED_BY: &str = "proxima-engine";
const LABEL: &str = "app.kubernetes.io/managed-by";

#[derive(Clone)]
struct Kube {
    client: Client,
    base: String,
    namespace: String,
    field_manager: String,
}

impl Kube {
    fn from_env() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let host = env::var("KUBERNETES_SERVICE_HOST")?;
        let port = env::var("KUBERNETES_SERVICE_PORT_HTTPS")
            .or_else(|_| env::var("KUBERNETES_SERVICE_PORT"))
            .unwrap_or_else(|_| "443".into());
        let base = env::var("PROXIMA_KUBERNETES_API_URL")
            .unwrap_or_else(|_| format!("https://{host}:{port}"));
        let token_path = env::var("PROXIMA_KUBERNETES_TOKEN_FILE")
            .unwrap_or_else(|_| "/var/run/secrets/kubernetes.io/serviceaccount/token".into());
        let ca_path = env::var("PROXIMA_KUBERNETES_CA_FILE")
            .unwrap_or_else(|_| "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt".into());
        let namespace_path = env::var("PROXIMA_KUBERNETES_NAMESPACE_FILE")
            .unwrap_or_else(|_| "/var/run/secrets/kubernetes.io/serviceaccount/namespace".into());
        let token = fs::read_to_string(token_path)?;
        let ca = reqwest::Certificate::from_pem(&fs::read(ca_path)?)?;
        let client = Client::builder().add_root_certificate(ca)
            .timeout(Duration::from_secs(20)).redirect(reqwest::redirect::Policy::none()).build()?;
        let namespace = env::var("PROXIMA_KUBERNETES_NAMESPACE")
            .or_else(|_| fs::read_to_string(namespace_path).map(|s| s.trim().to_owned()))?;
        if namespace.is_empty() || namespace.len() > 63 {
            return Err("invalid Kubernetes namespace".into());
        }
        Ok(Self { client, base: base.trim_end_matches('/').into(), namespace,
            field_manager: "proxima-engine-runtime".into() })
    }

    async fn request(&self, method: Method, path: &str, body: Option<Value>, apply: bool)
        -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let mut req = self.client.request(method, format!("{}{}", self.base, path))
            .bearer_auth(fs::read_to_string(env::var("PROXIMA_KUBERNETES_TOKEN_FILE")
                .unwrap_or_else(|_| "/var/run/secrets/kubernetes.io/serviceaccount/token".into()))?.trim());
        if let Some(body) = body {
            req = if apply {
                req.header(header::CONTENT_TYPE, "application/apply-patch+yaml").json(&body)
            } else { req.json(&body) };
        }
        let response = req.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if status == StatusCode::NOT_FOUND { return Ok(json!({"_not_found":true})); }
        if !status.is_success() {
            return Err(format!("Kubernetes API {status}: {}", body.chars().take(1200).collect::<String>()).into());
        }
        if body.trim().is_empty() { return Ok(json!({})); }
        Ok(serde_json::from_str(&body)?)
    }

    fn path(&self, resource: &str, name: Option<&str>) -> String {
        let api = if resource == "services" { "/api/v1" } else { "/apis/apps/v1" };
        let root = format!("{api}/namespaces/{}/{}", self.namespace, resource);
        match name {
            Some(name) => format!("{root}/{name}?fieldManager={}&force=true", self.field_manager),
            None => root,
        }
    }

    async fn apply(&self, resource: &str, name: &str, value: Value)
        -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.request(Method::PATCH, &self.path(resource, Some(name)), Some(value), true).await?;
        Ok(())
    }
}

fn dns_name(raw: &str) -> Option<String> {
    let value: String = raw.to_ascii_lowercase().chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    let value = value.trim_matches('-').chars().take(50).collect::<String>();
    if value.is_empty() { None } else { Some(format!("px-{value}")) }
}

fn gateway(assignment: &Value) -> Option<(&'static str, &'static str, u16)> {
    match assignment.get("gateway_runtime")?.as_str()? {
        "proxima-mysql-gateway" => Some(("mysql", "proxima-mysql-gateway", 3307)),
        "proxima-mongodb-gateway" => Some(("mongodb", "proxima-mongodb-gateway", 27018)),
        "proxima-redis-gateway" => Some(("redis", "proxima-redis-gateway", 6380)),
        _ => None,
    }
}

fn secret_name(kind: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let key = match kind {
        "mysql" => "PROXIMA_K8S_MYSQL_GATEWAY_SECRET",
        "mongodb" => "PROXIMA_K8S_MONGODB_GATEWAY_SECRET",
        "redis" => "PROXIMA_K8S_REDIS_GATEWAY_SECRET",
        _ => return Err("unsupported gateway".into()),
    };
    let value = env::var(key).map_err(|_| format!("{key} must name a pre-created Kubernetes Secret"))?;
    if value.is_empty() || value.len() > 253 || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
        return Err(format!("{key} is not a valid Secret name").into());
    }
    Ok(value)
}

fn labels(name: &str, assignment: &str) -> Value {
    json!({LABEL:MANAGED_BY,"proxima.io/assignment":name,"proxima.io/assignment-id":assignment})
}

fn resources(assignment: &Value, namespace: &str) -> Result<Option<(Value, Value, String)>, Box<dyn std::error::Error + Send + Sync>> {
    let Some((kind, binary, port)) = gateway(assignment) else { return Ok(None); };
    let id = assignment.get("assignment_id").and_then(Value::as_str).ok_or("assignment_id missing")?;
    let name = dns_name(id).ok_or("invalid assignment name")?;
    let target = assignment.get("database_target_id").and_then(Value::as_str).ok_or("database_target_id missing")?;
    let revision = assignment.get("config_revision").and_then(Value::as_u64).ok_or("config_revision missing")?;
    let endpoint = assignment.get("endpoint").ok_or("endpoint missing")?;
    let host = endpoint.get("host").and_then(Value::as_str).ok_or("endpoint.host missing")?;
    let db_port = endpoint.get("port").and_then(Value::as_u64).filter(|p| (1..=65535).contains(p)).ok_or("endpoint.port invalid")?;
    if host.is_empty() || host.len() > 253 || host.contains('/') || host.contains('\n') {
        return Err("endpoint.host invalid".into());
    }
    let database = assignment.get("database_name").and_then(Value::as_str).unwrap_or("");
    let secret = secret_name(kind)?;
    let mut envs = vec![
        json!({"name":(format!("PROXIMA_{}_LISTEN_ADDR", kind.to_ascii_uppercase())),"value":format!("0.0.0.0:{port}")}),
        json!({"name":(format!("PROXIMA_{}_UPSTREAM_ADDR", kind.to_ascii_uppercase())),"value":format!("{host}:{db_port}")}),
        json!({"name":(format!("PROXIMA_{}_IDENTITY_REGISTRY", kind.to_ascii_uppercase())),"value":"/var/run/proxima/users.json"}),
    ];
    if !database.is_empty() {
        envs.push(json!({"name":"PROXIMA_DATABASE_NAME","value":database}));
    }
    if kind == "mongodb" || kind == "redis" {
        envs.extend([
            json!({"name":(format!("PROXIMA_{}_TLS_CERT_FILE", kind.to_ascii_uppercase())),"value":"/var/run/proxima/tls.crt"}),
            json!({"name":(format!("PROXIMA_{}_TLS_KEY_FILE", kind.to_ascii_uppercase())),"value":"/var/run/proxima/tls.key"}),
            json!({"name":(format!("PROXIMA_{}_UPSTREAM_TLS_CA_FILE", kind.to_ascii_uppercase())),"value":"/var/run/proxima/ca.crt"}),
        ]);
    }
    let common = labels(&name, id);
    let deployment = json!({
        "apiVersion":"apps/v1","kind":"Deployment",
        "metadata":{"name":name,"namespace":namespace,"labels":common.clone()},
        "spec":{"replicas":1,"selector":{"matchLabels":{"proxima.io/assignment":name}},
          "template":{"metadata":{"labels":common.clone(),"annotations":{"proxima.io/config-revision":revision.to_string(),"proxima.io/target-id":target}},
            "spec":{"automountServiceAccountToken":false,
              "securityContext":{"runAsNonRoot":true,"runAsUser":10001,"runAsGroup":10001,"seccompProfile":{"type":"RuntimeDefault"}},
              "containers":[{"name":"gateway","image":env::var("PROXIMA_KUBERNETES_GATEWAY_IMAGE").unwrap_or_else(|_|"ghcr.io/proxima-engine/proxima-engine:latest".into()),
                "imagePullPolicy":"IfNotPresent","command":[format!("/usr/local/bin/{binary}")],"env":envs,
                "ports":[{"name":"client","containerPort":port,"protocol":"TCP"}],
                "volumeMounts":[{"name":"identity-registry","mountPath":"/var/run/proxima","readOnly":true}],
                "securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}},
                "resources":{"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"cpu":"1","memory":"512Mi"}},
                "readinessProbe":{"tcpSocket":{"port":"client"},"periodSeconds":5,"failureThreshold":3},
                "livenessProbe":{"tcpSocket":{"port":"client"},"periodSeconds":10,"failureThreshold":3}}],
              "volumes":[{"name":"identity-registry","secret":{"secretName":secret,"defaultMode":288}}]}}}
    });
    let service = json!({"apiVersion":"v1","kind":"Service","metadata":{"name":name,"namespace":namespace,"labels":common},
        "spec":{"type":"ClusterIP","selector":{"proxima.io/assignment":name},"ports":[{"name":"client","port":port,"targetPort":"client","protocol":"TCP"}]}});
    Ok(Some((deployment, service, name)))
}

fn desired_assignments(document: &Value) -> Result<&Vec<Value>, Box<dyn std::error::Error + Send + Sync>> {
    if document.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("unsupported Engine desired-state schema version".into());
    }
    for field in ["node_id", "organization_id"] {
        if document.get(field).and_then(Value::as_str).is_none_or(|value| value.trim().is_empty()) {
            return Err(format!("Engine desired state is missing {field}").into());
        }
    }
    let assignments = document.get("assignments").and_then(Value::as_array)
        .ok_or("desired state has no assignments array")?;
    let mut ids = HashSet::new();
    for assignment in assignments {
        let id = assignment.get("assignment_id").and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty()).ok_or("desired assignment has no assignment_id")?;
        if !ids.insert(id) { return Err("desired state contains duplicate assignment IDs".into()); }
        let runtime = assignment.get("gateway_runtime").and_then(Value::as_str)
            .ok_or("desired assignment has no gateway_runtime")?;
        if !matches!(runtime, "proxima-engine" | "proxima-mysql-gateway" | "proxima-mongodb-gateway" | "proxima-redis-gateway") {
            return Err("desired assignment contains an unsupported gateway_runtime".into());
        }
    }
    Ok(assignments)
}

pub async fn reconcile_once(kube: &Kube, config_path: &PathBuf) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let raw = fs::read(config_path)?;
    let desired: Value = serde_json::from_slice(&raw)?;
    let assignments = desired_assignments(&desired)?;
    let mut desired_names = HashSet::new();
    let mut applied = 0usize;
    for assignment in assignments {
        if let Some((deployment, service, name)) = resources(assignment, &kube.namespace)? {
            if !desired_names.insert(name.clone()) { return Err("duplicate gateway assignment resource name".into()); }
            kube.apply("deployments", &name, deployment).await?;
            kube.apply("services", &name, service).await?;
            applied += 1;
        }
    }
    // Remove only resources carrying our explicit ownership label. Never touch
    // customer-managed workloads or any Secret.
    for resource in ["deployments", "services"] {
        let path = format!("{}?labelSelector={}={}", kube.path(resource, None), LABEL, MANAGED_BY);
        let list = kube.request(Method::GET, &path, None, false).await?;
        if let Some(items) = list.get("items").and_then(Value::as_array) {
            for item in items {
                let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else { continue; };
                if !desired_names.contains(name) {
                    let delete_path = format!("{}/{}?propagationPolicy=Foreground", kube.path(resource, None), name);
                    kube.request(Method::DELETE, &delete_path, None, false).await?;
                    info!(resource, name, "removed stale Engine-managed Kubernetes gateway workload");
                }
            }
        }
    }
    Ok(applied)
}

pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let kube = Kube::from_env()?;
    let path = PathBuf::from(env::var("PROXIMA_NODE_DATABASE_CONFIG_PATH")
        .unwrap_or_else(|_| "/var/lib/proxima/database-targets.json".into()));
    let seconds = env::var("PROXIMA_KUBERNETES_RECONCILE_SECONDS").ok()
        .and_then(|v| v.parse::<u64>().ok()).filter(|v| (5..=300).contains(v)).unwrap_or(15);
    info!(namespace=%kube.namespace, path=%path.display(), interval_seconds=seconds,
        "Kubernetes gateway desired-state reconciler started");
    let mut ticker = interval(Duration::from_secs(seconds));
    loop {
        ticker.tick().await;
        match reconcile_once(&kube, &path).await {
            Ok(count) => info!(managed_gateway_assignments=count, "Kubernetes gateway workloads reconciled"),
            Err(error) => warn!(%error, "Kubernetes gateway reconciliation failed; last applied workloads are retained"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn desired_state_contract_accepts_multiple_gateway_assignments() {
        let state = json!({
            "schema_version":1,"node_id":"node-a","organization_id":"org-a",
            "assignments":[
                {"assignment_id":"mysql-a","gateway_runtime":"proxima-mysql-gateway"},
                {"assignment_id":"mysql-b","gateway_runtime":"proxima-mysql-gateway"},
                {"assignment_id":"mongo-a","gateway_runtime":"proxima-mongodb-gateway"}
            ]
        });
        assert_eq!(desired_assignments(&state).unwrap().len(), 3);
    }

    #[test]
    fn desired_state_contract_accepts_empty_revocation_document() {
        let state = json!({"schema_version":1,"node_id":"node-a","organization_id":"org-a","assignments":[]});
        assert!(desired_assignments(&state).unwrap().is_empty());
    }

    #[test]
    fn desired_state_contract_rejects_wrong_schema_and_duplicate_ids() {
        let wrong_schema = json!({"schema_version":2,"node_id":"node-a","organization_id":"org-a","assignments":[]});
        let duplicate = json!({"schema_version":1,"node_id":"node-a","organization_id":"org-a","assignments":[
            {"assignment_id":"same"},{"assignment_id":"same"}
        ]});
        assert!(desired_assignments(&wrong_schema).is_err());
        assert!(desired_assignments(&duplicate).is_err());
    }

    #[test]
    fn maps_only_existing_gateway_runtime_binaries() {
        assert_eq!(gateway(&json!({"gateway_runtime":"proxima-mysql-gateway"})).unwrap().0,"mysql");
        assert_eq!(gateway(&json!({"gateway_runtime":"proxima-mongodb-gateway"})).unwrap().0,"mongodb");
        assert_eq!(gateway(&json!({"gateway_runtime":"proxima-redis-gateway"})).unwrap().0,"redis");
        assert!(gateway(&json!({"gateway_runtime":"proxima-engine"})).is_none());
        assert!(gateway(&json!({"gateway_runtime":"dynamodb"})).is_none());
    }
    #[test]
    fn assignment_resource_names_are_dns_safe_and_bounded() {
        let value=dns_name("Assignment/With Spaces_AND.UPPER");
        assert!(value.as_ref().is_some_and(|v|v.len()<=53 && v.starts_with("px-")));
    }
}
