//! Kubernetes workload reconciler for authenticated Engine desired state.
//! Applies only gateway Deployments, Services, Secrets and NetworkPolicies carrying this controller's ownership labels.
use reqwest::{header, Client, Method, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::interval;
use tracing::{info, warn};

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
        let _token = fs::read_to_string(token_path)?;
        let ca = reqwest::Certificate::from_pem(&fs::read(ca_path)?)?;
        let client = Client::builder()
            .add_root_certificate(ca)
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let namespace = env::var("PROXIMA_KUBERNETES_NAMESPACE")
            .or_else(|_| fs::read_to_string(namespace_path).map(|s| s.trim().to_owned()))?;
        if namespace.is_empty() || namespace.len() > 63 {
            return Err("invalid Kubernetes namespace".into());
        }
        Ok(Self {
            client,
            base: base.trim_end_matches('/').into(),
            namespace,
            field_manager: "proxima-engine-runtime".into(),
        })
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        apply: bool,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let mut req = self
            .client
            .request(method, format!("{}{}", self.base, path))
            .bearer_auth(
                fs::read_to_string(env::var("PROXIMA_KUBERNETES_TOKEN_FILE").unwrap_or_else(
                    |_| "/var/run/secrets/kubernetes.io/serviceaccount/token".into(),
                ))?
                .trim(),
            );
        if let Some(body) = body {
            req = if apply {
                req.header(header::CONTENT_TYPE, "application/apply-patch+yaml")
                    .json(&body)
            } else {
                req.json(&body)
            };
        }
        let response = req.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(json!({"_not_found":true}));
        }
        if !status.is_success() {
            return Err(format!(
                "Kubernetes API {status}: {}",
                body.chars().take(1200).collect::<String>()
            )
            .into());
        }
        if body.trim().is_empty() {
            return Ok(json!({}));
        }
        Ok(serde_json::from_str(&body)?)
    }

    fn path(&self, resource: &str, name: Option<&str>) -> String {
        let api = match resource {
            "services" | "secrets" => "/api/v1",
            "networkpolicies" => "/apis/networking.k8s.io/v1",
            _ => "/apis/apps/v1",
        };
        let root = format!("{api}/namespaces/{}/{}", self.namespace, resource);
        match name {
            Some(name) => format!("{root}/{name}"),
            None => root,
        }
    }

    async fn apply(
        &self,
        resource: &str,
        name: &str,
        value: Value,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = format!(
            "{}?fieldManager={}&force=true",
            self.path(resource, Some(name)),
            self.field_manager
        );
        self.request(Method::PATCH, &path, Some(value), true)
            .await?;
        Ok(())
    }
}

fn valid_node_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn labels_for_node(name: &str, assignment_id: &str, node_id: &str) -> Value {
    json!({
        "app.kubernetes.io/managed-by": MANAGED_BY,
        "proxima.io/assignment": name,
        "proxima.io/assignment-id": assignment_id,
        "proxima.io/node-id": node_id
    })
}

fn ownership_selector(node_id: &str) -> String {
    format!("{LABEL}={MANAGED_BY},proxima.io/node-id={node_id}")
}
fn dns_name(raw: &str) -> Option<String> {
    let value: String = raw
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let value = value.trim_matches('-').chars().take(50).collect::<String>();
    if value.is_empty() {
        None
    } else {
        Some(format!("px-{value}"))
    }
}

fn gateway(assignment: &Value) -> Option<(&'static str, &'static str, u16)> {
    match assignment.get("gateway_runtime")?.as_str()? {
        "proxima-mysql-gateway" => Some(("mysql", "proxima-mysql-gateway", 3307)),
        "proxima-mongodb-gateway" => Some(("mongodb", "proxima-mongodb-gateway", 27018)),
        "proxima-redis-gateway" => Some(("redis", "proxima-redis-gateway", 6380)),
        "proxima-sqlserver-tds-gateway" => {
            Some(("sqlserver", "proxima-sqlserver-tds-gateway", 14330))
        }
        _ => None,
    }
}

fn desired_secret_assignments<'a>(
    document: &'a Value,
    expected_node_id: &str,
    expected_delivery_id: &str,
) -> Result<&'a Vec<Value>, Box<dyn std::error::Error + Send + Sync>> {
    if document.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("unsupported Engine gateway-secret manifest schema".into());
    }
    if document.get("node_id").and_then(Value::as_str) != Some(expected_node_id)
        || document.get("delivery_id").and_then(Value::as_str) != Some(expected_delivery_id)
    {
        return Err(
            "gateway-secret manifest does not match the current Engine node delivery".into(),
        );
    }
    let assignments = document
        .get("assignments")
        .and_then(Value::as_array)
        .ok_or("gateway-secret manifest has no assignments array")?;
    let mut ids = HashSet::new();
    for assignment in assignments {
        let id = assignment
            .get("assignment_id")
            .and_then(Value::as_str)
            .ok_or("gateway secret assignment_id missing")?;
        if !ids.insert(id) {
            return Err("gateway-secret manifest contains duplicate assignment IDs".into());
        }
        if assignment.get("files").and_then(Value::as_object).is_none()
            || assignment.get("secret_config").is_none()
            || assignment
                .get("config_revision")
                .and_then(Value::as_i64)
                .is_none()
        {
            return Err("gateway-secret manifest entry is incomplete".into());
        }
    }
    Ok(assignments)
}

async fn resources(
    assignment: &Value,
    secret_assignment: &Value,
    namespace: &str,
    node_id: &str,
) -> Result<Option<(Value, Value, Value, Value, String)>, Box<dyn std::error::Error + Send + Sync>>
{
    let Some((kind, binary, port)) = gateway(assignment) else {
        return Ok(None);
    };
    if secret_assignment
        .get("active_tenant_count")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0
    {
        return Ok(None);
    }
    let id = assignment
        .get("assignment_id")
        .and_then(Value::as_str)
        .ok_or("assignment_id missing")?;
    if secret_assignment
        .get("assignment_id")
        .and_then(Value::as_str)
        != Some(id)
        || secret_assignment
            .get("gateway_runtime")
            .and_then(Value::as_str)
            != assignment.get("gateway_runtime").and_then(Value::as_str)
        || secret_assignment
            .get("config_revision")
            .and_then(Value::as_i64)
            != assignment.get("config_revision").and_then(Value::as_i64)
    {
        return Err(
            "gateway secret manifest does not match its desired assignment revision".into(),
        );
    }
    let name = dns_name(id).ok_or("invalid assignment name")?;
    let secret_resource_name =
        dns_name(&format!("{id}-credentials")).ok_or("invalid gateway secret name")?;
    let target_id = assignment
        .get("database_target_id")
        .and_then(Value::as_str)
        .ok_or("database_target_id missing")?;
    let revision = assignment
        .get("config_revision")
        .and_then(Value::as_u64)
        .ok_or("config_revision missing")?;
    let endpoint = assignment.get("endpoint").ok_or("endpoint missing")?;
    let host = endpoint
        .get("host")
        .and_then(Value::as_str)
        .ok_or("endpoint.host missing")?;
    let db_port = endpoint
        .get("port")
        .and_then(Value::as_u64)
        .filter(|p| (1..=65535).contains(p))
        .ok_or("endpoint.port invalid")? as u16;
    if host.is_empty() || host.len() > 253 || host.contains('/') || host.contains('\n') {
        return Err("endpoint.host invalid".into());
    }

    let secret_config = secret_assignment
        .get("secret_config")
        .ok_or("secret_config missing")?;
    let config_kind = secret_config
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("secret config kind missing")?;
    if config_kind != kind {
        return Err("gateway secret config kind does not match provider".into());
    }
    let files = secret_assignment
        .get("files")
        .and_then(Value::as_object)
        .ok_or("gateway secret files missing")?;
    let mut data = serde_json::Map::new();
    for (key, value) in files {
        let encoded = value
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or("gateway secret file value is invalid")?;
        data.insert(key.clone(), Value::String(encoded.to_owned()));
    }
    let config_key = if kind == "sqlserver" {
        "config"
    } else {
        "runtime_config"
    };
    let runtime_config = secret_config
        .get(config_key)
        .ok_or("gateway runtime configuration missing")?;
    let runtime_bytes = serde_json::to_vec(runtime_config)?;
    use base64::Engine as _;
    data.insert(
        if kind == "sqlserver" {
            "config.json".into()
        } else {
            "users.json".into()
        },
        Value::String(base64::engine::general_purpose::STANDARD.encode(runtime_bytes)),
    );
    let common = labels_for_node(&name, id, node_id);
    let secret = json!({
        "apiVersion":"v1","kind":"Secret",
        "metadata":{"name":secret_resource_name,"namespace":namespace,"labels":common.clone()},
        "type":"Opaque","data":data
    });

    let mut envs = vec![];
    match kind {
        "mysql" => {
            envs.push(json!({"name":"PROXIMA_MYSQL_LISTEN_ADDR","value":"0.0.0.0:3307"}));
            envs.push(json!({"name":"PROXIMA_MYSQL_IDENTITY_REGISTRY","value":"/var/run/proxima/users.json"}));
            envs.push(
                json!({"name":"PROXIMA_MYSQL_TLS_CERT_FILE","value":"/var/run/proxima/tls.crt"}),
            );
            envs.push(
                json!({"name":"PROXIMA_MYSQL_TLS_KEY_FILE","value":"/var/run/proxima/tls.key"}),
            );
            envs.push(json!({"name":"PROXIMA_MYSQL_ALLOW_NON_LOOPBACK","value":"true"}));
        }
        "mongodb" => {
            envs.extend([
                json!({"name":"PROXIMA_MONGODB_LISTEN_ADDR","value":"0.0.0.0:27018"}),
                json!({"name":"PROXIMA_MONGODB_IDENTITY_REGISTRY","value":"/var/run/proxima/users.json"}),
                json!({"name":"PROXIMA_MONGODB_UPSTREAM_ADDR","value":format!("{host}:{db_port}")}),
                json!({"name":"PROXIMA_MONGODB_UPSTREAM_TLS","value":"true"}),
                json!({"name":"PROXIMA_MONGODB_UPSTREAM_TLS_SERVER_NAME","value":runtime_config.get("upstream_server_name").and_then(Value::as_str).unwrap_or(host)}),
                json!({"name":"PROXIMA_MONGODB_UPSTREAM_TLS_CA_FILE","value":"/var/run/proxima/ca.crt"}),
                json!({"name":"PROXIMA_MONGODB_TLS_CERT_FILE","value":"/var/run/proxima/tls.crt"}),
                json!({"name":"PROXIMA_MONGODB_TLS_KEY_FILE","value":"/var/run/proxima/tls.key"}),
            ]);
        }
        "redis" => {
            envs.extend([
                json!({"name":"PROXIMA_REDIS_LISTEN_ADDR","value":"0.0.0.0:6380"}),
                json!({"name":"PROXIMA_REDIS_IDENTITY_REGISTRY","value":"/var/run/proxima/users.json"}),
                json!({"name":"PROXIMA_REDIS_UPSTREAM_ADDR","value":format!("{host}:{db_port}")}),
                json!({"name":"PROXIMA_REDIS_UPSTREAM_TLS","value":"true"}),
                json!({"name":"PROXIMA_REDIS_UPSTREAM_TLS_SERVER_NAME","value":runtime_config.get("upstream_server_name").and_then(Value::as_str).unwrap_or(host)}),
                json!({"name":"PROXIMA_REDIS_UPSTREAM_TLS_CA_FILE","value":"/var/run/proxima/ca.crt"}),
                json!({"name":"PROXIMA_REDIS_TLS_CERT_FILE","value":"/var/run/proxima/tls.crt"}),
                json!({"name":"PROXIMA_REDIS_TLS_KEY_FILE","value":"/var/run/proxima/tls.key"}),
            ]);
        }
        "sqlserver" => {
            envs.extend([
                json!({"name":"PROXIMA_SQLSERVER_TDS_CONFIG","value":"/var/run/proxima/config.json"}),
                json!({"name":"PROXIMA_SQLSERVER_TDS_ALLOW_NON_LOOPBACK","value":"true"}),
            ]);
        }
        _ => unreachable!(),
    }

    let deployment = json!({
        "apiVersion":"apps/v1","kind":"Deployment",
        "metadata":{"name":name,"namespace":namespace,"labels":common.clone()},
        "spec":{"replicas":1,"selector":{"matchLabels":{"proxima.io/assignment":name}},
          "template":{"metadata":{"labels":common.clone(),"annotations":{"proxima.io/config-revision":revision.to_string(),"proxima.io/target-id":target_id}},
            "spec":{"automountServiceAccountToken":false,
              "securityContext":{"runAsNonRoot":true,"runAsUser":10001,"runAsGroup":10001,"fsGroup":10001,"fsGroupChangePolicy":"OnRootMismatch","seccompProfile":{"type":"RuntimeDefault"}},
              "containers":[{"name":"gateway","image":env::var("PROXIMA_KUBERNETES_GATEWAY_IMAGE").unwrap_or_else(|_|"ghcr.io/proxima-engine/proxima-engine:latest".into()),
                "imagePullPolicy":"IfNotPresent","command":[format!("/usr/local/bin/{binary}")],"env":envs,
                "ports":[{"name":"client","containerPort":port,"protocol":"TCP"}],
                "volumeMounts":[{"name":"gateway-secret","mountPath":"/var/run/proxima","readOnly":true}],
                "securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}},
                "resources":{"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"cpu":"1","memory":"512Mi"}},
                "readinessProbe":{"tcpSocket":{"port":"client"},"periodSeconds":5,"failureThreshold":3},
                "livenessProbe":{"tcpSocket":{"port":"client"},"periodSeconds":10,"failureThreshold":3}}],
              "volumes":[{"name":"gateway-secret","secret":{"secretName":secret_resource_name,"defaultMode":288}}]}}}
    });
    let service = json!({"apiVersion":"v1","kind":"Service","metadata":{"name":name,"namespace":namespace,"labels":common.clone()},
        "spec":{"type":"ClusterIP","selector":{"proxima.io/assignment":name},"ports":[{"name":"client","port":port,"targetPort":"client","protocol":"TCP"}]}});

    let mut egress = vec![
        json!({"to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}],"ports":[{"protocol":"UDP","port":53},{"protocol":"TCP","port":53}]}),
        json!({"to":[{"ipBlock":{"cidr":"::/0"}}],"ports":[{"protocol":"UDP","port":53},{"protocol":"TCP","port":53}]}),
    ];
    let mut resolved_upstream_addresses = 0usize;
    for address in tokio::net::lookup_host(format!("{host}:{db_port}")).await? {
        resolved_upstream_addresses += 1;
        let cidr = match address.ip() {
            std::net::IpAddr::V4(ip) => format!("{ip}/32"),
            std::net::IpAddr::V6(ip) => format!("{ip}/128"),
        };
        egress.push(
            json!({"to":[{"ipBlock":{"cidr":cidr}}],"ports":[{"protocol":"TCP","port":db_port}]}),
        );
    }
    if resolved_upstream_addresses == 0 {
        return Err(format!(
            "upstream database host {host} did not resolve to an address for NetworkPolicy egress"
        )
        .into());
    }
    let policy = json!({
        "apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
        "metadata":{"name":name,"namespace":namespace,"labels":common.clone()},
        "spec":{"podSelector":{"matchLabels":{"proxima.io/assignment":name}},
          "policyTypes":["Ingress","Egress"],
          "ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":namespace}}}],"ports":[{"protocol":"TCP","port":port}]}],
          "egress":egress}
    });
    Ok(Some((deployment, service, secret, policy, name)))
}

fn desired_assignments(
    document: &Value,
) -> Result<&Vec<Value>, Box<dyn std::error::Error + Send + Sync>> {
    if document.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("unsupported Engine desired-state schema version".into());
    }
    if document
        .get("delivery_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err("Engine desired state is missing delivery_id".into());
    }
    for field in ["node_id", "organization_id"] {
        if document
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(format!("Engine desired state is missing {field}").into());
        }
    }
    let node_id = document
        .get("node_id")
        .and_then(Value::as_str)
        .ok_or("Engine desired state is missing node_id")?;
    if !valid_node_label(node_id) {
        return Err("Engine desired state node_id is not a valid Kubernetes label value".into());
    }
    let assignments = document
        .get("assignments")
        .and_then(Value::as_array)
        .ok_or("desired state has no assignments array")?;
    let mut ids = HashSet::new();
    for assignment in assignments {
        let id = assignment
            .get("assignment_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("desired assignment has no assignment_id")?;
        if !ids.insert(id) {
            return Err("desired state contains duplicate assignment IDs".into());
        }
        let runtime = assignment
            .get("gateway_runtime")
            .and_then(Value::as_str)
            .ok_or("desired assignment has no gateway_runtime")?;
        if !matches!(
            runtime,
            "proxima-engine"
                | "proxima-mysql-gateway"
                | "proxima-mongodb-gateway"
                | "proxima-redis-gateway"
                | "proxima-sqlserver-tds-gateway"
                | "proxima-engine-native-sqlite"
                | "proxima-engine-native-oracle"
                | "proxima-engine-native-dynamodb"
                | "proxima-engine-native-cassandra"
                | "proxima-engine-native-search"
        ) {
            return Err("desired assignment contains an unsupported gateway_runtime".into());
        }
    }
    Ok(assignments)
}

async fn wait_for_deployment_ready(
    kube: &Kube,
    name: &str,
    timeout: Duration,
) -> Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let document = kube
            .request(
                Method::GET,
                &kube.path("deployments", Some(name)),
                None,
                false,
            )
            .await?;
        let generation = document
            .pointer("/metadata/generation")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let observed = document
            .pointer("/status/observedGeneration")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let ready = document
            .pointer("/status/readyReplicas")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let desired = document
            .pointer("/spec/replicas")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        if generation > 0 && observed >= generation && ready >= desired && desired > 0 {
            return Ok((ready, generation));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("Kubernetes gateway Deployment {name} did not become ready (ready {ready}/{desired}, observed generation {observed}/{generation})").into());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn write_gateway_status(
    config_path: &Path,
    node_id: &str,
    delivery_id: &str,
    assignments: &[Value],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let output_path = env::var_os("PROXIMA_NODE_GATEWAY_STATUS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| config_path.with_file_name("gateway-runtime-status.json"));
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let generated_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let document = json!({"schema_version":1,"node_id":node_id,"delivery_id":delivery_id,"generated_at":generated_at,"assignments":assignments});
    let temporary = output_path.with_extension("json.tmp");
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(serde_json::to_string_pretty(&document)?.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    fs::write(&temporary, serde_json::to_vec_pretty(&document)?)?;
    if output_path.exists() {
        fs::remove_file(&output_path)?;
    }
    fs::rename(&temporary, &output_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub async fn reconcile_once(
    kube: &Kube,
    config_path: &PathBuf,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let raw = fs::read(config_path)?;
    let desired: Value = serde_json::from_slice(&raw)?;
    let assignments = desired_assignments(&desired)?;
    let secret_path = env::var_os("PROXIMA_NODE_DATABASE_SECRETS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| config_path.with_file_name("database-target-secrets.json"));
    let secret_raw = fs::read(secret_path)?;
    let secret_document: Value = serde_json::from_slice(&secret_raw)?;
    let node_id = desired
        .get("node_id")
        .and_then(Value::as_str)
        .ok_or("Engine desired state is missing node_id")?;
    let delivery_id = desired
        .get("delivery_id")
        .and_then(Value::as_str)
        .ok_or("Engine desired state is missing delivery_id")?;
    let secret_assignments = desired_secret_assignments(&secret_document, node_id, delivery_id)?;
    let secret_by_id: HashMap<&str, &Value> = secret_assignments
        .iter()
        .filter_map(|entry| {
            entry
                .get("assignment_id")
                .and_then(Value::as_str)
                .map(|id| (id, entry))
        })
        .collect();
    let mut desired_names = HashSet::new();
    let mut status_entries = Vec::new();
    let mut applied = 0usize;
    for assignment in assignments {
        let Some((kind, _, _)) = gateway(assignment) else {
            continue;
        };
        let id = assignment
            .get("assignment_id")
            .and_then(Value::as_str)
            .ok_or("assignment ID missing")?;
        let secret_assignment = secret_by_id
            .get(id)
            .ok_or("active gateway assignment has no corresponding secret manifest")?;
        let active_tenant_count = secret_assignment
            .get("active_tenant_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let revision = assignment
            .get("config_revision")
            .and_then(Value::as_i64)
            .ok_or("config_revision missing")?;
        if active_tenant_count == 0 {
            status_entries.push(json!({"assignment_id":id,"config_revision":revision,"status":"removed","ready_replicas":0}));
            continue;
        }
        let Some((deployment, service, secret, policy, name)) =
            resources(assignment, secret_assignment, &kube.namespace, node_id).await?
        else {
            continue;
        };
        if !desired_names.insert(name.clone()) {
            return Err("duplicate gateway assignment resource name".into());
        }
        let secret_name = secret
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .ok_or("managed Secret name missing")?
            .to_owned();
        kube.apply("secrets", &secret_name, secret).await?;
        kube.apply("deployments", &name, deployment).await?;
        kube.apply("services", &name, service).await?;
        kube.apply("networkpolicies", &name, policy).await?;
        let (ready_replicas, observed_generation) =
            wait_for_deployment_ready(kube, &name, Duration::from_secs(180)).await?;
        let service_dns = format!("{name}.{}.svc.cluster.local", kube.namespace);
        let client_port = gateway(assignment)
            .map(|(_, _, port)| port)
            .unwrap_or_default();
        status_entries.push(json!({
            "assignment_id":id,"config_revision":revision,"status":"ready",
            "deployment":name,"service":name,"service_dns":service_dns,
            "port":client_port,"ready_replicas":ready_replicas,"observed_generation":observed_generation,
            "secret_resource":secret_name
        }));
        info!(
            kind,
            name,
            ready_replicas,
            "reconciled Engine-managed gateway, credentials, network policy and readiness"
        );
        applied += 1;
    }
    // Remove only resources carrying our explicit ownership label. Customer
    // Secrets and workloads without this label are never touched.
    for resource in ["deployments", "services", "secrets", "networkpolicies"] {
        let path = format!(
            "{}?labelSelector={}",
            kube.path(resource, None),
            ownership_selector(node_id)
        );
        let list = kube.request(Method::GET, &path, None, false).await?;
        if let Some(items) = list.get("items").and_then(Value::as_array) {
            for item in items {
                let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
                    continue;
                };
                let assignment_name = if resource == "secrets" {
                    name.strip_suffix("-credentials").unwrap_or(name)
                } else {
                    name
                };
                if !desired_names.contains(assignment_name) {
                    let delete_path = format!(
                        "{}/{}?propagationPolicy=Foreground",
                        kube.path(resource, None),
                        name
                    );
                    kube.request(Method::DELETE, &delete_path, None, false)
                        .await?;
                    info!(
                        resource,
                        name, "removed stale Engine-managed Kubernetes resource"
                    );
                }
            }
        }
    }
    write_gateway_status(config_path, node_id, delivery_id, &status_entries)?;
    Ok(applied)
}

pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let kube = Kube::from_env()?;
    let path = PathBuf::from(
        env::var("PROXIMA_NODE_DATABASE_CONFIG_PATH")
            .unwrap_or_else(|_| "/var/lib/proxima/database-targets.json".into()),
    );
    let seconds = env::var("PROXIMA_KUBERNETES_RECONCILE_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| (5..=300).contains(v))
        .unwrap_or(15);
    info!(namespace=%kube.namespace, path=%path.display(), interval_seconds=seconds,
        "Kubernetes gateway desired-state reconciler started");
    let mut ticker = interval(Duration::from_secs(seconds));
    loop {
        ticker.tick().await;
        match reconcile_once(&kube, &path).await {
            Ok(count) => info!(
                managed_gateway_assignments = count,
                "Kubernetes gateway workloads reconciled"
            ),
            Err(error) => {
                warn!(%error, "Kubernetes gateway reconciliation failed; last applied workloads are retained")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn desired_state_contract_accepts_multiple_gateway_assignments() {
        let state = json!({
            "schema_version":1,"node_id":"node-a","organization_id":"org-a","delivery_id":"test-delivery",
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
        let state = json!({"schema_version":1,"node_id":"node-a","organization_id":"org-a","delivery_id":"test-delivery","assignments":[]});
        assert!(desired_assignments(&state).unwrap().is_empty());
    }

    #[test]
    fn desired_state_contract_rejects_wrong_schema_and_duplicate_ids() {
        let wrong_schema = json!({"schema_version":2,"node_id":"node-a","organization_id":"org-a","delivery_id":"test-delivery","assignments":[]});
        let duplicate = json!({"schema_version":1,"node_id":"node-a","organization_id":"org-a","delivery_id":"test-delivery","assignments":[
            {"assignment_id":"same","gateway_runtime":"proxima-mysql-gateway"},
            {"assignment_id":"same","gateway_runtime":"proxima-redis-gateway"}
        ]});
        let unsupported = json!({"schema_version":1,"node_id":"node-a","organization_id":"org-a","delivery_id":"test-delivery","assignments":[
            {"assignment_id":"bad","gateway_runtime":"unknown-gateway"}
        ]});
        let invalid_node_id = json!({"schema_version":1,"node_id":"node/unsafe","organization_id":"org-a","delivery_id":"test-delivery","assignments":[]});
        assert!(desired_assignments(&wrong_schema).is_err());
        assert!(desired_assignments(&duplicate).is_err());
        assert!(desired_assignments(&unsupported).is_err());
        assert!(desired_assignments(&invalid_node_id).is_err());
    }

    #[test]
    fn gateway_resources_and_cleanup_are_scoped_to_the_owning_node() {
        let labels = labels_for_node("px-assignment", "assignment-id", "node-a");
        assert_eq!(
            labels.get("proxima.io/node-id").and_then(Value::as_str),
            Some("node-a")
        );
        assert_eq!(
            ownership_selector("node-a"),
            "app.kubernetes.io/managed-by=proxima-engine,proxima.io/node-id=node-a"
        );
        assert_ne!(ownership_selector("node-a"), ownership_selector("node-b"));
        assert!(valid_node_label("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!valid_node_label("node/unsafe"));
    }

    #[test]
    fn maps_only_existing_gateway_runtime_binaries() {
        assert_eq!(
            gateway(&json!({"gateway_runtime":"proxima-mysql-gateway"}))
                .unwrap()
                .0,
            "mysql"
        );
        assert_eq!(
            gateway(&json!({"gateway_runtime":"proxima-mongodb-gateway"}))
                .unwrap()
                .0,
            "mongodb"
        );
        assert_eq!(
            gateway(&json!({"gateway_runtime":"proxima-redis-gateway"}))
                .unwrap()
                .0,
            "redis"
        );
        assert_eq!(
            gateway(&json!({"gateway_runtime":"proxima-sqlserver-tds-gateway"}))
                .unwrap()
                .0,
            "sqlserver"
        );
        assert!(gateway(&json!({"gateway_runtime":"proxima-engine"})).is_none());
        assert!(gateway(&json!({"gateway_runtime":"proxima-engine-native-sqlite"})).is_none());
        assert!(gateway(&json!({"gateway_runtime":"dynamodb"})).is_none());
    }
    #[test]
    fn assignment_resource_names_are_dns_safe_and_bounded() {
        let value = dns_name("Assignment/With Spaces_AND.UPPER");
        assert!(value
            .as_ref()
            .is_some_and(|v| v.len() <= 53 && v.starts_with("px-")));
    }
}
