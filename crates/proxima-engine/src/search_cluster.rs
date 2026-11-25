use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use std::{fmt, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchProvider {
    Elasticsearch,
    OpenSearch,
}

#[derive(Debug)]
pub enum SearchError {
    InvalidConfiguration(&'static str),
    InvalidTenant,
    Http(String),
    Serialization(String),
    UnhealthyCluster(String),
    IdentityVerificationFailed,
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(v) => write!(f, "invalid search cluster configuration: {v}"),
            Self::InvalidTenant => write!(f, "invalid tenant identifier"),
            Self::Http(v) => write!(f, "search cluster API request failed: {v}"),
            Self::Serialization(v) => write!(f, "search cluster response error: {v}"),
            Self::UnhealthyCluster(v) => write!(f, "search cluster is unhealthy: {v}"),
            Self::IdentityVerificationFailed => {
                write!(f, "tenant identity or role verification failed")
            }
        }
    }
}

impl std::error::Error for SearchError {}

#[derive(Clone)]
pub struct TenantSearchCredential {
    pub provider: SearchProvider,
    pub tenant_id: String,
    pub username: String,
    pub role_name: String,
    password: String,
}

impl TenantSearchCredential {
    /// The caller must transfer this secret directly into its encrypted
    /// credential store. Do not log it or place it in ordinary configuration.
    pub fn expose_secret(&self) -> &str {
        &self.password
    }

    pub fn to_value(&self) -> Value {
        json!({
            "provider": match self.provider { SearchProvider::Elasticsearch => "elasticsearch", SearchProvider::OpenSearch => "opensearch" },
            "tenant_id": self.tenant_id,
            "username": self.username,
            "role_name": self.role_name,
            "password": self.password
        })
    }

    pub fn from_value(value: &Value) -> Result<Self, SearchError> {
        let provider = match required_identity_field(value, "provider")? {
            "elasticsearch" => SearchProvider::Elasticsearch,
            "opensearch" => SearchProvider::OpenSearch,
            _ => {
                return Err(SearchError::Serialization(
                    "stored search identity has an unknown provider".into(),
                ))
            }
        };
        let tenant_id = required_identity_field(value, "tenant_id")?.to_owned();
        let username = required_identity_field(value, "username")?.to_owned();
        let role_name = required_identity_field(value, "role_name")?.to_owned();
        let password = required_identity_field(value, "password")?.to_owned();
        if password.is_empty()
            || tenant_id.is_empty()
            || username.is_empty()
            || role_name.is_empty()
        {
            return Err(SearchError::Serialization(
                "stored search identity contains an empty field".into(),
            ));
        }
        Ok(Self {
            provider,
            tenant_id,
            username,
            role_name,
            password,
        })
    }
}

fn required_identity_field<'a>(value: &'a Value, name: &str) -> Result<&'a str, SearchError> {
    value.get(name).and_then(Value::as_str).ok_or_else(|| {
        SearchError::Serialization(format!("stored search identity is missing {name}"))
    })
}

pub struct SearchClusterClient {
    provider: SearchProvider,
    endpoint: String,
    admin_username: String,
    admin_password: String,
    client: Client,
}

impl SearchClusterClient {
    pub fn connect(
        provider: SearchProvider,
        endpoint: &str,
        admin_username: &str,
        admin_password: &str,
        ca_pem: Option<&[u8]>,
    ) -> Result<Self, SearchError> {
        let parsed = reqwest::Url::parse(endpoint)
            .map_err(|_| SearchError::InvalidConfiguration("endpoint URL is invalid"))?;

        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !matches!(parsed.path(), "" | "/")
        {
            return Err(SearchError::InvalidConfiguration(
                "endpoint must be an HTTPS origin without embedded credentials, query, fragment or path",
            ));
        }

        if admin_username.trim().is_empty() || admin_password.is_empty() {
            return Err(SearchError::InvalidConfiguration(
                "administrative username and password are required",
            ));
        }

        let mut builder = Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(90))
            .redirect(reqwest::redirect::Policy::none());

        if let Some(pem) = ca_pem {
            let certificate = reqwest::Certificate::from_pem(pem).map_err(|e| {
                SearchError::InvalidConfiguration(Box::leak(
                    format!("invalid CA certificate: {e}").into_boxed_str(),
                ))
            })?;
            builder = builder.add_root_certificate(certificate);
        }

        let client = builder
            .build()
            .map_err(|e| SearchError::Http(e.to_string()))?;

        Ok(Self {
            provider,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            admin_username: admin_username.to_owned(),
            admin_password: admin_password.to_owned(),
            client,
        })
    }

    fn resource_path(&self, kind: &str, name: &str) -> Result<String, SearchError> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        {
            return Err(SearchError::InvalidTenant);
        }

        let path = match (self.provider, kind) {
            (SearchProvider::Elasticsearch, "role") => format!("/_security/role/{name}"),
            (SearchProvider::Elasticsearch, "user") => format!("/_security/user/{name}"),
            (SearchProvider::OpenSearch, "role") => format!("/_plugins/_security/api/roles/{name}"),
            (SearchProvider::OpenSearch, "user") => {
                format!("/_plugins/_security/api/internalusers/{name}")
            }
            (SearchProvider::OpenSearch, "mapping") => {
                format!("/_plugins/_security/api/rolesmapping/{name}")
            }
            _ => return Err(SearchError::InvalidConfiguration("unknown resource type")),
        };

        Ok(path)
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        allow_not_found: bool,
    ) -> Result<Value, SearchError> {
        let url = format!("{}{}", self.endpoint, path);
        let mut request = self
            .client
            .request(method, url)
            .basic_auth(&self.admin_username, Some(&self.admin_password))
            .header(reqwest::header::ACCEPT, "application/json");

        if let Some(value) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(value);
        }

        let response = request
            .send()
            .await
            .map_err(|e| SearchError::Http(e.to_string()))?;

        let status = response.status();

        if allow_not_found && status == StatusCode::NOT_FOUND {
            return Ok(json!({"already_absent": true}));
        }

        let text = response
            .text()
            .await
            .map_err(|e| SearchError::Http(e.to_string()))?;

        if !status.is_success() {
            return Err(SearchError::Http(format!(
                "HTTP {status}: {}",
                text.chars().take(1200).collect::<String>()
            )));
        }

        if text.trim().is_empty() {
            return Ok(json!({}));
        }

        serde_json::from_str(&text).map_err(|e| SearchError::Serialization(e.to_string()))
    }

    pub async fn health_check(&self) -> Result<(), SearchError> {
        let response = self
            .request(Method::GET, "/_cluster/health", None, false)
            .await?;

        let status = response
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SearchError::Serialization("cluster health response has no status".into())
            })?;

        if status == "red" {
            return Err(SearchError::UnhealthyCluster(status.to_owned()));
        }

        Ok(())
    }

    fn role_body(&self, tenant_id: &str) -> Result<Value, SearchError> {
        match self.provider {
            SearchProvider::Elasticsearch => {
                crate::elasticsearch_tenant::elasticsearch_role_descriptor(tenant_id)
                    .ok_or(SearchError::InvalidTenant)
            }
            SearchProvider::OpenSearch => {
                crate::opensearch_tenant::opensearch_role_descriptor(tenant_id)
                    .ok_or(SearchError::InvalidTenant)
            }
        }
    }

    pub async fn provision_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<TenantSearchCredential, SearchError> {
        let password = format!(
            "{}{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        self.provision_tenant_with_password(tenant_id, &password)
            .await
    }

    /// Provision or reconcile a tenant identity using a password supplied by
    /// the encrypted Cloud desired-state envelope. This keeps the credential
    /// revision under Cloud control instead of generating a secret that cannot
    /// be returned to the Cloud credential store.
    pub async fn provision_tenant_with_password(
        &self,
        tenant_id: &str,
        supplied_password: &str,
    ) -> Result<TenantSearchCredential, SearchError> {
        self.health_check().await?;

        let valid = match self.provider {
            SearchProvider::Elasticsearch => {
                crate::elasticsearch_tenant::valid_tenant_id(tenant_id)
            }
            SearchProvider::OpenSearch => crate::opensearch_tenant::valid_tenant_id(tenant_id),
        };

        if !valid {
            return Err(SearchError::InvalidTenant);
        }
        if supplied_password.len() < 24
            || !supplied_password
                .bytes()
                .all(|byte| (33..=126).contains(&byte))
        {
            return Err(SearchError::InvalidConfiguration(
                "tenant password must contain at least 24 printable ASCII characters",
            ));
        }

        let role_name = format!("proxima_tenant_{tenant_id}");
        let username = format!("px_{tenant_id}");
        let password = supplied_password.to_owned();

        let role_path = self.resource_path("role", &role_name)?;
        let user_path = self.resource_path("user", &username)?;
        let role_body = self.role_body(tenant_id)?;

        self.request(Method::PUT, &role_path, Some(&role_body), false)
            .await?;

        let user_body = match self.provider {
            SearchProvider::Elasticsearch => json!({
                "password": password,
                "roles": [role_name],
                "full_name": format!("Proxima tenant {tenant_id}"),
                "enabled": true
            }),
            SearchProvider::OpenSearch => json!({
                "password": password,
                "backend_roles": [role_name],
                "attributes": {
                    "managed_by": "proxima-engine",
                    "tenant_id": tenant_id
                }
            }),
        };

        self.request(Method::PUT, &user_path, Some(&user_body), false)
            .await?;
        if self.provider == SearchProvider::OpenSearch {
            let mapping_path = self.resource_path("mapping", &role_name)?;
            let mapping = json!({"backend_roles":[role_name],"hosts":[],"users":[]});
            self.request(Method::PUT, &mapping_path, Some(&mapping), false)
                .await?;
        }

        let credential = TenantSearchCredential {
            provider: self.provider,
            tenant_id: tenant_id.to_owned(),
            username,
            role_name,
            password,
        };

        self.verify_tenant(&credential).await?;
        self.verify_tenant_authentication(&credential).await?;
        Ok(credential)
    }

    pub async fn verify_tenant_authentication(
        &self,
        credential: &TenantSearchCredential,
    ) -> Result<(), SearchError> {
        if credential.provider != self.provider {
            return Err(SearchError::InvalidConfiguration(
                "credential belongs to a different provider",
            ));
        }
        let path = match self.provider {
            SearchProvider::Elasticsearch => "/_security/_authenticate",
            SearchProvider::OpenSearch => "/_plugins/_security/authinfo",
        };
        let response = self
            .client
            .get(format!("{}{}", self.endpoint, path))
            .basic_auth(&credential.username, Some(&credential.password))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| SearchError::Http(e.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| SearchError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(SearchError::IdentityVerificationFailed);
        }
        let value: Value =
            serde_json::from_str(&body).map_err(|e| SearchError::Serialization(e.to_string()))?;
        let username_matches = match self.provider {
            SearchProvider::Elasticsearch => {
                value.get("username").and_then(Value::as_str) == Some(credential.username.as_str())
            }
            SearchProvider::OpenSearch => {
                value.get("user_name").and_then(Value::as_str) == Some(credential.username.as_str())
            }
        };
        let roles = match self.provider {
            SearchProvider::Elasticsearch => value.get("roles").and_then(Value::as_array),
            SearchProvider::OpenSearch => value.get("backend_roles").and_then(Value::as_array),
        };
        let role_matches = roles.is_some_and(|values| {
            values
                .iter()
                .any(|item| item.as_str() == Some(credential.role_name.as_str()))
        });
        if !username_matches || !role_matches {
            return Err(SearchError::IdentityVerificationFailed);
        }
        Ok(())
    }

    pub async fn rotate_credential(
        &self,
        credential: &mut TenantSearchCredential,
    ) -> Result<(), SearchError> {
        if credential.provider != self.provider {
            return Err(SearchError::InvalidConfiguration(
                "credential belongs to a different provider",
            ));
        }

        self.verify_tenant(credential).await?;

        let password = format!(
            "{}{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );

        let user_path = self.resource_path("user", &credential.username)?;
        let body = match self.provider {
            SearchProvider::Elasticsearch => json!({
                "password": password,
                "roles": [credential.role_name],
                "full_name": format!("Proxima tenant {}", credential.tenant_id),
                "enabled": true
            }),
            SearchProvider::OpenSearch => json!({
                "password": password,
                "backend_roles": [credential.role_name],
                "attributes": {
                    "managed_by": "proxima-engine",
                    "tenant_id": credential.tenant_id
                }
            }),
        };

        self.request(Method::PUT, &user_path, Some(&body), false)
            .await?;
        credential.password = password;
        self.verify_tenant(credential).await?;
        self.verify_tenant_authentication(credential).await
    }

    pub async fn verify_tenant(
        &self,
        credential: &TenantSearchCredential,
    ) -> Result<(), SearchError> {
        if credential.provider != self.provider {
            return Err(SearchError::InvalidConfiguration(
                "credential belongs to a different provider",
            ));
        }

        let user_path = self.resource_path("user", &credential.username)?;
        let role_path = self.resource_path("role", &credential.role_name)?;

        let user = self.request(Method::GET, &user_path, None, false).await?;
        let role = self.request(Method::GET, &role_path, None, false).await?;
        if self.provider == SearchProvider::OpenSearch {
            let mapping_path = self.resource_path("mapping", &credential.role_name)?;
            let mapping = self
                .request(Method::GET, &mapping_path, None, false)
                .await?;
            let mapping_value = mapping.get(&credential.role_name).unwrap_or(&mapping);
            let backend_roles = mapping_value.get("backend_roles").and_then(Value::as_array);
            if !backend_roles.is_some_and(|items| {
                items.len() == 1 && items[0].as_str() == Some(credential.role_name.as_str())
            }) {
                return Err(SearchError::IdentityVerificationFailed);
            }
        }

        let user_exists = match self.provider {
            SearchProvider::Elasticsearch => user.get(&credential.username).is_some(),
            SearchProvider::OpenSearch => {
                user.get("user").is_some() || user.get(&credential.username).is_some()
            }
        };

        if !user_exists || role.is_null() || role.as_object().is_some_and(|v| v.is_empty()) {
            return Err(SearchError::IdentityVerificationFailed);
        }

        Ok(())
    }

    pub async fn revoke_tenant(
        &self,
        credential: &TenantSearchCredential,
    ) -> Result<(), SearchError> {
        if credential.provider != self.provider {
            return Err(SearchError::InvalidConfiguration(
                "credential belongs to a different provider",
            ));
        }

        let user_path = self.resource_path("user", &credential.username)?;
        let role_path = self.resource_path("role", &credential.role_name)?;

        self.request(Method::DELETE, &user_path, None, true).await?;
        if self.provider == SearchProvider::OpenSearch {
            let mapping_path = self.resource_path("mapping", &credential.role_name)?;
            self.request(Method::DELETE, &mapping_path, None, true)
                .await?;
        }
        self.request(Method::DELETE, &role_path, None, true).await?;

        Ok(())
    }
}
