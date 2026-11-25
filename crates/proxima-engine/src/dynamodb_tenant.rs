use async_trait::async_trait;
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamoTenantError {
    InvalidTenantId,
    InvalidTableArn,
    Provider(String),
}
impl std::fmt::Display for DynamoTenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTenantId => write!(f, "invalid DynamoDB tenant partition key"),
            Self::InvalidTableArn => write!(f, "invalid DynamoDB table ARN"),
            Self::Provider(e) => write!(f, "DynamoDB IAM operation failed: {e}"),
        }
    }
}
impl std::error::Error for DynamoTenantError {}

/// Tenant binding for a shared DynamoDB table. IAM LeadingKeys restricts all
/// item-level access to the authenticated tenant partition key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamoTenant {
    tenant_id: String,
    table_arn: String,
}
impl DynamoTenant {
    pub fn new(tenant_id: &str, table_arn: &str) -> Result<Self, DynamoTenantError> {
        validate_tenant_id(tenant_id)?;
        validate_table_arn(table_arn)?;
        Ok(Self {
            tenant_id: tenant_id.to_owned(),
            table_arn: table_arn.to_owned(),
        })
    }
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn table_arn(&self) -> &str {
        &self.table_arn
    }
    pub fn role_name(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.tenant_id.as_bytes());
        let suffix = safe_role_suffix(&self.tenant_id);
        let short = suffix.chars().take(39).collect::<String>();
        format!("AgataProxima-{}-{}", short, hex::encode(&digest[..5]))
    }
    pub fn iam_policy(&self) -> Value {
        json!({"Version":"2012-10-17","Statement":[{"Sid":"TenantPartitionKeyAccess","Effect":"Allow","Action":["dynamodb:GetItem","dynamodb:PutItem","dynamodb:UpdateItem","dynamodb:DeleteItem","dynamodb:Query"],"Resource":self.table_arn,"Condition":{"Null":{"dynamodb:LeadingKeys":"false"},"ForAllValues:StringEquals":{"dynamodb:LeadingKeys":[self.tenant_id]}}}]})
    }

    /// Executes provisioning against an IAM adapter. This deliberately uses an
    /// IAM role (short-lived STS credentials), never long-lived access keys.
    pub async fn provision<A: DynamoIamAdmin>(
        &self,
        admin: &A,
        trust_policy: Value,
    ) -> Result<String, DynamoTenantError> {
        validate_trust_policy(&trust_policy)?;
        let role = self.role_name();
        admin
            .create_or_update_role(&role, trust_policy, 3600)
            .await
            .map_err(provider)?;
        admin
            .put_inline_policy(&role, "AgataProximaTenantBoundary", self.iam_policy())
            .await
            .map_err(provider)?;
        self.verify(admin).await?;
        Ok(role)
    }
    pub async fn verify<A: DynamoIamAdmin>(&self, admin: &A) -> Result<(), DynamoTenantError> {
        let role = self.role_name();
        if !admin.role_exists(&role).await.map_err(provider)? {
            return Err(provider("IAM role is absent"));
        }
        let actual = admin
            .get_inline_policy(&role, "AgataProximaTenantBoundary")
            .await
            .map_err(provider)?;
        if actual != self.iam_policy() {
            return Err(provider(
                "tenant IAM policy does not exactly match expected LeadingKeys boundary",
            ));
        }
        Ok(())
    }
    /// Rotation replaces the trust policy and policy document in place. Clients
    /// must obtain fresh STS sessions; existing sessions expire within 1 hour.
    pub async fn rotate<A: DynamoIamAdmin>(
        &self,
        admin: &A,
        new_trust_policy: Value,
    ) -> Result<(), DynamoTenantError> {
        validate_trust_policy(&new_trust_policy)?;
        let role = self.role_name();
        admin
            .create_or_update_role(&role, new_trust_policy, 3600)
            .await
            .map_err(provider)?;
        admin
            .put_inline_policy(&role, "AgataProximaTenantBoundary", self.iam_policy())
            .await
            .map_err(provider)?;
        self.verify(admin).await
    }
    pub async fn revoke<A: DynamoIamAdmin>(&self, admin: &A) -> Result<(), DynamoTenantError> {
        admin.delete_role(&self.role_name()).await.map_err(provider)
    }
}
#[async_trait]
pub trait DynamoIamAdmin: Send + Sync {
    async fn create_or_update_role(
        &self,
        role: &str,
        trust_policy: Value,
        max_session_seconds: u32,
    ) -> Result<(), String>;
    async fn put_inline_policy(
        &self,
        role: &str,
        policy_name: &str,
        policy: Value,
    ) -> Result<(), String>;
    async fn role_exists(&self, role: &str) -> Result<bool, String>;
    async fn get_inline_policy(&self, role: &str, policy_name: &str) -> Result<Value, String>;
    /// Must detach managed policies and delete inline policies before deleting role.
    async fn delete_role(&self, role: &str) -> Result<(), String>;
}
fn validate_trust_policy(policy: &Value) -> Result<(), DynamoTenantError> {
    let statements = policy
        .get("Statement")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| provider("trust policy must contain a non-empty Statement array"))?;
    for statement in statements {
        if statement.get("Effect").and_then(Value::as_str) != Some("Allow") {
            return Err(provider("trust policy statements must use Effect=Allow"));
        }
        let action_allowed = match statement.get("Action") {
            Some(Value::String(value)) => value == "sts:AssumeRole",
            Some(Value::Array(values)) => {
                !values.is_empty()
                    && values
                        .iter()
                        .all(|value| value.as_str() == Some("sts:AssumeRole"))
            }
            _ => false,
        };
        if !action_allowed {
            return Err(provider("trust policy may grant only sts:AssumeRole"));
        }
        let principal = statement
            .get("Principal")
            .ok_or_else(|| provider("trust policy principal is required"))?;
        if principal.to_string().contains("\"*\"") {
            return Err(provider("wildcard trust principals are forbidden"));
        }
        let principal_values = [
            principal.get("AWS"),
            principal.get("Service"),
            principal.get("Federated"),
        ];
        let has_specific_principal =
            principal_values
                .into_iter()
                .flatten()
                .any(|value| match value {
                    Value::String(name) => !name.trim().is_empty() && name != "*",
                    Value::Array(names) => {
                        !names.is_empty()
                            && names.iter().all(|name| {
                                name.as_str()
                                    .is_some_and(|s| !s.trim().is_empty() && s != "*")
                            })
                    }
                    _ => false,
                });
        if !has_specific_principal {
            return Err(provider(
                "trust policy must name a specific AWS, Service, or Federated principal",
            ));
        }
    }
    Ok(())
}

fn provider(e: impl ToString) -> DynamoTenantError {
    DynamoTenantError::Provider(e.to_string())
}
fn safe_role_suffix(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}
pub fn validate_tenant_id(id: &str) -> Result<(), DynamoTenantError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
    {
        return Err(DynamoTenantError::InvalidTenantId);
    }
    Ok(())
}
fn validate_table_arn(arn: &str) -> Result<(), DynamoTenantError> {
    let p: Vec<&str> = arn.split(':').collect();
    let allowed = matches!(
        p.get(1).copied(),
        Some("aws" | "aws-cn" | "aws-us-gov" | "aws-iso" | "aws-iso-b")
    );
    let region = !p.get(3).unwrap_or(&"").is_empty()
        && p[3]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let table = p
        .get(5)
        .and_then(|r| r.strip_prefix("table/"))
        .unwrap_or("");
    if p.len() != 6
        || p[0] != "arn"
        || !allowed
        || p[2] != "dynamodb"
        || !region
        || p[4].len() != 12
        || !p[4].bytes().all(|b| b.is_ascii_digit())
        || !(3..=255).contains(&table.len())
        || !table
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(DynamoTenantError::InvalidTableArn);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    const ARN: &str = "arn:aws:dynamodb:us-east-1:123456789012:table/proxima-records";
    #[test]
    fn policy_is_tenant_scoped() {
        let t = DynamoTenant::new("tenant-a", ARN).unwrap();
        let p = t.iam_policy();
        assert_eq!(p["Statement"][0]["Resource"], ARN);
        assert_eq!(
            p["Statement"][0]["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"][0],
            "tenant-a"
        );
        assert!(!p.to_string().contains("dynamodb:Scan"));
    }
    #[test]
    fn validates_arn_and_tenant() {
        assert!(DynamoTenant::new("tenant-a", ARN).is_ok());
        assert!(DynamoTenant::new("../x", ARN).is_err());
        assert!(DynamoTenant::new("tenant-a", "*").is_err());
    }

    #[test]
    fn rejects_wildcard_or_unrelated_trust_policy() {
        let wildcard = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]});
        let wrong_action = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:*"}]});
        let valid = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]});
        assert!(validate_trust_policy(&wildcard).is_err());
        assert!(validate_trust_policy(&wrong_action).is_err());
        assert!(validate_trust_policy(&valid).is_ok());
    }
}

/// Concrete AWS IAM implementation. Credentials and region are resolved through
/// the standard AWS SDK provider chain (environment, shared config, web identity,
/// ECS task role, or EC2 instance profile); no static keys are stored by Proxima.
#[derive(Clone)]
pub struct AwsSdkDynamoIamAdmin {
    client: aws_sdk_iam::Client,
}

impl AwsSdkDynamoIamAdmin {
    pub async fn from_default_credential_chain() -> Result<Self, DynamoTenantError> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Ok(Self {
            client: aws_sdk_iam::Client::new(&config),
        })
    }

    pub fn from_client(client: aws_sdk_iam::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl DynamoIamAdmin for AwsSdkDynamoIamAdmin {
    async fn create_or_update_role(
        &self,
        role: &str,
        trust_policy: Value,
        max_session_seconds: u32,
    ) -> Result<(), String> {
        if !(3_600..=43_200).contains(&max_session_seconds) {
            return Err(
                "IAM role maximum session duration must be between 3600 and 43200 seconds".into(),
            );
        }
        let document = trust_policy.to_string();
        match self
            .client
            .create_role()
            .role_name(role)
            .assume_role_policy_document(document.clone())
            .max_session_duration(max_session_seconds as i32)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(create_error) => {
                self.client.update_assume_role_policy()
                    .role_name(role)
                    .policy_document(document)
                    .send().await
                    .map_err(|update_error| format!(
                        "CreateRole failed ({create_error}); UpdateAssumeRolePolicy failed ({update_error})"
                    ))?;
                self.client
                    .update_role()
                    .role_name(role)
                    .max_session_duration(max_session_seconds as i32)
                    .send()
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
        }
    }

    async fn put_inline_policy(
        &self,
        role: &str,
        policy_name: &str,
        policy: Value,
    ) -> Result<(), String> {
        self.client
            .put_role_policy()
            .role_name(role)
            .policy_name(policy_name)
            .policy_document(policy.to_string())
            .send()
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn role_exists(&self, role: &str) -> Result<bool, String> {
        match self.client.get_role().role_name(role).send().await {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_no_such_entity_exception()) =>
            {
                Ok(false)
            }
            Err(error) => Err(error.to_string()),
        }
    }

    async fn get_inline_policy(&self, role: &str, policy_name: &str) -> Result<Value, String> {
        let response = self
            .client
            .get_role_policy()
            .role_name(role)
            .policy_name(policy_name)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let document = response.policy_document();
        match serde_json::from_str(document) {
            Ok(policy) => Ok(policy),
            Err(original) => {
                let decoded = urlencoding::decode(document)
                    .map_err(|e| format!("IAM policy URL decoding failed: {e}"))?;
                serde_json::from_str(&decoded)
                    .map_err(|_| format!("IAM returned an invalid policy document: {original}"))
            }
        }
    }

    async fn delete_role(&self, role: &str) -> Result<(), String> {
        if !self.role_exists(role).await? {
            return Ok(());
        }
        // IAM list APIs are paginated. Remove every inline and attached policy
        // before deleting the role; otherwise DeleteRole fails with DeleteConflict.
        let mut marker: Option<String> = None;
        loop {
            let mut request = self.client.list_role_policies().role_name(role);
            if let Some(value) = marker.as_deref() {
                request = request.marker(value);
            }
            let page = request.send().await.map_err(|e| e.to_string())?;
            for name in page.policy_names() {
                self.client
                    .delete_role_policy()
                    .role_name(role)
                    .policy_name(name.as_str())
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
            }
            if !page.is_truncated() {
                break;
            }
            marker = page.marker().map(str::to_owned);
            if marker.is_none() {
                return Err("IAM inline-policy pagination omitted marker".into());
            }
        }
        marker = None;
        loop {
            let mut request = self.client.list_attached_role_policies().role_name(role);
            if let Some(value) = marker.as_deref() {
                request = request.marker(value);
            }
            let page = request.send().await.map_err(|e| e.to_string())?;
            for policy in page.attached_policies() {
                let arn = policy
                    .policy_arn()
                    .ok_or_else(|| "IAM attached policy omitted ARN".to_owned())?;
                self.client
                    .detach_role_policy()
                    .role_name(role)
                    .policy_arn(arn)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
            }
            if !page.is_truncated() {
                break;
            }
            marker = page.marker().map(str::to_owned);
            if marker.is_none() {
                return Err("IAM attached-policy pagination omitted marker".into());
            }
        }
        self.client
            .delete_role()
            .role_name(role)
            .send()
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}
