use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamoTenantError {
    InvalidTenantId,
    InvalidTableArn,
}
impl std::fmt::Display for DynamoTenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTenantId => write!(f, "invalid DynamoDB tenant partition key"),
            Self::InvalidTableArn => write!(f, "invalid DynamoDB table ARN"),
        }
    }
}
impl std::error::Error for DynamoTenantError {}

/// Tenant binding for a shared DynamoDB table. The authenticated tenant ID
/// must be the table partition key; AWS IAM enforces it through LeadingKeys.
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
    /// Identity policy intentionally excludes Scan, PartiQL, transactions,
    /// streams, and table administration.
    pub fn iam_policy(&self) -> Value {
        json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "TenantPartitionKeyAccess",
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query"],
                "Resource": self.table_arn,
                "Condition": {
                    "Null": { "dynamodb:LeadingKeys": "false" },
                    "ForAllValues:StringEquals": { "dynamodb:LeadingKeys": [self.tenant_id] }
                }
            }]
        })
    }
}
pub fn validate_tenant_id(id: &str) -> Result<(), DynamoTenantError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':')
    {
        return Err(DynamoTenantError::InvalidTenantId);
    }
    Ok(())
}
fn validate_table_arn(arn: &str) -> Result<(), DynamoTenantError> {
    let p: Vec<&str> = arn.split(':').collect();
    let allowed_partition = matches!(
        p.get(1).copied(),
        Some("aws" | "aws-cn" | "aws-us-gov" | "aws-iso" | "aws-iso-b")
    );
    let region_valid = !p.get(3).unwrap_or(&"").is_empty()
        && p[3]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let table_name = p
        .get(5)
        .and_then(|resource| resource.strip_prefix("table/"))
        .unwrap_or("");
    let table_name_valid = (3..=255).contains(&table_name.len())
        && table_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if p.len() != 6
        || p[0] != "arn"
        || !allowed_partition
        || p[2] != "dynamodb"
        || !region_valid
        || p[4].len() != 12
        || !p[4].bytes().all(|b| b.is_ascii_digit())
        || !table_name_valid
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
    fn policy_binds_exact_table_and_tenant_leading_key() {
        let p = DynamoTenant::new("tenant-a", ARN).unwrap().iam_policy();
        let s = &p["Statement"][0];
        assert_eq!(s["Resource"], ARN);
        assert_eq!(
            s["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"][0],
            "tenant-a"
        );
        assert_eq!(s["Condition"]["Null"]["dynamodb:LeadingKeys"], "false");
        let a = s["Action"].as_array().unwrap();
        assert!(a.iter().any(|v| v == "dynamodb:Query"));
        assert!(!a.iter().any(|v| v == "dynamodb:Scan"));
    }
    #[test]
    fn rejects_wildcard_or_malformed_table_arns() {
        for arn in [
            "*",
            "arn:aws:dynamodb:us-east-1:123456789012:table/*",
            "arn:aws:s3:::bucket",
            "arn:aws:dynamodb:us-east-1:abc:table/records",
            "arn:aws:dynamodb:us-east-1:123456789012:table/ab",
            "arn:aws:dynamodb:us-east-1:123456789012:table/a/b",
        ] {
            assert!(matches!(
                DynamoTenant::new("tenant-a", arn),
                Err(DynamoTenantError::InvalidTableArn)
            ));
        }
    }
    #[test]
    fn accepts_regional_aws_partitions() {
        assert!(DynamoTenant::new(
            "tenant-a",
            "arn:aws-us-gov:dynamodb:us-gov-west-1:123456789012:table/proxima-records"
        )
        .is_ok());
        assert!(DynamoTenant::new(
            "tenant-a",
            "arn:aws-cn:dynamodb:cn-north-1:123456789012:table/proxima-records"
        )
        .is_ok());
    }
    #[test]
    fn validates_partition_keys() {
        for id in ["", "../tenant", "tenant/a", "tenant a", &"x".repeat(129)] {
            assert!(matches!(
                validate_tenant_id(id),
                Err(DynamoTenantError::InvalidTenantId)
            ));
        }
        assert!(validate_tenant_id("org:tenant_01").is_ok());
    }
}
