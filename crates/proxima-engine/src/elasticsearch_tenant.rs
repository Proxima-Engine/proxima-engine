//! Elasticsearch native-role policy helpers. These helpers do not connect to
//! clusters, provision credentials, or implement an Elasticsearch/OpenSearch proxy.
use serde_json::{json, Value};

pub fn valid_tenant_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 48 && value.bytes().all(|b|
        b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

pub fn tenant_index_pattern(tenant_id: &str) -> Option<String> {
    valid_tenant_id(tenant_id).then(|| format!("tenant-{tenant_id}-*"))
}

/// Build a least-privilege Elasticsearch role descriptor. The caller must
/// provision it through a trusted admin channel and test effective privileges.
pub fn elasticsearch_role_descriptor(tenant_id: &str) -> Option<Value> {
    let pattern = tenant_index_pattern(tenant_id)?;
    Some(json!({
        "indices": [{
            "names": [pattern],
            "privileges": ["read", "write"],
            "query": {"term": {"tenant_id": tenant_id}},
            "field_security": {"grant": ["tenant_id", "id", "created_at", "updated_at", "data"]}
        }],
        "cluster": [],
        "applications": [],
        "run_as": [],
        "metadata": {"managed_by": "proxima-engine", "tenant_id": tenant_id},
        "transient_metadata": {"enabled": true}
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tenant_namespace_is_exact_and_bounded() {
        assert_eq!(tenant_index_pattern("tenant_42").as_deref(), Some("tenant-tenant_42-*"));
        assert!(tenant_index_pattern("Tenant_42").is_none());
        assert!(tenant_index_pattern("tenant/42").is_none());
        assert!(tenant_index_pattern("").is_none());
        assert!(tenant_index_pattern(&"a".repeat(49)).is_none());
    }

    #[test]
    fn role_descriptor_scopes_index_and_document_access() {
        let role = elasticsearch_role_descriptor("acme_01").unwrap();
        assert_eq!(role["indices"][0]["names"][0], "tenant-acme_01-*");
        assert_eq!(role["indices"][0]["query"]["term"]["tenant_id"], "acme_01");
        assert_eq!(role["indices"][0]["privileges"], json!(["read", "write"]));
        assert_eq!(role["cluster"], json!([]));
        assert!(elasticsearch_role_descriptor("Acme").is_none());
    }
}
