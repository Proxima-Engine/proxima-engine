//! OpenSearch Security-plugin role descriptor helpers.
//!
//! This module builds an OpenSearch-specific role payload. It is deliberately
//! separate from Elasticsearch's native role API; it does not provision roles,
//! create API keys, or connect to a cluster.
use serde_json::{json, Value};

pub fn valid_tenant_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 48
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

pub fn tenant_index_pattern(tenant_id: &str) -> Option<String> {
    valid_tenant_id(tenant_id).then(|| format!("tenant-{tenant_id}-*"))
}

/// Build a Security-plugin role body with an exact tenant index pattern,
/// explicit data-plane actions, DLS and FLS. The authenticated caller must
/// still bind the resulting role to a tenant-specific backend role or API key.
pub fn opensearch_role_descriptor(tenant_id: &str) -> Option<Value> {
    let pattern = tenant_index_pattern(tenant_id)?;
    let dls = json!({"term":{"tenant_id":tenant_id}}).to_string();
    Some(json!({
        "cluster_permissions": [],
        "index_permissions": [{
            "index_patterns": [pattern],
            "allowed_actions": [
                "indices:data/read/search",
                "indices:data/read/get",
                "indices:data/write/index",
                "indices:data/write/update",
                "indices:data/write/delete"
            ],
            "dls": dls,
            "fls": ["tenant_id", "id", "created_at", "updated_at", "data"]
        }],
        "tenant_permissions": [],
        "description": format!("Proxima tenant-scoped role for {tenant_id}")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_is_scoped_and_has_no_cluster_permissions() {
        let role = opensearch_role_descriptor("org_01").unwrap();
        assert_eq!(role["cluster_permissions"], json!([]));
        assert_eq!(role["tenant_permissions"], json!([]));
        assert_eq!(
            role["index_permissions"][0]["index_patterns"][0],
            "tenant-org_01-*"
        );
        assert_eq!(
            role["index_permissions"][0]["fls"],
            json!(["tenant_id", "id", "created_at", "updated_at", "data"])
        );
        let dls: Value =
            serde_json::from_str(role["index_permissions"][0]["dls"].as_str().unwrap()).unwrap();
        assert_eq!(dls["term"]["tenant_id"], "org_01");
    }

    #[test]
    fn rejects_ambiguous_or_injected_tenant_ids() {
        for value in ["", "Org_01", "../org", "org/a", "org a", &"x".repeat(49)] {
            assert!(opensearch_role_descriptor(value).is_none());
        }
    }
}
