//! Signed tenant-binding lifecycle reporting for the Proxima Engine.
//!
//! This module is the Engine half of Cloud's `/api/v1/nodes/tenant-bindings/ack`
//! contract. Provider implementations must call `report_active` only after they
//! have created/verified the native tenant identity and independently verified
//! the provider's isolation boundary. A successful TCP probe is not sufficient.

use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantBindingEvidence {
    pub provider_key: String,
    pub identity_reference: String,
    pub identity_verified: bool,
    pub isolation_verified: bool,
    pub operation_id: String,
    pub observed_at_unix: u64,
    #[serde(default)]
    pub details: Value,
}

fn canonical_payload(
    node_id: Uuid,
    organization_id: Uuid,
    nonce: Uuid,
    binding_id: Uuid,
    target_id: Uuid,
    revision: i64,
    timestamp: i64,
    status: &str,
    identity_verified: bool,
    isolation_verified: bool,
    evidence: &Value,
    error_code: Option<&str>,
) -> String {
    format!(
        "proxima-node-tenant-binding-ack-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        node_id,
        organization_id,
        nonce,
        binding_id,
        target_id,
        revision,
        timestamp,
        status,
        if identity_verified {
            "identity_verified"
        } else {
            "identity_unverified"
        },
        if isolation_verified {
            "isolation_verified"
        } else {
            "isolation_unverified"
        },
        evidence,
        error_code.unwrap_or("")
    )
}

fn sign(key: &[u8], canonical: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if key.len() != 32 {
        return Err("node signing key must contain exactly 32 bytes".into());
    }
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(canonical.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[allow(clippy::too_many_arguments)]
pub async fn report(
    client: &Client,
    control_plane_base_url: &str,
    node_id: Uuid,
    organization_id: Uuid,
    signing_key: &[u8],
    binding_id: Uuid,
    target_id: Uuid,
    config_revision: i64,
    status: &str,
    evidence: Value,
    error_code: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if config_revision < 1 || evidence.is_null() || evidence.to_string().len() > 16_384 {
        return Err("invalid tenant binding report identity, revision, or evidence".into());
    }
    let (identity_verified, isolation_verified) = match status {
        "provisioning" | "failed" | "revoked" => (false, false),
        "active" => {
            let identity = evidence
                .get("identity_verified")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let isolation = evidence
                .get("isolation_verified")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !identity || !isolation || error_code.is_some() {
                return Err(
                    "active requires verified native identity and isolation evidence".into(),
                );
            }
            (true, true)
        }
        _ => return Err("unsupported tenant binding lifecycle status".into()),
    };
    if status == "failed" && error_code.is_none() {
        return Err("failed reports require a machine-readable error code".into());
    }
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let nonce = Uuid::new_v4();
    let canonical = canonical_payload(
        node_id,
        organization_id,
        nonce,
        binding_id,
        target_id,
        config_revision,
        timestamp,
        status,
        identity_verified,
        isolation_verified,
        &evidence,
        error_code,
    );
    let signature = sign(signing_key, &canonical)?;
    let body = serde_json::json!({
        "node_id": node_id.to_string(),
        "nonce": nonce.to_string(),
        "binding_id": binding_id.to_string(),
        "database_target_id": target_id.to_string(),
        "config_revision": config_revision,
        "timestamp": timestamp,
        "status": status,
        "provider_identity_verified": identity_verified,
        "isolation_verified": isolation_verified,
        "runtime_evidence": evidence,
        "error_code": error_code,
        "signature": signature
    });
    let url = format!(
        "{}/api/v1/nodes/tenant-bindings/ack",
        control_plane_base_url.trim_end_matches('/')
    );
    client
        .post(url)
        .json(&body)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{canonical_payload, sign};
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn signature_is_bound_to_binding_revision_and_evidence() {
        let node = Uuid::new_v4();
        let org = Uuid::new_v4();
        let nonce = Uuid::new_v4();
        let binding = Uuid::new_v4();
        let target = Uuid::new_v4();
        let evidence = json!({"identity_verified":true,"isolation_verified":true});
        let canonical = canonical_payload(
            node,
            org,
            nonce,
            binding,
            target,
            4,
            1_800_000_000,
            "active",
            true,
            true,
            &evidence,
            None,
        );
        let key = [7u8; 32];
        let signature = sign(&key, &canonical).unwrap();
        let changed = canonical_payload(
            node,
            org,
            nonce,
            binding,
            target,
            5,
            1_800_000_000,
            "active",
            true,
            true,
            &evidence,
            None,
        );
        assert_ne!(signature, sign(&key, &changed).unwrap());
    }

    #[test]
    fn rejects_non_32_byte_node_keys() {
        assert!(sign(&[1u8; 16], "payload").is_err());
    }
}
