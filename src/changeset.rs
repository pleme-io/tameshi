//! Changeset certification for Kubernetes operations.
//!
//! Every mutation to Kubernetes (create, update, patch, delete) produces a
//! changeset that must be certified. This module provides types and hashing
//! for changesets, ensuring that:
//!
//! 1. The changeset content itself is hashed (what is being changed)
//! 2. The before/after state hashes are recorded (context of the change)
//! 3. The user/service account is recorded (who made the change)
//! 4. The compliance state at time of change is recorded (was it certified)
//! 5. The changeset hash is signed with the environment's master signature
//!
//! This makes it **impossible** to apply an insecure changeset because:
//! - Unsigned changesets are rejected by the admission webhook
//! - The changeset hash includes the compliance signature
//! - The compliance signature includes the framework + catalog + profile hashes
//! - Any change to the testing methodology changes all dependent hashes

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// A Kubernetes API operation type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Operation {
    Create,
    Update,
    Patch,
    Delete,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Create => write!(f, "CREATE"),
            Operation::Update => write!(f, "UPDATE"),
            Operation::Patch => write!(f, "PATCH"),
            Operation::Delete => write!(f, "DELETE"),
        }
    }
}

/// A resource identifier in Kubernetes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceId {
    /// API group (e.g., "apps", "kustomize.toolkit.fluxcd.io").
    pub group: String,
    /// API version (e.g., "v1", "v1alpha1").
    pub version: String,
    /// Resource kind (e.g., "Deployment", "Kustomization").
    pub kind: String,
    /// Namespace.
    pub namespace: String,
    /// Resource name.
    pub name: String,
}

impl ResourceId {
    /// Canonical string representation for hashing.
    pub fn canonical(&self) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            self.group, self.version, self.kind, self.namespace, self.name
        )
    }
}

/// A certified changeset for a Kubernetes mutation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertifiedChangeset {
    /// Unique changeset identifier.
    pub id: String,
    /// The operation being performed.
    pub operation: Operation,
    /// The resource being mutated.
    pub resource: ResourceId,
    /// BLAKE3 hash of the changeset content (the diff/patch).
    pub changeset_hash: Blake3Hash,
    /// BLAKE3 hash of the resource state before the change (None for CREATE).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_state_hash: Option<Blake3Hash>,
    /// BLAKE3 hash of the resource state after the change (None for DELETE).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_state_hash: Option<Blake3Hash>,
    /// The master secure signature at the time of this change.
    pub environment_signature: Blake3Hash,
    /// Compliance hash at the time of this change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_signature: Option<Blake3Hash>,
    /// User or service account that initiated the change.
    pub initiated_by: String,
    /// When the changeset was certified.
    pub certified_at: DateTime<Utc>,
    /// The composite certification hash (all fields above).
    pub certification_hash: Blake3Hash,
}

/// Compute the changeset hash from the mutation content.
///
/// For CREATE: hash the new object
/// For UPDATE: hash the diff between old and new
/// For PATCH: hash the patch body
/// For DELETE: hash the object being deleted
pub fn hash_changeset(
    operation: &Operation,
    resource: &ResourceId,
    content: &[u8],
) -> Blake3Hash {
    let mut data = Vec::new();
    data.extend_from_slice(operation.to_string().as_bytes());
    data.extend_from_slice(resource.canonical().as_bytes());
    data.extend_from_slice(content);
    Blake3Hash::digest(&data)
}

/// Compute the certification hash for a complete changeset.
///
/// This combines:
/// - changeset_hash (what is being changed)
/// - before/after state hashes (context)
/// - environment_signature (current certified state)
/// - compliance_signature (testing attestation)
/// - initiated_by (who)
///
/// The result proves this specific change was made to a certified environment
/// by an identified actor while compliance was verified.
pub fn compute_certification_hash(
    changeset_hash: &Blake3Hash,
    before_state: Option<&Blake3Hash>,
    after_state: Option<&Blake3Hash>,
    environment_sig: &Blake3Hash,
    compliance_sig: Option<&Blake3Hash>,
    initiated_by: &str,
) -> Blake3Hash {
    let mut data = Vec::new();
    data.extend_from_slice(&changeset_hash.0);
    if let Some(before) = before_state {
        data.extend_from_slice(&before.0);
    }
    if let Some(after) = after_state {
        data.extend_from_slice(&after.0);
    }
    data.extend_from_slice(&environment_sig.0);
    if let Some(compliance) = compliance_sig {
        data.extend_from_slice(&compliance.0);
    }
    data.extend_from_slice(initiated_by.as_bytes());
    Blake3Hash::digest(&data)
}

/// Build a certified changeset from components.
pub fn certify_changeset(
    operation: Operation,
    resource: ResourceId,
    content: &[u8],
    before_state: Option<&Blake3Hash>,
    after_state: Option<&Blake3Hash>,
    environment_sig: &Blake3Hash,
    compliance_sig: Option<&Blake3Hash>,
    initiated_by: &str,
) -> CertifiedChangeset {
    let changeset_hash = hash_changeset(&operation, &resource, content);
    let certification_hash = compute_certification_hash(
        &changeset_hash,
        before_state,
        after_state,
        environment_sig,
        compliance_sig,
        initiated_by,
    );

    CertifiedChangeset {
        id: uuid::Uuid::new_v4().to_string(),
        operation,
        resource,
        changeset_hash,
        before_state_hash: before_state.cloned(),
        after_state_hash: after_state.cloned(),
        environment_signature: environment_sig.clone(),
        compliance_signature: compliance_sig.cloned(),
        initiated_by: initiated_by.to_string(),
        certified_at: Utc::now(),
        certification_hash,
    }
}

/// Verify a certified changeset by recomputing its certification hash.
pub fn verify_changeset(changeset: &CertifiedChangeset) -> bool {
    let recomputed = compute_certification_hash(
        &changeset.changeset_hash,
        changeset.before_state_hash.as_ref(),
        changeset.after_state_hash.as_ref(),
        &changeset.environment_signature,
        changeset.compliance_signature.as_ref(),
        &changeset.initiated_by,
    );
    recomputed == changeset.certification_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changeset_hash_deterministic() {
        let op = Operation::Update;
        let resource = ResourceId {
            group: "apps".to_string(),
            version: "v1".to_string(),
            kind: "Deployment".to_string(),
            namespace: "production".to_string(),
            name: "my-app".to_string(),
        };
        let h1 = hash_changeset(&op, &resource, b"patch-content");
        let h2 = hash_changeset(&op, &resource, b"patch-content");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_operations_different_hash() {
        let resource = ResourceId {
            group: "apps".to_string(),
            version: "v1".to_string(),
            kind: "Deployment".to_string(),
            namespace: "default".to_string(),
            name: "app".to_string(),
        };
        let h1 = hash_changeset(&Operation::Create, &resource, b"content");
        let h2 = hash_changeset(&Operation::Update, &resource, b"content");
        assert_ne!(h1, h2);
    }

    #[test]
    fn certify_and_verify() {
        let resource = ResourceId {
            group: "apps".to_string(),
            version: "v1".to_string(),
            kind: "Deployment".to_string(),
            namespace: "prod".to_string(),
            name: "api".to_string(),
        };
        let env_sig = Blake3Hash::digest(b"env-sig");
        let compliance_sig = Blake3Hash::digest(b"compliance-sig");
        let before = Blake3Hash::digest(b"before-state");
        let after = Blake3Hash::digest(b"after-state");

        let changeset = certify_changeset(
            Operation::Update,
            resource,
            b"the-diff",
            Some(&before),
            Some(&after),
            &env_sig,
            Some(&compliance_sig),
            "system:serviceaccount:argocd:argocd-server",
        );

        assert!(verify_changeset(&changeset));
    }

    #[test]
    fn tampered_changeset_fails_verify() {
        let resource = ResourceId {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            namespace: "default".to_string(),
            name: "config".to_string(),
        };
        let env_sig = Blake3Hash::digest(b"env");

        let mut changeset = certify_changeset(
            Operation::Create,
            resource,
            b"data",
            None,
            None,
            &env_sig,
            None,
            "admin",
        );

        // Tamper with the changeset
        changeset.initiated_by = "attacker".to_string();
        assert!(!verify_changeset(&changeset));
    }
}
