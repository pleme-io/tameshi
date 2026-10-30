//! The evidence ledger: an append-only Merkle ledger of Attested Verification
//! Tuple leaves from test receipts and incident artifacts.
//!
//! The ledger holds the evidence itself, so every leaf, its status and the
//! root are recomputed when a ledger is read: a status cannot be edited
//! without changing a leaf, and a leaf cannot change without changing the
//! root. The root is [`crate::merkle::compute_leaf_root`] over the leaves in
//! fold order; proofs are [`crate::merkle::leaf_inclusion_proof`] paths.

use serde::{Deserialize, Serialize};

use super::bluecrash::BlueCrash;
use crate::canonicalize::canonical_json_bytes;
use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::merkle::{compute_leaf_root, leaf_inclusion_proof, verify_leaf_inclusion};
use crate::receipt::{B3, ControlId, Receipt, Status, schema_tag};

schema_tag!(LedgerSchema, "tameshi-ledger.v1");
schema_tag!(InclusionSchema, "tameshi-inclusion.v1");

/// One piece of evidence the ledger holds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Evidence {
    /// A test receipt.
    Test {
        /// The receipt.
        receipt: Box<Receipt>,
    },
    /// A blue crash artifact.
    Incident {
        /// The artifact.
        bluecrash: BlueCrash,
    },
}

impl Evidence {
    /// The evidence digest: the receipt digest or the artifact digest.
    #[must_use]
    pub fn digest(&self) -> Blake3Hash {
        match self {
            Self::Test { receipt } => receipt.digest(),
            Self::Incident { bluecrash } => bluecrash.digest(),
        }
    }

    fn leaves(&self) -> Vec<LedgerLeaf> {
        let evidence = B3(self.digest());
        let (kind, status, leaves) = match self {
            Self::Test { receipt } => (
                LeafKind::Test,
                match receipt.status() {
                    Status::Pass => LeafStatus::Pass,
                    Status::Fail => LeafStatus::Fail,
                },
                receipt.leaves(),
            ),
            Self::Incident { bluecrash } => {
                (LeafKind::Incident, LeafStatus::Incident, bluecrash.leaves())
            }
        };
        leaves
            .into_iter()
            .map(|l| LedgerLeaf {
                leaf: l.leaf,
                control: l.control,
                kind,
                status,
                evidence: evidence.clone(),
            })
            .collect()
    }
}

/// Where a leaf came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeafKind {
    /// A test receipt.
    Test,
    /// An incident artifact.
    Incident,
}

/// The verdict a leaf carries, derived from its evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LeafStatus {
    /// A passing test.
    #[serde(rename = "PASS")]
    Pass,
    /// A failing test.
    #[serde(rename = "FAIL")]
    Fail,
    /// An incident.
    #[serde(rename = "INCIDENT")]
    Incident,
}

impl LeafStatus {
    /// Parse `PASS`, `FAIL` or `INCIDENT`.
    ///
    /// # Errors
    ///
    /// Refuses any other text.
    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "PASS" => Ok(Self::Pass),
            "FAIL" => Ok(Self::Fail),
            "INCIDENT" => Ok(Self::Incident),
            _ => Err(TameshiError::InvalidInput(format!(
                "status {text:?} is not PASS, FAIL or INCIDENT"
            ))),
        }
    }
}

/// One leaf of the ledger.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerLeaf {
    /// The tuple leaf.
    pub leaf: B3,
    /// The control it evidences.
    pub control: ControlId,
    /// Where it came from.
    pub kind: LeafKind,
    /// Its verdict.
    pub status: LeafStatus,
    /// The digest of the evidence that produced it.
    pub evidence: B3,
}

/// Why a fold was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum FoldRefusal {
    /// The evidence is already in the ledger.
    Duplicate(B3),
}

/// The append-only evidence ledger.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EvidenceLedger {
    entries: Vec<Evidence>,
    leaves: Vec<LedgerLeaf>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerFile {
    schema: LedgerSchema,
    entries: Vec<Evidence>,
    leaves: Vec<LedgerLeaf>,
    root: B3,
}

impl EvidenceLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one piece of evidence and its leaves.
    ///
    /// # Errors
    ///
    /// Refuses evidence already in the ledger; the ledger is unchanged.
    pub fn fold(
        &mut self,
        evidence: Evidence,
    ) -> std::result::Result<Vec<LedgerLeaf>, FoldRefusal> {
        let digest = evidence.digest();
        if self.leaves.iter().any(|l| l.evidence.0 == digest) {
            return Err(FoldRefusal::Duplicate(B3(digest)));
        }
        let added = evidence.leaves();
        self.leaves.extend(added.iter().cloned());
        self.entries.push(evidence);
        Ok(added)
    }

    /// Append a test receipt.
    ///
    /// # Errors
    ///
    /// As [`EvidenceLedger::fold`].
    pub fn fold_receipt(
        &mut self,
        receipt: Receipt,
    ) -> std::result::Result<Vec<LedgerLeaf>, FoldRefusal> {
        self.fold(Evidence::Test {
            receipt: Box::new(receipt),
        })
    }

    /// Append an incident artifact.
    ///
    /// # Errors
    ///
    /// As [`EvidenceLedger::fold`].
    pub fn fold_incident(
        &mut self,
        bluecrash: BlueCrash,
    ) -> std::result::Result<Vec<LedgerLeaf>, FoldRefusal> {
        self.fold(Evidence::Incident { bluecrash })
    }

    /// The leaves in fold order.
    #[must_use]
    pub fn leaves(&self) -> &[LedgerLeaf] {
        &self.leaves
    }

    /// The evidence in fold order.
    #[must_use]
    pub fn entries(&self) -> &[Evidence] {
        &self.entries
    }

    /// The ledger root.
    #[must_use]
    pub fn root(&self) -> Blake3Hash {
        compute_leaf_root(&self.leaf_hashes())
    }

    /// The ledger's record of a leaf.
    #[must_use]
    pub fn find(&self, leaf: &Blake3Hash) -> Option<&LedgerLeaf> {
        self.leaves.iter().find(|l| &l.leaf.0 == leaf)
    }

    /// An inclusion proof for a leaf, when the ledger holds it.
    #[must_use]
    pub fn prove(&self, leaf: &Blake3Hash) -> Option<InclusionProof> {
        let hashes = self.leaf_hashes();
        let index = hashes.iter().position(|h| h == leaf)?;
        let siblings = leaf_inclusion_proof(&hashes, index)?;
        Some(InclusionProof {
            schema: InclusionSchema,
            leaf: B3(leaf.clone()),
            index: index as u64,
            total: hashes.len() as u64,
            siblings: siblings.into_iter().map(B3).collect(),
            root: B3(compute_leaf_root(&hashes)),
        })
    }

    /// The canonical `tameshi-ledger.v1` bytes.
    ///
    /// # Panics
    ///
    /// Never: a ledger always serializes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        let file = LedgerFile {
            schema: LedgerSchema,
            entries: self.entries.clone(),
            leaves: self.leaves.clone(),
            root: B3(self.root()),
        };
        canonical_json_bytes(&file).expect("a ledger always serializes")
    }

    /// Read a ledger, recomputing every leaf, status and the root from the
    /// evidence it holds.
    ///
    /// # Errors
    ///
    /// Refuses a malformed file, repeated evidence, and leaves or a root that
    /// do not match the evidence.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let file: LedgerFile = serde_json::from_slice(bytes)
            .map_err(|e| TameshiError::InvalidInput(format!("ledger refused: {e}")))?;
        let mut ledger = Self::new();
        for evidence in file.entries {
            ledger.fold(evidence).map_err(|FoldRefusal::Duplicate(d)| {
                TameshiError::InvalidInput(format!("ledger refused: evidence {d} appears twice"))
            })?;
        }
        if ledger.leaves != file.leaves {
            return Err(TameshiError::InvalidInput(
                "ledger refused: its leaves do not match its evidence".to_string(),
            ));
        }
        if ledger.root() != file.root.0 {
            return Err(TameshiError::InvalidInput(
                "ledger refused: its root does not match its leaves".to_string(),
            ));
        }
        Ok(ledger)
    }

    fn leaf_hashes(&self) -> Vec<Blake3Hash> {
        self.leaves.iter().map(|l| l.leaf.0.clone()).collect()
    }
}

/// A `tameshi-inclusion.v1` proof that a leaf is in a ledger root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProof {
    /// Always `tameshi-inclusion.v1`.
    pub schema: InclusionSchema,
    /// The leaf.
    pub leaf: B3,
    /// Its position in fold order.
    pub index: u64,
    /// How many leaves the ledger had.
    pub total: u64,
    /// The sibling path, leaf to root.
    pub siblings: Vec<B3>,
    /// The root the path reaches.
    pub root: B3,
}

impl InclusionProof {
    /// Parse a proof strictly.
    ///
    /// # Errors
    ///
    /// Refuses unknown fields, a wrong schema and malformed hashes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| TameshiError::InvalidInput(format!("inclusion proof refused: {e}")))
    }

    /// Canonical JSON bytes.
    ///
    /// # Panics
    ///
    /// Never: a proof always serializes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json_bytes(self).expect("a proof always serializes")
    }

    /// The path takes the proof's leaf to the proof's root.
    #[must_use]
    pub fn verify(&self) -> bool {
        let (Ok(index), Ok(total)) = (usize::try_from(self.index), usize::try_from(self.total))
        else {
            return false;
        };
        let siblings: Vec<Blake3Hash> = self.siblings.iter().map(|s| s.0.clone()).collect();
        verify_leaf_inclusion(&siblings, &self.root.0, &self.leaf.0, index, total)
    }

    /// The path takes `leaf` to `root`: the proof is about this leaf and this root.
    #[must_use]
    pub fn verify_against(&self, root: &Blake3Hash, leaf: &Blake3Hash) -> bool {
        &self.root.0 == root && &self.leaf.0 == leaf && self.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::tests::{sample, sample_parts};

    fn failing() -> Receipt {
        let mut parts = sample_parts();
        parts.status = Status::Fail;
        parts.assertions.failed = 1;
        Receipt::new(parts).unwrap()
    }

    fn crash() -> BlueCrash {
        BlueCrash::parse(br#"{"def_hash":"b3:00","exit":70,"frame":{"granted":["clock"]}}"#)
            .unwrap()
    }

    fn ledger() -> EvidenceLedger {
        let mut ledger = EvidenceLedger::new();
        ledger.fold_receipt(sample()).unwrap();
        ledger.fold_receipt(failing()).unwrap();
        ledger.fold_incident(crash()).unwrap();
        ledger
    }

    #[test]
    fn every_leaf_proves_against_the_root() {
        let ledger = ledger();
        assert_eq!(ledger.leaves().len(), 2 + 2 + 3);
        for leaf in ledger.leaves() {
            let proof = ledger.prove(&leaf.leaf.0).unwrap();
            assert!(proof.verify_against(&ledger.root(), &leaf.leaf.0));
        }
    }

    #[test]
    fn a_fail_receipt_leaf_is_marked_fail_and_an_incident_leaf_incident() {
        let ledger = ledger();
        let fail = failing().leaves()[0].leaf.0.clone();
        assert_eq!(ledger.find(&fail).unwrap().status, LeafStatus::Fail);
        let pass = sample().leaves()[0].leaf.0.clone();
        assert_eq!(ledger.find(&pass).unwrap().status, LeafStatus::Pass);
        let ir = crash().leaves()[0].leaf.0.clone();
        assert_eq!(ledger.find(&ir).unwrap().status, LeafStatus::Incident);
    }

    #[test]
    fn folding_the_same_evidence_twice_is_refused_and_changes_nothing() {
        let mut ledger = ledger();
        let before = ledger.root();
        assert!(matches!(
            ledger.fold_receipt(sample()),
            Err(FoldRefusal::Duplicate(_))
        ));
        assert_eq!(ledger.root(), before);
    }

    #[test]
    fn a_ledger_round_trips_and_refuses_an_edited_status() {
        let ledger = ledger();
        let bytes = ledger.to_json();
        assert_eq!(EvidenceLedger::from_json(&bytes).unwrap(), ledger);
        let text = String::from_utf8(bytes).unwrap();
        let forged = text.replacen(r#""status":"FAIL""#, r#""status":"PASS""#, 1);
        assert_ne!(forged, text);
        assert!(EvidenceLedger::from_json(forged.as_bytes()).is_err());
    }

    #[test]
    fn a_proof_from_an_older_root_fails_against_the_newer_root() {
        let mut ledger = EvidenceLedger::new();
        ledger.fold_receipt(sample()).unwrap();
        let leaf = sample().leaves()[0].leaf.0.clone();
        let old = ledger.prove(&leaf).unwrap();
        ledger.fold_receipt(failing()).unwrap();
        assert!(old.verify());
        assert!(!old.verify_against(&ledger.root(), &leaf));
    }

    #[test]
    fn an_empty_ledger_has_the_sentinel_root_and_no_proofs() {
        let ledger = EvidenceLedger::new();
        assert_eq!(ledger.root(), Blake3Hash::digest(b"empty-tree"));
        assert!(ledger.prove(&Blake3Hash::digest(b"x")).is_none());
        assert_eq!(
            EvidenceLedger::from_json(&ledger.to_json()).unwrap(),
            ledger
        );
    }
}
