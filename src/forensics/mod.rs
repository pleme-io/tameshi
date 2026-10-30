//! Forensics module — append-only Merkle ledger, temporal indexes, and blast-radius queries.
//!
//! Provides the `MerkleLedger` for tamper-evident recording of every
//! `CertificationArtifact` deployment, multi-dimensional indexes for
//! rapid forensic lookup, and query engines for blast-radius analysis,
//! timeline reconstruction, and point-in-time provenance.
//!
//! `evidence` is the Merkle ledger of Attested Verification Tuple leaves
//! (test receipts and incidents, with inclusion proofs); `bluecrash` ingests
//! blue crash artifacts into it as IR-4/5/6 evidence.

pub mod bluecrash;
pub mod evidence;
pub mod index;
pub mod ledger;
pub mod query;
pub mod storage;
pub mod types;
