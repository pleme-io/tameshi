//! Forensics module — append-only Merkle ledger, temporal indexes, and blast-radius queries.
//!
//! Provides the `MerkleLedger` for tamper-evident recording of every
//! `CertificationArtifact` deployment, multi-dimensional indexes for
//! rapid forensic lookup, and query engines for blast-radius analysis,
//! timeline reconstruction, and point-in-time provenance.

pub mod index;
pub mod ledger;
pub mod query;
pub mod types;
