//! Attested Verification Tuples: `tameshi-receipt.v1` compliance evidence.
//!
//! A receipt records one test run of one target inside one sandbox: which
//! controls it evidences, the target and test hashes, the verdict, the
//! assertion counts, the runner's execution frame when it has one, the digest
//! of everything the run printed, and the derivation that ran it.
//!
//! ```text
//! ReceiptDigest = BLAKE3(canonical receipt bytes)
//! Leaf          = BLAKE3(lp(ControlID) ‖ lp(TargetHash) ‖ lp(TestHash)
//!                        ‖ lp(ReceiptDigest) ‖ lp(NixDerivationHash))
//! lp(x)         = u32_be(len(x)) ‖ utf8(x)
//! ```
//!
//! `TargetHash`, `TestHash` and `ReceiptDigest` are the `b3:<hex>` strings;
//! `NixDerivationHash` is `sandbox.derivation`, the `.drv` store path,
//! verbatim. One leaf per control; the leaves fold into the evidence ledger
//! ([`crate::forensics::evidence`]).

pub mod fragment;
pub mod runner;

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::canonicalize::canonical_json_bytes;
use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;

/// A unit type that serializes to exactly one schema string and refuses any other.
macro_rules! schema_tag {
    ($name:ident, $tag:literal) => {
        #[doc = concat!("The `", $tag, "` schema tag; any other string is refused.")]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct $name;

        impl $name {
            /// The schema string.
            pub const TAG: &'static str = $tag;
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str($tag)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::std::result::Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                if text == $tag {
                    Ok($name)
                } else {
                    Err(<D::Error as ::serde::de::Error>::custom(format!(
                        "schema {text:?} is not {:?}",
                        $tag
                    )))
                }
            }
        }
    };
}
pub(crate) use schema_tag;

schema_tag!(ReceiptSchema, "tameshi-receipt.v1");

/// A BLAKE3 hash written `b3:<lowercase hex>`; any other spelling is refused.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct B3(pub Blake3Hash);

impl B3 {
    /// Parse the strict `b3:` form.
    ///
    /// # Errors
    ///
    /// Refuses anything but `b3:` and 64 lowercase hex digits.
    pub fn parse(text: &str) -> Result<Self> {
        Blake3Hash::from_b3(text).map(Self)
    }
}

impl fmt::Display for B3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_b3())
    }
}

impl From<Blake3Hash> for B3 {
    fn from(hash: Blake3Hash) -> Self {
        Self(hash)
    }
}

impl Serialize for B3 {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_b3())
    }
}

impl<'de> Deserialize<'de> for B3 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// A control identifier: an uppercase letter, then uppercase letters, digits
/// and underscores (`NIST_SP_800_53R5_AC_6`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ControlId(String);

impl ControlId {
    /// Validate a control identifier.
    ///
    /// # Errors
    ///
    /// Refuses an empty identifier or one with a character outside `[A-Z0-9_]`
    /// or not starting with a letter.
    pub fn new(text: &str) -> Result<Self> {
        let mut bytes = text.bytes();
        let starts_upper = bytes.next().is_some_and(|b| b.is_ascii_uppercase());
        if starts_upper && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            Ok(Self(text.to_string()))
        } else {
            Err(TameshiError::InvalidInput(format!(
                "control id {text:?} is not [A-Z][A-Z0-9_]*"
            )))
        }
    }

    /// The identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ControlId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ControlId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(&text).map_err(serde::de::Error::custom)
    }
}

/// What a receipt's target is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetKind {
    /// A blue definition, hashed by its `def_hash`.
    #[serde(rename = "blue-def")]
    BlueDef,
    /// A nix store output.
    #[serde(rename = "nix-output")]
    NixOutput,
}

/// The thing under test.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// What the target is.
    pub kind: TargetKind,
    /// Its BLAKE3 hash.
    pub hash: B3,
}

/// The test runner that produced the run.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Runner {
    /// `cargo test`.
    Cargo,
    /// `pytest`.
    Pytest,
    /// `go test`.
    Go,
    /// `blue test`.
    Blue,
    /// Any other runner, named; never one of the four above.
    Other(String),
}

impl Runner {
    /// Name a runner; a known name becomes its variant.
    ///
    /// # Errors
    ///
    /// Refuses an empty name or one containing whitespace or control characters.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "cargo" => Ok(Self::Cargo),
            "pytest" => Ok(Self::Pytest),
            "go" => Ok(Self::Go),
            "blue" => Ok(Self::Blue),
            _ if !name.is_empty() && !name.chars().any(|c| c.is_whitespace() || c.is_control()) => {
                Ok(Self::Other(name.to_string()))
            }
            _ => Err(TameshiError::InvalidInput(format!(
                "runner name {name:?} is empty or has whitespace"
            ))),
        }
    }

    /// The runner's name as the receipt writes it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Cargo => "cargo",
            Self::Pytest => "pytest",
            Self::Go => "go",
            Self::Blue => "blue",
            Self::Other(name) => name,
        }
    }
}

impl Serialize for Runner {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Runner {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// The test that ran.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestRef {
    /// The runner.
    pub runner: Runner,
    /// The BLAKE3 hash of the test source.
    pub hash: B3,
}

/// The verdict of a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Status {
    /// The command exited 0 and no assertion failed.
    #[serde(rename = "PASS")]
    Pass,
    /// Anything else: a non-zero exit, a signal, a failed assertion, a command
    /// that could not start.
    #[serde(rename = "FAIL")]
    Fail,
}

impl Status {
    /// `PASS` or `FAIL`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }
}

/// Assertion counts the run reported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertions {
    /// Assertions that held.
    pub passed: u64,
    /// Assertions that failed.
    pub failed: u64,
}

/// The capability frame a runner executed the test under.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    /// Capabilities the frame granted.
    pub granted: Vec<String>,
    /// Capabilities the frame withheld.
    pub withheld: Vec<String>,
    /// Host I/O operations the test performed.
    pub host_io: u64,
}

/// A `/nix/store/…drv` path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct DrvPath(String);

impl DrvPath {
    /// Validate a derivation store path.
    ///
    /// # Errors
    ///
    /// Refuses a path outside `/nix/store/`, a nested path, or one not ending
    /// in `.drv`.
    pub fn new(path: &str) -> Result<Self> {
        let name = path.strip_prefix("/nix/store/").unwrap_or("");
        let is_drv = std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext == "drv");
        if is_drv && !name.contains('/') {
            Ok(Self(path.to_string()))
        } else {
            Err(TameshiError::InvalidInput(format!(
                "derivation {path:?} is not /nix/store/<name>.drv"
            )))
        }
    }

    /// The path text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DrvPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(&text).map_err(serde::de::Error::custom)
    }
}

/// The sandbox the run happened in.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    /// The derivation that ran the test.
    pub derivation: DrvPath,
    /// Whether an outbound network route existed during the run.
    pub network: bool,
    /// The nix system the run executed on.
    pub system: String,
}

fn present<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Every field of a receipt, unvalidated across fields. [`Receipt::new`]
/// checks the cross-field rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptParts {
    /// Always `tameshi-receipt.v1`.
    pub schema: ReceiptSchema,
    /// The controls this run evidences: at least one, no repeats.
    pub controls: Vec<ControlId>,
    /// The target.
    pub target: Target,
    /// The test.
    pub test: TestRef,
    /// The verdict.
    pub status: Status,
    /// Assertion counts.
    pub assertions: Assertions,
    /// Evaluation steps, when the runner counts them; present as `null` otherwise.
    #[serde(deserialize_with = "present")]
    pub steps: Option<u64>,
    /// The capability frame, when the runner has one; present as `null` otherwise.
    #[serde(deserialize_with = "present")]
    pub frame: Option<Frame>,
    /// `BLAKE3(stdout ‖ stderr)` of the run.
    pub output_digest: B3,
    /// The sandbox.
    pub sandbox: Sandbox,
}

/// A validated `tameshi-receipt.v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ReceiptParts", into = "ReceiptParts")]
pub struct Receipt {
    parts: ReceiptParts,
}

impl TryFrom<ReceiptParts> for Receipt {
    type Error = TameshiError;

    fn try_from(parts: ReceiptParts) -> Result<Self> {
        Self::new(parts)
    }
}

impl From<Receipt> for ReceiptParts {
    fn from(receipt: Receipt) -> Self {
        receipt.parts
    }
}

/// One control's leaf.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlLeaf {
    /// The control.
    pub control: ControlId,
    /// Its leaf.
    pub leaf: B3,
}

/// The Attested Verification Tuple leaf: BLAKE3 over the five length-prefixed fields.
#[must_use]
pub fn tuple_leaf(
    control: &str,
    target_hash: &str,
    test_hash: &str,
    receipt_digest: &str,
    derivation: &str,
) -> Blake3Hash {
    Blake3Hash::digest_fields(&[
        control.as_bytes(),
        target_hash.as_bytes(),
        test_hash.as_bytes(),
        receipt_digest.as_bytes(),
        derivation.as_bytes(),
    ])
}

impl Receipt {
    /// Validate the cross-field rules: at least one control, no control twice,
    /// and no `PASS` with a failed assertion.
    ///
    /// # Errors
    ///
    /// Returns [`TameshiError::InvalidInput`] naming the broken rule.
    pub fn new(parts: ReceiptParts) -> Result<Self> {
        if parts.controls.is_empty() {
            return Err(TameshiError::InvalidInput(
                "a receipt evidences at least one control".to_string(),
            ));
        }
        let mut seen = BTreeSet::new();
        if let Some(repeat) = parts.controls.iter().find(|c| !seen.insert(*c)) {
            return Err(TameshiError::InvalidInput(format!(
                "control {repeat} is listed twice"
            )));
        }
        if parts.status == Status::Pass && parts.assertions.failed > 0 {
            return Err(TameshiError::InvalidInput(format!(
                "status PASS with {} failed assertions",
                parts.assertions.failed
            )));
        }
        Ok(Self { parts })
    }

    /// Parse a receipt strictly: unknown fields, a wrong schema, a missing
    /// field, a non-integer count and a broken cross-field rule are refused.
    ///
    /// # Errors
    ///
    /// Returns [`TameshiError::InvalidInput`] naming what was refused.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| TameshiError::InvalidInput(format!("receipt refused: {e}")))
    }

    /// Parse a receipt and refuse it unless `bytes` are exactly its canonical form.
    ///
    /// # Errors
    ///
    /// Everything [`Receipt::parse`] refuses, and non-canonical bytes.
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self> {
        let receipt = Self::parse(bytes)?;
        if receipt.canonical_bytes() == bytes {
            Ok(receipt)
        } else {
            Err(TameshiError::InvalidInput(
                "receipt is not in canonical form (sorted keys, no whitespace)".to_string(),
            ))
        }
    }

    /// The canonical JSON bytes: keys sorted, no insignificant whitespace, UTF-8.
    ///
    /// # Panics
    ///
    /// Never: a receipt holds only strings, integers, booleans and nulls.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json_bytes(self).expect("a receipt always serializes")
    }

    /// `ReceiptDigest = BLAKE3(canonical bytes)`.
    #[must_use]
    pub fn digest(&self) -> Blake3Hash {
        Blake3Hash::digest(&self.canonical_bytes())
    }

    /// One leaf per control, in the receipt's control order.
    #[must_use]
    pub fn leaves(&self) -> Vec<ControlLeaf> {
        let digest = self.digest().to_b3();
        let target = self.parts.target.hash.to_string();
        let test = self.parts.test.hash.to_string();
        let derivation = self.parts.sandbox.derivation.as_str();
        self.parts
            .controls
            .iter()
            .map(|control| ControlLeaf {
                control: control.clone(),
                leaf: B3(tuple_leaf(
                    control.as_str(),
                    &target,
                    &test,
                    &digest,
                    derivation,
                )),
            })
            .collect()
    }

    /// Every field.
    #[must_use]
    pub fn parts(&self) -> &ReceiptParts {
        &self.parts
    }

    /// The controls.
    #[must_use]
    pub fn controls(&self) -> &[ControlId] {
        &self.parts.controls
    }

    /// The verdict.
    #[must_use]
    pub fn status(&self) -> Status {
        self.parts.status
    }

    /// The target.
    #[must_use]
    pub fn target(&self) -> &Target {
        &self.parts.target
    }

    /// The test.
    #[must_use]
    pub fn test(&self) -> &TestRef {
        &self.parts.test
    }

    /// The sandbox.
    #[must_use]
    pub fn sandbox(&self) -> &Sandbox {
        &self.parts.sandbox
    }

    /// The assertion counts.
    #[must_use]
    pub fn assertions(&self) -> Assertions {
        self.parts.assertions
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sample_parts() -> ReceiptParts {
        ReceiptParts {
            schema: ReceiptSchema,
            controls: vec![
                ControlId::new("NIST_SP_800_53R5_SA_11").unwrap(),
                ControlId::new("NIST_SP_800_53R5_SI_7").unwrap(),
            ],
            target: Target {
                kind: TargetKind::NixOutput,
                hash: B3(Blake3Hash::digest(b"target")),
            },
            test: TestRef {
                runner: Runner::Cargo,
                hash: B3(Blake3Hash::digest(b"test")),
            },
            status: Status::Pass,
            assertions: Assertions {
                passed: 3,
                failed: 0,
            },
            steps: None,
            frame: None,
            output_digest: B3(Blake3Hash::digest(b"out")),
            sandbox: Sandbox {
                derivation: DrvPath::new("/nix/store/aaaa-run.drv").unwrap(),
                network: false,
                system: "aarch64-darwin".to_string(),
            },
        }
    }

    pub(crate) fn sample() -> Receipt {
        Receipt::new(sample_parts()).unwrap()
    }

    #[test]
    fn canonical_bytes_sort_keys_and_round_trip() {
        let receipt = sample();
        let bytes = receipt.canonical_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with(r#"{"assertions":{"failed":0,"passed":3},"controls":["#));
        assert!(!text.contains(' '));
        assert!(text.contains(r#""frame":null"#));
        assert!(text.contains(r#""steps":null"#));
        assert_eq!(Receipt::parse_canonical(&bytes).unwrap(), receipt);
    }

    #[test]
    fn non_canonical_bytes_parse_but_are_not_canonical() {
        let receipt = sample();
        let pretty = serde_json::to_vec_pretty(&receipt).unwrap();
        assert_eq!(Receipt::parse(&pretty).unwrap(), receipt);
        assert!(Receipt::parse_canonical(&pretty).is_err());
    }

    fn edited(f: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut value = serde_json::to_value(sample()).unwrap();
        f(&mut value);
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn strict_parse_refuses_each_bad_field() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("unknown top field", edited(|v| v["extra"] = 1.into())),
            (
                "unknown nested field",
                edited(|v| v["sandbox"]["extra"] = true.into()),
            ),
            (
                "wrong schema",
                edited(|v| v["schema"] = "tameshi-receipt.v2".into()),
            ),
            (
                "missing steps",
                edited(|v| {
                    v.as_object_mut().unwrap().remove("steps");
                }),
            ),
            (
                "missing frame",
                edited(|v| {
                    v.as_object_mut().unwrap().remove("frame");
                }),
            ),
            (
                "float count",
                edited(|v| v["assertions"]["passed"] = 3.0.into()),
            ),
            (
                "negative count",
                edited(|v| v["assertions"]["passed"] = (-1).into()),
            ),
            (
                "blake3 prefix",
                edited(|v| {
                    v["output_digest"] =
                        format!("blake3:{}", Blake3Hash::digest(b"out").to_hex()).into();
                }),
            ),
            ("bad status", edited(|v| v["status"] = "pass".into())),
            ("bad kind", edited(|v| v["target"]["kind"] = "oci".into())),
            ("bad control", edited(|v| v["controls"][0] = "ac-6".into())),
            (
                "no controls",
                edited(|v| v["controls"] = serde_json::json!([])),
            ),
            (
                "repeat control",
                edited(|v| v["controls"] = serde_json::json!(["AC_6", "AC_6"])),
            ),
            (
                "pass with failure",
                edited(|v| v["assertions"]["failed"] = 1.into()),
            ),
            (
                "store path not drv",
                edited(|v| v["sandbox"]["derivation"] = "/nix/store/aaaa-run".into()),
            ),
            ("empty runner", edited(|v| v["test"]["runner"] = "".into())),
        ];
        for (name, bytes) in cases {
            assert!(Receipt::parse(&bytes).is_err(), "accepted: {name}");
        }
    }

    #[test]
    fn fail_with_failures_and_other_runner_parse() {
        let bytes = edited(|v| {
            v["status"] = "FAIL".into();
            v["assertions"]["failed"] = 2.into();
            v["test"]["runner"] = "jest".into();
            v["steps"] = 41.into();
            v["frame"] =
                serde_json::json!({"granted": ["clock"], "withheld": ["network"], "host_io": 2});
        });
        let receipt = Receipt::parse(&bytes).unwrap();
        assert_eq!(receipt.status(), Status::Fail);
        assert_eq!(receipt.test().runner, Runner::Other("jest".to_string()));
        assert_eq!(receipt.parts().steps, Some(41));
    }

    #[test]
    fn a_known_runner_name_is_never_other() {
        assert_eq!(Runner::parse("cargo").unwrap(), Runner::Cargo);
        assert_eq!(Runner::parse("blue").unwrap(), Runner::Blue);
        assert!(Runner::parse("my runner").is_err());
    }

    #[test]
    fn one_leaf_per_control_matching_the_tuple() {
        let receipt = sample();
        let leaves = receipt.leaves();
        assert_eq!(leaves.len(), 2);
        let expected = tuple_leaf(
            "NIST_SP_800_53R5_SA_11",
            &Blake3Hash::digest(b"target").to_b3(),
            &Blake3Hash::digest(b"test").to_b3(),
            &receipt.digest().to_b3(),
            "/nix/store/aaaa-run.drv",
        );
        assert_eq!(leaves[0].leaf.0, expected);
        assert_ne!(leaves[0].leaf, leaves[1].leaf);
    }

    #[test]
    fn tuple_fields_cannot_slide_across_boundaries() {
        assert_ne!(
            tuple_leaf("AB", "C", "t", "d", "x"),
            tuple_leaf("A", "BC", "t", "d", "x")
        );
    }

    #[test]
    fn one_changed_field_changes_the_digest() {
        let base = sample();
        let mut parts = sample_parts();
        parts.assertions.passed = 4;
        assert_ne!(Receipt::new(parts).unwrap().digest(), base.digest());
    }
}
