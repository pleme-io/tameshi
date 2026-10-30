//! A blue `.bluecrash` artifact as incident evidence (NIST IR-4, IR-5, IR-6).
//!
//! Any JSON object with `def_hash` (a non-empty string), `exit` and `frame`
//! is accepted; every other field is kept as it came. Its leaves use the
//! receipt tuple with the test slot set to `incident:bluecrash`, which no
//! receipt's `b3:` test hash can equal:
//!
//! ```text
//! Leaf = tuple_leaf(IR control, def_hash, "incident:bluecrash",
//!                   b3(BLAKE3(canonical artifact)), derivation or "")
//! ```

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::canonicalize::canonical_json_bytes;
use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;
use crate::receipt::{B3, ControlId, ControlLeaf, tuple_leaf};

/// The incident-response controls a crash evidences.
pub const IR_CONTROLS: [&str; 3] = [
    "NIST_SP_800_53R5_IR_4",
    "NIST_SP_800_53R5_IR_5",
    "NIST_SP_800_53R5_IR_6",
];

/// The test slot of an incident leaf.
pub const INCIDENT_TEST_SLOT: &str = "incident:bluecrash";

/// A validated `.bluecrash` artifact.
#[derive(Clone, Debug, PartialEq)]
pub struct BlueCrash {
    value: Value,
}

impl BlueCrash {
    /// Parse a `.bluecrash` artifact.
    ///
    /// # Errors
    ///
    /// Refuses anything but a JSON object holding a non-empty string
    /// `def_hash`, an `exit` and a `frame`.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = serde_json::from_slice(bytes)
            .map_err(|e| TameshiError::InvalidInput(format!("bluecrash refused: {e}")))?;
        Self::from_value(value)
    }

    /// Validate a parsed artifact.
    ///
    /// # Errors
    ///
    /// As [`BlueCrash::parse`].
    pub fn from_value(value: Value) -> Result<Self> {
        let Some(object) = value.as_object() else {
            return Err(TameshiError::InvalidInput(
                "bluecrash refused: not a JSON object".to_string(),
            ));
        };
        if object
            .get("def_hash")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(TameshiError::InvalidInput(
                "bluecrash refused: def_hash is not a non-empty string".to_string(),
            ));
        }
        if let Some(missing) = ["exit", "frame"].iter().find(|k| !object.contains_key(**k)) {
            return Err(TameshiError::InvalidInput(format!(
                "bluecrash refused: no {missing} field"
            )));
        }
        Ok(Self { value })
    }

    /// The crashed definition's hash.
    #[must_use]
    pub fn def_hash(&self) -> &str {
        self.value["def_hash"].as_str().unwrap_or_default()
    }

    /// How the process exited, as the artifact states it.
    #[must_use]
    pub fn exit(&self) -> &Value {
        &self.value["exit"]
    }

    /// The capability frame, as the artifact states it.
    #[must_use]
    pub fn frame(&self) -> &Value {
        &self.value["frame"]
    }

    /// The whole artifact.
    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// Canonical JSON bytes of the artifact.
    ///
    /// # Panics
    ///
    /// Never: a parsed JSON value always serializes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json_bytes(&self.value).expect("a JSON value always serializes")
    }

    /// `BLAKE3(canonical bytes)`.
    #[must_use]
    pub fn digest(&self) -> Blake3Hash {
        Blake3Hash::digest(&self.canonical_bytes())
    }

    /// One leaf per IR control.
    ///
    /// # Panics
    ///
    /// Never: [`IR_CONTROLS`] are valid control ids.
    #[must_use]
    pub fn leaves(&self) -> Vec<ControlLeaf> {
        let digest = self.digest().to_b3();
        let derivation = self.value["derivation"].as_str().unwrap_or_default();
        IR_CONTROLS
            .iter()
            .map(|control| ControlLeaf {
                control: ControlId::new(control).expect("IR control ids are valid"),
                leaf: B3(tuple_leaf(
                    control,
                    self.def_hash(),
                    INCIDENT_TEST_SLOT,
                    &digest,
                    derivation,
                )),
            })
            .collect()
    }

    /// What the crashed process could reach: the frame's granted and withheld
    /// capabilities and the actors the artifact links, when it has them.
    #[must_use]
    pub fn blast_radius(&self) -> IncidentBlastRadius {
        let frame = self.frame();
        IncidentBlastRadius {
            def_hash: self.def_hash().to_string(),
            exit: self.exit().clone(),
            evidence: B3(self.digest()),
            controls: self.leaves().into_iter().map(|l| l.control).collect(),
            granted: names(&frame["granted"]),
            withheld: names(&frame["withheld"]),
            host_io: frame["host_io"].as_u64(),
            actors: names(&self.value["actors"]),
        }
    }
}

fn names(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| items.iter().map(name).collect())
        .unwrap_or_default()
}

fn name(item: &Value) -> String {
    match item {
        Value::String(s) => s.clone(),
        Value::Object(o) => ["id", "name", "pid"]
            .iter()
            .find_map(|k| o.get(*k))
            .map_or_else(
                || item.to_string(),
                |v| v.as_str().map_or_else(|| v.to_string(), str::to_string),
            ),
        other => other.to_string(),
    }
}

impl Serialize for BlueCrash {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BlueCrash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Self::from_value(Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The reach of a crashed blue process.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct IncidentBlastRadius {
    /// The crashed definition.
    pub def_hash: String,
    /// How it exited.
    pub exit: Value,
    /// The artifact's digest.
    pub evidence: B3,
    /// The controls it evidences.
    pub controls: Vec<ControlId>,
    /// Capabilities the frame granted: what the process could touch.
    pub granted: Vec<String>,
    /// Capabilities the frame withheld.
    pub withheld: Vec<String>,
    /// Host I/O operations performed, when the frame counts them.
    pub host_io: Option<u64>,
    /// Actors the artifact links to the crash.
    pub actors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crash() -> BlueCrash {
        BlueCrash::parse(
            br#"{"def_hash":"b3:00","exit":{"kind":"raise","code":70},"frame":{"granted":["filesystem","clock"],"withheld":["network"],"host_io":3},"actors":["supervisor",{"pid":7},{"name":"worker"}],"journal":[1,2]}"#,
        )
        .unwrap()
    }

    #[test]
    fn a_crash_evidences_ir_4_5_and_6() {
        let leaves = crash().leaves();
        let controls: Vec<&str> = leaves.iter().map(|l| l.control.as_str()).collect();
        assert_eq!(
            controls,
            [
                "NIST_SP_800_53R5_IR_4",
                "NIST_SP_800_53R5_IR_5",
                "NIST_SP_800_53R5_IR_6"
            ]
        );
        assert_eq!(leaves.len(), 3);
        assert_ne!(leaves[0].leaf, leaves[1].leaf);
    }

    #[test]
    fn the_blast_radius_names_the_frame_and_the_actors() {
        let radius = crash().blast_radius();
        assert_eq!(radius.granted, vec!["filesystem", "clock"]);
        assert_eq!(radius.withheld, vec!["network"]);
        assert_eq!(radius.host_io, Some(3));
        assert_eq!(radius.actors, vec!["supervisor", "7", "worker"]);
    }

    #[test]
    fn a_crash_without_actors_or_frame_fields_has_an_empty_radius() {
        let c = BlueCrash::parse(br#"{"def_hash":"x","exit":1,"frame":null}"#).unwrap();
        let radius = c.blast_radius();
        assert!(radius.granted.is_empty() && radius.actors.is_empty());
        assert_eq!(radius.host_io, None);
    }

    #[test]
    fn a_crash_missing_a_required_field_is_refused() {
        for bad in [
            &b"[]"[..],
            br#"{"exit":1,"frame":{}}"#,
            br#"{"def_hash":"","exit":1,"frame":{}}"#,
            br#"{"def_hash":7,"exit":1,"frame":{}}"#,
            br#"{"def_hash":"x","frame":{}}"#,
            br#"{"def_hash":"x","exit":1}"#,
        ] {
            assert!(
                BlueCrash::parse(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn opaque_fields_are_kept_and_digested() {
        let a = crash();
        let mut value = a.value().clone();
        value["journal"] = serde_json::json!([1, 3]);
        let b = BlueCrash::from_value(value).unwrap();
        assert_ne!(a.digest(), b.digest());
        assert_ne!(a.leaves(), b.leaves());
    }
}
