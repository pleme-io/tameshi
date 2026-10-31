//! The source guard for "the group secret is never one scalar".
//!
//! frost-ed25519 exports `keys::reconstruct` (Lagrange interpolation of the
//! whole key), `keys::split` (shares from a whole key) and `SigningKey` (a
//! whole key). These tests read the threshold module's own source and hold
//! that it names frost only through `use frost_ed25519 as frost;`, names
//! only the items each file's allowlist lists, that no allowlist holds a
//! whole-key item, that the signing file names no key generation, and that
//! no other file in `src/` names frost at all.

use std::collections::BTreeSet;
use std::path::Path;

const NEVER: &[&str] = &[
    "frost::keys::reconstruct",
    "frost::keys::split",
    "frost::SigningKey",
    "frost::keys::refresh",
    "frost::keys::repairable",
];

const KEY_GENERATION: &[&str] = &["frost::keys::dkg", "frost::keys::generate_with_dealer"];

const MOD_ALLOWED: &[&str] = &[
    "frost::Error",
    "frost::Error::InvalidProofOfKnowledge",
    "frost::Error::InvalidSecretShare",
    "frost::Error::InvalidSignature",
    "frost::Error::InvalidSignatureShare",
    "frost::Identifier",
    "frost::Identifier::try_from",
    "frost::VerifyingKey",
    "frost::keys::KeyPackage",
    "frost::keys::KeyPackage::deserialize",
    "frost::keys::PublicKeyPackage",
    "frost::keys::PublicKeyPackage::deserialize",
];

const KEYGEN_ALLOWED: &[&str] = &[
    "frost::Identifier",
    "frost::keys::IdentifierList::Default",
    "frost::keys::KeyPackage::try_from",
    "frost::keys::dkg::part1",
    "frost::keys::dkg::part2",
    "frost::keys::dkg::part3",
    "frost::keys::dkg::round1::Package",
    "frost::keys::dkg::round1::SecretPackage",
    "frost::keys::dkg::round2::Package",
    "frost::keys::dkg::round2::SecretPackage",
    "frost::keys::generate_with_dealer",
];

const SIGNING_ALLOWED: &[&str] = &[
    "frost::Error::IncorrectCommitment",
    "frost::Error::MissingCommitment",
    "frost::SigningPackage",
    "frost::SigningPackage::new",
    "frost::aggregate",
    "frost::round1::SigningCommitments",
    "frost::round1::SigningNonces",
    "frost::round1::commit",
    "frost::round2::SignatureShare",
    "frost::round2::sign",
];

const TESTS_ALLOWED: &[&str] = &[
    "frost::SigningPackage::new",
    "frost::aggregate",
    "frost::keys::KeyPackage",
    "frost::keys::KeyPackage::new",
    "frost::keys::PublicKeyPackage::new",
    "frost::round1::commit",
    "frost::round2::sign",
];

const FILES: &[(&str, &str, &[&str])] = &[
    ("mod.rs", include_str!("mod.rs"), MOD_ALLOWED),
    ("keygen.rs", include_str!("keygen.rs"), KEYGEN_ALLOWED),
    ("signing.rs", include_str!("signing.rs"), SIGNING_ALLOWED),
    ("tests.rs", include_str!("tests.rs"), TESTS_ALLOWED),
];

fn frost_paths(source: &str) -> Result<BTreeSet<String>, String> {
    let mut paths = BTreeSet::new();
    let mut rest = source;
    while let Some(at) = rest.find("frost::") {
        let tail = &rest[at..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
            .unwrap_or(tail.len());
        let path = tail[..end].trim_end_matches(':');
        if tail[end..].starts_with('{') || tail[end..].starts_with('*') {
            return Err(format!("`{path}::{{..}}` hides the items it imports"));
        }
        paths.insert(path.to_string());
        rest = &tail[end..];
    }
    Ok(paths)
}

fn crate_name_uses(source: &str) -> Vec<&str> {
    source
        .match_indices("frost_ed25519")
        .filter_map(|(at, name)| {
            let line_start = source[..at].rfind('\n').map_or(0, |n| n + 1);
            let line_end = source[at..].find('\n').map_or(source.len(), |n| at + n);
            let line = source[line_start..line_end].trim();
            let as_path = source[at + name.len()..].starts_with("::");
            let as_import = line.starts_with("use frost_ed25519")
                || line.starts_with("pub use frost_ed25519")
                || line.starts_with("extern crate frost_ed25519");
            (as_path || as_import).then_some(line)
        })
        .collect()
}

#[test]
fn each_file_names_only_its_allowed_frost_items() {
    for (file, source, allowed) in FILES {
        let used = frost_paths(source).unwrap_or_else(|e| panic!("{file}: {e}"));
        let allowed: BTreeSet<String> = allowed.iter().map(ToString::to_string).collect();
        let unlisted: Vec<_> = used.difference(&allowed).collect();
        assert!(
            unlisted.is_empty(),
            "{file} names frost items no allowlist admits: {unlisted:?}"
        );
        let stale: Vec<_> = allowed.difference(&used).collect();
        assert!(
            stale.is_empty(),
            "{file}'s allowlist admits items it no longer names: {stale:?}"
        );
    }
}

#[test]
fn no_allowlist_admits_an_item_that_holds_or_rebuilds_the_whole_key() {
    for (file, _, allowed) in FILES {
        for item in *allowed {
            assert!(
                !NEVER.iter().any(|never| item.starts_with(never)),
                "{file} may name {item}, which holds or rebuilds the whole key"
            );
        }
    }
}

#[test]
fn the_signing_path_names_no_key_generation() {
    for item in SIGNING_ALLOWED {
        assert!(
            !KEY_GENERATION.iter().any(|keygen| item.starts_with(keygen)),
            "signing.rs may name {item}"
        );
    }
}

fn frost_imports(source: &str) -> Vec<&str> {
    source
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("use ") || line.starts_with("pub use "))
        .filter(|line| line.contains("frost"))
        .collect()
}

#[test]
fn frost_is_named_only_as_frost_inside_the_threshold_module() {
    for (file, source, _) in FILES {
        for line in crate_name_uses(source) {
            assert_eq!(line, "use frost_ed25519 as frost;", "{file}");
        }
        for line in frost_imports(source) {
            assert!(
                ["use frost_ed25519 as frost;", "use super::frost;"].contains(&line),
                "{file} renames frost: {line}"
            );
        }
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let threshold = src.join("threshold");
    let mut pending = vec![src];
    let mut scanned = 0;
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path != threshold {
                    pending.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                scanned += 1;
                let source = std::fs::read_to_string(&path).unwrap();
                assert!(
                    crate_name_uses(&source).is_empty(),
                    "{} names frost outside src/threshold/",
                    path.display()
                );
            }
        }
    }
    assert!(
        scanned > 50,
        "the walk read {scanned} files; src/ was not found"
    );
}

#[test]
fn the_scanner_sees_a_reconstruct_call_and_a_hidden_import() {
    let used = frost_paths("let key = frost::keys::reconstruct(&shares)?;").unwrap();
    assert!(used.contains("frost::keys::reconstruct"));
    assert!(frost_paths("use frost::keys::{reconstruct};").is_err());
    assert!(frost_paths("use frost::keys::*;").is_err());
    assert_eq!(
        crate_name_uses("use frost_ed25519::keys::reconstruct;"),
        vec!["use frost_ed25519::keys::reconstruct;"]
    );
    assert_eq!(
        crate_name_uses("let key = ::frost_ed25519::keys::reconstruct(&shares)?;"),
        vec!["let key = ::frost_ed25519::keys::reconstruct(&shares)?;"]
    );
    assert_eq!(
        crate_name_uses("use frost_ed25519 as f;"),
        vec!["use frost_ed25519 as f;"]
    );
    assert_eq!(
        crate_name_uses(r#"fn frost_ed25519_test() { "frost_ed25519" }"#),
        Vec::<&str>::new()
    );
}
