//! Attested Verification Tuples end to end: receipt, leaf, ledger, proof,
//! incident ingest and the `tameshi` CLI words.

use std::path::{Path, PathBuf};
use std::process::Command;

use tameshi::forensics::bluecrash::BlueCrash;
use tameshi::forensics::evidence::{EvidenceLedger, LeafStatus};
use tameshi::hash::Blake3Hash;
use tameshi::receipt::{
    Assertions, B3, ControlId, DrvPath, Receipt, ReceiptParts, ReceiptSchema, Runner, Sandbox,
    Status, Target, TargetKind, TestRef, tuple_leaf,
};

fn receipt(status: Status, failed: u64) -> Receipt {
    Receipt::new(ReceiptParts {
        schema: ReceiptSchema,
        controls: vec![
            ControlId::new("NIST_SP_800_53R5_SA_11").unwrap(),
            ControlId::new("NIST_SP_800_53R5_AC_6").unwrap(),
        ],
        target: Target {
            kind: TargetKind::NixOutput,
            hash: B3(Blake3Hash::digest(b"fixture target")),
        },
        test: TestRef {
            runner: Runner::Cargo,
            hash: B3(Blake3Hash::digest(b"fixture test")),
        },
        status,
        assertions: Assertions { passed: 3, failed },
        steps: None,
        frame: None,
        output_digest: B3(Blake3Hash::digest(b"stdout stderr")),
        sandbox: Sandbox {
            derivation: DrvPath::new("/nix/store/0000000000000000000000000000000a-run.drv")
                .unwrap(),
            network: false,
            system: "aarch64-darwin".to_string(),
        },
    })
    .unwrap()
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn every_one_byte_edit_of_a_receipt_is_refused_or_changes_its_digest_and_breaks_its_proof() {
    let original = receipt(Status::Pass, 0);
    let mut ledger = EvidenceLedger::new();
    ledger.fold_receipt(original.clone()).unwrap();
    let root = ledger.root();
    let leaf = original.leaves()[0].leaf.0.clone();
    let proof = ledger.prove(&leaf).unwrap();
    assert!(proof.verify_against(&root, &leaf));

    let bytes = original.canonical_bytes();
    let (mut refused, mut changed) = (0, 0);
    for i in 0..bytes.len() {
        let mut edited = bytes.clone();
        edited[i] = if edited[i] == b'1' { b'2' } else { b'1' };
        match Receipt::parse(&edited) {
            Err(_) => refused += 1,
            Ok(parsed) => {
                changed += 1;
                assert_ne!(parsed.digest(), original.digest(), "edit at byte {i}");
                let edited_leaf = parsed.leaves()[0].leaf.0.clone();
                assert!(
                    !proof.verify_against(&root, &edited_leaf),
                    "edit at byte {i}"
                );
            }
        }
    }
    assert_eq!(refused + changed, bytes.len());
    assert!(changed > 0 && refused > 0);
}

#[test]
fn a_fail_receipt_still_produces_leaves_and_the_ledger_marks_them_fail() {
    let fail = receipt(Status::Fail, 1);
    let mut ledger = EvidenceLedger::new();
    let added = ledger.fold_receipt(fail.clone()).unwrap();
    assert_eq!(added.len(), 2);
    assert!(added.iter().all(|l| l.status == LeafStatus::Fail));
    let leaf = fail.leaves()[1].leaf.0.clone();
    assert!(
        ledger
            .prove(&leaf)
            .unwrap()
            .verify_against(&ledger.root(), &leaf)
    );
}

#[test]
fn the_length_prefix_keeps_ab_c_apart_from_a_bc() {
    assert_ne!(
        tuple_leaf("AB", "C", "b3:t", "b3:d", "/nix/store/x.drv"),
        tuple_leaf("A", "BC", "b3:t", "b3:d", "/nix/store/x.drv")
    );
    assert_ne!(
        tuple_leaf("C", "b3:t", "b3:d", "/nix/store/x.drv", ""),
        tuple_leaf("C", "b3:t", "b3:d", "", "/nix/store/x.drv")
    );
}

#[test]
fn the_bluecrash_fixture_ingests_as_ir_4_5_and_6_beside_receipts() {
    let crash = BlueCrash::parse(&std::fs::read(fixture("sample.bluecrash")).unwrap()).unwrap();
    let mut ledger = EvidenceLedger::new();
    ledger.fold_receipt(receipt(Status::Pass, 0)).unwrap();
    let added = ledger.fold_incident(crash.clone()).unwrap();
    let controls: Vec<&str> = added.iter().map(|l| l.control.as_str()).collect();
    assert_eq!(
        controls,
        [
            "NIST_SP_800_53R5_IR_4",
            "NIST_SP_800_53R5_IR_5",
            "NIST_SP_800_53R5_IR_6"
        ]
    );
    assert!(added.iter().all(|l| l.status == LeafStatus::Incident));
    for l in &added {
        assert!(
            ledger
                .prove(&l.leaf.0)
                .unwrap()
                .verify_against(&ledger.root(), &l.leaf.0)
        );
    }
    let radius = crash.blast_radius();
    assert_eq!(radius.granted, vec!["filesystem", "clock"]);
    assert_eq!(radius.actors, vec!["supervisor", "worker"]);
    let reread = EvidenceLedger::from_json(&ledger.to_json()).unwrap();
    assert_eq!(reread.root(), ledger.root());
}

fn tameshi(args: &[&str]) -> (bool, serde_json::Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_tameshi"))
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value = serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Null);
    (out.status.success(), value)
}

fn write_fragment(dir: &Path, threshold: Option<&str>) -> (serde_json::Value, serde_json::Value) {
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("t.rs"), b"test source").unwrap();
    let run = Command::new(env!("CARGO_BIN_EXE_tameshi"))
        .current_dir(&work)
        .args(["receipt", "run", "--out"])
        .arg(dir.join("run"))
        .args([
            "--",
            "/bin/sh",
            "-c",
            "echo 'test result: ok. 1 passed; 0 failed;'",
        ])
        .output()
        .unwrap();
    assert!(run.status.success());
    let mut write = Command::new(env!("CARGO_BIN_EXE_tameshi"));
    write
        .env_remove("TAMESHI_FRAGMENT_THRESHOLD__ENABLED")
        .env("HOME", dir)
        .args(["receipt", "write", "--run"])
        .arg(dir.join("run"))
        .args([
            "--derivation",
            "/nix/store/0000000000000000000000000000000a-run.drv",
            "--system",
            "aarch64-darwin",
            "--control",
            "NIST_SP_800_53R5_SC_13",
            "--target-kind",
            "nix-output",
            "--target-path",
        ])
        .arg(&work)
        .args(["--runner", "cargo", "--test-path"])
        .arg(work.join("t.rs"))
        .arg("--out")
        .arg(dir.join("out"));
    if let Some(value) = threshold {
        write.env("TAMESHI_FRAGMENT_THRESHOLD__ENABLED", value);
    }
    let out = write.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let (ok, verdict) = tameshi(&[
        "receipt",
        "verify",
        &dir.join("out/tameshi-receipt.v1.json")
            .display()
            .to_string(),
        "--fragment",
        &dir.join("out/tameshi-fragment.v1.json")
            .display()
            .to_string(),
    ]);
    assert!(ok, "{verdict}");
    (written, verdict)
}

#[test]
fn the_cli_signs_new_fragments_with_the_threshold_group_unless_switched_off() {
    let dir = tempfile::tempdir().unwrap();
    let (written, verdict) = write_fragment(dir.path(), None);
    assert_eq!(written["algorithm"], "frost_ed25519:2-of-3");
    assert_eq!(written["key_mode"], "test");
    assert_eq!(verdict["fragment"]["signature_valid"], true);

    let dir = tempfile::tempdir().unwrap();
    let (written, verdict) = write_fragment(dir.path(), Some("false"));
    assert_eq!(written["algorithm"], "ed25519_local");
    assert_eq!(verdict["fragment"]["signature_valid"], true);

    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".config/tameshi")).unwrap();
    std::fs::write(
        dir.path().join(".config/tameshi/fragment.yaml"),
        "threshold:\n  enabled: false\n",
    )
    .unwrap();
    let (written, _) = write_fragment(dir.path(), None);
    assert_eq!(written["algorithm"], "ed25519_local");
}

#[test]
fn the_cli_runs_writes_folds_proves_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("t.rs"), b"test source").unwrap();

    let run = Command::new(env!("CARGO_BIN_EXE_tameshi"))
        .current_dir(&work)
        .args([
            "receipt",
            "run",
            "--out",
            &path("run"),
            "--",
            "/bin/sh",
            "-c",
        ])
        .arg("echo 'test result: FAILED. 2 passed; 1 failed;'; exit 101")
        .output()
        .unwrap();
    assert!(run.status.success(), "a red test is recorded, not an error");
    let record: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(record["exit_code"], 101);

    let (ok, written) = tameshi(&[
        "receipt",
        "write",
        "--run",
        &path("run"),
        "--derivation",
        "/nix/store/0000000000000000000000000000000a-run.drv",
        "--system",
        "aarch64-darwin",
        "--control",
        "NIST_SP_800_53R5_SA_11",
        "--target-kind",
        "nix-output",
        "--target-path",
        &work.display().to_string(),
        "--runner",
        "cargo",
        "--test-path",
        &work.join("t.rs").display().to_string(),
        "--out",
        &path("out"),
    ]);
    assert!(ok);
    assert_eq!(written["status"], "FAIL");
    assert_eq!(written["assertions"]["failed"], 1);
    assert_eq!(written["key_mode"], "test");

    let receipt = path("out/tameshi-receipt.v1.json");
    let (ok, verdict) = tameshi(&[
        "receipt",
        "verify",
        &receipt,
        "--fragment",
        &path("out/tameshi-fragment.v1.json"),
    ]);
    assert!(ok, "{verdict}");
    assert_eq!(verdict["canonical"], true);

    let (ok, folded) = tameshi(&["ledger", "fold", &path("ledger.json"), &receipt]);
    assert!(ok);
    assert_eq!(folded["leaves"], 1);
    let (ok, again) = tameshi(&["ledger", "fold", &path("ledger.json"), &receipt]);
    assert!(ok);
    assert_eq!(again["already_present"].as_array().unwrap().len(), 1);

    let (ok, _) = tameshi(&[
        "ledger",
        "prove",
        &path("ledger.json"),
        "--receipt",
        &receipt,
        "--control",
        "NIST_SP_800_53R5_SA_11",
        "--out",
        &path("proof.json"),
    ]);
    assert!(ok);
    let verify = |status: &str| {
        tameshi(&[
            "ledger",
            "verify",
            &path("proof.json"),
            "--ledger",
            &path("ledger.json"),
            "--receipt",
            &receipt,
            "--control",
            "NIST_SP_800_53R5_SA_11",
            "--expect-status",
            status,
        ])
    };
    let (ok, verdict) = verify("FAIL");
    assert!(ok, "{verdict}");
    assert_eq!(verdict["status"], "FAIL");
    assert!(!verify("PASS").0);
}

#[test]
fn the_cli_ingests_a_bluecrash_into_a_ledger_written_elsewhere() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("absent.json").display().to_string();
    let out = dir.path().join("new/ledger.json");
    let (ok, ingested) = tameshi(&[
        "incident",
        "ingest",
        &input,
        &fixture("sample.bluecrash").display().to_string(),
        "--out",
        &out.display().to_string(),
    ]);
    assert!(ok);
    assert_eq!(ingested["added"].as_array().unwrap().len(), 3);
    assert_eq!(ingested["blast_radius"]["withheld"][0], "network");
    let ledger = EvidenceLedger::from_json(&std::fs::read(out).unwrap()).unwrap();
    assert_eq!(ledger.root().to_b3(), ingested["root"]);
}
