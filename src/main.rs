//! `tameshi`: receipts, the evidence ledger and incident ingest from the command line.
//!
//! - `receipt run` runs a test command and records it (the sandboxed step).
//! - `receipt write` turns a run into a receipt and a signed fragment.
//! - `receipt verify`, `receipt leaves`, `receipt sign` check, list and re-sign.
//! - `ledger fold`, `ledger prove`, `ledger verify` maintain and prove the ledger.
//! - `incident ingest` folds a `.bluecrash` artifact as IR-4/5/6 evidence.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use tameshi::error::{Result, TameshiError};
use tameshi::forensics::bluecrash::BlueCrash;
use tameshi::forensics::evidence::{EvidenceLedger, FoldRefusal, InclusionProof, LeafStatus};
use tameshi::hash::{Blake3Hash, blake3_tree};
use tameshi::receipt::fragment::{
    AttestationFragment, KeyMode, parse_key_hex, sign_fragment, verify_fragment,
};
use tameshi::receipt::runner::{ReceiptRequest, receipt_from_run, run_command};
use tameshi::receipt::{B3, ControlId, DrvPath, Receipt, Runner, Target, TargetKind, TestRef};
use tameshi::signing::LocalSigner;

/// The receipt file name inside a `wrapTest` output.
const RECEIPT_FILE: &str = "tameshi-receipt.v1.json";
/// The fragment file name inside a `wrapTest` output.
const FRAGMENT_FILE: &str = "tameshi-fragment.v1.json";

/// Tameshi (試し): attested verification receipts and the evidence ledger.
#[derive(Parser)]
#[command(name = "tameshi", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run, write, verify and sign `tameshi-receipt.v1` receipts.
    #[command(subcommand)]
    Receipt(ReceiptCommand),
    /// Fold receipts into a ledger, and prove and verify leaf inclusion.
    #[command(subcommand)]
    Ledger(LedgerCommand),
    /// Ingest incident evidence.
    #[command(subcommand)]
    Incident(IncidentCommand),
}

#[derive(Subcommand)]
enum ReceiptCommand {
    /// Run a test command, capturing stdout, stderr and the exit status; a red
    /// test is recorded, never an error.
    Run {
        /// The run directory to write.
        #[arg(long)]
        out: PathBuf,
        /// Point HOME at a fresh empty directory first.
        #[arg(long)]
        fresh_home: bool,
        /// The command and its arguments.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Write a receipt and its signed fragment from a run directory.
    Write(Box<WriteArgs>),
    /// Check a receipt strictly, and its fragment when given.
    Verify {
        /// The receipt.
        receipt: PathBuf,
        /// The fragment to check against it.
        #[arg(long)]
        fragment: Option<PathBuf>,
        /// The verifying key the fragment must carry, 64 hex digits.
        #[arg(long)]
        trusted_key: Option<String>,
    },
    /// Print a receipt's digest and its one leaf per control.
    Leaves {
        /// The receipt.
        receipt: PathBuf,
    },
    /// Sign a receipt with a seed read now from a file outside the nix store.
    Sign {
        /// The receipt.
        receipt: PathBuf,
        /// A file holding the 32-byte Ed25519 seed as 64 hex digits.
        #[arg(long)]
        seed_file: PathBuf,
        /// The signer's name in the signed root.
        #[arg(long, default_value = "tameshi")]
        signer_id: String,
        /// The fragment file to write.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Args)]
struct WriteArgs {
    /// The run directory `receipt run` wrote.
    #[arg(long)]
    run: PathBuf,
    /// The derivation the run happened in.
    #[arg(long)]
    derivation: String,
    /// The nix system the run executed on.
    #[arg(long)]
    system: String,
    /// A control the run evidences; repeat for more.
    #[arg(long = "control", required = true)]
    controls: Vec<String>,
    /// `blue-def` or `nix-output`.
    #[arg(long)]
    target_kind: String,
    /// The target's `b3:` hash.
    #[arg(
        long,
        conflicts_with = "target_path",
        required_unless_present = "target_path"
    )]
    target_hash: Option<String>,
    /// A file or directory to hash as the target.
    #[arg(long)]
    target_path: Option<PathBuf>,
    /// The test runner: cargo, pytest, go, blue or another name.
    #[arg(long)]
    runner: String,
    /// The test's `b3:` hash.
    #[arg(
        long,
        conflicts_with = "test_path",
        required_unless_present = "test_path"
    )]
    test_hash: Option<String>,
    /// A file or directory to hash as the test.
    #[arg(long)]
    test_path: Option<PathBuf>,
    /// The directory to write the receipt and fragment into.
    #[arg(long)]
    out: PathBuf,
    /// Sign with this seed file instead of the public test key.
    #[arg(long)]
    seed_file: Option<PathBuf>,
    /// The signer's name in the signed root.
    #[arg(long, default_value = "tameshi")]
    signer_id: String,
}

#[derive(Args)]
struct LeafSelector {
    /// The leaf, `b3:<hex>`.
    #[arg(long, conflicts_with_all = ["receipt", "bluecrash"])]
    leaf: Option<String>,
    /// Compute the leaf from this receipt and `--control`.
    #[arg(long, requires = "control", conflicts_with = "bluecrash")]
    receipt: Option<PathBuf>,
    /// Compute the leaf from this `.bluecrash` and `--control`.
    #[arg(long, requires = "control")]
    bluecrash: Option<PathBuf>,
    /// The control whose leaf to take.
    #[arg(long)]
    control: Option<String>,
}

#[derive(Subcommand)]
enum LedgerCommand {
    /// Fold receipts into a ledger, creating it when absent. A receipt already
    /// folded is skipped; a malformed one is refused and the rest still fold.
    Fold {
        /// The ledger file.
        ledger: PathBuf,
        /// Receipt files.
        #[arg(required = true)]
        receipts: Vec<PathBuf>,
        /// Write the new ledger here instead of over the input.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Issue an inclusion proof for a leaf of the ledger.
    Prove {
        /// The ledger file.
        ledger: PathBuf,
        #[command(flatten)]
        leaf: LeafSelector,
        /// Write the proof here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify an inclusion proof, against a ledger or a root when given.
    Verify {
        /// The proof file.
        proof: PathBuf,
        /// Verify against this ledger's root (the ledger is fully rechecked).
        #[arg(long, conflicts_with = "root")]
        ledger: Option<PathBuf>,
        /// Verify against this root, `b3:<hex>`.
        #[arg(long)]
        root: Option<String>,
        #[command(flatten)]
        leaf: LeafSelector,
        /// Also require the ledger to mark the leaf PASS, FAIL or INCIDENT.
        #[arg(long, requires = "ledger")]
        expect_status: Option<String>,
    },
}

#[derive(Subcommand)]
enum IncidentCommand {
    /// Fold a `.bluecrash` artifact into a ledger as IR-4, IR-5 and IR-6
    /// evidence and print its blast radius.
    Ingest {
        /// The ledger file.
        ledger: PathBuf,
        /// The `.bluecrash` artifact.
        bluecrash: PathBuf,
        /// Write the new ledger here instead of over the input.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("tameshi: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<bool> {
    match cli.command {
        Command::Receipt(command) => receipt(command),
        Command::Ledger(command) => ledger(command),
        Command::Incident(IncidentCommand::Ingest {
            ledger,
            bluecrash,
            out,
        }) => ingest(&ledger, &bluecrash, out.as_deref().unwrap_or(&ledger)),
    }
}

fn receipt(command: ReceiptCommand) -> Result<bool> {
    match command {
        ReceiptCommand::Run {
            out,
            fresh_home,
            command,
        } => {
            let record = run_command(&command, &std::env::current_dir()?, &out, fresh_home)?;
            print_json(&record)?;
            Ok(true)
        }
        ReceiptCommand::Write(args) => write(*args),
        ReceiptCommand::Verify {
            receipt,
            fragment,
            trusted_key,
        } => verify_receipt(&receipt, fragment.as_deref(), trusted_key.as_deref()),
        ReceiptCommand::Leaves { receipt } => {
            let receipt = Receipt::parse(&read(&receipt)?)?;
            print_json(&serde_json::json!({
                "digest": B3(receipt.digest()),
                "leaves": receipt.leaves(),
            }))?;
            Ok(true)
        }
        ReceiptCommand::Sign {
            receipt,
            seed_file,
            signer_id,
            out,
        } => {
            let receipt = Receipt::parse(&read(&receipt)?)?;
            let signer = LocalSigner::from_seed(read_seed(&seed_file)?, &signer_id);
            let fragment = sign_fragment(&receipt, &signer, KeyMode::SeedFile);
            write_file(&out, &fragment.canonical_bytes())?;
            Ok(true)
        }
    }
}

fn write(args: WriteArgs) -> Result<bool> {
    let controls = args
        .controls
        .iter()
        .map(|c| ControlId::new(c))
        .collect::<Result<Vec<_>>>()?;
    let kind: TargetKind =
        serde_json::from_value(args.target_kind.clone().into()).map_err(|_| {
            TameshiError::InvalidInput(format!(
                "target kind {:?} is not blue-def or nix-output",
                args.target_kind
            ))
        })?;
    let request = ReceiptRequest {
        controls,
        target: Target {
            kind,
            hash: hash_arg(args.target_hash.as_deref(), args.target_path.as_deref())?,
        },
        test: TestRef {
            runner: Runner::parse(&args.runner)?,
            hash: hash_arg(args.test_hash.as_deref(), args.test_path.as_deref())?,
        },
        derivation: DrvPath::new(&args.derivation)?,
        system: args.system,
    };
    let receipt = receipt_from_run(&args.run, request)?;
    let (signer, mode) = match &args.seed_file {
        Some(path) => (
            LocalSigner::from_seed(read_seed(path)?, &args.signer_id),
            KeyMode::SeedFile,
        ),
        None => (LocalSigner::for_testing(), KeyMode::Test),
    };
    let fragment = sign_fragment(&receipt, &signer, mode);
    std::fs::create_dir_all(&args.out)?;
    std::fs::write(args.out.join(RECEIPT_FILE), receipt.canonical_bytes())?;
    std::fs::write(args.out.join(FRAGMENT_FILE), fragment.canonical_bytes())?;
    print_json(&serde_json::json!({
        "digest": B3(receipt.digest()),
        "status": receipt.status(),
        "assertions": receipt.assertions(),
        "key_mode": mode,
    }))?;
    Ok(true)
}

fn hash_arg(hash: Option<&str>, path: Option<&Path>) -> Result<B3> {
    match (hash, path) {
        (Some(hash), None) => B3::parse(hash),
        (None, Some(path)) => Ok(B3(blake3_tree(path)?)),
        _ => Err(TameshiError::InvalidInput(
            "give exactly one of a hash or a path".to_string(),
        )),
    }
}

#[derive(Serialize)]
struct ReceiptVerdict {
    digest: B3,
    status: tameshi::receipt::Status,
    canonical: bool,
    leaves: Vec<tameshi::receipt::ControlLeaf>,
    fragment: Option<tameshi::receipt::fragment::FragmentVerdict>,
    key_mode: Option<KeyMode>,
}

fn verify_receipt(path: &Path, fragment: Option<&Path>, trusted_key: Option<&str>) -> Result<bool> {
    let bytes = read(path)?;
    let receipt = Receipt::parse(&bytes)?;
    let trusted = trusted_key.map(parse_key_hex).transpose()?;
    let fragment = fragment
        .map(|f| AttestationFragment::parse(&read(f)?))
        .transpose()?;
    let fragment_verdict = fragment
        .as_ref()
        .map(|f| verify_fragment(f, &receipt, trusted.as_ref()));
    let verdict = ReceiptVerdict {
        digest: B3(receipt.digest()),
        status: receipt.status(),
        canonical: Receipt::parse_canonical(&bytes).is_ok(),
        leaves: receipt.leaves(),
        fragment: fragment_verdict,
        key_mode: fragment.map(|f| f.key_mode),
    };
    print_json(&verdict)?;
    Ok(fragment_verdict.is_none_or(|v| v.ok()))
}

fn ledger(command: LedgerCommand) -> Result<bool> {
    match command {
        LedgerCommand::Fold {
            ledger,
            receipts,
            out,
        } => fold(&ledger, &receipts, out.as_deref().unwrap_or(&ledger)),
        LedgerCommand::Prove { ledger, leaf, out } => {
            let book = load_ledger(&ledger)?;
            let leaf = select_leaf(&leaf)?.ok_or_else(|| {
                TameshiError::InvalidInput(
                    "name a leaf: --leaf, or --receipt/--bluecrash with --control".to_string(),
                )
            })?;
            let proof = book.prove(&leaf).ok_or_else(|| {
                TameshiError::InvalidInput(format!("leaf {} is not in the ledger", leaf.to_b3()))
            })?;
            match out {
                Some(out) => write_file(&out, &proof.canonical_bytes())?,
                None => println!("{}", String::from_utf8_lossy(&proof.canonical_bytes())),
            }
            Ok(true)
        }
        LedgerCommand::Verify {
            proof,
            ledger,
            root,
            leaf,
            expect_status,
        } => verify_inclusion(
            &proof,
            ledger.as_deref(),
            root.as_deref(),
            &leaf,
            expect_status.as_deref(),
        ),
    }
}

#[derive(Serialize)]
struct FoldReport {
    root: B3,
    leaves: usize,
    added: Vec<tameshi::forensics::evidence::LedgerLeaf>,
    already_present: Vec<String>,
    refused: Vec<(String, String)>,
}

fn fold(path: &Path, receipts: &[PathBuf], out: &Path) -> Result<bool> {
    let mut book = load_or_new(path)?;
    let mut report = FoldReport {
        root: B3(book.root()),
        leaves: 0,
        added: Vec::new(),
        already_present: Vec::new(),
        refused: Vec::new(),
    };
    for file in receipts {
        match read(file).and_then(|bytes| Receipt::parse(&bytes)) {
            Ok(receipt) => match book.fold_receipt(receipt) {
                Ok(added) => report.added.extend(added),
                Err(FoldRefusal::Duplicate(_)) => {
                    report.already_present.push(file.display().to_string());
                }
            },
            Err(e) => report
                .refused
                .push((file.display().to_string(), e.to_string())),
        }
    }
    write_file(out, &book.to_json())?;
    report.root = B3(book.root());
    report.leaves = book.leaves().len();
    print_json(&report)?;
    Ok(report.refused.is_empty())
}

#[derive(Serialize)]
struct InclusionVerdict {
    ok: bool,
    path_valid: bool,
    anchored: bool,
    leaf: B3,
    root: B3,
    status: Option<LeafStatus>,
}

fn verify_inclusion(
    proof: &Path,
    ledger: Option<&Path>,
    root: Option<&str>,
    leaf: &LeafSelector,
    expect_status: Option<&str>,
) -> Result<bool> {
    let proof = InclusionProof::parse(&read(proof)?)?;
    let book = ledger.map(load_ledger).transpose()?;
    let anchor = match (&book, root) {
        (Some(book), _) => Some(book.root()),
        (None, Some(root)) => Some(B3::parse(root)?.0),
        (None, None) => None,
    };
    let expected_root = anchor.clone().unwrap_or_else(|| proof.root.0.clone());
    let expected_leaf = select_leaf(leaf)?.unwrap_or_else(|| proof.leaf.0.clone());
    let path_valid = proof.verify_against(&expected_root, &expected_leaf);
    let status = book
        .as_ref()
        .and_then(|b| b.find(&expected_leaf))
        .map(|l| l.status);
    let status_ok = match expect_status {
        Some(want) => status == Some(LeafStatus::parse(want)?),
        None => true,
    };
    let verdict = InclusionVerdict {
        ok: path_valid && status_ok,
        path_valid,
        anchored: anchor.is_some(),
        leaf: B3(expected_leaf),
        root: B3(expected_root),
        status,
    };
    print_json(&verdict)?;
    Ok(verdict.ok)
}

fn select_leaf(selector: &LeafSelector) -> Result<Option<Blake3Hash>> {
    let leaves = match (&selector.leaf, &selector.receipt, &selector.bluecrash) {
        (Some(leaf), _, _) => return Ok(Some(B3::parse(leaf)?.0)),
        (None, Some(receipt), _) => Receipt::parse(&read(receipt)?)?.leaves(),
        (None, None, Some(crash)) => BlueCrash::parse(&read(crash)?)?.leaves(),
        (None, None, None) => return Ok(None),
    };
    let control = ControlId::new(selector.control.as_deref().unwrap_or_default())?;
    leaves
        .into_iter()
        .find(|l| l.control == control)
        .map(|l| Some(l.leaf.0))
        .ok_or_else(|| {
            TameshiError::InvalidInput(format!("the evidence does not evidence {control}"))
        })
}

fn ingest(path: &Path, crash: &Path, out: &Path) -> Result<bool> {
    let crash = BlueCrash::parse(&read(crash)?)?;
    let radius = crash.blast_radius();
    let mut book = load_or_new(path)?;
    let added = book.fold_incident(crash).unwrap_or_default();
    write_file(out, &book.to_json())?;
    print_json(&serde_json::json!({
        "root": B3(book.root()),
        "added": added,
        "blast_radius": radius,
    }))?;
    Ok(true)
}

fn load_ledger(path: &Path) -> Result<EvidenceLedger> {
    EvidenceLedger::from_json(&read(path)?)
}

fn load_or_new(path: &Path) -> Result<EvidenceLedger> {
    if path.exists() {
        load_ledger(path)
    } else {
        Ok(EvidenceLedger::new())
    }
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| TameshiError::InvalidInput(format!("{}: {e}", path.display())))
}

fn read_seed(path: &Path) -> Result<[u8; 32]> {
    let real = std::fs::canonicalize(path)?;
    if real.starts_with("/nix/store") {
        return Err(TameshiError::InvalidInput(format!(
            "refusing a signing seed inside the nix store: {}",
            real.display()
        )));
    }
    parse_key_hex(&String::from_utf8_lossy(&read(&real)?))
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
