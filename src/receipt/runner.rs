//! Running a test command and turning the run into a receipt.
//!
//! [`run_command`] runs any argv with stdout and stderr captured to files and
//! records the exit status; it never fails because the test failed. A command
//! may write a facts file (path in `TAMESHI_FACTS`) to report assertion
//! counts, steps or a frame the logs cannot. [`receipt_from_run`] reads that
//! run directory and writes the receipt.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use super::{
    Assertions, B3, ControlId, DrvPath, Frame, Receipt, ReceiptParts, ReceiptSchema, Runner,
    Sandbox, Status, Target, TestRef, schema_tag,
};
use crate::canonicalize::canonical_json_bytes;
use crate::error::{Result, TameshiError};
use crate::hash::Blake3Hash;

schema_tag!(RunSchema, "tameshi-run.v1");

/// The run record file inside a run directory.
pub const RUN_FILE: &str = "run.json";
/// The captured standard output.
pub const STDOUT_FILE: &str = "stdout.log";
/// The captured standard error.
pub const STDERR_FILE: &str = "stderr.log";
/// The facts the command reported, copied in when it wrote any.
pub const FACTS_FILE: &str = "facts.json";
/// The environment variable naming where a command may write its facts.
pub const FACTS_ENV: &str = "TAMESHI_FACTS";

/// What happened when the command ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    /// Always `tameshi-run.v1`.
    pub schema: RunSchema,
    /// The argv that ran.
    pub argv: Vec<String>,
    /// The exit code, when the command exited.
    pub exit_code: Option<i32>,
    /// The signal that ended the command, when one did.
    pub signal: Option<i32>,
    /// Why the command could not start, when it could not.
    pub spawn_error: Option<String>,
    /// Whether an outbound network route existed during the run.
    pub network: bool,
}

/// Facts a command reports about itself through `TAMESHI_FACTS`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunFacts {
    /// Assertion counts; these win over counts read from the logs.
    #[serde(default)]
    pub assertions: Option<Assertions>,
    /// Evaluation steps.
    #[serde(default)]
    pub steps: Option<u64>,
    /// The capability frame.
    #[serde(default)]
    pub frame: Option<Frame>,
}

/// Run `argv` in `work` and record it under `out`.
///
/// `fresh_home` points `HOME` at a new empty directory first, for sandboxes
/// whose `HOME` cannot be written. A command that cannot start is recorded,
/// not returned as an error.
///
/// # Errors
///
/// Returns an error only when `out` or the log files cannot be written.
pub fn run_command(
    argv: &[String],
    work: &Path,
    out: &Path,
    fresh_home: bool,
) -> Result<RunRecord> {
    std::fs::create_dir_all(out)?;
    let facts_path = work.join(".tameshi-facts.json");
    let stdout = std::fs::File::create(out.join(STDOUT_FILE))?;
    let stderr = std::fs::File::create(out.join(STDERR_FILE))?;
    let network = network_reachable();
    let (exit_code, signal, spawn_error) = match argv.split_first() {
        None => (None, None, Some("empty command".to_string())),
        Some((program, rest)) => {
            let mut command = Command::new(program);
            command
                .args(rest)
                .current_dir(work)
                .env(FACTS_ENV, &facts_path)
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr));
            if fresh_home {
                let home = work.join(".tameshi-home");
                std::fs::create_dir_all(&home)?;
                command.env("HOME", home);
            }
            match command.status() {
                Ok(status) => (status.code(), exit_signal(status), None),
                Err(e) => (None, None, Some(format!("{program}: {e}"))),
            }
        }
    };
    if facts_path.exists() {
        std::fs::copy(&facts_path, out.join(FACTS_FILE))?;
    }
    let record = RunRecord {
        schema: RunSchema,
        argv: argv.to_vec(),
        exit_code,
        signal,
        spawn_error,
        network,
    };
    std::fs::write(out.join(RUN_FILE), canonical_json_bytes(&record)?)?;
    Ok(record)
}

#[cfg(unix)]
fn exit_signal(status: std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: std::process::ExitStatus) -> Option<i32> {
    None
}

/// Whether the host has a route out: a UDP `connect` to a documentation
/// address (RFC 5737, RFC 3849) selects a route and sends nothing. A nix
/// sandbox has no route, so both fail there.
#[must_use]
pub fn network_reachable() -> bool {
    let routed = |bind: &str, peer: &str| {
        std::net::UdpSocket::bind(bind)
            .and_then(|socket| socket.connect(peer))
            .is_ok()
    };
    routed("0.0.0.0:0", "192.0.2.1:9") || routed("[::]:0", "[2001:db8::1]:9")
}

/// Count assertions from a runner's output.
///
/// `cargo` sums every `test result:` line; `blue` sums every
/// `test(s): P passed, F failed` line; `pytest` reads the last summary line
/// (errors count as failures); `go` counts `--- PASS:` and `--- FAIL:` lines.
/// Any other runner counts nothing: it reports through the facts file.
#[must_use]
pub fn count_assertions(runner: &Runner, output: &str) -> Assertions {
    let sum = |lines: &mut dyn Iterator<Item = &str>| {
        lines.fold(Assertions::default(), |acc, line| Assertions {
            passed: acc.passed + count_before(line, "passed"),
            failed: acc.failed + count_before(line, "failed"),
        })
    };
    match runner {
        Runner::Cargo => sum(&mut output
            .lines()
            .filter(|l| l.trim_start().starts_with("test result:"))),
        Runner::Blue => sum(&mut output.lines().filter(|l| l.contains(" test(s): "))),
        Runner::Pytest => output
            .lines()
            .rev()
            .find(|l| l.contains(" passed") || l.contains(" failed") || l.contains(" error"))
            .map(|line| Assertions {
                passed: count_before(line, "passed"),
                failed: count_before(line, "failed")
                    + count_before(line, "error")
                    + count_before(line, "errors"),
            })
            .unwrap_or_default(),
        Runner::Go => {
            let count = |tag: &str| {
                output
                    .lines()
                    .filter(|l| l.trim_start().starts_with(tag))
                    .count() as u64
            };
            Assertions {
                passed: count("--- PASS:"),
                failed: count("--- FAIL:"),
            }
        }
        Runner::Other(_) => Assertions::default(),
    }
}

fn count_before(line: &str, word: &str) -> u64 {
    let tokens: Vec<&str> = line
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '.' | '='))
        .filter(|t| !t.is_empty())
        .collect();
    tokens
        .windows(2)
        .filter(|w| w[1] == word)
        .filter_map(|w| w[0].parse::<u64>().ok())
        .sum()
}

/// Everything a receipt needs that the run directory does not hold.
#[derive(Clone, Debug)]
pub struct ReceiptRequest {
    /// The controls the run evidences.
    pub controls: Vec<ControlId>,
    /// The target.
    pub target: Target,
    /// The test.
    pub test: TestRef,
    /// The derivation the run happened in.
    pub derivation: DrvPath,
    /// The nix system.
    pub system: String,
}

/// Read a run directory and write its receipt.
///
/// The verdict is `PASS` only when the command started, exited 0 and no
/// assertion failed; counts come from the facts file when it has them, else
/// from the logs.
///
/// # Errors
///
/// Returns an error when the run directory is unreadable or malformed, or the
/// receipt breaks a rule ([`Receipt::new`]).
pub fn receipt_from_run(run_dir: &Path, request: ReceiptRequest) -> Result<Receipt> {
    let record: RunRecord = parse_json(&run_dir.join(RUN_FILE), "run record")?;
    let stdout = std::fs::read(run_dir.join(STDOUT_FILE))?;
    let stderr = std::fs::read(run_dir.join(STDERR_FILE))?;
    let facts_path = run_dir.join(FACTS_FILE);
    let facts: RunFacts = if facts_path.exists() {
        parse_json(&facts_path, "facts")?
    } else {
        RunFacts::default()
    };
    let mut output = stdout.clone();
    output.extend_from_slice(&stderr);
    let assertions = facts.assertions.unwrap_or_else(|| {
        count_assertions(&request.test.runner, &String::from_utf8_lossy(&output))
    });
    let clean_exit = record.spawn_error.is_none() && record.exit_code == Some(0);
    let status = if clean_exit && assertions.failed == 0 {
        Status::Pass
    } else {
        Status::Fail
    };
    Receipt::new(ReceiptParts {
        schema: ReceiptSchema,
        controls: request.controls,
        target: request.target,
        test: request.test,
        status,
        assertions,
        steps: facts.steps,
        frame: facts.frame,
        output_digest: B3(Blake3Hash::digest(&output)),
        sandbox: Sandbox {
            derivation: request.derivation,
            network: record.network,
            system: request.system,
        },
    })
}

fn parse_json<T: for<'de> Deserialize<'de>>(path: &PathBuf, what: &str) -> Result<T> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| TameshiError::InvalidInput(format!("{what} {} refused: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::TargetKind;

    #[test]
    fn cargo_counts_sum_every_result_line() {
        let out = "running 2 tests\n\
            test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\
            test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n";
        assert_eq!(
            count_assertions(&Runner::Cargo, out),
            Assertions {
                passed: 3,
                failed: 1
            }
        );
    }

    #[test]
    fn pytest_counts_read_the_summary_line() {
        let out = "x.py ..F\n==== 2 passed, 1 failed, 1 error in 0.12s ====\n";
        assert_eq!(
            count_assertions(&Runner::Pytest, out),
            Assertions {
                passed: 2,
                failed: 2
            }
        );
    }

    #[test]
    fn go_counts_pass_and_fail_lines() {
        let out = "=== RUN T\n--- PASS: TestA (0.00s)\n    --- PASS: TestA/sub (0.00s)\n--- FAIL: TestB (0.00s)\nFAIL\n";
        assert_eq!(
            count_assertions(&Runner::Go, out),
            Assertions {
                passed: 2,
                failed: 1
            }
        );
    }

    #[test]
    fn blue_counts_its_tally_lines() {
        let out = "a.b: 4 test(s): 4 passed, 0 failed\nb.b: 2 test(s): 1 passed, 1 failed\n";
        assert_eq!(
            count_assertions(&Runner::Blue, out),
            Assertions {
                passed: 5,
                failed: 1
            }
        );
    }

    #[test]
    fn an_unknown_runner_counts_nothing_and_empty_output_counts_nothing() {
        let other = Runner::Other("jest".to_string());
        assert_eq!(count_assertions(&other, "3 passed"), Assertions::default());
        assert_eq!(count_assertions(&Runner::Cargo, ""), Assertions::default());
    }

    fn request() -> ReceiptRequest {
        ReceiptRequest {
            controls: vec![ControlId::new("NIST_SP_800_53R5_SA_11").unwrap()],
            target: Target {
                kind: TargetKind::NixOutput,
                hash: B3(Blake3Hash::digest(b"t")),
            },
            test: TestRef {
                runner: Runner::Cargo,
                hash: B3(Blake3Hash::digest(b"x")),
            },
            derivation: DrvPath::new("/nix/store/aaaa-run.drv").unwrap(),
            system: "aarch64-darwin".to_string(),
        }
    }

    fn run_in(dir: &Path, argv: &[&str]) -> RunRecord {
        let argv: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
        let work = dir.join("work");
        std::fs::create_dir_all(&work).unwrap();
        run_command(&argv, &work, &dir.join("out"), true).unwrap()
    }

    #[test]
    fn a_red_command_is_recorded_not_raised_and_reads_as_fail() {
        let dir = tempfile::tempdir().unwrap();
        let record = run_in(
            dir.path(),
            &[
                "/bin/sh",
                "-c",
                "echo 'test result: FAILED. 0 passed; 1 failed;'; exit 101",
            ],
        );
        assert_eq!(record.exit_code, Some(101));
        let receipt = receipt_from_run(&dir.path().join("out"), request()).unwrap();
        assert_eq!(receipt.status(), Status::Fail);
        assert_eq!(
            receipt.assertions(),
            Assertions {
                passed: 0,
                failed: 1
            }
        );
    }

    #[test]
    fn a_missing_program_is_a_fail_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let record = run_in(dir.path(), &["/nonexistent/tameshi-no-such-program"]);
        assert!(record.spawn_error.is_some());
        let receipt = receipt_from_run(&dir.path().join("out"), request()).unwrap();
        assert_eq!(receipt.status(), Status::Fail);
    }

    #[test]
    fn facts_override_log_counts_and_carry_steps_and_frame() {
        let dir = tempfile::tempdir().unwrap();
        run_in(
            dir.path(),
            &[
                "/bin/sh",
                "-c",
                r#"printf '{"assertions":{"passed":7,"failed":0},"steps":12,"frame":{"granted":["clock"],"withheld":[],"host_io":1}}' > "$TAMESHI_FACTS""#,
            ],
        );
        let receipt = receipt_from_run(&dir.path().join("out"), request()).unwrap();
        assert_eq!(receipt.status(), Status::Pass);
        assert_eq!(receipt.assertions().passed, 7);
        assert_eq!(receipt.parts().steps, Some(12));
        assert_eq!(
            receipt.parts().frame.as_ref().unwrap().granted,
            vec!["clock"]
        );
    }
}
