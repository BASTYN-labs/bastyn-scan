//! End-to-end tests for the terminal progress UI, driving the real binary.
//!
//! `Command::output()` never gives the child a TTY on either stream, so these
//! cannot exercise the live spinner — that is covered by the unit tests in
//! `src/progress.rs`, which drive the suppression predicate and the line
//! renderers directly. What these prove instead is the contract that matters
//! most: progress never leaks a byte into stdout, and every suppression
//! condition really does suppress it, on the real binary.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::path::Path;
use std::process::{Command, Output};

use assert_cmd::prelude::*;
use predicates::prelude::*;

const ESCAPE: char = '\u{1b}';

fn clean_fixture() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/clean_agent"
    ))
}

fn vulnerable_fixture() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/vulnerable_agent"
    ))
}

fn bastyn(cwd: &Path) -> Command {
    let mut command = Command::cargo_bin("bastyn").unwrap();
    command.current_dir(cwd);
    command
}

fn run(cwd: &Path, args: &[&str]) -> Output {
    bastyn(cwd).args(args).output().unwrap()
}

#[test]
fn json_output_has_no_escape_bytes_and_parses() {
    let output = run(
        vulnerable_fixture(),
        &["scan", "--offline", "--format", "json"],
    );
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        !stdout.contains(ESCAPE),
        "progress must never leak into stdout: {stdout:?}"
    );
    let _: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format json must produce valid JSON");
}

#[test]
fn sarif_output_has_no_escape_bytes_and_parses() {
    let output = run(
        vulnerable_fixture(),
        &["scan", "--offline", "--format", "sarif"],
    );
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        !stdout.contains(ESCAPE),
        "progress must never leak into stdout: {stdout:?}"
    );
    let _: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format sarif must produce valid JSON");
}

#[test]
fn a_piped_run_shows_no_progress_on_stderr() {
    // `Command::output()` pipes both streams, so stderr is never a TTY here —
    // this is exactly the case that must produce no spinner and no step
    // lines at all.
    let output = run(clean_fixture(), &["scan", "--offline"]);
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(
        !stderr.contains(ESCAPE),
        "a non-TTY stderr must carry no escape bytes: {stderr:?}"
    );
}

#[test]
fn quiet_produces_no_progress_on_either_stream() {
    let output = run(vulnerable_fixture(), &["scan", "--offline", "--quiet"]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(!stdout.contains(ESCAPE), "stdout: {stdout:?}");
    assert!(!stderr.contains(ESCAPE), "stderr: {stderr:?}");
}

#[test]
fn no_color_produces_no_progress_escapes() {
    let output = run(vulnerable_fixture(), &["scan", "--offline", "--no-color"]);
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(!stderr.contains(ESCAPE), "stderr: {stderr:?}");
}

#[test]
fn no_color_env_produces_no_progress_escapes() {
    let mut command = bastyn(vulnerable_fixture());
    command.env("NO_COLOR", "1");
    command.args(["scan", "--offline"]);
    let output = command.output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(!stderr.contains(ESCAPE), "stderr: {stderr:?}");
}

/// The machine formats render no text report, so the closing summary on stderr
/// is the only thing that tells an interactive user what happened.
///
/// `bastyn scan --format json > out.json` finished in silence once.
#[test]
fn a_machine_format_still_says_what_it_found_on_stderr() {
    for format in ["json", "sarif"] {
        let output = run(
            vulnerable_fixture(),
            &["scan", "--offline", "--format", format],
        );
        let stderr = String::from_utf8(output.stderr).unwrap();

        assert!(
            stderr.contains("defect") && stderr.contains("found"),
            "--format {format} said nothing on stderr: {stderr:?}"
        );
        assert!(
            !stderr.contains(ESCAPE),
            "a piped stderr must stay plain: {stderr:?}"
        );

        // And still not a byte of it in the stream a pipeline parses.
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(!stdout.contains("found ("), "stdout: {stdout:?}");
    }
}

/// A text report that went to a file leaves the terminal with nothing, so the
/// summary speaks there too.
///
/// `Command::output()` pipes stdout, which is exactly that case.
#[test]
fn a_redirected_text_report_still_says_what_it_found_on_stderr() {
    let output = run(vulnerable_fixture(), &["scan", "--offline"]);
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(
        stderr.contains("defect") && stderr.contains("found"),
        "a redirected report left the terminal silent: {stderr:?}"
    );

    let clean = run(clean_fixture(), &["scan", "--offline"]);
    let stderr = String::from_utf8(clean.stderr).unwrap();
    assert!(
        stderr.contains("No defects found"),
        "a clean scan must say so too: {stderr:?}"
    );
}

/// `--quiet` already prints the summary on stdout; a second copy on stderr is
/// what it asked not to have.
#[test]
fn quiet_says_it_once_and_on_stdout() {
    for extra in [vec![], vec!["--format", "json"]] {
        let mut args = vec!["scan", "--offline", "--quiet"];
        args.extend(&extra);
        let output = run(vulnerable_fixture(), &args);
        let stderr = String::from_utf8(output.stderr).unwrap();

        assert!(
            stderr.is_empty(),
            "{extra:?} left something on stderr: {stderr:?}"
        );
    }
}

#[test]
fn a_clean_fixture_exits_zero() {
    bastyn(clean_fixture())
        .args(["scan", "--offline"])
        .assert()
        .code(0);
}

#[test]
fn a_vulnerable_fixture_exits_one() {
    bastyn(vulnerable_fixture())
        .args(["scan", "--offline"])
        .assert()
        .code(1);
}

#[test]
fn a_missing_path_is_an_execution_error() {
    bastyn(clean_fixture())
        .args(["scan", "--offline", "does-not-exist"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("could not scan"));
}
