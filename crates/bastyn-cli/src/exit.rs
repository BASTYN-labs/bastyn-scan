//! Exit codes.
//!
//! These are the CLI's contract with CI systems and pre-commit hooks, so a
//! caller can gate on a scan without parsing the report.
//!
//! An execution error outranks findings: if the scan could not complete, the
//! caller must not read a `1` and conclude the code merely has issues.

use std::process::ExitCode;

/// Nothing to act on at or above the configured threshold.
pub(crate) const CLEAN: u8 = 0;

/// Findings at or above the configured threshold.
pub(crate) const FINDINGS: u8 = 1;

/// The scan could not complete: bad input, unreadable tree, or I/O failure.
///
/// `2` is also what `clap` uses for invalid usage, which belongs in the same
/// bucket — in both cases the scan never ran.
pub(crate) const EXECUTION_ERROR: u8 = 2;

/// The code as the process reports it.
///
/// Plain `u8` above rather than `ExitCode`, because the scan report prints the
/// exit status it is about to finish with and a printed status that can
/// disagree with `$?` is worse than none. One set of numbers, read twice.
pub(crate) fn code(value: u8) -> ExitCode {
    ExitCode::from(value)
}
