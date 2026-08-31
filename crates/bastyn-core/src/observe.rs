//! Progress reporting.
//!
//! The engine announces what it is doing so a caller can show progress. It
//! deliberately knows nothing about terminals, spinners, or colour — those are
//! the CLI's business, and the engine must behave identically whether or not
//! anyone is watching.
//!
//! Phase names describe what actually runs. A phase must never be announced
//! for work the scan did not do: a user who sees "classifying prompts" and gets
//! no injection findings will reasonably conclude none exist.

use std::fmt::Write as _;

use crate::finding::Finding;

/// A step in the scan.
///
/// These are sequential and non-overlapping, which is a correctness property
/// rather than a presentation one. An earlier version modelled parsing, rule
/// matching and MCP inspection as three phases, but one pass over the tree does
/// all three per file, so they all started and finished together and a caller
/// could not tell which produced a given finding — findings appeared under
/// "Walking the tree". One phase per genuinely sequential stage means
/// attribution is right by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Phase {
    /// Walking the tree to decide what to read.
    Walking,
    /// Reading and analysing files: tree-sitter parsing, `ast-grep` rule
    /// matching, and MCP manifest inspection, in one pass.
    Analysing {
        /// How many files will be read.
        files: usize,
        /// How many rules are loaded.
        rules: usize,
        /// How many MCP configuration files were found.
        mcp_configs: usize,
    },
    /// Looking dependencies up against OSV.
    Cve {
        /// How many resolved dependencies will be queried.
        dependencies: usize,
    },
    /// Assembling the report.
    Reporting,
}

impl Phase {
    /// A short, present-tense label naming what this phase does.
    ///
    /// Truthful by construction: each label names the real tool or data source,
    /// so the terminal cannot advertise an engine that did not run.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Walking => "Walking the tree".to_owned(),
            Self::Analysing {
                files,
                rules,
                mcp_configs,
            } => {
                let mut label = format!(
                    "Analysing code (tree-sitter, ast-grep) \u{2014} {files} files, {rules} rules"
                );
                if *mcp_configs > 0 {
                    let _ = write!(label, ", {mcp_configs} MCP configs");
                }
                label
            }
            Self::Cve { dependencies: 0 } => {
                "Checking dependencies (OSV) \u{2014} none resolved".to_owned()
            }
            Self::Cve { dependencies } => {
                format!("Checking dependencies (OSV) \u{2014} {dependencies} dependencies")
            }
            Self::Reporting => "Assembling the report".to_owned(),
        }
    }
}

/// Receives progress events during a scan.
///
/// Every method has a default no-op body, so an implementor only overrides
/// what it cares about, and the engine can call freely without a `None` check.
pub trait Observer {
    /// A phase is about to run.
    fn phase_started(&self, phase: &Phase) {
        let _ = phase;
    }

    /// A phase finished.
    fn phase_finished(&self, phase: &Phase) {
        let _ = phase;
    }

    /// A finding was produced. Called as findings are discovered, before
    /// deduplication and sorting, so a caller can show progress but must not
    /// treat these as the final result.
    fn found(&self, finding: &Finding) {
        let _ = finding;
    }
}

/// An [`Observer`] that discards everything. The default when nobody is
/// watching.
#[derive(Debug, Clone, Copy, Default)]
pub struct Silent;

impl Observer for Silent {}
