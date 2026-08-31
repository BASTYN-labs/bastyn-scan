//! `bastyn scan` — analyse a repository and report what is wrong.

use std::cell::Cell;
use std::io::{BufWriter, IsTerminal as _, Write};

use anyhow::Context as _;
use bastyn_core::render::{CrosswalkDetail, Glyphs, ScanResult, StdoutOptions};
use bastyn_core::{
    Finding, Framework, Observer, Phase, Report, ScanOptions, Severity, WalkOptions, render,
    scan_observed,
};

use crate::cli::{FailOn, Format, GlobalArgs, ScanArgs};
use crate::exit;
use crate::progress::{self, Progress};

/// The outcome of a scan, as far as the exit code is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Nothing at or above the threshold.
    Clean,
    /// Something at or above the threshold.
    Findings,
}

impl Outcome {
    /// The process exit code this outcome produces.
    ///
    /// The report prints this number, and `main` returns it. One function, so
    /// the printed status and `$?` cannot drift apart.
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::Clean => exit::CLEAN,
            Self::Findings => exit::FINDINGS,
        }
    }

    /// How the report states it.
    const fn result(self) -> ScanResult {
        match self {
            Self::Clean => ScanResult::Passed,
            Self::Findings => ScanResult::Failed,
        }
    }
}

/// Run the `scan` subcommand.
pub(crate) fn run(args: &ScanArgs, global: &GlobalArgs) -> anyhow::Result<Outcome> {
    let options = ScanOptions {
        walk: WalkOptions {
            respect_ignore_files: !args.no_ignore,
            include_hidden: args.hidden,
            follow_symlinks: args.follow_symlinks,
            max_depth: args.max_depth,
            excludes: args.exclude.clone(),
        },
        offline: args.offline,
        include_observations: args.show_observations,
    };

    let progress = Progress::start(global);
    let watched = Counts::watching(&progress);

    let mut report = scan_observed(&args.path, &options, &watched)
        .with_context(|| format!("could not scan {}", args.path.display()))?;

    // Grouping is applied to the finished report rather than threaded into the
    // scan: it regroups what was found and changes nothing about what was
    // found, so the engine has no business knowing which view was asked for.
    //
    // Every framework by default, one when `--group-by` names one. A reader
    // who has to remember a flag to see the EU AI Act would also have to
    // remember a second one to see NIST, and whichever they forgot would look
    // like an area with nothing in it. `--group-by` therefore chooses which
    // framework to expand in full, not whether compliance areas appear at all.
    let frameworks: Vec<Framework> = match args.group_by.framework() {
        Some(framework) => vec![framework],
        None => Framework::ALL.to_vec(),
    };
    report.crosswalks = frameworks
        .into_iter()
        .map(|framework| bastyn_core::crosswalk(&report, framework))
        .collect();
    let report = report;

    // Decided before anything is printed, because the report states it: the
    // `RESULT` line and the process exit code are the same fact, and deriving
    // them separately is how they end up disagreeing.
    let outcome = outcome(&report, args.fail_on);

    // Detail level is stated, never inferred from how many crosswalks came
    // out: one framework asked for by name is one the reader wants the
    // findings of, and three they did not ask for are three they want the
    // shape of.
    let crosswalks = if args.group_by.framework().is_some() {
        CrosswalkDetail::Detailed
    } else {
        CrosswalkDetail::Summary
    };

    let terminal = TerminalInputs::gathered(global);
    let (payload, summary) = match global.format {
        Format::Text => {
            let rendered = render::stdout(
                &report,
                StdoutOptions {
                    color: color_decision(terminal),
                    glyphs: glyph_decision(terminal),
                    crosswalks,
                    offline: args.offline,
                    rules: watched.rules.get(),
                    dependencies: watched.dependencies.get(),
                    result: outcome.result(),
                    exit_code: outcome.exit_code(),
                },
            );
            (rendered.text, Some(rendered.summary))
        }
        Format::Json => (
            render::json(&report).context("could not render JSON")?,
            None,
        ),
        Format::Sarif => (
            render::sarif(&report).context("could not render SARIF")?,
            None,
        ),
    };

    // `--quiet` prints the summary the renderer handed back, never a line the
    // caller went looking for by position.
    let payload = match summary.filter(|_| global.quiet) {
        Some(summary) => format!("{summary}\n"),
        None => payload,
    };
    write_out(&payload)?;
    // Only where stdout is not already carrying the verdict — see
    // `progress::summary_enabled`.
    progress::summary(&report, global);

    Ok(outcome)
}

/// An [`Observer`] that forwards to `inner` and keeps the two counts the
/// finished report does not carry.
///
/// The rule count and the resolved-dependency count are facts about the scan
/// that ran, and the report's shape is a published contract that has no field
/// for either. Announcing them is already the engine's job, so this listens
/// rather than asking the engine to say the same thing twice.
///
/// `Cell` rather than an atomic because the engine announces phases from the
/// thread that called it; the parallel pass never touches the observer.
struct Counts<'a> {
    inner: &'a dyn Observer,
    rules: Cell<usize>,
    dependencies: Cell<usize>,
}

impl<'a> Counts<'a> {
    fn watching(inner: &'a dyn Observer) -> Self {
        Self {
            inner,
            rules: Cell::new(0),
            dependencies: Cell::new(0),
        }
    }
}

impl Observer for Counts<'_> {
    fn phase_started(&self, phase: &Phase) {
        match phase {
            Phase::Analysing { rules, .. } => self.rules.set(*rules),
            Phase::Cve { dependencies } => self.dependencies.set(*dependencies),
            _ => {}
        }
        self.inner.phase_started(phase);
    }

    fn phase_finished(&self, phase: &Phase) {
        self.inner.phase_finished(phase);
    }

    fn found(&self, finding: &Finding) {
        self.inner.found(finding);
    }
}

/// Everything the terminal decisions are made from, gathered once.
///
/// One place asks the environment, so colour and glyphs cannot end up
/// disagreeing about what kind of terminal this is, and both decisions stay
/// testable without one.
#[derive(Debug, Clone, Copy)]
struct TerminalInputs {
    no_color_flag: bool,
    no_color_env: bool,
    format: Format,
    stdout_is_tty: bool,
}

impl TerminalInputs {
    fn gathered(global: &GlobalArgs) -> Self {
        Self {
            no_color_flag: global.no_color,
            no_color_env: std::env::var_os("NO_COLOR").is_some(),
            format: global.format,
            stdout_is_tty: std::io::stdout().is_terminal(),
        }
    }
}

/// Whether to emit ANSI colour on the report.
///
/// `--no-color` wins, then `NO_COLOR` as the cross-tool convention, then
/// whether stdout is actually a terminal. The last one matters: `bastyn scan >
/// report.txt` should produce a readable file, not one peppered with escape
/// sequences, and a CI log should not be full of them either.
const fn color_decision(inputs: TerminalInputs) -> bool {
    inputs.stdout_is_tty
        && matches!(inputs.format, Format::Text)
        && !inputs.no_color_flag
        && !inputs.no_color_env
}

/// Whether the report may draw with Unicode.
///
/// A different question from colour, and it turns on a smaller set of inputs.
/// `--no-color` asks for plain text, not for a report that spells its ticks
/// `[ok]`; a terminal that renders colour renders a tick. What Unicode cannot
/// survive is going somewhere that is not a terminal at all — a log file, a CI
/// job's captured output, a pipe — or a `NO_COLOR` that, in practice, is set
/// by people whose terminal is the reason they set it.
const fn glyph_decision(inputs: TerminalInputs) -> Glyphs {
    if inputs.stdout_is_tty && !inputs.no_color_env {
        Glyphs::Unicode
    } else {
        Glyphs::Ascii
    }
}

/// Decide the exit outcome from the report and the threshold.
///
/// Only defects count. An observation must never fail a build — the repository
/// has not shown that the missing control is wrong, so blocking on it is the
/// behaviour that gets a scanner removed from CI.
fn outcome(report: &Report, fail_on: FailOn) -> Outcome {
    let Some(threshold) = threshold(fail_on) else {
        return Outcome::Clean;
    };

    let blocking = report
        .findings
        .iter()
        .filter(|finding| finding.kind == bastyn_core::Kind::Defect)
        .any(|finding| finding.severity >= threshold);

    if blocking {
        Outcome::Findings
    } else {
        Outcome::Clean
    }
}

/// The severity floor for a threshold, or `None` for "never fail".
const fn threshold(fail_on: FailOn) -> Option<Severity> {
    match fail_on {
        FailOn::None => None,
        FailOn::Low => Some(Severity::Low),
        FailOn::Medium => Some(Severity::Medium),
        FailOn::High => Some(Severity::High),
        FailOn::Critical => Some(Severity::Critical),
    }
}

/// Write to stdout, treating a closed downstream pipe as success.
///
/// `bastyn scan | head` is a normal thing to type; the reader disappearing is
/// not a failure of the scan.
fn write_out(payload: &str) -> anyhow::Result<()> {
    let stdout = std::io::stdout().lock();
    let mut out = BufWriter::new(stdout);

    let result = out.write_all(payload.as_bytes()).and_then(|()| out.flush());
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(anyhow::Error::new(error).context("could not write output")),
    }
}

#[cfg(test)]
mod tests {
    use super::{Glyphs, Outcome, TerminalInputs, color_decision, glyph_decision};
    use crate::cli::Format;
    use crate::exit;

    fn tty_text() -> TerminalInputs {
        TerminalInputs {
            no_color_flag: false,
            no_color_env: false,
            format: Format::Text,
            stdout_is_tty: true,
        }
    }

    #[test]
    fn colour_on_a_text_terminal() {
        assert!(color_decision(tty_text()));
    }

    #[test]
    fn no_colour_when_stdout_is_redirected() {
        // `bastyn scan > report.txt` must produce a readable file.
        let inputs = TerminalInputs {
            stdout_is_tty: false,
            ..tty_text()
        };
        assert!(!color_decision(inputs));
    }

    #[test]
    fn no_colour_for_machine_formats() {
        for format in [Format::Json, Format::Sarif] {
            let inputs = TerminalInputs {
                format,
                ..tty_text()
            };
            assert!(!color_decision(inputs), "{format:?} must never be coloured");
        }
    }

    #[test]
    fn no_color_flag_and_env_both_disable_colour() {
        assert!(!color_decision(TerminalInputs {
            no_color_flag: true,
            ..tty_text()
        }));
        assert!(!color_decision(TerminalInputs {
            no_color_env: true,
            ..tty_text()
        }));
    }

    /// A tick and a box-drawing rule survive a real terminal and mangle
    /// everywhere else, so the fallback turns on for everywhere else.
    #[test]
    fn unicode_only_on_a_terminal_that_did_not_ask_to_be_left_alone() {
        assert_eq!(glyph_decision(tty_text()), Glyphs::Unicode);

        assert_eq!(
            glyph_decision(TerminalInputs {
                stdout_is_tty: false,
                ..tty_text()
            }),
            Glyphs::Ascii,
            "a redirect or a CI log must get ASCII"
        );
        assert_eq!(
            glyph_decision(TerminalInputs {
                no_color_env: true,
                ..tty_text()
            }),
            Glyphs::Ascii,
            "NO_COLOR is usually set by someone whose terminal is the reason"
        );
    }

    /// `--no-color` asks for plain text, not for a report that spells its
    /// ticks `[ok]`.
    #[test]
    fn the_no_color_flag_does_not_take_the_glyphs_with_it() {
        let inputs = TerminalInputs {
            no_color_flag: true,
            ..tty_text()
        };
        assert!(!color_decision(inputs));
        assert_eq!(glyph_decision(inputs), Glyphs::Unicode);
    }

    /// The number the report prints is the number the process returns.
    #[test]
    fn the_printed_exit_status_is_the_real_one() {
        assert_eq!(Outcome::Clean.exit_code(), exit::CLEAN);
        assert_eq!(Outcome::Findings.exit_code(), exit::FINDINGS);
        assert_ne!(Outcome::Clean.exit_code(), Outcome::Findings.exit_code());
    }
}
