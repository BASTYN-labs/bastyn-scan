//! The release gate: measures the engine's precision and recall against
//! `tests/corpus/expected.toml` rather than asserting either in prose. See
//! `tests/corpus/FORMAT.md` for the manifest contract this file implements.
//!
//! The corpus is scanned exactly once, as a whole, with `tests/corpus` as the
//! scan root. `Finding::location.file` is therefore already relative to
//! `tests/corpus`, which is exactly how `expected.toml` paths are written —
//! no rebasing is needed, and matching is a direct string comparison
//! (forward-slash-normalised, since the manifest is always written with `/`).
//!
//! The corpus content (`tests/corpus/vulnerable/**`, `tests/corpus/clean/**`)
//! is owned and written by a different task and may not exist yet, or may
//! exist only partially, in any given worktree. Rather than fail on that,
//! every `[[expect]]` entry whose file is not yet present on disk is treated
//! as "pending" and printed, not counted as a recall failure. Once the real
//! file lands, the entry starts being checked automatically — nothing in
//! this file needs to change.

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::path::{Path, PathBuf};

use bastyn_core::{Category, Finding, Kind, ScanOptions, Severity, scan};
use serde::Deserialize;

/// The corpus manifest: what Bastyn is expected to find, not find, and known
/// to miss. `deny_unknown_fields` makes a typo'd field a parse error instead
/// of a silently ignored expectation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    #[serde(default, rename = "expect")]
    expect: Vec<Expect>,
    #[serde(default, rename = "expect_none")]
    expect_none: Vec<ExpectNone>,
    #[serde(default, rename = "known_gap")]
    known_gap: Vec<KnownGap>,
    #[serde(default, rename = "known_false_positive")]
    known_false_positive: Vec<KnownFalsePositive>,
}

/// A finding the engine must produce.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    file: String,
    line: usize,
    #[serde(default)]
    rule: Option<String>,
    category: Category,
    kind: Kind,
    severity: Severity,
    why: String,
}

/// A file the engine must not produce any finding for.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectNone {
    file: String,
    why: String,
}

/// A known miss. Does not fail the build, but is printed every run, and is
/// promoted loudly if it starts matching.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnownGap {
    file: String,
    line: usize,
    category: Category,
    why: String,
    /// True when the only reason this is not detected is that the gate runs
    /// offline.
    ///
    /// These are not blind spots. `BAS-CVE-001` finds them the moment it can
    /// reach OSV; the gate refuses to depend on the network so CI stays
    /// deterministic. Counting them alongside genuine detection gaps would
    /// make the headline number claim we cannot find things we can.
    #[serde(default)]
    requires_network: bool,
}

/// A known false positive: the engine reports a finding here and provably
/// should not, but the exclusion cannot currently be expressed precisely.
///
/// This is the mirror image of `KnownGap`, not a variant of it. A
/// `known_gap` is a recall debt: a real defect the engine misses, and
/// `find_promotable` watches for it starting to match so it can be
/// promoted to `[[expect]]`. A `known_false_positive` is a precision debt:
/// a safe call the engine wrongly flags, where "the finding now exists"
/// is the *expected*, unchanged state, not something to promote. Keeping
/// these as one `known_gap` list made the gate print "promote to
/// [[expect]]" for entries where doing so would assert that provably-safe
/// code is a defect -- see tests/corpus/expected.toml's comment on
/// `eval_guarded_by_local_check.py` for the concrete case that forced this
/// split.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnownFalsePositive {
    file: String,
    line: usize,
    category: Category,
    why: String,
}

/// Genuine detection gaps today — entries the engine could not find even with
/// a network connection. This number must only ever go down.
///
/// Raising it means we shipped a rule that stopped working, or admitted a new
/// blind spot without fixing it. Either needs a human decision, not a silent
/// constant bump.
///
/// Entries marked `requires_network` are excluded: they are measurement limits
/// of an offline gate, not things the scanner cannot detect.
const MAX_KNOWN_GAPS: usize = 12;
// Lowered from 14 to 12 on 2026-08-28: the two eval_guarded_by_local_check.py
// entries moved out to `known_false_positive` (see MAX_KNOWN_FALSE_POSITIVES
// below). They were counted here since the "Admitted, +2" entry below, but
// they were never recall gaps -- BAS-LLM10-004 does not miss anything on
// that file, it over-reports on code that is provably safe. Counting a
// precision problem inside a recall-gap ceiling made `corpus_gate` print
// "promote to [[expect]]" for both every run, which would have asserted
// safe code is a defect had anyone followed the suggestion.
//
// 15 on 2026-08-28 morning, then two independent changes landed together:
// three gaps closed (-3) and two admitted (+2), giving 14.
//
// Closed, -3:
// Lowered from 15 to 12 on 2026-08-28: three JS/TS category gaps closed by
// adding the twins Python already had and JS/TS entirely lacked --
// BAS-LLM08-002 (secret in a prompt template), BAS-LLM06-002 (LLM call with
// no token ceiling), and BAS-ZT2-002 (wildcard tool grant). All three
// existing known_gap entries move to [[expect]] unchanged except line
// numbers where the shipped rule's actual match position differed from the
// pre-rule guess (BAS-LLM08-002 reports the `export const ... =` line, not
// the string's own line one below it). ZT2 in particular had defeated an
// earlier attempt: an ungated `$FN($$$PRE, "*")` is not a tool-grant
// pattern, it is "any call whose last argument is the string *", and
// matched CORS headers and route wildcards across the 65-repo measurement
// corpus. Gating FN on the same tool|agent substring the call's own name
// already carries (a structural fact about the function, not a guess about
// the value) closed the gap with zero of that noise.
//
// Admitted, +2 (later corrected -- see the 14-to-12 entry above):
// Raised from 15 to 17 on 2026-08-28, admitting what looked at the time like
// the one deliberate exception this constant's own doc comment allows: two
// known_gap entries were added for
// vulnerable/real_misses/eval_guarded_by_local_check.py, both false
// positives BAS-LLM10-004 cannot avoid without seeing a sibling statement
// (a prior assignment or guard clause) that this engine's `none:`/`inside:`
// have no way to reach -- see that file's docstring and bastyn.yml's comment
// on BAS-LLM10-004 for the full investigation. These run in the *opposite*
// direction from every other entry counted here: a precision gap (the rule
// over-triggers and cannot be told not to) rather than a recall gap (the
// rule misses a real defect). Recorded rather than papered over with an
// approximate `none:` pattern that would risk silently swallowing a real
// unvalidated eval() elsewhere. Filing them as `known_gap` was itself the
// mistake this comment thread describes admitting -- see the 14-to-12 entry
// above for where that got fixed.
// Lowered from 16 to 15 on 2026-08-28, on merging the routing fix with the
// dead-rule triage. Both branches independently promoted a gap on
// llm10_eval_on_model_reply.ts:40 and each expected its own rule to be the
// one that caught it. Only one rule survives: dropping the name gate made
// BAS-LLM10-005 fire, and it reaches .ts because JavaScript rules now compile
// against the TypeScript grammar. Its TypeScript twin was a byte-identical
// duplicate and is gone, so the expectation names BAS-LLM10-005.
// Lowered from 17 to 16 on 2026-08-28: vulnerable/zt4_no_delimiter.ts is now
// caught. Nothing about the rule changed. `language: javascript` rules were
// only ever compiled into the JavaScript bucket, so a `.ts` file was scanned
// by whichever rules happened to be declared `typescript` and silently skipped
// the rest. BAS-ZT4-003 had been correct the whole time and simply never ran
// on that file. Fixing the dispatch also made the two `language: typescript`
// rules redundant -- both were byte-identical copies of a JavaScript rule --
// so they were deleted, and the ZT1 credential expectation now names
// BAS-ZT1-003 rather than its removed duplicate.
//
// Lowered from 17 to 16 on 2026-08-28. Two gaps closed, one admitted:
//
//   - closed: `llm10_eval_on_model_reply.ts:40`. BAS-LLM10-008 dropped the
//     response/reply/... name gate on eval()'s argument. That gate was
//     measured, not guessed — across 65 real third-party repositories the
//     name-gated JS/TS eval rules never fired once, because real code names
//     the variable for what the value is (`expression`, `resolved`).
//   - closed: `llm03_excessive_agency.js:22`. BAS-LLM03-002 used to require
//     a `name:` property inside the SDK's tool({...}) call. That property
//     does not exist in the API it names; the tool's name is the binding.
//   - admitted: `llm03_excessive_agency.js:52`, the other binding shape (a
//     property key in a tools object), which ast-grep's JS `Pattern` cannot
//     express without matching approximately. See that entry for the
//     measurement.
//
// Raised from 7 to 17 on 2026-08-27, deliberately.
//
// TypeScript and JavaScript support landed, and with it a TS/JS corpus written
// against real LangChain.js, Vercel AI SDK and MCP SDK code. Of 11
// TS/JS instances, the new rules catch one. That is not a regression — none of
// it was detectable at all yesterday — but it is an honest admission that the
// engine now reads two more languages far better than the rules understand
// them.
//
// The cause is the same one the Python side already showed: metavariable
// keyword regexes do not survive real code. Real developers write
// `runbookText`, `suggestion` and `assistantNote`, not `llmResponse`.
// Raised from 5 to 7 on 2026-08-27, deliberately, with the reason recorded here
// because the constant exists to make exactly this visible:
//
// Scanning a real production application found two shapes the corpus did not
// cover — a system prompt override with three interpolations, and an
// uppercase-and-dashes admin token in a dict literal. Neither is a regression;
// both are blind spots that already existed and that the corpus was not yet
// honest enough to show. Adding them here is the corpus getting more truthful,
// not the scanner getting worse.
//
// The lesson worth keeping: a corpus written alongside the rules only tests
// what the rules already do. Both of these came from pointing the binary at
// code nobody wrote for it.

/// Known false positives today -- cases where a rule reports a finding that
/// is provably not a defect, and the exclusion cannot currently be expressed
/// precisely. This number must only ever go down, exactly like
/// `MAX_KNOWN_GAPS`, but it is tracked as its own ceiling rather than folded
/// into that one.
///
/// A recall gap and a precision gap are different debts, and conflating them
/// hides one inside the other's number: a reviewer asking "how many real
/// defects do we still miss" should not have that inflated by findings we
/// already know are spurious, and a reviewer asking "how noisy is this tool"
/// should not have that hidden inside the miss count. They also fail in
/// opposite directions, which is what actually forced the split -- treating
/// a known false positive as a `known_gap` makes `find_promotable` recommend
/// moving it to `[[expect]]` the moment the (already-present) finding is
/// observed, which for a false positive means asserting that safe code is a
/// defect.
///
/// Raising it means a rule started over-triggering on a new case that
/// cannot currently be excluded precisely -- that needs a human decision in
/// the PR description, not a silent bump, exactly like `MAX_KNOWN_GAPS`.
const MAX_KNOWN_FALSE_POSITIVES: usize = 2;
// 2 on 2026-08-28: split out of MAX_KNOWN_GAPS (see that constant's 14-to-12
// history entry). Both entries are BAS-LLM10-004 flagging an eval()/exec()
// call whose argument a human can see is safe by reading a sibling
// statement -- a prior assignment or guard clause -- that this engine's
// `none:` (same-node only) and `inside:` (ancestors only) cannot reach. See
// vulnerable/real_misses/eval_guarded_by_local_check.py's docstring and
// bastyn.yml's comment on BAS-LLM10-004 for the investigation.

/// `crates/bastyn-core` -> `tests/corpus`.
fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus")
}

/// Load and parse the manifest. `Ok(None)` means "not there yet, skip
/// cleanly"; `Err` means it exists but does not parse, which fails the build.
fn load_manifest(root: &Path) -> Result<Option<Manifest>, String> {
    let path = root.join("expected.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };
    toml::from_str(&text)
        .map(Some)
        .map_err(|source| format!("{} does not parse: {source}", path.display()))
}

/// Forward-slash-normalised comparison between a finding's location and a
/// manifest-written path, since the manifest is always written with `/`.
fn same_path(finding_file: &Path, manifest_file: &str) -> bool {
    finding_file.to_string_lossy().replace('\\', "/") == manifest_file
}

/// Whether `finding` satisfies one `[[expect]]` or `[[known_gap]]` location:
/// same file, same line, a matching category, and — when the entry names one
/// — the same rule. An entry with no `rule` accepts any rule that maps to the
/// right category at that line.
fn matches(
    finding: &Finding,
    file: &str,
    line: usize,
    category: Category,
    rule: Option<&str>,
) -> bool {
    same_path(&finding.location.file, file)
        && finding.location.line == line
        && finding.categories.contains(&category)
        && rule.is_none_or(|wanted| finding.rule_id == wanted)
}

/// A percentage, or `None` when there is nothing to divide by — not a
/// failure, just nothing measured yet.
#[expect(
    clippy::cast_precision_loss,
    reason = "corpus counts are a handful of manifest entries, far under f64's 52-bit mantissa"
)]
fn percentage(numerator: usize, denominator: usize) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64 * 100.0)
    }
}

fn format_percentage(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |pct| format!("{pct:.0}%"))
}

/// One `[[expect]]` entry, resolved against the scan.
enum ExpectOutcome<'a> {
    /// The referenced file is not on disk yet.
    Pending(&'a Expect),
    /// The file exists and a finding matched.
    Matched,
    /// The file exists and nothing matched: a recall failure.
    Missing(&'a Expect),
}

fn resolve_expect<'a>(root: &Path, entry: &'a Expect, findings: &[Finding]) -> ExpectOutcome<'a> {
    if !root.join(&entry.file).exists() {
        return ExpectOutcome::Pending(entry);
    }
    let found = findings.iter().any(|finding| {
        matches(
            finding,
            &entry.file,
            entry.line,
            entry.category,
            entry.rule.as_deref(),
        )
    });
    if found {
        ExpectOutcome::Matched
    } else {
        ExpectOutcome::Missing(entry)
    }
}

/// The `[[expect]]` list, resolved against one scan.
#[derive(Default)]
struct ExpectSummary<'a> {
    /// Entries whose file exists on disk (whether matched or not).
    ready: usize,
    /// Ready entries with a matching finding.
    matched: usize,
    /// Entries whose file is not on disk yet.
    pending: Vec<&'a Expect>,
    /// Ready entries with no matching finding: a recall failure.
    missing: Vec<&'a Expect>,
}

fn resolve_expects<'a>(
    root: &Path,
    expect: &'a [Expect],
    findings: &[Finding],
) -> ExpectSummary<'a> {
    let mut summary = ExpectSummary::default();
    for entry in expect {
        match resolve_expect(root, entry, findings) {
            ExpectOutcome::Pending(entry) => summary.pending.push(entry),
            ExpectOutcome::Matched => {
                summary.matched += 1;
                summary.ready += 1;
            }
            ExpectOutcome::Missing(entry) => {
                summary.ready += 1;
                summary.missing.push(entry);
            }
        }
    }
    summary
}

/// A finding inside a file that `[[expect_none]]` says must be clean.
struct Violation<'a> {
    entry: &'a ExpectNone,
    finding: &'a Finding,
}

fn find_violations<'a>(
    expect_none: &'a [ExpectNone],
    findings: &'a [Finding],
) -> Vec<Violation<'a>> {
    let mut violations = Vec::new();
    for entry in expect_none {
        for finding in findings {
            if same_path(&finding.location.file, &entry.file) {
                violations.push(Violation { entry, finding });
            }
        }
    }
    violations
}

/// Gaps that now have a matching finding and should be promoted to
/// `[[expect]]`.
fn find_promotable<'a>(known_gaps: &'a [KnownGap], findings: &[Finding]) -> Vec<&'a KnownGap> {
    known_gaps
        .iter()
        .filter(|gap| {
            findings
                .iter()
                .any(|finding| matches(finding, &gap.file, gap.line, gap.category, None))
        })
        .collect()
}

/// `known_false_positive` entries whose finding no longer appears in the
/// scan. Unlike `find_promotable`, a match here is the *expected* steady
/// state (the entry claims the scanner still over-reports at this
/// location); it is the absence of a match that is news. That absence means
/// the rule stopped over-triggering there, which is good, but leaves the
/// entry describing something the scanner no longer does -- surfaced so the
/// manifest does not quietly go stale.
fn find_resolved_false_positives<'a>(
    entries: &'a [KnownFalsePositive],
    findings: &[Finding],
) -> Vec<&'a KnownFalsePositive> {
    entries
        .iter()
        .filter(|entry| {
            !findings
                .iter()
                .any(|finding| matches(finding, &entry.file, entry.line, entry.category, None))
        })
        .collect()
}

/// The report `FORMAT.md` specifies, plus a note when the corpus is not
/// fully written yet. Always printed, pass or fail.
fn print_summary(
    summary: &ExpectSummary<'_>,
    unexpected: usize,
    gaps: GapCounts,
    false_positives: usize,
) {
    let pending = summary.pending.len();
    if summary.ready == 0 && pending > 0 {
        println!(
            "corpus: 0/0 planted defects found   (n/a — {pending} pending, corpus not yet written)"
        );
    } else {
        println!(
            "corpus: {}/{} planted defects found   (found {})",
            summary.matched,
            summary.ready,
            format_percentage(percentage(summary.matched, summary.ready))
        );
    }
    println!(
        "        {unexpected} unexpected finding{}             (precision {})",
        if unexpected == 1 { "" } else { "s" },
        format_percentage(percentage(summary.matched, summary.matched + unexpected)),
    );
    println!(
        "        {} known gap{}{}",
        gaps.real,
        if gaps.real == 1 { "" } else { "s" },
        if gaps.network == 0 {
            String::new()
        } else {
            format!(
                " (+{} reachable only with a network connection)",
                gaps.network
            )
        }
    );
    println!(
        "        {} known false positive{} (precision debt -- tracked separately from known gaps, see MAX_KNOWN_FALSE_POSITIVES)",
        false_positives,
        if false_positives == 1 { "" } else { "s" },
    );
}

fn print_pending(pending: &[&Expect]) {
    if pending.is_empty() {
        return;
    }
    println!("\npending (corpus file not present yet):");
    for entry in pending {
        println!(
            "  {}:{} [{}] {}",
            entry.file, entry.line, entry.category, entry.why
        );
    }
}

fn print_known_gaps(known_gap: &[KnownGap]) {
    println!("\nknown gaps:");
    for gap in known_gap {
        println!("  {}:{} [{}] {}", gap.file, gap.line, gap.category, gap.why);
    }
}

fn print_promotable(promotable: &[&KnownGap]) {
    if promotable.is_empty() {
        return;
    }
    println!(
        "\n*** {} known gap(s) now produce a matching finding — promote to [[expect]]: ***",
        promotable.len()
    );
    for gap in promotable {
        println!(
            "  {}:{} [{}] {} — move this entry from [[known_gap]] to [[expect]] in tests/corpus/expected.toml",
            gap.file, gap.line, gap.category, gap.why
        );
    }
}

fn print_known_false_positives(entries: &[KnownFalsePositive]) {
    if entries.is_empty() {
        return;
    }
    println!(
        "\nknown false positives (precision debt -- the scanner reports these and provably should not):"
    );
    for entry in entries {
        println!(
            "  {}:{} [{}] {}",
            entry.file, entry.line, entry.category, entry.why
        );
    }
}

/// The mirror of `print_promotable`: entries whose finding has stopped
/// appearing, which is good news but leaves the manifest entry stale.
/// Printed, never a build failure -- the same treatment `print_promotable`
/// gives a closed `known_gap`.
fn print_resolved_false_positives(resolved: &[&KnownFalsePositive]) {
    if resolved.is_empty() {
        return;
    }
    println!(
        "\n*** {} known false positive(s) no longer produce a matching finding -- the entry is stale, remove it from tests/corpus/expected.toml: ***",
        resolved.len()
    );
    for entry in resolved {
        println!(
            "  {}:{} [{}] {}",
            entry.file, entry.line, entry.category, entry.why
        );
    }
}

/// Prints the missing `[[expect]]` entries and returns one failure line per
/// entry.
fn print_missing(missing: &[&Expect]) -> Vec<String> {
    if missing.is_empty() {
        return Vec::new();
    }
    println!("\nmissing expectations (recall failure):");
    missing
        .iter()
        .map(|entry| {
            let line = format!(
                "  {}:{} [{}] severity={:?} kind={:?} — {}",
                entry.file, entry.line, entry.category, entry.severity, entry.kind, entry.why
            );
            println!("{line}");
            line
        })
        .collect()
}

/// Prints the unexpected findings and returns one failure line per finding.
fn print_violations(violations: &[Violation<'_>]) -> Vec<String> {
    if violations.is_empty() {
        return Vec::new();
    }
    println!("\nunexpected findings (precision failure):");
    violations
        .iter()
        .map(|violation| {
            let categories = violation
                .finding
                .categories
                .iter()
                .map(|category| category.id())
                .collect::<Vec<_>>()
                .join(",");
            let line = format!(
                "  {}:{} [{categories}] rule={} — {} (expect_none because: {})",
                violation.finding.location.file.display(),
                violation.finding.location.line,
                violation.finding.rule_id,
                violation.finding.title,
                violation.entry.why
            );
            println!("{line}");
            line
        })
        .collect()
}

#[test]
fn corpus_gate() -> Result<(), String> {
    let root = corpus_root();
    if !root.is_dir() {
        println!(
            "corpus_gate: {} is not a directory yet, skipping",
            root.display()
        );
        return Ok(());
    }
    let Some(manifest) = load_manifest(&root)? else {
        println!(
            "corpus_gate: {}/expected.toml not found yet, skipping",
            root.display()
        );
        return Ok(());
    };

    let options = ScanOptions {
        offline: true,
        include_observations: true,
        ..ScanOptions::default()
    };
    let report = scan(&root, &options)
        .map_err(|source| format!("scanning {} failed: {source}", root.display()))?;

    let summary = resolve_expects(&root, &manifest.expect, &report.findings);
    let violations = find_violations(&manifest.expect_none, &report.findings);
    let promotable = find_promotable(&manifest.known_gap, &report.findings);
    let resolved_false_positives =
        find_resolved_false_positives(&manifest.known_false_positive, &report.findings);

    print_summary(
        &summary,
        violations.len(),
        GapCounts::of(&manifest.known_gap),
        manifest.known_false_positive.len(),
    );
    print_pending(&summary.pending);
    print_known_gaps(&manifest.known_gap);
    print_promotable(&promotable);
    print_known_false_positives(&manifest.known_false_positive);
    print_resolved_false_positives(&resolved_false_positives);

    let mut failures = print_missing(&summary.missing);
    failures.extend(print_violations(&violations));

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "corpus gate failed with {} problem(s); see report above",
            failures.len()
        ))
    }
}

/// How the known gaps split between real blind spots and offline-only limits.
#[derive(Debug, Clone, Copy)]
struct GapCounts {
    /// Genuine detection gaps.
    real: usize,
    /// Entries only unreachable because the gate runs offline.
    network: usize,
}

impl GapCounts {
    fn of(gaps: &[KnownGap]) -> Self {
        let network = gaps.iter().filter(|gap| gap.requires_network).count();
        Self {
            real: gaps.len() - network,
            network,
        }
    }
}

/// Guards the known-gap count: it may only ever shrink.
///
/// Lowering `MAX_KNOWN_GAPS` (by fixing a gap and moving its entry to
/// `[[expect]]`) is the goal. Raising it means a rule regressed or a new
/// blind spot was admitted without being fixed — that needs a human decision
/// in the PR description, not a silent constant bump.
#[test]
fn known_gap_count_does_not_grow() -> Result<(), String> {
    let root = corpus_root();
    let Some(manifest) = load_manifest(&root)? else {
        println!("known_gap_count_does_not_grow: manifest not found yet, skipping");
        return Ok(());
    };
    // Only genuine detection gaps count. A `requires_network` entry is a limit
    // of running the gate offline, not something the scanner cannot find.
    let actual = manifest
        .known_gap
        .iter()
        .filter(|gap| !gap.requires_network)
        .count();
    if actual <= MAX_KNOWN_GAPS {
        Ok(())
    } else {
        Err(format!(
            "known_gap count grew from {MAX_KNOWN_GAPS} to {actual} — either a rule regressed \
             or a new gap was admitted without a human decision to raise MAX_KNOWN_GAPS"
        ))
    }
}

/// Guards the known-false-positive count: it may only ever shrink. The
/// precision-debt counterpart to `known_gap_count_does_not_grow` -- see
/// `MAX_KNOWN_FALSE_POSITIVES` for why this is a separate ceiling rather
/// than folded into `MAX_KNOWN_GAPS`.
#[test]
fn known_false_positive_count_does_not_grow() -> Result<(), String> {
    let root = corpus_root();
    let Some(manifest) = load_manifest(&root)? else {
        println!("known_false_positive_count_does_not_grow: manifest not found yet, skipping");
        return Ok(());
    };
    let actual = manifest.known_false_positive.len();
    if actual <= MAX_KNOWN_FALSE_POSITIVES {
        Ok(())
    } else {
        Err(format!(
            "known_false_positive count grew from {MAX_KNOWN_FALSE_POSITIVES} to {actual} — \
             either a rule started over-triggering on a new case or a false positive was \
             admitted without a human decision to raise MAX_KNOWN_FALSE_POSITIVES"
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use bastyn_core::{Confidence, Location};

    use super::*;

    fn finding(rule: &str, file: &str, line: usize, category: Category) -> Finding {
        Finding {
            rule_id: rule.to_owned(),
            title: "test finding".to_owned(),
            kind: Kind::Defect,
            severity: Severity::High,
            confidence: Confidence::High,
            categories: vec![category],
            location: Location {
                file: PathBuf::from(file),
                line,
                column: 1,
            },
            snippet: String::new(),
            description: String::new(),
            remediation: String::new(),
            secondary_rule_ids: Vec::new(),
            references: Vec::new(),
        }
    }

    #[test]
    fn matches_on_file_line_and_category() {
        let f = finding("BAS-LLM10-001", "vulnerable/a.py", 9, Category::Llm10);
        assert!(matches(&f, "vulnerable/a.py", 9, Category::Llm10, None));
    }

    #[test]
    fn a_named_rule_does_not_match_a_different_rule_at_the_same_location() {
        let f = finding("BAS-LLM10-002", "vulnerable/a.py", 9, Category::Llm10);
        assert!(!matches(
            &f,
            "vulnerable/a.py",
            9,
            Category::Llm10,
            Some("BAS-LLM10-001")
        ));
    }

    #[test]
    fn no_rule_named_matches_any_rule_with_the_right_category() {
        let f = finding("BAS-LLM10-002", "vulnerable/a.py", 9, Category::Llm10);
        assert!(matches(&f, "vulnerable/a.py", 9, Category::Llm10, None));
    }

    #[test]
    fn wrong_line_does_not_match() {
        let f = finding("BAS-LLM10-001", "vulnerable/a.py", 9, Category::Llm10);
        assert!(!matches(&f, "vulnerable/a.py", 10, Category::Llm10, None));
    }

    #[test]
    fn unknown_manifest_field_is_a_parse_error() {
        let toml = r#"
            [[expect]]
            file = "a.py"
            line = 1
            category = "LLM10"
            kind = "defect"
            severity = "critical"
            why = "x"
            typo_field = "oops"
        "#;
        let result: Result<Manifest, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn known_manifest_fields_parse() {
        let toml = r#"
            [[expect]]
            file = "a.py"
            line = 1
            category = "LLM10"
            kind = "defect"
            severity = "critical"
            why = "x"
        "#;
        let manifest: Manifest = toml::from_str(toml).unwrap();
        assert_eq!(manifest.expect.len(), 1);
    }

    #[test]
    fn recall_and_precision_arithmetic() {
        // 18/22 recall, 0 unexpected findings out of 18 true positives.
        assert_eq!(percentage(18, 22), Some(18.0 / 22.0 * 100.0));
        assert_eq!(percentage(18, 18), Some(100.0));
    }

    #[test]
    fn zero_expectations_does_not_divide_by_zero() {
        assert_eq!(percentage(0, 0), None);
        assert_eq!(format_percentage(percentage(0, 0)), "n/a");
    }

    #[test]
    fn known_false_positive_field_parses() {
        let toml = r#"
            [[known_false_positive]]
            file     = "vulnerable/real_misses/eval_guarded_by_local_check.py"
            line     = 65
            category = "LLM10"
            why      = "x"
        "#;
        let manifest: Manifest = toml::from_str(toml).unwrap();
        assert_eq!(manifest.known_false_positive.len(), 1);
        assert_eq!(manifest.known_false_positive[0].line, 65);
    }

    #[test]
    fn known_false_positive_unknown_field_is_a_parse_error() {
        let toml = r#"
            [[known_false_positive]]
            file     = "a.py"
            line     = 1
            category = "LLM10"
            why      = "x"
            typo_field = "oops"
        "#;
        let result: Result<Manifest, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    /// A finding that still exists at a `known_false_positive` location must
    /// not be reported as resolved -- it is still the precision debt it
    /// claims to be.
    #[test]
    fn still_reproducing_false_positive_is_not_resolved() {
        let entry = KnownFalsePositive {
            file: "vulnerable/a.py".to_owned(),
            line: 65,
            category: Category::Llm10,
            why: "x".to_owned(),
        };
        let f = finding("BAS-LLM10-004", "vulnerable/a.py", 65, Category::Llm10);
        let resolved = find_resolved_false_positives(std::slice::from_ref(&entry), &[f]);
        assert!(resolved.is_empty());
    }

    /// A `known_false_positive` entry whose finding has stopped appearing is
    /// stale -- the scanner no longer over-triggers there, so the entry
    /// should be surfaced for removal, not silently kept.
    #[test]
    fn no_longer_reproducing_false_positive_is_resolved() {
        let entry = KnownFalsePositive {
            file: "vulnerable/a.py".to_owned(),
            line: 65,
            category: Category::Llm10,
            why: "x".to_owned(),
        };
        let resolved = find_resolved_false_positives(std::slice::from_ref(&entry), &[]);
        assert_eq!(resolved.len(), 1);
    }

    /// `find_promotable` only ever sees `[[known_gap]]` entries -- a
    /// `known_false_positive` cannot be passed to it at all, by type. This
    /// pins the type-level guarantee that the gate can never again suggest
    /// promoting a known false positive to `[[expect]]`.
    #[test]
    fn promotable_gaps_do_not_include_false_positives() {
        let gap = KnownGap {
            file: "vulnerable/a.py".to_owned(),
            line: 9,
            category: Category::Llm10,
            why: "x".to_owned(),
            requires_network: false,
        };
        let f = finding("BAS-LLM10-001", "vulnerable/a.py", 9, Category::Llm10);
        let promotable = find_promotable(std::slice::from_ref(&gap), &[f]);
        assert_eq!(promotable.len(), 1);
        // KnownFalsePositive has no path into find_promotable's input type;
        // this asserts the KnownGap-shaped case behaves as before the split.
    }
}
