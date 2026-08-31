//! Recognising machine-generated source from its bytes.
//!
//! A minified bundle cannot produce an actionable finding. It is vendor output
//! nobody in the repository wrote, its identifiers have been renamed to single
//! letters, and its remediation is "rebuild it from the source it came from",
//! which no rule can say. It is also the single most expensive thing a scanner
//! can be handed: one calibration-corpus repository commits seven Next.js
//! bundles under `_next/static/`, three of them 20 MB on effectively one
//! line, and parsing them accounted for two thirds of that repository's scan
//! time and 6.5 GB of its peak memory.
//!
//! # Why a content signal rather than a path blocklist
//!
//! The obvious alternative — skip anything under `dist/`, `build/`, `out/`,
//! `static/` — was measured against the 65-repository calibration corpus on
//! 2026-08-28 and is wrong in both directions:
//!
//! | directory name | source files under it | actually minified |
//! |---|---|---|
//! | `static/` | 417 | 357 |
//! | `_next/` | 399 | 357 |
//! | `dist/` | 34 | 1 |
//! | `assets/` | 21 | 4 |
//! | `public/` | 5 | 0 |
//! | `build/`, `out/`, `generated/`, `vendor/` | 0 | 0 |
//!
//! The 60 non-minified files under `static/` are handwritten browser
//! JavaScript served by a Python web app — `app/static/crabtrading.js`,
//! `backend/static/js/audio-recorder.js`. Fourteen of the files under
//! `assets/` are handwritten Python: `valuecell/adapters/assets/*.py`, one of
//! them 58 KB of market-data adapter. Blocklisting either name hides real,
//! fixable source. Meanwhile the names people reach for first — `build/`,
//! `out/`, `vendor/` — do not occur at all, so a blocklist buys nothing where
//! it is safe and costs coverage exactly where it is not.
//!
//! # The signal
//!
//! Mean line length over a bounded prefix. Minification's defining act is
//! deleting the line structure, so it moves the mean by orders of magnitude,
//! while a single long line — an embedded SVG path, a base64 blob, a generated
//! protobuf descriptor — barely moves it at all. Measured over all 13,721
//! source files in the corpus:
//!
//! - the largest mean for a handwritten file is **298.6 bytes/line**
//!   (`valuecell/frontend/src/mock/agent-data.tsx`);
//! - the smallest mean for a generated file is **548.0 bytes/line**
//!   (a Vite-built `material-extra-theme-TVq-kNRT.js`);
//! - nothing in the corpus falls between the two.
//!
//! [`MINIFIED_MEAN_LINE_BYTES`] sits in that gap. It is placed high in it, not
//! in the middle: a file wrongly skipped is a place a real finding hides,
//! while a bundle wrongly scanned only costs time.
//!
//! # Signals deliberately not used
//!
//! *Maximum* line length is the tempting version of the same idea and is
//! measurably worse: 432 corpus files have a line over 500 bytes and 3 have
//! one over 5,000 while being ordinary source, including a 46 KB handwritten
//! `.tsx` mock with a 20 KB line in it.
//!
//! A `sourceMappingURL` trailer is worse still. Nine corpus files carry one;
//! three of them are Bootstrap's *unminified* distribution, which is readable
//! source at 30 bytes a line and which a rule can say something true about.
//! The trailer marks "this was built", not "this is unreadable", and only the
//! second is a reason to stop looking.
//!
//! A `.min.js` suffix is a real signal but a redundant one: all four corpus
//! files carrying it are already over the mean threshold by a factor of at
//! least 15. Nothing is added by naming it, so it is not named — the detector
//! reads bytes, and every path is judged by the same evidence.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

/// How much of a file is read before the decision is made.
///
/// The whole point is not to touch the other 7.7 MB. This is also the window
/// the decision is made in, and the report says so: a file that is ordinary
/// for its first 64 KiB and minified afterwards is scanned, not skipped.
pub(crate) const PREFIX_BYTES: usize = 64 * 1024;

/// Below this size a file is never judged generated.
///
/// Skipping a sub-kilobyte file saves no measurable time and no memory at all,
/// so the only thing such a judgement can do is be wrong. The smallest
/// genuinely minified file in the corpus is 1,644 bytes, so nothing is lost by
/// declining to guess below 1,024.
const MIN_BYTES: usize = 1024;

/// Mean line length, in bytes, at or above which a prefix is minified.
///
/// Sits in the empty band between 298.6 (largest handwritten mean measured)
/// and 548.0 (smallest generated mean measured). See the module docs.
const MINIFIED_MEAN_LINE_BYTES: usize = 500;

/// A file the scan will not parse because its bytes say it is machine output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Generated {
    /// Mean line length across the inspected prefix, in bytes.
    mean_line_bytes: usize,
    /// How much of the file was inspected, in bytes.
    prefix_bytes: usize,
}

impl Generated {
    /// What was measured, for the report's coverage-gap listing.
    ///
    /// The numbers are there so a reader can disagree with the verdict without
    /// re-deriving it: an exclusion nobody can audit is the thing this whole
    /// module is trying not to become. The word "generated" is not repeated
    /// here — [`crate::report::Skip::generated`] owns that half of the
    /// sentence, so the prose has one home.
    pub(crate) fn measurement(&self) -> String {
        format!(
            "minified, {} bytes per line on average over the first {} bytes",
            self.mean_line_bytes, self.prefix_bytes
        )
    }
}

/// Judge a file on disk without reading all of it.
///
/// Reads at most [`PREFIX_BYTES`], which is the whole point: the decision has
/// to be cheap enough to make before a 7.7 MB bundle is read into memory and
/// handed to a parser. An unreadable file is `None` — being unreadable is
/// reported one step later, by the caller, and under its own true reason.
pub(crate) fn inspect(path: &Path) -> Option<Generated> {
    let file = File::open(path).ok()?;
    let mut prefix = Vec::new();
    file.take(PREFIX_BYTES as u64)
        .read_to_end(&mut prefix)
        .ok()?;
    classify(&prefix)
}

/// Judge a file from a prefix of its bytes.
///
/// `prefix` is the first [`PREFIX_BYTES`] of the file, or the whole file if it
/// is smaller. `None` means "scan it" — the safe answer, and the one every
/// uncertain case gets.
pub(crate) fn classify(prefix: &[u8]) -> Option<Generated> {
    if prefix.len() < MIN_BYTES {
        return None;
    }

    // Bytes that are not text cannot be minified code, whatever their line
    // lengths look like. They are skipped anyway, one step later and as
    // "unreadable" — which is the true reason. Claiming they were generated
    // would be a wrong statement in the report, and the report is the only
    // thing standing between an exclusion and a hiding place.
    if !is_mostly_utf8(prefix) {
        return None;
    }

    // The trailing partial line counts as a whole one. That understates the
    // mean for a truncated prefix, which errs towards scanning.
    let lines = prefix.split(|&byte| byte == b'\n').count();
    let mean_line_bytes = prefix.len() / lines;

    (mean_line_bytes >= MINIFIED_MEAN_LINE_BYTES).then_some(Generated {
        mean_line_bytes,
        prefix_bytes: prefix.len(),
    })
}

/// Whether `prefix` is valid UTF-8, allowing for a multi-byte character cut in
/// half by the prefix boundary.
///
/// `Utf8Error::error_len` is `None` exactly when the input ended mid-character
/// and everything before it was valid, which is the one failure a bounded read
/// can cause by itself.
fn is_mostly_utf8(prefix: &[u8]) -> bool {
    match std::str::from_utf8(prefix) {
        Ok(_) => true,
        Err(error) => error.error_len().is_none(),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    use std::fmt::Write as _;
    use std::fs;

    use tempfile::TempDir;

    /// Exactly `bytes` of plausible minified JavaScript, on one line.
    fn minified_line(bytes: usize) -> String {
        let unit = "function(e,t){return e.n(t)},";
        let mut line = unit.repeat(bytes.div_ceil(unit.len()));
        line.truncate(bytes);
        line
    }

    /// A page of plausible handwritten Python.
    fn handwritten(lines: usize) -> String {
        let mut out = String::new();
        for line in [
            "def advise(question: str) -> str:",
            "    \"\"\"Ask the model and return its reply.\"\"\"",
            "    reply = client.chat.completions.create(messages=[{\"role\": \"user\"}])",
            "    return reply.choices[0].message.content",
            "",
        ]
        .iter()
        .cycle()
        .take(lines)
        {
            let _ = writeln!(out, "{line}");
        }
        out
    }

    #[test]
    fn a_whole_bundle_on_one_line_is_generated() {
        let prefix = minified_line(PREFIX_BYTES);
        let found = classify(prefix.as_bytes()).expect("a 64 KiB single line is minified");
        assert!(
            found.mean_line_bytes >= PREFIX_BYTES,
            "{found:?} should measure the whole prefix as one line"
        );
    }

    #[test]
    fn ordinary_source_is_not_generated() {
        assert_eq!(classify(handwritten(400).as_bytes()), None);
    }

    /// The measured band the threshold sits in. Both numbers come from the
    /// calibration corpus (see the module docs), so a change to
    /// [`MINIFIED_MEAN_LINE_BYTES`] that walks out of that band fails here
    /// rather than in somebody's repository.
    #[test]
    #[expect(
        clippy::assertions_on_constants,
        reason = "the constants are the subject: this test guards the threshold itself"
    )]
    fn the_threshold_stays_inside_the_measured_band() {
        const LARGEST_HANDWRITTEN_MEAN: usize = 299;
        const SMALLEST_GENERATED_MEAN: usize = 548;

        assert!(
            MINIFIED_MEAN_LINE_BYTES > LARGEST_HANDWRITTEN_MEAN,
            "the threshold must sit above every handwritten file measured"
        );
        assert!(
            MINIFIED_MEAN_LINE_BYTES <= SMALLEST_GENERATED_MEAN,
            "the threshold must sit at or below every generated file measured"
        );
    }

    /// The widest handwritten file in the corpus,
    /// `valuecell/frontend/src/mock/agent-data.tsx`: 46,287 bytes over 155
    /// lines, one of which is 20,373 bytes long. Mean 298.6.
    #[test]
    fn the_widest_handwritten_corpus_file_is_scanned() {
        let mut prefix = String::from("export const agentData = [\n");
        for index in 0..153 {
            let _ = writeln!(
                prefix,
                "  {{ id: {index}, name: \"agent {index}\", blurb: \"{}\" }},",
                "lorem ipsum ".repeat(11)
            );
        }
        let _ = writeln!(prefix, "  {{ svg: \"{}\" }},", "M0 0L1 1".repeat(2546));
        prefix.push_str("];\n");

        let lines = prefix.matches('\n').count() + 1;
        let mean = prefix.len() / lines;
        assert!(
            (250..350).contains(&mean),
            "fixture must reproduce the measured shape, got {mean} bytes/line"
        );
        assert_eq!(classify(prefix.as_bytes()), None);
    }

    /// One enormous line does not make a file generated. Three corpus files
    /// have a line over 5,000 bytes while being ordinary source, which is why
    /// the signal is the mean and not the maximum.
    #[test]
    fn a_single_enormous_line_in_ordinary_source_is_not_generated() {
        let mut prefix = handwritten(2000);
        let _ = writeln!(prefix, "SCHEMA = \"{}\"", "x".repeat(20_000));

        assert_eq!(classify(prefix.as_bytes()), None);
    }

    /// Bootstrap ships its unminified distribution with a `sourceMappingURL`
    /// trailer. Three corpus files are exactly that: readable source a rule
    /// can say something true about, at 30 bytes a line.
    #[test]
    fn a_source_map_trailer_alone_does_not_make_a_file_generated() {
        let mut prefix = handwritten(2000);
        prefix.push_str("//# sourceMappingURL=bootstrap.js.map\n");

        assert_eq!(classify(prefix.as_bytes()), None);
    }

    #[test]
    fn a_file_too_small_to_be_worth_skipping_is_scanned() {
        let prefix = minified_line(MIN_BYTES - 1);
        assert!(
            prefix.len() < MIN_BYTES,
            "fixture must stay under the floor"
        );

        assert_eq!(
            classify(prefix.as_bytes()),
            None,
            "skipping a sub-kilobyte file saves nothing and can only be wrong"
        );
    }

    #[test]
    fn binary_content_is_left_for_the_unreadable_path_to_report() {
        // Long "lines" and no text: without the UTF-8 guard this would be
        // reported as generated, which is a false statement about a file that
        // is really just unreadable.
        let prefix: Vec<u8> = (0..8192u32).map(|i| 128 + (i % 100) as u8).collect();
        assert!(!prefix.contains(&b'\n'), "fixture must have no line breaks");

        assert_eq!(classify(&prefix), None);
    }

    #[test]
    fn a_prefix_cut_mid_character_is_still_judged() {
        let mut prefix = minified_line(PREFIX_BYTES - 8).into_bytes();
        // A three-byte character with its tail lopped off, exactly what a
        // bounded read does to a file at the 64 KiB boundary.
        prefix.extend_from_slice("€".as_bytes());
        prefix.pop();

        assert!(
            classify(&prefix).is_some(),
            "a truncated final character must not defeat the detector"
        );
    }

    #[test]
    fn an_empty_prefix_is_scanned() {
        assert_eq!(classify(&[]), None);
    }

    #[test]
    fn inspect_reads_a_bounded_prefix_and_judges_a_file_on_disk() {
        let dir = TempDir::new().unwrap();

        let bundle = dir.path().join("bundle.js");
        // Ten times the prefix, so a verdict that had read the whole file
        // would report a different measurement than one that stopped.
        fs::write(&bundle, minified_line(PREFIX_BYTES * 10)).unwrap();
        let found = inspect(&bundle).expect("a 640 KiB single line is minified");
        assert_eq!(
            found.prefix_bytes, PREFIX_BYTES,
            "the decision must be made from a bounded read, not the whole file"
        );

        let ordinary = dir.path().join("app.py");
        fs::write(&ordinary, handwritten(400)).unwrap();
        assert_eq!(inspect(&ordinary), None);
    }

    #[test]
    fn inspect_leaves_an_unreadable_file_to_be_reported_as_unreadable() {
        let dir = TempDir::new().unwrap();

        assert_eq!(inspect(&dir.path().join("nope.js")), None);
    }

    #[test]
    fn the_reason_names_what_was_measured() {
        let found = classify(minified_line(PREFIX_BYTES).as_bytes()).expect("minified");
        let measurement = found.measurement();
        let skip = crate::report::Skip::generated("web/bundle.js".to_owned(), measurement.clone());

        assert!(measurement.contains("minified"), "{measurement}");
        assert!(
            measurement.contains(&found.mean_line_bytes.to_string()),
            "the report must carry the measurement, not just the verdict: {measurement}"
        );
        assert!(
            measurement.contains(&PREFIX_BYTES.to_string()),
            "{measurement}"
        );
        assert!(
            skip.line().contains("generated"),
            "the verdict must reach the report: {}",
            skip.line()
        );
    }
}
