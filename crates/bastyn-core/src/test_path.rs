//! Recognising files that hold test code rather than shipped code.
//!
//! Measured against 65 real third-party AI repositories on 2026-08-28: the
//! hardcoded-credential rule `BAS-ZT1-002` produced 32 findings, and 23 of
//! them (72%) sat in a path containing "test". Every one of those 23 was a
//! placeholder DSN in a fixture — `user:password@localhost` — and one target
//! repository had already annotated several of them `# pragma: allowlist
//! secret` for its own secret scanner. A credential invented so a test can
//! connect to a throwaway container is not a credential anybody can use, and
//! reporting it as a critical defect is the single largest measured source of
//! false positives the scanner has.
//!
//! # Why the match is exact, not a substring
//!
//! The obvious implementation — "does the path contain `test`" — is what
//! produced the measurement above, and it is wrong in the other direction
//! too: `latest/`, `contest/`, `attestation.py` and `protest/` all contain
//! it. A false *negative* here costs one hidden finding; a false *positive*
//! silently demotes real defects in shipped code, which is far worse. So a
//! directory only counts when a whole path component equals one of
//! [`TEST_DIRECTORIES`], and a file only counts under one of the naming
//! conventions in [`is_test_file_name`]. Both lists are deliberately short:
//! every entry is a name that means "test" and nothing else.
//!
//! `fixtures/` is a deliberate omission. It reads like a test directory but
//! an application can legitimately own one (a `fixtures` module of seed data
//! that ships), and this list errs toward missing a test path rather than
//! claiming one.
//!
//! # Filename-suffix coverage, re-verified 2026-08-28
//!
//! A precision review flagged one calibration-corpus `BAS-ZT1-003` finding
//! -- reported as a defect in a `.spec.ts` file -- as evidence this module
//! matches only path *components* and never a filename *suffix*, missing the
//! dominant JavaScript/TypeScript convention (and, by the same gap, Python's
//! `test_*.py`/`*_test.py`).
//!
//! Re-checked directly against that claim: [`is_test_file_name`] already
//! implements both conventions, and does so correctly on the requested
//! near-misses (`greatest.spec_of_a_thing.ts`, `latest.ts`, `manifest.ts`
//! all stay unmatched). Scanning the full 65-repository corpus with
//! `--show-observations` confirms it end-to-end: every finding from a
//! default-policy (`downgrade`) rule in a `.spec.`/`.test.`/`test_*.py`/
//! `*_test.py` path already reports as `Kind::Observation`. The one
//! exception is exactly the cited `BAS-ZT1-003` finding, and it is not a
//! path-recognition miss: that rule sets `in_test_paths: report`
//! deliberately (a leaked provider key is worth reporting wherever it
//! sits), in the same commit that wrote this file, so its findings report
//! unconditionally regardless of what this module decides. No change was
//! needed here; see `jest_vitest_style_suffixed_paths_from_the_corpus_match`
//! below for the pinned evidence.

use std::path::Path;

/// Directory names that mean "test code" and nothing else.
///
/// Matched against a whole path component, case-insensitively. Nothing here
/// is a plausible name for a directory of shipped application code.
const TEST_DIRECTORIES: &[&str] = &[
    "test",
    "tests",
    "spec",
    "specs",
    "__tests__",
    "__mocks__",
    "testdata",
];

/// File names that mean "test code" and nothing else, by convention.
///
/// Matched case-insensitively against the file name alone:
///
/// - `conftest.py` — pytest's per-directory fixture module.
/// - a `test_` prefix or `_test` suffix on the stem (`test_client.py`,
///   `client_test.py`), the two pytest/`unittest` conventions.
/// - a `.test` or `.spec` stem suffix (`client.test.ts`, `client.spec.tsx`),
///   the Jest/Vitest/Jasmine convention.
///
/// The stem is everything before the final extension, so `client.test.ts`
/// has stem `client.test` and `client_test.py` has stem `client_test`.
fn is_test_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == "conftest.py" {
        return true;
    }
    let stem = lower
        .rsplit_once('.')
        .map_or(lower.as_str(), |(stem, _)| stem);
    if stem.starts_with("test_") || stem.ends_with("_test") {
        return true;
    }
    // The Jest/Vitest infix, which is the stem's own last dotted segment:
    // `client.test.ts` has stem `client.test`.
    matches!(stem.rsplit_once('.'), Some((_, infix)) if infix == "test" || infix == "spec")
}

/// Whether `path` is test code rather than shipped code.
///
/// `path` is expected to be relative to the scan root, which is what the
/// engine carries on every finding. An absolute path still works, but a
/// scan root that itself lives under a directory called `tests` would then
/// make every file in the tree a test file — one more reason findings carry
/// root-relative paths.
pub(crate) fn is_test_path(path: &Path) -> bool {
    let file_name = path.file_name().and_then(|name| name.to_str());
    if file_name.is_some_and(is_test_file_name) {
        return true;
    }

    // Only the directory components: a *file* called `spec` is not a test
    // suite, and the file name has already had its own, stricter, say.
    path.parent().is_some_and(|parent| {
        parent.components().any(|component| {
            component.as_os_str().to_str().is_some_and(|name| {
                TEST_DIRECTORIES
                    .iter()
                    .any(|dir| name.eq_ignore_ascii_case(dir))
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tests_directory_component_matches() {
        for path in [
            "tests/unit/test_db.py",
            "test/conftest.py",
            "src/spec/client.py",
            "specs/api.js",
            "web/__tests__/render.js",
            "web/__mocks__/fs.js",
            "internal/testdata/seed.py",
        ] {
            assert!(is_test_path(Path::new(path)), "{path}");
        }
    }

    /// The whole point of matching a component rather than a substring. A
    /// directory that merely *contains* "test" is ordinary application code,
    /// and demoting its findings would hide real defects.
    #[test]
    fn a_directory_that_merely_contains_test_does_not_match() {
        for path in [
            "latest/client.py",
            "contest/scoring.py",
            "attestation/verify.py",
            "protest/organise.py",
            "src/testing_utils/helpers.py",
            "src/pytest_plugin/hooks.py",
            "greatest_hits/index.js",
        ] {
            assert!(!is_test_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn conventional_test_file_names_match() {
        for path in [
            "src/test_client.py",
            "src/client_test.py",
            "src/conftest.py",
            "src/client.test.ts",
            "src/client.spec.tsx",
            "src/client.test.js",
            "e2e/onboarding.spec.ts",
        ] {
            assert!(is_test_path(Path::new(path)), "{path}");
        }
    }

    /// A file name that merely contains "test" or "spec" is not a test file:
    /// `latest.py` and `spectrum.py` are the names this list must never
    /// claim.
    #[test]
    fn a_file_name_that_merely_contains_test_does_not_match() {
        for path in [
            "src/latest.py",
            "src/attestation.py",
            "src/contest_results.py",
            "src/spectrum.py",
            "src/protester.js",
            "src/testimony.ts",
            "src/manifest.ts",
        ] {
            assert!(!is_test_path(Path::new(path)), "{path}");
        }
    }

    /// Case matters on Linux and does not on macOS; the answer must not.
    #[test]
    fn matching_ignores_case() {
        assert!(is_test_path(Path::new("Tests/unit/db.py")));
        assert!(is_test_path(Path::new("src/Client.Spec.ts")));
        assert!(!is_test_path(Path::new("Latest/client.py")));
    }

    #[test]
    fn ordinary_source_is_not_a_test_path() {
        for path in [
            "src/agent.py",
            "app/main.ts",
            "packages/web/src/index.tsx",
            "requirements.txt",
        ] {
            assert!(!is_test_path(Path::new(path)), "{path}");
        }
    }

    /// A directory called `test` counts; a *file* called `test` does not get
    /// there by the directory rule, because only parent components are
    /// searched.
    #[test]
    fn a_bare_file_named_test_is_not_a_test_path() {
        assert!(!is_test_path(Path::new("src/test")));
        assert!(!is_test_path(Path::new("src/spec")));
    }

    /// Real `.spec.ts`/`.test.ts` paths from the 65-repository calibration
    /// corpus, which lives in a separate private repository and is never
    /// committed here -- only the path shapes are reproduced below. Pinned
    /// across every js/jsx/ts/tsx/mjs/cjs extension actually seen, not just
    /// `.ts`, since [`is_test_file_name`] works off the stem and does not
    /// special-case the extension.
    ///
    /// The first path is also `BAS-ZT1-003`'s (`crates/bastyn-core/rules/
    /// bastyn.yml`) one corpus finding in a `.spec.ts` file. That rule sets
    /// `in_test_paths: report` deliberately -- a leaked provider key is
    /// worth reporting wherever it sits -- so its finding there stays
    /// `Kind::Defect` regardless of what this module decides. That is a
    /// rule-policy choice, made in the same commit that wrote this file, not
    /// evidence that the path itself goes unrecognised: the assertion below
    /// pins the path recognition directly so the two cannot be conflated.
    #[test]
    fn jest_vitest_style_suffixed_paths_from_the_corpus_match() {
        for path in [
            "src/workspaces/adapters/omp.spec.ts",
            "services/connector/src/adapters/feishu.spec.ts",
            "src/middleware/openai-audit.test.ts",
            "tests/security/middleware.test.ts",
            "apps/desktop/src/workspace-acceptance-smoke.spec.ts",
            "packages/openzeppelin-contracts/test/token/ERC1155/ERC1155URIStorage.test.js",
            "component.spec.jsx",
            "component.test.jsx",
            "util.test.mjs",
            "util.spec.cjs",
        ] {
            assert!(is_test_path(Path::new(path)), "{path}");
        }
    }

    /// The near-misses the suffix rule must not catch, alongside the hits
    /// above: a `.spec`/`.test` *infix* is an exact dotted segment, not a
    /// substring, so `spec_of_a_thing` (no dot before `_of_a_thing`, so it
    /// is one dotted segment, not `spec` followed by something else) must
    /// not match just because it starts with `spec`.
    #[test]
    fn a_suffix_that_merely_starts_with_spec_or_test_does_not_match() {
        for path in ["greatest.spec_of_a_thing.ts", "latest.ts", "manifest.ts"] {
            assert!(!is_test_path(Path::new(path)), "{path}");
        }
    }
}
