//! Deterministic traversal of a source tree.
//!
//! # Skipping is an attack surface
//!
//! Every path this module drops is a place a finding could have been. "Put it
//! in `dist/`" is a real move against a scanner, so the rule here is that the
//! traversal may narrow what a scan covers but may never narrow it quietly:
//! anything an exclude pattern or a `.bastynignore` removes comes back in
//! [`Traversal::skipped`] and reaches the report, naming the rule that did it.
//! That is why the exclude patterns are matched here, by hand, rather than
//! handed to [`WalkBuilder::overrides`] — filtering inside the walker is
//! cheaper to write and produces an exclusion nobody downstream can see.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use ignore::WalkBuilder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::report::Skip;

/// The name of the per-directory file that says "tracked, but not worth
/// scanning".
///
/// Distinct from `.gitignore` on purpose. "Do not commit this" and "do not
/// analyse this" are different statements, and a repository has every reason
/// to make the second about files it deliberately makes the first about
/// nothing at all: committed vendor bundles, a checked-in `dist/`, a fixture
/// corpus of deliberately vulnerable code.
const BASTYN_IGNORE: &str = ".bastynignore";

/// Directories that are never useful to a scanner and are always skipped.
///
/// `node_modules` is here for the same reason as `.git`: nothing inside it
/// belongs to the repository being scanned. A finding in a vendored package
/// is not the author's defect and its remediation is "upgrade the
/// dependency", which is `BAS-CVE-001`'s job, not a rule's. Most
/// repositories gitignore it and never reach this list — 2 of 65 real
/// repositories measured on 2026-08-28 committed it, and those two supplied
/// 5 of 93 findings, all in the TypeScript compiler's or protobufjs's own
/// source.
const ALWAYS_SKIP: &[&str] = &[".git", ".hg", ".svn", "node_modules"];

/// How a source tree should be traversed.
///
/// The default mirrors what a developer expects from a tool run inside a
/// repository: everything Git would track, and nothing it would not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct WalkOptions {
    /// Honour `.gitignore`, `.ignore`, `.bastynignore` and global Git
    /// excludes.
    pub respect_ignore_files: bool,
    /// Include dot-files and dot-directories.
    pub include_hidden: bool,
    /// Follow symbolic links instead of reporting them as-is.
    pub follow_symlinks: bool,
    /// Stop descending after this many directory levels below the root.
    ///
    /// `None` means unlimited depth.
    pub max_depth: Option<usize>,
    /// Patterns, in `.gitignore` syntax, whose matches are not scanned.
    ///
    /// Unlike the ignore *files*, these come from the caller rather than from
    /// the tree, so [`respect_ignore_files`](Self::respect_ignore_files) does
    /// not switch them off: an instruction typed on this run is not a file the
    /// repository left lying around.
    ///
    /// Every match is reported in [`Traversal::skipped`].
    pub excludes: Vec<String>,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            respect_ignore_files: true,
            include_hidden: false,
            follow_symlinks: false,
            max_depth: None,
            excludes: Vec::new(),
        }
    }
}

/// What one traversal found, and what it deliberately left out.
///
/// The second half is not decoration. A scan that covered less than it claimed
/// is worse than one that failed, so the paths a pattern removed travel
/// alongside the paths it kept, all the way into the report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Traversal {
    /// Files to analyse, relative to the root, sorted.
    pub files: Vec<PathBuf>,
    /// One entry per deliberate exclusion, sorted, each carrying why it is
    /// there as well as what it is.
    ///
    /// A directory appears once, with a trailing `/`, and is not descended
    /// into: enumerating every file beneath an excluded tree would bury the
    /// shape of the loss in the case where a reader most needs to see it.
    pub skipped: Vec<Skip>,
}

/// Collect every file under `root`, honouring `options`.
///
/// Paths are returned relative to `root` and sorted, so two runs over an
/// unchanged tree always produce byte-identical output — a prerequisite for
/// diffable reports and reproducible CI runs. The same is true of
/// [`Traversal::skipped`].
///
/// Only files are returned; directories are traversed but never reported,
/// except as a single [`Traversal::skipped`] entry when a pattern excluded the
/// whole directory.
///
/// # Errors
///
/// Returns [`Error::PathNotFound`] or [`Error::NotADirectory`] if `root` is not
/// a readable directory, [`Error::ExcludePattern`] if one of
/// [`WalkOptions::excludes`] is not a valid pattern, and [`Error::Walk`] if
/// traversal fails part-way through — an unreadable subdirectory is an error,
/// not a silently smaller result set.
pub fn collect_files(root: impl AsRef<Path>, options: &WalkOptions) -> Result<Traversal> {
    let root = root.as_ref();

    let metadata = std::fs::metadata(root).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            Error::PathNotFound {
                path: root.to_path_buf(),
            }
        } else {
            Error::Io {
                path: root.to_path_buf(),
                source,
            }
        }
    })?;

    if !metadata.is_dir() {
        return Err(Error::NotADirectory {
            path: root.to_path_buf(),
        });
    }

    let excludes = compile_excludes(root, &options.excludes)?;

    // Written into from inside the walker's `filter_entry`, which takes a
    // `Fn` and must outlive the borrow of `root`. There is one walker thread,
    // so the lock is never contended; it is here to satisfy the signature,
    // not to arbitrate anything.
    let skipped = Arc::new(Mutex::new(BTreeSet::new()));

    // The root is the one directory `filter_entry` is never asked about, so
    // the `.bastynignore` most repositories actually have -- the one at the
    // top -- would go unreported if the closure were the only place that
    // looked. `record` de-duplicates, so a future `ignore` that does pass the
    // root through changes nothing.
    if options.respect_ignore_files {
        note_bastynignore(&skipped, root, root);
    }

    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(!options.include_hidden)
        .follow_links(options.follow_symlinks)
        .parents(options.respect_ignore_files)
        .git_global(options.respect_ignore_files)
        .git_ignore(options.respect_ignore_files)
        .git_exclude(options.respect_ignore_files)
        .ignore(options.respect_ignore_files)
        .require_git(false)
        .max_depth(options.max_depth)
        .filter_entry({
            let root = root.to_path_buf();
            let skipped = Arc::clone(&skipped);
            let respect_ignore_files = options.respect_ignore_files;
            move |entry| {
                let is_dir = entry
                    .file_type()
                    .is_some_and(|file_type| file_type.is_dir());

                if is_dir
                    && entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| ALWAYS_SKIP.contains(&name))
                {
                    return false;
                }

                if let ignore::Match::Ignore(glob) = excludes.matched(entry.path(), is_dir) {
                    let mut path = display_path(&root, entry.path());
                    if is_dir {
                        path.push('/');
                    }
                    record(&skipped, Skip::excluded(path, glob.original()));
                    return false;
                }

                if respect_ignore_files && is_dir {
                    note_bastynignore(&skipped, &root, entry.path());
                }

                true
            }
        });

    if options.respect_ignore_files {
        builder.add_custom_ignore_filename(BASTYN_IGNORE);
    }

    let mut files = Vec::new();
    for entry in builder.build() {
        let entry = entry.map_err(|source| Error::Walk {
            path: root.to_path_buf(),
            source,
        })?;

        // `file_type` is `None` only for the stdin pseudo-entry, which this
        // walk never produces.
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }

        let path = entry.path();
        files.push(path.strip_prefix(root).unwrap_or(path).to_path_buf());
    }

    files.sort_unstable();
    let skipped = skipped
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .cloned()
        .collect();

    Ok(Traversal { files, skipped })
}

/// Build one matcher from the caller's exclude patterns.
///
/// `.gitignore` syntax, from [`GitignoreBuilder`], because that is the syntax
/// every user of this flag already knows and because it brings the behaviour
/// people expect for free: an unanchored pattern matches at any depth, a
/// leading `/` anchors it to the root, a trailing `/` restricts it to
/// directories, and `!` re-includes.
fn compile_excludes(root: &Path, patterns: &[String]) -> Result<Gitignore> {
    let mut builder = GitignoreBuilder::new(root);
    for pattern in patterns {
        // A pattern that failed to compile would silently exclude nothing,
        // which is a silent loss of the exclusion the caller asked for.
        builder
            .add_line(None, pattern)
            .map_err(|source| Error::ExcludePattern {
                pattern: pattern.clone(),
                source,
            })?;
    }
    builder.build().map_err(|source| Error::ExcludePattern {
        pattern: patterns.join(" "),
        source,
    })
}

/// Record that `directory` holds a `.bastynignore`, if it does.
///
/// Detected from the directory rather than from the walk's own results,
/// because the file is a dot-file: `hidden(true)` has already dropped it from
/// those by the time anyone downstream could look, and honouring a file the
/// report never mentions is the silent exclusion this module exists to
/// prevent.
///
/// A `.bastynignore` inside a directory that was itself excluded is never
/// reached, and could not have excluded anything this scan would have seen.
fn note_bastynignore(skipped: &Arc<Mutex<BTreeSet<Skip>>>, root: &Path, directory: &Path) {
    let ignore_file = directory.join(BASTYN_IGNORE);
    if ignore_file.is_file() {
        record(skipped, Skip::ignore_file(display_path(root, &ignore_file)));
    }
}

/// Add one entry to the exclusion record.
///
/// A poisoned lock is recovered from rather than skipped past. Nothing in
/// here can leave the set half-written, and dropping an entry would turn a
/// reported exclusion into a silent one, which is the failure this whole
/// module is built to avoid.
fn record(skipped: &Arc<Mutex<BTreeSet<Skip>>>, skip: Skip) {
    skipped
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(skip);
}

/// `path` relative to `root`, with forward slashes, so a report is identical
/// on every platform.
fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    use std::fs;

    use tempfile::TempDir;

    /// Builds a tree from `(relative path, contents)` pairs.
    fn tree(entries: &[&str]) -> TempDir {
        let dir = TempDir::new().unwrap();
        for entry in entries {
            let path = dir.path().join(entry);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, b"contents").unwrap();
        }
        dir
    }

    fn as_strings(paths: &[PathBuf]) -> Vec<String> {
        paths
            .iter()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .collect()
    }

    #[test]
    fn returns_sorted_relative_paths() {
        let dir = tree(&["src/main.rs", "README.md", "src/lib.rs"]);

        let files = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;

        assert_eq!(
            as_strings(&files),
            ["README.md", "src/lib.rs", "src/main.rs"]
        );
    }

    #[test]
    fn directories_are_not_reported() {
        let dir = tree(&["nested/deep/file.txt"]);

        let files = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;

        assert_eq!(as_strings(&files), ["nested/deep/file.txt"]);
    }

    #[test]
    fn honours_gitignore_by_default() {
        let dir = tree(&["keep.rs", "target/build.o", ".gitignore"]);
        fs::write(dir.path().join(".gitignore"), "target/\n").unwrap();

        let files = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;

        assert_eq!(as_strings(&files), ["keep.rs"]);
    }

    #[test]
    fn ignore_files_can_be_disabled() {
        let dir = tree(&["keep.rs", "target/build.o"]);
        fs::write(dir.path().join(".gitignore"), "target/\n").unwrap();

        let options = WalkOptions {
            respect_ignore_files: false,
            ..WalkOptions::default()
        };
        let files = collect_files(dir.path(), &options).unwrap().files;

        assert_eq!(as_strings(&files), ["keep.rs", "target/build.o"]);
    }

    #[test]
    fn hidden_files_are_excluded_by_default_and_included_on_request() {
        let dir = tree(&["visible.rs", ".env"]);

        let hidden_excluded = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;
        assert_eq!(as_strings(&hidden_excluded), ["visible.rs"]);

        let options = WalkOptions {
            include_hidden: true,
            ..WalkOptions::default()
        };
        let hidden_included = collect_files(dir.path(), &options).unwrap().files;
        assert_eq!(as_strings(&hidden_included), [".env", "visible.rs"]);
    }

    /// Vendored dependency trees are somebody else's code. A finding there
    /// is not actionable — the remediation is "upgrade the package", not
    /// "fix this line" — and it is not the repository's defect. Measured on
    /// 2026-08-28: 5 of 93 findings across 65 real repositories came from
    /// one committed `node_modules`, every one of them in the TypeScript
    /// compiler's or protobufjs's own source.
    #[test]
    fn vendored_dependency_directories_are_always_skipped() {
        let dir = tree(&[
            "src/app.js",
            "node_modules/protobufjs/index.js",
            "packages/web/node_modules/left-pad/index.js",
        ]);

        let options = WalkOptions {
            respect_ignore_files: false,
            ..WalkOptions::default()
        };
        let files = collect_files(dir.path(), &options).unwrap().files;

        assert_eq!(as_strings(&files), ["src/app.js"]);
    }

    /// A directory whose name merely contains `node_modules` is not one.
    #[test]
    fn a_directory_that_merely_contains_node_modules_is_not_skipped() {
        let dir = tree(&["node_modules_backup/app.js"]);

        let options = WalkOptions {
            respect_ignore_files: false,
            ..WalkOptions::default()
        };
        let files = collect_files(dir.path(), &options).unwrap().files;

        assert_eq!(as_strings(&files), ["node_modules_backup/app.js"]);
    }

    #[test]
    fn version_control_directories_are_always_skipped() {
        let dir = tree(&["src/main.rs", ".git/config", ".git/objects/ab/cdef"]);

        let options = WalkOptions {
            include_hidden: true,
            respect_ignore_files: false,
            ..WalkOptions::default()
        };
        let files = collect_files(dir.path(), &options).unwrap().files;

        assert_eq!(as_strings(&files), ["src/main.rs"]);
    }

    /// An exclusion is a place a finding can hide, so the report has to name
    /// every one. This is the difference between a scanner that covers less
    /// and a scanner that lies about what it covered.
    #[test]
    fn an_excluded_path_is_reported_not_silently_dropped() {
        let dir = tree(&["src/app.py", "vendor/bundle.js"]);

        let options = WalkOptions {
            excludes: vec!["vendor/".to_owned()],
            ..WalkOptions::default()
        };
        let walked = collect_files(dir.path(), &options).unwrap();

        assert_eq!(as_strings(&walked.files), ["src/app.py"]);
        assert_eq!(
            walked.skipped.len(),
            1,
            "the excluded directory must be reported: {:#?}",
            walked.skipped
        );
        assert!(
            walked.skipped[0]
                .line()
                .starts_with("vendor/ \u{2014} excluded by pattern"),
            "{:#?}",
            walked.skipped
        );
        assert!(
            walked.skipped[0].line().contains("vendor/"),
            "the report must name the pattern that did it: {:#?}",
            walked.skipped
        );
    }

    /// A directory is reported once and never descended into. Enumerating
    /// every file under an excluded tree would drown the report in exactly
    /// the case where the reader most needs to see the shape of what was
    /// dropped.
    #[test]
    fn an_excluded_directory_is_reported_once_not_per_file() {
        let dir = tree(&[
            "keep.py",
            "out/a.js",
            "out/b.js",
            "out/nested/c.js",
            "out/nested/deeper/d.js",
        ]);

        let options = WalkOptions {
            excludes: vec!["out".to_owned()],
            ..WalkOptions::default()
        };
        let walked = collect_files(dir.path(), &options).unwrap();

        assert_eq!(as_strings(&walked.files), ["keep.py"]);
        assert_eq!(walked.skipped.len(), 1, "{:#?}", walked.skipped);
    }

    /// `.gitignore` syntax, because that is the syntax every user of this
    /// flag already knows: unanchored patterns match at any depth, a leading
    /// slash anchors to the root, and `!` re-includes.
    #[test]
    fn exclude_patterns_use_gitignore_syntax() {
        let dir = tree(&[
            "app.js",
            "web/vendor.min.js",
            "web/deep/other.min.js",
            "build/keep.js",
            "sub/build/dropped.js",
        ]);

        let options = WalkOptions {
            excludes: vec!["*.min.js".to_owned(), "/build".to_owned()],
            ..WalkOptions::default()
        };
        let walked = collect_files(dir.path(), &options).unwrap();

        assert_eq!(
            as_strings(&walked.files),
            ["app.js", "sub/build/dropped.js"],
            "unanchored patterns match at any depth, anchored ones do not"
        );
        assert_eq!(walked.skipped.len(), 3, "{:#?}", walked.skipped);
    }

    #[test]
    fn several_exclude_patterns_all_apply() {
        let dir = tree(&["app.py", "a/one.js", "b/two.js"]);

        let options = WalkOptions {
            excludes: vec!["a/".to_owned(), "b/".to_owned()],
            ..WalkOptions::default()
        };
        let walked = collect_files(dir.path(), &options).unwrap();

        assert_eq!(as_strings(&walked.files), ["app.py"]);
        assert_eq!(walked.skipped.len(), 2, "{:#?}", walked.skipped);
    }

    #[test]
    fn a_malformed_exclude_pattern_is_an_error_not_a_silently_ignored_one() {
        let dir = tree(&["app.py"]);

        let options = WalkOptions {
            excludes: vec!["dist/{unclosed".to_owned()],
            ..WalkOptions::default()
        };
        let error = collect_files(dir.path(), &options).unwrap_err();

        assert!(
            matches!(error, Error::ExcludePattern { .. }),
            "a pattern that excludes nothing because it did not compile is a
             silent loss of the exclusion the user asked for: got {error:?}"
        );
    }

    /// `.bastynignore` says "tracked, but not worth scanning", which is a
    /// different statement from `.gitignore`'s "do not commit this" — a
    /// repository has every reason to commit its vendored bundles and still
    /// not want them analysed.
    #[test]
    fn a_bastynignore_is_honoured_and_its_existence_reported() {
        let dir = tree(&["src/app.py", "vendor/bundle.js"]);
        fs::write(dir.path().join(".bastynignore"), "vendor/\n").unwrap();

        let walked = collect_files(dir.path(), &WalkOptions::default()).unwrap();

        assert_eq!(as_strings(&walked.files), ["src/app.py"]);
        assert!(
            walked
                .skipped
                .iter()
                .any(|entry| entry.line().starts_with(".bastynignore \u{2014}")),
            "a scan whose coverage a file quietly reduced must say the file
             was there: {:#?}",
            walked.skipped
        );
    }

    #[test]
    fn a_nested_bastynignore_applies_to_its_own_directory() {
        let dir = tree(&["src/app.py", "web/vendor/bundle.js", "web/src/main.ts"]);
        fs::write(dir.path().join("web/.bastynignore"), "vendor/\n").unwrap();

        let walked = collect_files(dir.path(), &WalkOptions::default()).unwrap();

        assert_eq!(as_strings(&walked.files), ["src/app.py", "web/src/main.ts"]);
        assert!(
            walked
                .skipped
                .iter()
                .any(|entry| entry.line().starts_with("web/.bastynignore \u{2014}")),
            "{:#?}",
            walked.skipped
        );
    }

    #[test]
    fn a_bastynignore_that_excludes_nothing_is_still_reported() {
        // It is a standing reduction in coverage whether or not it bit on
        // this particular tree, and a reader comparing two reports should not
        // have to guess why one of them saw fewer files.
        let dir = tree(&["src/app.py"]);
        fs::write(dir.path().join(".bastynignore"), "vendor/\n").unwrap();

        let walked = collect_files(dir.path(), &WalkOptions::default()).unwrap();

        assert_eq!(as_strings(&walked.files), ["src/app.py"]);
        assert_eq!(walked.skipped.len(), 1, "{:#?}", walked.skipped);
    }

    #[test]
    fn no_bastynignore_means_nothing_is_reported() {
        let dir = tree(&["src/app.py"]);

        let walked = collect_files(dir.path(), &WalkOptions::default()).unwrap();

        assert!(walked.skipped.is_empty(), "{:#?}", walked.skipped);
    }

    #[test]
    fn disabling_ignore_files_also_disables_bastynignore() {
        let dir = tree(&["src/app.py", "vendor/bundle.js"]);
        fs::write(dir.path().join(".bastynignore"), "vendor/\n").unwrap();

        let options = WalkOptions {
            respect_ignore_files: false,
            ..WalkOptions::default()
        };
        let walked = collect_files(dir.path(), &options).unwrap();

        assert_eq!(
            as_strings(&walked.files),
            ["src/app.py", "vendor/bundle.js"]
        );
        assert!(walked.skipped.is_empty(), "{:#?}", walked.skipped);
    }

    /// `--no-ignore` turns off ignore *files*. An `--exclude` the user typed
    /// on this very command line is not one of those.
    #[test]
    fn disabling_ignore_files_does_not_disable_exclude_patterns() {
        let dir = tree(&["src/app.py", "vendor/bundle.js"]);

        let options = WalkOptions {
            respect_ignore_files: false,
            excludes: vec!["vendor/".to_owned()],
            ..WalkOptions::default()
        };
        let walked = collect_files(dir.path(), &options).unwrap();

        assert_eq!(as_strings(&walked.files), ["src/app.py"]);
        assert_eq!(walked.skipped.len(), 1, "{:#?}", walked.skipped);
    }

    #[test]
    fn the_traversal_is_identical_on_repeated_runs() {
        let dir = tree(&["b.py", "a.py", "x/one.js", "x/two.js", "y/z.js"]);
        fs::write(dir.path().join(".bastynignore"), "y/\n").unwrap();

        let options = WalkOptions {
            excludes: vec!["x/one.js".to_owned()],
            ..WalkOptions::default()
        };
        let first = collect_files(dir.path(), &options).unwrap();
        for _ in 0..4 {
            assert_eq!(collect_files(dir.path(), &options).unwrap(), first);
        }
        assert_eq!(first.skipped.len(), 2, "{:#?}", first.skipped);
    }

    #[test]
    fn max_depth_limits_descent() {
        let dir = tree(&["top.rs", "one/mid.rs", "one/two/deep.rs"]);

        let options = WalkOptions {
            max_depth: Some(2),
            ..WalkOptions::default()
        };
        let files = collect_files(dir.path(), &options).unwrap().files;

        assert_eq!(as_strings(&files), ["one/mid.rs", "top.rs"]);
    }

    #[test]
    fn empty_directory_yields_no_files() {
        let dir = TempDir::new().unwrap();

        let files = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;

        assert!(files.is_empty());
    }

    #[test]
    fn missing_root_is_reported() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope");

        let error = collect_files(&missing, &WalkOptions::default()).unwrap_err();

        assert!(matches!(error, Error::PathNotFound { .. }), "got {error:?}");
    }

    #[test]
    fn file_root_is_rejected() {
        let dir = tree(&["single.rs"]);
        let file = dir.path().join("single.rs");

        let error = collect_files(&file, &WalkOptions::default()).unwrap_err();

        assert!(
            matches!(error, Error::NotADirectory { .. }),
            "got {error:?}"
        );
    }
}
