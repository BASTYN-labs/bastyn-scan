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
//!
//! The same principle cuts the other way for dot-files: the default excludes
//! them (see [`WalkOptions::include_hidden`]), and for most of a repository
//! that default is right. But a fixed, small set of dot-paths are where the
//! most sensitive material in a modern AI-agent repository actually lives —
//! `.env`, MCP server manifests, `.claude/`, `.github/workflows/` — and a
//! scanner that silently never looks at them on the documented, flag-free
//! `bastyn scan` invocation is a real gap, not a benchmark curiosity. Those
//! specific paths are always walked, regardless of
//! [`WalkOptions::include_hidden`], by [`collect_files`]'s allowlist pass.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use ignore::WalkBuilder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::mcp;
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
    ///
    /// When this is `false` (the default), a fixed, small set of
    /// security-relevant dot-paths is still always walked, on top of
    /// whatever this option would otherwise include: `.env` and any
    /// `.env.*` file at the scan root, a dot-prefixed MCP manifest
    /// (`.mcp.json`, `.mcp.yaml`, `.mcp.yml`, `.mcp.toml`) at the scan root,
    /// everything under a root-level `.claude/`, and everything under a
    /// root-level `.github/workflows/`. These four are root-level
    /// conventions in every real tool that uses them, and they hold
    /// credentials, MCP server trust boundaries, agent configuration, and
    /// CI/CD pipeline definitions respectively — exactly the material a
    /// scanner should not miss just because a user ran `bastyn scan` with no
    /// flags, which is the documented default usage. This allowlist is not
    /// a blanket hidden-file default (that would also start walking
    /// `.venv/`, `.idea/`, `.next/`, `.terraform/`, and every other hidden
    /// directory a real repository accumulates, which is the cost this
    /// option exists to let a caller opt into rather than pay
    /// unconditionally). An explicit `--exclude`/[`WalkOptions::excludes`]
    /// pattern, or a respected `.gitignore`/`.bastynignore`, still drops an
    /// allowlisted path exactly as it would any other.
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
        .filter_entry(make_filter_entry(
            root.to_path_buf(),
            Arc::clone(&skipped),
            excludes.clone(),
            options.respect_ignore_files,
        ));

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

    // The main walk above already covers everything when hidden paths are
    // included, so running the allowlist too would just re-find the same
    // files for no benefit — skip the extra work.
    if !options.include_hidden {
        files.extend(allowlisted_files(root, options, &excludes, &skipped)?);
    }

    files.sort_unstable();
    files.dedup();
    let skipped = skipped
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .cloned()
        .collect();

    Ok(Traversal { files, skipped })
}

/// The four security-relevant dot-paths that are always scanned regardless
/// of [`WalkOptions::include_hidden`] — see the doc comment on that field for
/// why these four and not a blanket hidden-file default.
///
/// Each is anchored to the scan root: these are root-level conventions
/// (`.env`, MCP manifests, `.claude/`, `.github/workflows/`) in every real
/// tool that uses them, so this never needs a full-tree recursive search for
/// them.
fn allowlisted_files(
    root: &Path,
    options: &WalkOptions,
    excludes: &Gitignore,
    skipped: &Arc<Mutex<BTreeSet<Skip>>>,
) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    // `.env` and `.env.*`, plus dot-prefixed MCP manifests
    // (`.mcp.json`/`.mcp.yaml`/`.mcp.yml`/`.mcp.toml`). Walked rather than
    // read directly with `std::fs::read_dir` so a `.gitignore` line or an
    // `--exclude` pattern can still suppress them exactly as it would any
    // other path. Depth `1` keeps it to the root's immediate children, which
    // is all a `read_dir` would have reached anyway — but `--max-depth` is a
    // promise about levels below the scan root, and this scan *is* rooted
    // at the scan root, so a caller-supplied depth smaller than `1` has to
    // win: the tighter of the two constraints applies.
    let root_scan_depth = Some(options.max_depth.map_or(1, |depth| depth.min(1)));
    for path in walk_scoped(root, root, options, excludes, skipped, root_scan_depth)? {
        let is_allowlisted = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name == ".env"
                    || name.starts_with(".env.")
                    || (name.starts_with('.') && mcp::is_mcp_config(&path))
            });
        if is_allowlisted {
            files.push(path);
        }
    }

    // Everything under a root-level `.claude/`: skills, settings, agent
    // configuration. `.claude/` sits one level below the scan root, so
    // `--max-depth`'s "N levels below the root" promise means the local
    // depth handed to this sub-walk has to be `N` reduced by that one level
    // — see `depth_below`.
    let claude_dir = root.join(".claude");
    if claude_dir.is_dir()
        && !exclude_directory_root(root, &claude_dir, excludes, skipped)
        && !(options.respect_ignore_files
            && ignore_file_excludes_directory_root(root, &claude_dir, 1, options, skipped)?)
    {
        // The root's own `.bastynignore` is reported before the main walk
        // starts, for the same reason: `.claude/` is about to become a
        // walk's root, and a walk's root never passes through
        // `filter_entry`, which is the only other place a `.bastynignore`
        // would be noticed.
        if options.respect_ignore_files {
            note_bastynignore(skipped, root, &claude_dir);
        }
        files.extend(walk_scoped(
            root,
            &claude_dir,
            options,
            excludes,
            skipped,
            depth_below(options.max_depth, 1),
        )?);
    }

    // Everything under a root-level `.github/workflows/`: CI/CD pipeline
    // definitions, where secrets handling and supply-chain risk live.
    // `.github/workflows/` sits two levels below the scan root.
    let workflows_dir = root.join(".github").join("workflows");
    if workflows_dir.is_dir()
        && !exclude_directory_root(root, &workflows_dir, excludes, skipped)
        && !(options.respect_ignore_files
            && ignore_file_excludes_directory_root(root, &workflows_dir, 2, options, skipped)?)
    {
        if options.respect_ignore_files {
            note_bastynignore(skipped, root, &workflows_dir);
        }
        files.extend(walk_scoped(
            root,
            &workflows_dir,
            options,
            excludes,
            skipped,
            depth_below(options.max_depth, 2),
        )?);
    }

    Ok(files)
}

/// Whether `directory` itself — not its contents — matches an `--exclude`
/// pattern, recording it in `skipped` if so.
///
/// Needed because `directory` is about to become the *root* of its own
/// [`walk_scoped`] call, and a walk's root is never itself passed through
/// [`make_filter_entry`] (see that function's doc comment) — without this
/// check, excluding `.claude/` or `.github/workflows/` by name would have no
/// effect, since nothing inside either sub-walk is ever named `.claude` or
/// `.github/workflows`.
///
/// This only covers `--exclude`. The same gap for a repository's own
/// `.gitignore`/`.bastynignore` is handled separately, by
/// [`ignore_file_excludes_directory_root`], because that one cannot be
/// answered by matching against a hand-built [`Gitignore`] the way this one
/// is — see that function's doc comment for why.
fn exclude_directory_root(
    root: &Path,
    directory: &Path,
    excludes: &Gitignore,
    skipped: &Arc<Mutex<BTreeSet<Skip>>>,
) -> bool {
    if let ignore::Match::Ignore(glob) = excludes.matched(directory, true) {
        let mut path = display_path(root, directory);
        path.push('/');
        record(skipped, Skip::excluded(path, glob.original()));
        true
    } else {
        false
    }
}

/// Whether an ignore file the main walk in [`collect_files`] would itself
/// respect — a `.gitignore`, global Git excludes, or `.bastynignore` —
/// already excludes `directory`, recording it in `skipped` if so.
///
/// This exists for the same reason as [`exclude_directory_root`]:
/// `directory` is about to become the *root* of its own [`walk_scoped`]
/// call, so nothing inside that sub-walk would ever see `directory`'s own
/// name pass through [`make_filter_entry`] to test it against an
/// ignore-file rule. But unlike an `--exclude` pattern, there is no single
/// hand-built matcher to consult: ignore-file resolution can involve several
/// nested `.gitignore` files, global excludes, and `.bastynignore`, all
/// combined by rules this module deliberately does not reimplement (see this
/// module's own doc comment on why hand-rolling a second matcher is exactly
/// the mistake to avoid). So instead of answering the question directly,
/// this asks the real ignore-file stack: a cheap probe walk of `root`,
/// built with the same ignore-file settings the main walk uses, deep enough
/// to reach `directory`. If `directory` exists on disk (the caller has
/// already confirmed that with `is_dir()`) but this probe never yields it, a
/// real ignore-file rule is why — even though which rule, and in which
/// file, is not recoverable this way. Unlike the `--exclude` case, there is
/// no `glob.original()` to quote, so the recorded [`Skip`] names the path
/// without a specific pattern; that is an honest degradation, not a silent
/// one — the path still lands in [`Traversal::skipped`] either way.
///
/// Only meaningful, and only ever called, when
/// [`WalkOptions::respect_ignore_files`] is set: the caller gates on that,
/// matching how the rest of this module conditions ignore-file behaviour on
/// the same flag.
fn ignore_file_excludes_directory_root(
    root: &Path,
    directory: &Path,
    levels_below_root: usize,
    options: &WalkOptions,
    skipped: &Arc<Mutex<BTreeSet<Skip>>>,
) -> Result<bool> {
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .follow_links(options.follow_symlinks)
        .parents(options.respect_ignore_files)
        .git_global(options.respect_ignore_files)
        .git_ignore(options.respect_ignore_files)
        .git_exclude(options.respect_ignore_files)
        .ignore(options.respect_ignore_files)
        .require_git(false)
        .max_depth(Some(levels_below_root));

    if options.respect_ignore_files {
        builder.add_custom_ignore_filename(BASTYN_IGNORE);
    }

    for entry in builder.build() {
        let entry = entry.map_err(|source| Error::Walk {
            path: root.to_path_buf(),
            source,
        })?;
        if entry.path() == directory {
            // The probe still reaches it, so no ignore-file rule is hiding
            // it.
            return Ok(false);
        }
    }

    let mut path = display_path(root, directory);
    path.push('/');
    record(skipped, Skip::excluded(path, "a respected ignore file"));
    Ok(true)
}

/// How many directory levels below the scan root a sub-walk rooted
/// `levels_below_root` levels below it may still descend, given the
/// caller's own [`WalkOptions::max_depth`].
///
/// `--max-depth <N>` promises "stop descending after N levels below the
/// *scan root*", not below whatever directory a particular sub-walk happens
/// to be rooted at. A sub-walk rooted at `.claude/` (one level below the
/// scan root) or `.github/workflows/` (two levels below it) therefore has to
/// have its own local depth budget reduced by that many levels before it is
/// handed to [`walk_scoped`]. When the caller's budget is already smaller
/// than `levels_below_root`, the correct local depth is zero — descend no
/// further than the sub-walk's own root — rather than silently ignoring the
/// flag by falling back to unlimited depth.
fn depth_below(max_depth: Option<usize>, levels_below_root: usize) -> Option<usize> {
    max_depth.map(|depth| depth.saturating_sub(levels_below_root))
}

/// Walk `walk_root` (`root` itself, or a directory under it) the same way
/// the main walk in [`collect_files`] is built — same ignore-file handling,
/// same [`ALWAYS_SKIP`], same exclude-pattern matching and reporting — except
/// with hidden entries always included. This is the allowlist mechanism's
/// only walker: reusing the main walk's construction is what lets a
/// `.gitignore` line or an `--exclude` pattern still suppress an allowlisted
/// path, rather than the allowlist silently bypassing them.
fn walk_scoped(
    root: &Path,
    walk_root: &Path,
    options: &WalkOptions,
    excludes: &Gitignore,
    skipped: &Arc<Mutex<BTreeSet<Skip>>>,
    max_depth: Option<usize>,
) -> Result<Vec<PathBuf>> {
    let mut builder = WalkBuilder::new(walk_root);
    builder
        .hidden(false)
        .follow_links(options.follow_symlinks)
        .parents(options.respect_ignore_files)
        .git_global(options.respect_ignore_files)
        .git_ignore(options.respect_ignore_files)
        .git_exclude(options.respect_ignore_files)
        .ignore(options.respect_ignore_files)
        .require_git(false)
        .max_depth(max_depth)
        .filter_entry(make_filter_entry(
            root.to_path_buf(),
            Arc::clone(skipped),
            excludes.clone(),
            options.respect_ignore_files,
        ));

    if options.respect_ignore_files {
        builder.add_custom_ignore_filename(BASTYN_IGNORE);
    }

    let mut files = Vec::new();
    for entry in builder.build() {
        let entry = entry.map_err(|source| Error::Walk {
            path: walk_root.to_path_buf(),
            source,
        })?;

        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }

        let path = entry.path();
        files.push(path.strip_prefix(root).unwrap_or(path).to_path_buf());
    }

    Ok(files)
}

/// Build the `filter_entry` closure shared by every walk this module runs:
/// the main walk in [`collect_files`] and each scoped allowlist walk in
/// [`walk_scoped`]. `root` is always the scan root (not `walk_root`), so a
/// reported path or a `.bastynignore` detection is always relative to the
/// same place no matter which walk found it.
fn make_filter_entry(
    root: PathBuf,
    skipped: Arc<Mutex<BTreeSet<Skip>>>,
    excludes: Gitignore,
    respect_ignore_files: bool,
) -> impl Fn(&ignore::DirEntry) -> bool {
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
        // `.env` is not used as the example here: it is one of the
        // always-included security-relevant dot-paths (see
        // `dot_env_is_always_included_by_default` below), so it would not
        // exercise the general default this test is about.
        let dir = tree(&["visible.rs", ".some_random_hidden_file"]);

        let hidden_excluded = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;
        assert_eq!(as_strings(&hidden_excluded), ["visible.rs"]);

        let options = WalkOptions {
            include_hidden: true,
            ..WalkOptions::default()
        };
        let hidden_included = collect_files(dir.path(), &options).unwrap().files;
        assert_eq!(
            as_strings(&hidden_included),
            [".some_random_hidden_file", "visible.rs"]
        );
    }

    /// `.env` is one of the four security-relevant dot-paths that stays
    /// covered even when `include_hidden` is off: most of the highest-value
    /// findings in a real AI-agent repository — leaked credentials — live in
    /// exactly this file, and a scanner that silently never reaches it on
    /// the documented, flag-free `bastyn scan` invocation is a real gap.
    /// The unrelated hidden file proves this is a narrow allowlist and not
    /// a blanket flip of `include_hidden`'s default.
    #[test]
    fn dot_env_is_always_included_by_default() {
        let dir = tree(&["visible.rs", ".env", ".some_random_hidden_file"]);

        let files = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;

        assert_eq!(as_strings(&files), [".env", "visible.rs"]);
    }

    /// `.env.local`, `.env.production`, and friends are the same kind of
    /// credential-bearing file as `.env` and follow the same convention.
    #[test]
    fn dot_env_variants_are_always_included_by_default() {
        let dir = tree(&["visible.rs", ".env.production"]);

        let files = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;

        assert_eq!(as_strings(&files), [".env.production", "visible.rs"]);
    }

    /// `.mcp.json` is the dot-prefixed convention Claude Code and similar
    /// clients use for project-local MCP server configuration —
    /// `crate::mcp::is_mcp_config` already recognises it, but the walker
    /// never used to reach it by default because it is a dot-file.
    /// `mcp.json` (no leading dot) was already included before this change
    /// and must still be, since it was never hidden in the first place.
    #[test]
    fn dot_prefixed_mcp_manifest_is_always_included_by_default() {
        let dir = tree(&["visible.rs", ".mcp.json", "mcp.json"]);

        let files = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;

        assert_eq!(as_strings(&files), [".mcp.json", "mcp.json", "visible.rs"]);
    }

    /// `.claude/` holds skills, settings and agent configuration — exactly
    /// the kind of material a security scan should not silently skip. The
    /// sibling `.venv/` proves the fix does not fall back to a blanket
    /// hidden-directory default.
    #[test]
    fn dot_claude_directory_is_always_walked_by_default() {
        let dir = tree(&[
            "visible.rs",
            ".claude/skills/deploy/SKILL.md",
            ".venv/lib/foo.py",
        ]);

        let files = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;

        assert_eq!(
            as_strings(&files),
            [".claude/skills/deploy/SKILL.md", "visible.rs"]
        );
    }

    /// `.github/workflows/` holds CI/CD pipeline definitions: secrets
    /// handling and supply-chain risk live there.
    #[test]
    fn dot_github_workflows_directory_is_always_walked_by_default() {
        let dir = tree(&["visible.rs", ".github/workflows/ci.yml"]);

        let files = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;

        assert_eq!(
            as_strings(&files),
            [".github/workflows/ci.yml", "visible.rs"]
        );
    }

    /// The allowlist widens coverage; it does not override a repository's
    /// own decision to gitignore something. If the user's own `.gitignore`
    /// excludes `.env`, that is still honoured.
    #[test]
    fn a_gitignored_dot_env_is_not_reintroduced_by_the_allowlist() {
        // `.gitignore` itself is an ordinary hidden file, not one of the
        // four allowlisted paths, so it stays excluded by default like any
        // other dot-file; only `.env`'s presence is under test here.
        let dir = tree(&["visible.rs", ".env"]);
        fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();

        let files = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;

        assert_eq!(as_strings(&files), ["visible.rs"]);
    }

    /// An explicit `--exclude` is the one thing in this module that
    /// survives every other override (see [`WalkOptions::excludes`]'s doc
    /// comment) — including the allowlist.
    #[test]
    fn an_explicit_exclude_still_drops_an_allowlisted_path() {
        let dir = tree(&["visible.rs", ".env", ".claude/skills/deploy/SKILL.md"]);

        let options = WalkOptions {
            excludes: vec![".env".to_owned(), ".claude/".to_owned()],
            ..WalkOptions::default()
        };
        let files = collect_files(dir.path(), &options).unwrap().files;

        assert_eq!(as_strings(&files), ["visible.rs"]);
    }

    /// A repository's own `.gitignore` is just as capable of dropping an
    /// allowlisted path as an `--exclude` pattern is (see the previous
    /// test) — the module's own doc comment promises both. `.claude/` is
    /// the walk *root* of its own scoped sub-walk, so nothing inside that
    /// sub-walk is ever named `.claude` for a normal `filter_entry` check to
    /// catch; before this fix, that meant a `.gitignore` line of `.claude/`
    /// had no effect at all.
    #[test]
    fn a_gitignore_rule_still_drops_the_dot_claude_directory_root() {
        let dir = tree(&["visible.rs", ".claude/skills/x/SKILL.md"]);
        fs::write(dir.path().join(".gitignore"), ".claude/\n").unwrap();

        let walked = collect_files(dir.path(), &WalkOptions::default()).unwrap();

        assert_eq!(as_strings(&walked.files), ["visible.rs"]);
        assert!(
            walked
                .skipped
                .iter()
                .any(|entry| entry.line().contains(".claude")),
            "the exclusion must be reported, not silent: {:#?}",
            walked.skipped
        );
    }

    /// Same gap, for `.github/workflows/` instead of `.claude/` — it is the
    /// walk root of its own sub-walk two levels below the scan root rather
    /// than one, so the fix has to reach it too.
    #[test]
    fn a_gitignore_rule_still_drops_the_dot_github_workflows_directory_root() {
        let dir = tree(&["visible.rs", ".github/workflows/ci.yml"]);
        fs::write(dir.path().join(".gitignore"), ".github/workflows/\n").unwrap();

        let walked = collect_files(dir.path(), &WalkOptions::default()).unwrap();

        assert_eq!(as_strings(&walked.files), ["visible.rs"]);
        assert!(
            walked
                .skipped
                .iter()
                .any(|entry| entry.line().contains(".github/workflows")),
            "the exclusion must be reported, not silent: {:#?}",
            walked.skipped
        );
    }

    /// The same gap exists for `.bastynignore`, not just `.gitignore` — both
    /// are "a respected ignore file" as far as the probe this fix adds is
    /// concerned.
    #[test]
    fn a_bastynignore_rule_still_drops_the_dot_claude_directory_root() {
        let dir = tree(&["visible.rs", ".claude/skills/x/SKILL.md"]);
        fs::write(dir.path().join(".bastynignore"), ".claude/\n").unwrap();

        let walked = collect_files(dir.path(), &WalkOptions::default()).unwrap();

        assert_eq!(as_strings(&walked.files), ["visible.rs"]);
        assert!(
            walked
                .skipped
                .iter()
                .any(|entry| entry.line().contains(".claude")),
            "the exclusion must be reported, not silent: {:#?}",
            walked.skipped
        );
    }

    /// `--no-ignore` (`respect_ignore_files: false`) turns off ignore-file
    /// handling everywhere else in this module; the new probe has to honour
    /// that too, or a caller who explicitly asked for ignore files to be
    /// ignored would find `.claude/` disappearing anyway.
    #[test]
    fn disabling_ignore_files_also_disables_the_directory_root_probe() {
        let dir = tree(&["visible.rs", ".claude/skills/x/SKILL.md"]);
        fs::write(dir.path().join(".gitignore"), ".claude/\n").unwrap();

        let options = WalkOptions {
            respect_ignore_files: false,
            ..WalkOptions::default()
        };
        let files = collect_files(dir.path(), &options).unwrap().files;

        assert_eq!(
            as_strings(&files),
            [".claude/skills/x/SKILL.md", "visible.rs"]
        );
    }

    /// `--hidden` already includes everything; the allowlist pass must not
    /// run redundantly on top of it, and the result must be identical to
    /// what `include_hidden: true` produced before this change.
    #[test]
    fn hidden_flag_behaves_exactly_as_before_with_or_without_allowlisted_paths() {
        let dir = tree(&[
            "visible.rs",
            ".env",
            ".mcp.json",
            ".claude/skills/deploy/SKILL.md",
            ".github/workflows/ci.yml",
            ".some_random_hidden_file",
        ]);

        let options = WalkOptions {
            include_hidden: true,
            ..WalkOptions::default()
        };
        let files = collect_files(dir.path(), &options).unwrap().files;

        assert_eq!(
            as_strings(&files),
            [
                ".claude/skills/deploy/SKILL.md",
                ".env",
                ".github/workflows/ci.yml",
                ".mcp.json",
                ".some_random_hidden_file",
                "visible.rs",
            ]
        );
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

    /// `.claude/.bastynignore` sits directly at the *root* of `.claude/`'s
    /// own scoped sub-walk — the same reason [`collect_files`] has to call
    /// [`note_bastynignore`] for the scan root by hand instead of relying on
    /// `filter_entry`, applied one level down. The exclusion of `fixtures/`
    /// itself was never in doubt: the scoped walker already honours a
    /// `.bastynignore` sitting at its own root the same way the main walk
    /// honours one at the scan root. Only its *visibility* in
    /// [`Traversal::skipped`] was missing before this fix — mirroring
    /// `a_nested_bastynignore_applies_to_its_own_directory` above, but for a
    /// `.bastynignore` inside an allowlisted directory root rather than an
    /// ordinarily-walked one.
    ///
    /// `.claude/.bastynignore` itself shows up in `files`: unlike the scan
    /// root, `.claude/`'s sub-walk always includes hidden entries (see
    /// [`walk_scoped`]'s doc comment), and nothing about honouring a
    /// `.bastynignore`'s patterns excludes the file that declares them.
    #[test]
    fn a_bastynignore_directly_inside_dot_claude_is_reported() {
        let dir = tree(&[".claude/fixtures/x.py", ".claude/skills/y.py"]);
        fs::write(dir.path().join(".claude/.bastynignore"), "fixtures/\n").unwrap();

        let walked = collect_files(dir.path(), &WalkOptions::default()).unwrap();

        assert_eq!(
            as_strings(&walked.files),
            [".claude/.bastynignore", ".claude/skills/y.py"]
        );
        assert!(
            walked
                .skipped
                .iter()
                .any(|entry| entry.line().starts_with(".claude/.bastynignore \u{2014}")),
            "the top-level .bastynignore inside .claude/ must be reported, not silent: {:#?}",
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

    /// The allowlist pass runs its own extra walks on top of the main one;
    /// this confirms that does not introduce any nondeterminism into the
    /// merged, deduplicated result.
    #[test]
    fn the_traversal_is_identical_on_repeated_runs_with_allowlisted_paths() {
        let dir = tree(&[
            "b.py",
            "a.py",
            ".env",
            ".mcp.json",
            ".claude/skills/deploy/SKILL.md",
            ".github/workflows/ci.yml",
            "x/one.js",
        ]);
        fs::write(dir.path().join(".bastynignore"), "x/\n").unwrap();

        let options = WalkOptions::default();
        let first = collect_files(dir.path(), &options).unwrap();
        for _ in 0..4 {
            assert_eq!(collect_files(dir.path(), &options).unwrap(), first);
        }
        assert_eq!(
            as_strings(&first.files),
            [
                ".claude/skills/deploy/SKILL.md",
                ".env",
                ".github/workflows/ci.yml",
                ".mcp.json",
                "a.py",
                "b.py",
            ]
        );
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

    /// `--max-depth` counts levels below the *scan root*, not below whatever
    /// directory a particular sub-walk happens to be rooted at. `.claude/`
    /// itself sits one level below the scan root, so with `max_depth:
    /// Some(1)` the local depth budget handed to its sub-walk is
    /// `depth_below(Some(1), 1) == Some(0)`: the sub-walk may see `.claude/`
    /// itself but nothing inside it. That holds regardless of how deep
    /// inside `.claude/` a file sits — both `.claude/README.md` (one level
    /// below `.claude/`, so two below the scan root) and
    /// `.claude/skills/deploy/SKILL.md` (three levels below `.claude/`, so
    /// four below the scan root) are past a scan-root depth of `1`, exactly
    /// as an ordinary file at that same absolute depth would be. The
    /// allowlist widens *which* paths are covered; it must never widen *how
    /// deep* `--max-depth` is allowed to reach.
    #[test]
    fn max_depth_limits_descent_into_the_allowlisted_dot_claude_directory() {
        let dir = tree(&[
            "top.rs",
            ".claude/README.md",
            ".claude/skills/deploy/SKILL.md",
        ]);

        let options = WalkOptions {
            max_depth: Some(1),
            ..WalkOptions::default()
        };
        let files = collect_files(dir.path(), &options).unwrap().files;

        assert_eq!(as_strings(&files), ["top.rs"]);
    }

    /// `max_depth: None` (the default, unlimited) must behave exactly as it
    /// did before this fix: an unbounded scan still reaches arbitrarily deep
    /// files under `.claude/` and `.github/workflows/`, since
    /// `depth_below(None, _)` stays `None`.
    #[test]
    fn max_depth_none_still_reaches_deeply_nested_allowlisted_paths() {
        let dir = tree(&[
            "top.rs",
            ".claude/skills/deploy/nested/very/deep/SKILL.md",
            ".github/workflows/nested/deep/ci.yml",
        ]);

        let files = collect_files(dir.path(), &WalkOptions::default())
            .unwrap()
            .files;

        assert_eq!(
            as_strings(&files),
            [
                ".claude/skills/deploy/nested/very/deep/SKILL.md",
                ".github/workflows/nested/deep/ci.yml",
                "top.rs",
            ]
        );
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
