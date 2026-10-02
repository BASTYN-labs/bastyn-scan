//! A stable, opaque identifier for the project a scan belongs to.
//!
//! The identifier lets scans of the same repository, run from different
//! machines or CI runners, group together without the repository's name or
//! location ever appearing in clear. It is the SHA-256 of a fixed prefix and a
//! normalised string, so it cannot be reversed into a name, and the prefix
//! never depends on anything read from the scanned tree.
//!
//! # Where the identifier comes from
//!
//! 1. **The git remote.** The repository containing the scan root is found by
//!    walking up to the nearest `.git`, and its `origin` remote (or its only
//!    remote) is normalised to `host/owner/repo`. Ssh and https spellings of
//!    the same remote therefore give the same identifier.
//! 2. **CI variables.** When no usable remote exists (a shallow export, a
//!    tarball, a checkout with no remote), the CI provider's own repository
//!    variables are used instead.
//! 3. **A stored random value.** Otherwise a random 128-bit value is kept in
//!    the user state directory, keyed by a hash of the scan root's path. It
//!    identifies the project on this machine only.
//!
//! # Untrusted input
//!
//! This code runs against repositories that may be hostile. The git
//! configuration is read as plain data and parsed by a small, strict subset
//! parser; the `git` binary is never run, because a repository's config can
//! name programs (`core.fsmonitor`, `core.sshCommand`, and others) that git
//! would execute. `include`, `includeIf`, `url.<base>.insteadOf` and
//! `pushurl` are ignored on purpose: each would let the repository rewrite the
//! value that gets hashed.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::state::write_private;

/// Prefix hashed in front of a normalised remote.
const REMOTE_PREFIX: &str = "bastyn-project-v1:";
/// Prefix hashed in front of a stored random value.
const LOCAL_PREFIX: &str = "bastyn-project-v1-local:";
/// Largest git config that is read. Anything larger yields no remote.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// Largest `.git` pointer or `commondir` file that is read.
const MAX_POINTER_BYTES: u64 = 4096;
/// Largest stored local identifier file that is read.
const MAX_LOCAL_BYTES: u64 = 1024;
/// Length of the stored random value, in hex characters.
const LOCAL_HEX_LEN: usize = 32;

/// How a project identifier was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdSource {
    /// Derived from a repository remote, either from git config or from CI
    /// variables. Stable across machines.
    Remote,
    /// Derived from a random value stored on this machine. Stable on this
    /// machine only.
    Local,
}

impl IdSource {
    /// The lowercase name used in reports: `remote` or `local`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Remote => "remote",
            Self::Local => "local",
        }
    }
}

/// A human-readable account of how an identifier was derived, so a user can
/// check exactly what was hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// The exact string that was hashed, prefix included. For a local
    /// identifier this is the description `stored random ID`, never the
    /// secret value itself.
    pub hashed: String,
    /// A sentence saying where the input came from, such as the config file
    /// or the CI variables that were read.
    pub origin: String,
}

/// A derived project identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectId {
    /// 64 lowercase hex characters.
    pub id: String,
    /// Whether the identifier is remote-derived or local.
    pub source: IdSource,
    /// How the identifier was derived.
    pub explanation: Explanation,
}

/// Everything [`resolve`] reads. The environment is injected so tests never
/// depend on the real one.
pub struct Inputs<'a> {
    /// The directory being scanned. Need not be the repository root.
    pub scan_root: &'a Path,
    /// Environment lookup, used for the CI fallback.
    pub env: &'a dyn Fn(&str) -> Option<OsString>,
    /// The user state directory (see [`super::state::state_dir`]), if any.
    pub state_dir: Option<&'a Path>,
    /// Whether a missing local identifier may be created. When `false`,
    /// resolution never writes anything.
    pub create_local: bool,
}

/// The outcome of [`resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// An identifier was derived (or read back).
    Resolved(ProjectId),
    /// The project has no remote, no local identifier exists yet and
    /// `create_local` was `false`.
    LocalNotCreated,
    /// No identifier can be produced; the string says why.
    Unavailable(String),
}

/// Derives the project identifier for `inputs.scan_root`.
///
/// Tries the git remote, then CI variables, then the stored local identifier,
/// in that order. The CI variables are consulted only when the git config
/// yielded nothing, so a checkout's own remote always wins over the
/// environment. Never panics and never invents an identifier: any I/O
/// failure on the local path is reported as [`Resolution::Unavailable`].
#[must_use]
pub fn resolve(inputs: &Inputs<'_>) -> Resolution {
    if let Some((normalised, origin)) = remote_from_git(inputs.scan_root) {
        return Resolution::Resolved(remote_id(&normalised, origin));
    }
    if let Some((normalised, origin)) = remote_from_ci(inputs.env) {
        return Resolution::Resolved(remote_id(&normalised, origin));
    }
    resolve_local(inputs)
}

/// Normalises a git remote URL to `host/owner/repo` (lowercase), or `None`
/// when it is not a recognised remote.
///
/// Accepts `https`, `http`, `ssh` and `git` URLs and scp-like
/// `[user@]host:path` forms. Credentials, ports, queries, fragments, trailing
/// slashes and a trailing `.git` are dropped. Local paths, `file://` URLs,
/// values containing `%`, whitespace or control characters, and hosts outside
/// the known set (GitHub, GitLab, Bitbucket, Azure DevOps) give `None`. Every
/// Azure DevOps spelling maps to `dev.azure.com/{org}/{project}/{repo}`.
#[must_use]
pub fn normalise_remote(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty()
        || raw
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '%')
    {
        return None;
    }
    let (host, path) = split_remote(raw)?;
    let host = host.to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    if !valid_host(host) {
        return None;
    }

    let path = path.split(['?', '#']).next().unwrap_or_default();
    let path = path.to_ascii_lowercase();
    let path = path.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let segments: Vec<&str> = path.split('/').collect();
    if !clean_segments(&segments) {
        return None;
    }

    match host {
        "github.com" | "bitbucket.org" => {
            (segments.len() == 2).then(|| format!("{host}/{}", segments.join("/")))
        }
        "gitlab.com" => {
            // `/-/` separates the project from web-UI routes such as
            // `/-/tree/main`; nothing after it names the repository.
            let kept = segments
                .iter()
                .position(|segment| *segment == "-")
                .map_or(&segments[..], |at| &segments[..at]);
            (kept.len() >= 2).then(|| format!("{host}/{}", kept.join("/")))
        }
        "dev.azure.com" => match segments.as_slice() {
            [org, project, "_git", repo] => Some(azure(org, project, repo)),
            _ => None,
        },
        "ssh.dev.azure.com" | "vs-ssh.visualstudio.com" => match segments.as_slice() {
            ["v3", org, project, repo] => Some(azure(org, project, repo)),
            _ => None,
        },
        _ => {
            let org = host.strip_suffix(".visualstudio.com")?;
            if org.is_empty() || org.contains('.') {
                return None;
            }
            match segments.as_slice() {
                [project, "_git", repo] | ["defaultcollection", project, "_git", repo] => {
                    Some(azure(org, project, repo))
                }
                _ => None,
            }
        }
    }
}

fn azure(org: &str, project: &str, repo: &str) -> String {
    format!("dev.azure.com/{org}/{project}/{repo}")
}

/// Splits a remote into `(host, path)`, with credentials and port removed.
fn split_remote(raw: &str) -> Option<(String, String)> {
    if let Some((scheme, rest)) = raw.split_once("://") {
        if !matches!(
            scheme.to_ascii_lowercase().as_str(),
            "https" | "http" | "ssh" | "git"
        ) {
            return None;
        }
        let (authority, path) = rest.split_once('/')?;
        let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let host = match host_port.rsplit_once(':') {
            Some((host, port)) => {
                if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                host
            }
            None => host_port,
        };
        return Some((host.to_owned(), path.to_owned()));
    }

    // Local paths are never remotes. A Windows drive letter would otherwise
    // read as a one-letter scp host, which `scp_split` also rejects.
    if raw.starts_with(['/', '.', '\\', '~']) {
        return None;
    }
    let colon = raw.find(':')?;
    if raw.find('/').is_some_and(|slash| slash < colon) {
        return None;
    }
    let host_part = &raw[..colon];
    let host = host_part.rsplit_once('@').map_or(host_part, |(_, h)| h);
    if host.len() < 2 {
        return None;
    }
    let path = &raw[colon + 1..];
    let path = path.strip_prefix('/').unwrap_or(path);
    Some((host.to_owned(), path.to_owned()))
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// True when every segment is non-empty, is not `.` or `..`, and has no
/// backslash.
fn clean_segments(segments: &[&str]) -> bool {
    segments
        .iter()
        .all(|s| !s.is_empty() && *s != "." && *s != ".." && !s.contains('\\'))
}

fn remote_id(normalised: &str, origin: String) -> ProjectId {
    let hashed = format!("{REMOTE_PREFIX}{normalised}");
    ProjectId {
        id: sha256_hex(&[hashed.as_bytes()]),
        source: IdSource::Remote,
        explanation: Explanation { hashed, origin },
    }
}

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    to_hex(&hasher.finalize())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// Git config, read as data
// ---------------------------------------------------------------------------

/// The normalised remote of the repository containing `scan_root`, and a
/// sentence describing where it was read from.
fn remote_from_git(scan_root: &Path) -> Option<(String, String)> {
    let config = find_git_config(scan_root)?;
    let text = read_capped(&config, MAX_CONFIG_BYTES)?;
    let remotes = parse_remotes(&text);
    let (name, url) = choose_remote(&remotes)?;
    let normalised = normalise_remote(url)?;
    let origin = format!("remote '{name}' in {}", config.display());
    Some((normalised, origin))
}

/// Locates the git config for the repository containing `scan_root`.
///
/// Walks the canonical scan root and its ancestors for the first `.git`
/// entry. A `.git` file (worktrees, submodules) is followed through its
/// `gitdir:` pointer, and a `commondir` file redirects to the shared config.
fn find_git_config(scan_root: &Path) -> Option<PathBuf> {
    let canonical = fs::canonicalize(scan_root).ok()?;
    for ancestor in canonical.ancestors() {
        let dot_git = ancestor.join(".git");
        let Ok(meta) = fs::metadata(&dot_git) else {
            continue;
        };
        let git_dir = if meta.is_dir() {
            dot_git
        } else if meta.is_file() {
            let text = read_capped(&dot_git, MAX_POINTER_BYTES)?;
            let target = text.lines().next()?.strip_prefix("gitdir:")?.trim();
            if target.is_empty() {
                return None;
            }
            ancestor.join(target)
        } else {
            return None;
        };
        let config_dir = match read_capped(&git_dir.join("commondir"), MAX_POINTER_BYTES) {
            Some(text) if !text.trim().is_empty() => git_dir.join(text.trim()),
            _ => git_dir,
        };
        return Some(config_dir.join("config"));
    }
    None
}

/// Reads a regular file of at most `cap` bytes as UTF-8. Anything else
/// (missing, a pipe or device, too large, not UTF-8) is `None`.
fn read_capped(path: &Path, cap: u64) -> Option<String> {
    // A named pipe would block on open, so only regular files are read.
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > cap {
        return None;
    }
    let mut buf = Vec::new();
    File::open(path)
        .ok()?
        .take(cap.saturating_add(1))
        .read_to_end(&mut buf)
        .ok()?;
    if u64::try_from(buf.len()).ok()? > cap {
        return None;
    }
    String::from_utf8(buf).ok()
}

/// The `(name, first url)` of each `[remote "name"]` section, in file order.
///
/// Only `url` keys inside `remote` sections are read; every other section and
/// key is skipped.
fn parse_remotes(config: &str) -> Vec<(String, String)> {
    let mut remotes: Vec<(String, String)> = Vec::new();
    let mut current: Option<String> = None;
    for line in config.lines() {
        let line = line.trim();
        let body = if line.starts_with('[') {
            let (section, rest) = parse_header(line);
            current = section;
            rest
        } else {
            line
        };
        if body.is_empty() || body.starts_with(['#', ';']) {
            continue;
        }
        let Some(name) = &current else { continue };
        let Some((key, value)) = body.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("url") && !remotes.iter().any(|(seen, _)| seen == name) {
            remotes.push((name.clone(), clean_value(value)));
        }
    }
    remotes
}

/// Parses `[section "subsection"] rest`. Returns the remote name when the
/// section is a `remote` section, and whatever follows the closing bracket
/// (git allows a key on the header line).
fn parse_header(line: &str) -> (Option<String>, &str) {
    let inner = &line[1..];
    let name_end = inner
        .find(|c: char| c.is_whitespace() || c == ']' || c == '"')
        .unwrap_or(inner.len());
    let (name, after) = inner.split_at(name_end);
    let after = after.trim_start();
    if let Some(quoted) = after.strip_prefix('"') {
        let mut subsection = String::new();
        let mut chars = quoted.char_indices();
        let mut end = None;
        while let Some((at, c)) = chars.next() {
            match c {
                '\\' => {
                    if let Some((_, escaped)) = chars.next() {
                        subsection.push(escaped);
                    }
                }
                '"' => {
                    end = Some(at + 1);
                    break;
                }
                _ => subsection.push(c),
            }
        }
        let Some(end) = end else { return (None, "") };
        let Some(rest) = quoted[end..].trim_start().strip_prefix(']') else {
            return (None, "");
        };
        (
            name.eq_ignore_ascii_case("remote").then_some(subsection),
            rest.trim_start(),
        )
    } else if let Some(rest) = after.strip_prefix(']') {
        (None, rest.trim_start())
    } else {
        (None, "")
    }
}

/// A config value with quotes removed and any trailing ` #` or ` ;` comment
/// dropped. A comment marker only counts outside quotes and after whitespace,
/// so a `#` inside a URL is kept.
fn clean_value(raw: &str) -> String {
    let mut out = String::new();
    let mut in_quote = false;
    let mut previous_blank = true;
    let mut chars = raw.trim().chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => in_quote = !in_quote,
            '\\' => {
                if let Some(escaped) = chars.next() {
                    out.push(escaped);
                }
            }
            '#' | ';' if !in_quote && previous_blank => break,
            _ => out.push(c),
        }
        previous_blank = c.is_whitespace();
    }
    out.trim().to_owned()
}

/// `origin` if present, else the only remote, else none.
fn choose_remote(remotes: &[(String, String)]) -> Option<(&str, &str)> {
    fn pick(remote: &(String, String)) -> (&str, &str) {
        (remote.0.as_str(), remote.1.as_str())
    }
    if let Some(origin) = remotes.iter().find(|(name, _)| name == "origin") {
        return Some(pick(origin));
    }
    match remotes {
        [only] => Some(pick(only)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// CI fallback
// ---------------------------------------------------------------------------

/// A remote built from the CI provider's own variables.
///
/// The host comes from the provider, so any host is accepted (self-hosted
/// instances), but the repository path must still be clean.
fn remote_from_ci(env: &dyn Fn(&str) -> Option<OsString>) -> Option<(String, String)> {
    let get = |name: &str| {
        env(name)
            .and_then(|value| value.into_string().ok())
            .filter(|value| !value.is_empty())
    };
    if let (Some(server), Some(repository)) = (get("GITHUB_SERVER_URL"), get("GITHUB_REPOSITORY"))
        && let Some(host) = server_host(&server)
        && let Some(normalised) = ci_remote(&host, &repository, |count| count == 2)
    {
        return Some((
            normalised,
            "GITHUB_SERVER_URL and GITHUB_REPOSITORY".to_owned(),
        ));
    }
    if let (Some(host), Some(path)) = (get("CI_SERVER_HOST"), get("CI_PROJECT_PATH"))
        && let Some(host) = bare_host(&host)
        && let Some(normalised) = ci_remote(&host, &path, |count| count >= 2)
    {
        return Some((normalised, "CI_SERVER_HOST and CI_PROJECT_PATH".to_owned()));
    }
    None
}

/// The lowercase host of an `http(s)` server URL.
fn server_host(url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))?;
    bare_host(rest.split('/').next().unwrap_or_default())
}

/// A lowercase host with an optional numeric port removed.
fn bare_host(host_port: &str) -> Option<String> {
    let host_port = host_port.to_ascii_lowercase();
    let host = match host_port.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        Some(_) => return None,
        None => &host_port,
    };
    valid_host(host).then(|| host.to_owned())
}

fn ci_remote(host: &str, path: &str, count_ok: impl Fn(usize) -> bool) -> Option<String> {
    if path
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '%')
    {
        return None;
    }
    let segments: Vec<&str> = path.split('/').collect();
    if !clean_segments(&segments) || !count_ok(segments.len()) {
        return None;
    }
    Some(format!("{host}/{path}").to_ascii_lowercase())
}

// ---------------------------------------------------------------------------
// Local identifier
// ---------------------------------------------------------------------------

fn resolve_local(inputs: &Inputs<'_>) -> Resolution {
    let Some(state_dir) = inputs.state_dir else {
        return Resolution::Unavailable("no user state directory".to_owned());
    };
    let root = match fs::canonicalize(inputs.scan_root) {
        Ok(root) => root,
        Err(error) => {
            return Resolution::Unavailable(format!("cannot resolve the scan root: {error}"));
        }
    };
    // The file is named by a hash so the project's path is never written in
    // clear.
    let file = state_dir
        .join("local-projects")
        .join(sha256_hex(&[&path_bytes(&root)]));

    let stored = match read_stored(&file) {
        Ok(stored) => stored,
        Err(error) => {
            return Resolution::Unavailable(format!("cannot read {}: {error}", file.display()));
        }
    };
    let value = if let Some(value) = stored {
        value
    } else if inputs.create_local {
        let mut random = [0u8; LOCAL_HEX_LEN / 2];
        if let Err(error) = getrandom::fill(&mut random) {
            return Resolution::Unavailable(format!("no source of randomness: {error}"));
        }
        let value = to_hex(&random);
        if let Err(error) = write_private(&file, value.as_bytes()) {
            return Resolution::Unavailable(format!("cannot write {}: {error}", file.display()));
        }
        value
    } else {
        return Resolution::LocalNotCreated;
    };

    Resolution::Resolved(ProjectId {
        id: sha256_hex(&[LOCAL_PREFIX.as_bytes(), value.as_bytes()]),
        source: IdSource::Local,
        explanation: Explanation {
            hashed: "stored random ID".to_owned(),
            origin: format!("random ID stored at {}", file.display()),
        },
    })
}

/// The stored value, `None` when the file is missing or its content is not
/// 32 lowercase hex characters. Other I/O failures are errors.
fn read_stored(file: &Path) -> io::Result<Option<String>> {
    let handle = match File::open(file) {
        Ok(handle) => handle,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut buf = Vec::new();
    handle.take(MAX_LOCAL_BYTES).read_to_end(&mut buf)?;
    let valid = String::from_utf8(buf)
        .ok()
        .map(|text| text.trim().to_owned());
    Ok(valid.filter(|text| {
        text.len() == LOCAL_HEX_LEN
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }))
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().to_string_lossy().into_owned().into_bytes()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::format_push_string,
    reason = "a failed assumption in a test should fail the test, and the table tests are long by nature"
)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    /// SHA-256 of `bastyn-project-v1:github.com/acme/xpto`, computed with an
    /// independent implementation (python3 hashlib).
    const ACME_XPTO_ID: &str = "5d8e2a2195b216f9eebd1ff02ac986850af0c8d464335b8a4b6429a7f56241f6";

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        move |name| {
            owned
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    fn write(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// A directory containing `.git/config` with the given text.
    fn repo(config: &str) -> TempDir {
        let dir = TempDir::new().unwrap();
        write(&dir.path().join(".git/config"), config);
        dir
    }

    fn origin(url: &str) -> String {
        format!("[remote \"origin\"]\n\turl = {url}\n")
    }

    fn resolve_in(
        root: &Path,
        env: &[(&str, &str)],
        state: Option<&Path>,
        create_local: bool,
    ) -> Resolution {
        let env = env_of(env);
        resolve(&Inputs {
            scan_root: root,
            env: &env,
            state_dir: state,
            create_local,
        })
    }

    fn remote_id_of(root: &Path) -> String {
        match resolve_in(root, &[], None, false) {
            Resolution::Resolved(id) => {
                assert_eq!(id.source, IdSource::Remote);
                id.id
            }
            other => panic!("expected a remote id, got {other:?}"),
        }
    }

    fn local_id_of(root: &Path, state: &Path) -> ProjectId {
        match resolve_in(root, &[], Some(state), true) {
            Resolution::Resolved(id) => {
                assert_eq!(id.source, IdSource::Local);
                id
            }
            other => panic!("expected a local id, got {other:?}"),
        }
    }

    // --- known answer ------------------------------------------------------

    #[test]
    fn remote_id_matches_independently_computed_digest() {
        let dir = repo(&origin("https://github.com/acme/xpto.git"));
        assert_eq!(remote_id_of(dir.path()), ACME_XPTO_ID);
    }

    #[test]
    fn explanation_carries_the_exact_hashed_string() {
        let dir = repo(&origin("git@github.com:Acme/Xpto.git"));
        let Resolution::Resolved(id) = resolve_in(dir.path(), &[], None, false) else {
            panic!("expected a resolved id");
        };
        assert_eq!(
            id.explanation.hashed,
            "bastyn-project-v1:github.com/acme/xpto"
        );
        assert!(id.explanation.origin.contains("origin"));
    }

    // --- normalisation -----------------------------------------------------

    #[test]
    fn normalisation_table() {
        let azure = Some("dev.azure.com/org/project/repo");
        let cases: &[(&str, Option<&str>)] = &[
            // GitHub
            ("https://github.com/acme/xpto", Some("github.com/acme/xpto")),
            (
                "https://github.com/Acme/Xpto.git",
                Some("github.com/acme/xpto"),
            ),
            (
                "https://github.com/acme/xpto.git/",
                Some("github.com/acme/xpto"),
            ),
            (
                "http://www.github.com/acme/xpto/",
                Some("github.com/acme/xpto"),
            ),
            ("git@github.com:Acme/Xpto.git", Some("github.com/acme/xpto")),
            ("github.com:acme/xpto", Some("github.com/acme/xpto")),
            (
                "ssh://git@github.com/acme/xpto.git",
                Some("github.com/acme/xpto"),
            ),
            (
                "ssh://git@github.com:22/acme/xpto.git",
                Some("github.com/acme/xpto"),
            ),
            (
                "git://github.com/acme/xpto.git",
                Some("github.com/acme/xpto"),
            ),
            (
                "https://github.com:443/acme/xpto?tab=1#frag",
                Some("github.com/acme/xpto"),
            ),
            (
                "https://x-access-token:SECRET@github.com/Acme/Xpto.git",
                Some("github.com/acme/xpto"),
            ),
            ("https://github.com/acme", None),
            ("https://github.com/acme/xpto/extra", None),
            ("https://github.com/acme//xpto", None),
            ("https://github.com/acme/..", None),
            // GitLab
            (
                "https://gitlab.com/Group/Repo.git",
                Some("gitlab.com/group/repo"),
            ),
            (
                "https://gitlab.com/g/sub/Repo.git",
                Some("gitlab.com/g/sub/repo"),
            ),
            (
                "git@gitlab.com:g/sub/sub2/repo.git",
                Some("gitlab.com/g/sub/sub2/repo"),
            ),
            (
                "https://gitlab.com/g/repo/-/tree/main",
                Some("gitlab.com/g/repo"),
            ),
            (
                "ssh://git@gitlab.com:2222/g/repo.git",
                Some("gitlab.com/g/repo"),
            ),
            ("https://gitlab.com/solo", None),
            // Bitbucket
            (
                "https://user@bitbucket.org/Team/Repo.git",
                Some("bitbucket.org/team/repo"),
            ),
            (
                "git@bitbucket.org:team/repo.git",
                Some("bitbucket.org/team/repo"),
            ),
            ("https://bitbucket.org/team/repo/extra", None),
            // Azure DevOps: every spelling is the same string
            ("https://dev.azure.com/Org/Project/_git/Repo", azure),
            ("https://Org@dev.azure.com/Org/Project/_git/Repo", azure),
            ("https://org.visualstudio.com/Project/_git/Repo", azure),
            (
                "https://org.visualstudio.com/DefaultCollection/Project/_git/Repo",
                azure,
            ),
            ("git@ssh.dev.azure.com:v3/Org/Project/Repo", azure),
            ("ssh://git@ssh.dev.azure.com/v3/org/project/repo", azure),
            ("org@vs-ssh.visualstudio.com:v3/org/project/repo", azure),
            ("https://dev.azure.com/org/_git/repo", None),
            ("https://dev.azure.com/org/project/repo", None),
            ("git@ssh.dev.azure.com:v3/org/repo", None),
            // Unknown hosts and unusable values
            ("https://git.example.com/acme/xpto", None),
            ("git@example.com:acme/xpto.git", None),
            ("ftp://github.com/acme/xpto", None),
            ("", None),
            ("/srv/git/repo.git", None),
            ("./repo", None),
            ("../repo", None),
            ("file:///srv/repo", None),
            ("C:\\repo", None),
            ("C:/repo", None),
            ("https://github.com/acme/xp%20to", None),
            ("https://github.com/acme/ xpto", None),
            ("https://github.com/acme/x\u{7}pto", None),
            ("https://github.com:abc/acme/xpto", None),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                normalise_remote(raw).as_deref(),
                *expected,
                "normalising {raw:?}"
            );
        }
    }

    #[test]
    fn credentials_never_reach_the_result() {
        let result =
            normalise_remote("https://x-access-token:SECRET@github.com/Acme/Xpto.git").unwrap();
        assert!(!result.to_ascii_lowercase().contains("secret"));
        assert!(!result.contains("token"));
    }

    // --- remote resolution -------------------------------------------------

    #[test]
    fn ssh_and_https_spellings_give_the_same_id() {
        let ssh = repo(&origin("git@github.com:Acme/Xpto.git"));
        let https = repo(&origin("https://github.com/acme/xpto"));
        assert_eq!(remote_id_of(ssh.path()), remote_id_of(https.path()));
    }

    #[test]
    fn a_subdirectory_uses_the_repository_id() {
        let dir = repo(&origin("https://github.com/acme/xpto"));
        let sub = dir.path().join("src/deep");
        fs::create_dir_all(&sub).unwrap();
        assert_eq!(remote_id_of(&sub), ACME_XPTO_ID);
    }

    #[test]
    fn origin_is_preferred_over_other_remotes() {
        let dir = repo(
            "[remote \"upstream\"]\n\turl = https://github.com/other/repo\n\
             [remote \"origin\"]\n\turl = https://github.com/acme/xpto\n",
        );
        assert_eq!(remote_id_of(dir.path()), ACME_XPTO_ID);
    }

    #[test]
    fn a_single_non_origin_remote_is_used() {
        let dir = repo("[remote \"fork\"]\n\turl = https://github.com/acme/xpto\n");
        assert_eq!(remote_id_of(dir.path()), ACME_XPTO_ID);
    }

    #[test]
    fn two_non_origin_remotes_fall_through() {
        let dir = repo(
            "[remote \"a\"]\n\turl = https://github.com/acme/one\n\
             [remote \"b\"]\n\turl = https://github.com/acme/two\n",
        );
        assert_eq!(
            resolve_in(dir.path(), &[], None, false),
            Resolution::Unavailable("no user state directory".to_owned())
        );
    }

    #[test]
    fn an_unusable_origin_url_yields_nothing() {
        let dir = repo(&origin("https://git.example.com/acme/xpto"));
        assert_eq!(
            resolve_in(dir.path(), &[], None, false),
            Resolution::Unavailable("no user state directory".to_owned())
        );
    }

    #[test]
    fn config_syntax_variants_are_understood() {
        let dir = repo(
            "# comment\n[REMOTE \"origin\"] ; trailing\n\tURL = \"https://github.com/acme/xpto\" # note\n",
        );
        assert_eq!(remote_id_of(dir.path()), ACME_XPTO_ID);
    }

    #[test]
    fn first_url_of_a_remote_wins() {
        let dir = repo(
            "[remote \"origin\"]\n\turl = https://github.com/acme/xpto\n\turl = https://github.com/acme/other\n",
        );
        assert_eq!(remote_id_of(dir.path()), ACME_XPTO_ID);
    }

    #[test]
    fn hostile_config_is_read_as_data_only() {
        let marker_dir = TempDir::new().unwrap();
        let marker = marker_dir.path().join("marker");
        let included = marker_dir.path().join("included.cfg");
        write(
            &included,
            "[remote \"origin\"]\n\turl = https://github.com/evil/included\n",
        );
        let config = format!(
            "[core]\n\tfsmonitor = touch {marker}\n\tsshCommand = touch {marker}\n\
             [include]\n\tpath = {included}\n\
             [includeIf \"gitdir:/\"]\n\tpath = {included}\n\
             [url \"https://evil.example/\"]\n\tinsteadOf = https://github.com/\n\
             [remote \"origin\"]\n\turl = https://github.com/acme/xpto\n\
             \tpushurl = https://github.com/evil/pushed\n",
            marker = marker.display(),
            included = included.display(),
        );
        let dir = repo(&config);
        assert_eq!(remote_id_of(dir.path()), ACME_XPTO_ID);
        assert!(!marker.exists(), "nothing from the config may be executed");
    }

    #[test]
    fn an_include_alone_does_not_supply_a_remote() {
        let extra = TempDir::new().unwrap();
        let included = extra.path().join("included.cfg");
        write(
            &included,
            "[remote \"origin\"]\n\turl = https://github.com/evil/included\n",
        );
        let dir = repo(&format!("[include]\n\tpath = {}\n", included.display()));
        assert_eq!(
            resolve_in(dir.path(), &[], None, false),
            Resolution::Unavailable("no user state directory".to_owned())
        );
    }

    #[test]
    fn worktree_layout_reads_the_common_config() {
        let root = TempDir::new().unwrap();
        let main = root.path().join("main");
        write(
            &main.join(".git/config"),
            &origin("https://github.com/acme/xpto"),
        );
        let admin = main.join(".git/worktrees/wt");
        write(&admin.join("commondir"), "../..\n");
        // A decoy config in the per-worktree directory must be ignored.
        write(
            &admin.join("config"),
            &origin("https://github.com/decoy/decoy"),
        );
        let worktree = root.path().join("wt");
        write(
            &worktree.join(".git"),
            &format!("gitdir: {}\n", admin.display()),
        );
        assert_eq!(remote_id_of(&worktree), ACME_XPTO_ID);
    }

    #[test]
    fn relative_gitdir_pointer_is_resolved_against_the_pointer_file() {
        let root = TempDir::new().unwrap();
        write(
            &root.path().join("main/.git/config"),
            &origin("https://github.com/acme/xpto"),
        );
        write(
            &root.path().join("main/.git/worktrees/wt/commondir"),
            "../..",
        );
        let worktree = root.path().join("main/wt");
        write(&worktree.join(".git"), "gitdir: ../.git/worktrees/wt\n");
        assert_eq!(remote_id_of(&worktree), ACME_XPTO_ID);
    }

    #[test]
    fn submodule_layout_reads_the_module_config() {
        let root = TempDir::new().unwrap();
        let superproject = root.path();
        fs::create_dir_all(superproject.join(".git")).unwrap();
        write(
            &superproject.join(".git/modules/sub/config"),
            &origin("https://github.com/acme/xpto"),
        );
        let sub = superproject.join("sub");
        write(&sub.join(".git"), "gitdir: ../.git/modules/sub\n");
        assert_eq!(remote_id_of(&sub), ACME_XPTO_ID);
    }

    #[test]
    fn oversized_config_yields_nothing() {
        let mut config = origin("https://github.com/acme/xpto");
        config.push_str(&format!("# {}\n", "x".repeat(1024 * 1024)));
        let dir = repo(&config);
        let state = TempDir::new().unwrap();
        let id = local_id_of(dir.path(), state.path());
        assert_ne!(id.id, ACME_XPTO_ID);
    }

    // --- CI fallback -------------------------------------------------------

    #[test]
    fn github_actions_variables_are_used_without_a_remote() {
        let dir = TempDir::new().unwrap();
        let env = [
            ("GITHUB_SERVER_URL", "https://github.com"),
            ("GITHUB_REPOSITORY", "Acme/Xpto"),
        ];
        let Resolution::Resolved(id) = resolve_in(dir.path(), &env, None, false) else {
            panic!("expected a resolved id");
        };
        assert_eq!(id.id, ACME_XPTO_ID);
        assert_eq!(id.source, IdSource::Remote);
        assert!(id.explanation.origin.contains("GITHUB_REPOSITORY"));
    }

    #[test]
    fn gitlab_ci_variables_are_used_without_a_remote() {
        let dir = TempDir::new().unwrap();
        let env = [
            ("CI_SERVER_HOST", "GitLab.Example.com"),
            ("CI_PROJECT_PATH", "Group/Sub/Repo"),
        ];
        let Resolution::Resolved(id) = resolve_in(dir.path(), &env, None, false) else {
            panic!("expected a resolved id");
        };
        assert_eq!(
            id.explanation.hashed,
            "bastyn-project-v1:gitlab.example.com/group/sub/repo"
        );
    }

    #[test]
    fn custom_github_server_host_is_accepted() {
        let dir = TempDir::new().unwrap();
        let env = [
            ("GITHUB_SERVER_URL", "https://ghe.corp.example:8443"),
            ("GITHUB_REPOSITORY", "acme/xpto"),
        ];
        let Resolution::Resolved(id) = resolve_in(dir.path(), &env, None, false) else {
            panic!("expected a resolved id");
        };
        assert_eq!(
            id.explanation.hashed,
            "bastyn-project-v1:ghe.corp.example/acme/xpto"
        );
    }

    #[test]
    fn ci_variables_do_not_override_a_usable_remote() {
        let dir = repo(&origin("https://github.com/acme/xpto"));
        let env = [
            ("GITHUB_SERVER_URL", "https://github.com"),
            ("GITHUB_REPOSITORY", "someone/else"),
        ];
        let Resolution::Resolved(id) = resolve_in(dir.path(), &env, None, false) else {
            panic!("expected a resolved id");
        };
        assert_eq!(id.id, ACME_XPTO_ID);
    }

    #[test]
    fn dirty_ci_values_are_rejected() {
        let dir = TempDir::new().unwrap();
        let dirty: &[(&str, &str, &str, &str)] = &[
            (
                "GITHUB_SERVER_URL",
                "https://github.com",
                "GITHUB_REPOSITORY",
                "acme",
            ),
            (
                "GITHUB_SERVER_URL",
                "https://github.com",
                "GITHUB_REPOSITORY",
                "a/b/c",
            ),
            (
                "GITHUB_SERVER_URL",
                "https://github.com",
                "GITHUB_REPOSITORY",
                "acme/../x",
            ),
            (
                "GITHUB_SERVER_URL",
                "https://github.com",
                "GITHUB_REPOSITORY",
                "acme/x pto",
            ),
            (
                "GITHUB_SERVER_URL",
                "https://github.com",
                "GITHUB_REPOSITORY",
                "acme/x%20",
            ),
            (
                "GITHUB_SERVER_URL",
                "https://github.com",
                "GITHUB_REPOSITORY",
                "acme//xpto",
            ),
            (
                "GITHUB_SERVER_URL",
                "ftp://github.com",
                "GITHUB_REPOSITORY",
                "acme/xpto",
            ),
            (
                "GITHUB_SERVER_URL",
                "https://u:p@github.com",
                "GITHUB_REPOSITORY",
                "acme/xpto",
            ),
            (
                "CI_SERVER_HOST",
                "gitlab.example.com",
                "CI_PROJECT_PATH",
                "solo",
            ),
            (
                "CI_SERVER_HOST",
                "gitlab.example.com",
                "CI_PROJECT_PATH",
                "g/../r",
            ),
            ("CI_SERVER_HOST", "bad host", "CI_PROJECT_PATH", "g/r"),
        ];
        for (k1, v1, k2, v2) in dirty {
            let env = [(*k1, *v1), (*k2, *v2)];
            assert_eq!(
                resolve_in(dir.path(), &env, None, false),
                Resolution::Unavailable("no user state directory".to_owned()),
                "{env:?} must be rejected"
            );
        }
    }

    // --- local identifier --------------------------------------------------

    #[test]
    fn local_id_is_stable_across_calls() {
        let project = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        let first = local_id_of(project.path(), state.path());
        let second = local_id_of(project.path(), state.path());
        assert_eq!(first.id, second.id);
        assert_eq!(first.id.len(), 64);
        assert!(
            first
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(first.explanation.hashed, "stored random ID");
    }

    #[test]
    fn local_ids_differ_between_directories() {
        let a = TempDir::new().unwrap();
        let b = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        assert_ne!(
            local_id_of(a.path(), state.path()).id,
            local_id_of(b.path(), state.path()).id
        );
    }

    #[test]
    fn without_create_nothing_is_written() {
        let project = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        assert_eq!(
            resolve_in(project.path(), &[], Some(state.path()), false),
            Resolution::LocalNotCreated
        );
        assert_eq!(fs::read_dir(state.path()).unwrap().count(), 0);
    }

    #[test]
    fn without_create_an_existing_local_id_is_still_read() {
        let project = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        let created = local_id_of(project.path(), state.path());
        let Resolution::Resolved(read) = resolve_in(project.path(), &[], Some(state.path()), false)
        else {
            panic!("expected the stored id to be read");
        };
        assert_eq!(read.id, created.id);
    }

    #[test]
    fn no_state_directory_is_unavailable() {
        let project = TempDir::new().unwrap();
        assert_eq!(
            resolve_in(project.path(), &[], None, true),
            Resolution::Unavailable("no user state directory".to_owned())
        );
    }

    fn stored_file(state: &Path) -> PathBuf {
        let dir = state.join("local-projects");
        let mut entries: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 1);
        entries.pop().unwrap()
    }

    #[test]
    fn stored_file_name_hides_the_path() {
        let project = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        local_id_of(project.path(), state.path());
        let file = stored_file(state.path());
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name.len(), 64);
        let project_name = project.path().file_name().unwrap().to_string_lossy();
        assert!(!name.contains(project_name.as_ref()));
        let contents = fs::read_to_string(&file).unwrap();
        assert_eq!(contents.len(), 32);
        assert!(!contents.contains(project_name.as_ref()));
    }

    #[cfg(unix)]
    #[test]
    fn stored_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let project = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        local_id_of(project.path(), state.path());
        let mode = fs::metadata(stored_file(state.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn corrupt_stored_value_is_replaced() {
        let project = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        let first = local_id_of(project.path(), state.path());
        let file = stored_file(state.path());
        for corrupt in ["not hex at all", "", "ABCDEF0123456789ABCDEF0123456789"] {
            fs::write(&file, corrupt).unwrap();
            let replaced = local_id_of(project.path(), state.path());
            assert_ne!(replaced.id, first.id);
            let contents = fs::read_to_string(&file).unwrap();
            assert_eq!(contents.len(), 32);
            assert!(
                contents
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
        }
    }

    #[test]
    fn io_failure_is_unavailable_not_an_invented_id() {
        let project = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        // A regular file where the state directory should be makes every
        // write fail.
        let blocker = state.path().join("blocked");
        fs::write(&blocker, "x").unwrap();
        let result = resolve_in(project.path(), &[], Some(&blocker), true);
        assert!(matches!(result, Resolution::Unavailable(_)), "{result:?}");
    }

    #[test]
    fn id_source_names() {
        assert_eq!(IdSource::Remote.as_str(), "remote");
        assert_eq!(IdSource::Local.as_str(), "local");
    }
}
