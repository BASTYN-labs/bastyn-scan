//! The per-user state directory and a safe way to write small files into it.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The per-user directory where Bastyn keeps small state files.
///
/// Resolution order: `XDG_STATE_HOME`, then `$HOME/.local/state` (this
/// includes macOS, where the XDG layout is used as well so the location is
/// the same on every Unix-like system), then `LOCALAPPDATA` on Windows. A
/// value is only used when it is non-empty and absolute: a relative path
/// would resolve against whatever directory the scan happens to run in. The
/// returned path always ends in `bastyn`.
///
/// The environment is passed in as a lookup function so tests never touch the
/// real process environment. Returns `None` when nothing usable is set.
#[must_use]
pub fn state_dir(env: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let base = absolute_var(env, "XDG_STATE_HOME")
        .or_else(|| absolute_var(env, "HOME").map(|home| home.join(".local").join("state")))
        .or_else(|| {
            if cfg!(windows) {
                absolute_var(env, "LOCALAPPDATA")
            } else {
                None
            }
        })?;
    Some(base.join("bastyn"))
}

/// The variable's value as a path, if it is set, non-empty and absolute.
fn absolute_var(env: &dyn Fn(&str) -> Option<OsString>, name: &str) -> Option<PathBuf> {
    let value = env(name).filter(|value| !value.is_empty())?;
    let path = PathBuf::from(value);
    path.is_absolute().then_some(path)
}

/// Writes `contents` to `path` so that only the current user can read it.
///
/// Parent directories are created. The data goes to a temporary file in the
/// same directory (created with mode `0o600` on Unix) which is then renamed
/// over `path`, so a reader never sees a half-written file and the final file
/// is never briefly world-readable.
pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::create_dir_all(parent)?;

    let mut temp_name = OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".{}.tmp", std::process::id()));
    let temp = parent.join(temp_name);

    // A leftover from a crashed run with the same process id must not block
    // this write, and `create_new` below refuses to follow a planted link.
    let _ = fs::remove_file(&temp);
    let result = write_new_private(&temp, contents).and_then(|()| fs::rename(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Creates `path` (which must not exist) with owner-only permissions.
fn write_new_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    use tempfile::TempDir;

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

    #[test]
    fn xdg_state_home_is_honoured() {
        let dir = TempDir::new().unwrap();
        let xdg = dir.path().to_str().unwrap();
        let env = env_of(&[("XDG_STATE_HOME", xdg), ("HOME", xdg)]);
        assert_eq!(state_dir(&env), Some(dir.path().join("bastyn")));
    }

    #[test]
    fn relative_xdg_is_ignored_in_favour_of_home() {
        let dir = TempDir::new().unwrap();
        let home = dir.path().to_str().unwrap();
        let env = env_of(&[("XDG_STATE_HOME", "relative/state"), ("HOME", home)]);
        assert_eq!(
            state_dir(&env),
            Some(dir.path().join(".local").join("state").join("bastyn"))
        );
    }

    #[test]
    fn empty_xdg_is_ignored() {
        let dir = TempDir::new().unwrap();
        let home = dir.path().to_str().unwrap();
        let env = env_of(&[("XDG_STATE_HOME", ""), ("HOME", home)]);
        assert_eq!(
            state_dir(&env),
            Some(dir.path().join(".local").join("state").join("bastyn"))
        );
    }

    #[test]
    fn home_fallback_is_used_without_xdg() {
        let dir = TempDir::new().unwrap();
        let home = dir.path().to_str().unwrap();
        let env = env_of(&[("HOME", home)]);
        assert_eq!(
            state_dir(&env),
            Some(dir.path().join(".local").join("state").join("bastyn"))
        );
    }

    #[test]
    fn nothing_usable_gives_none() {
        assert_eq!(state_dir(&env_of(&[])), None);
        assert_eq!(state_dir(&env_of(&[("HOME", "relative")])), None);
        assert_eq!(state_dir(&env_of(&[("HOME", "")])), None);
    }

    #[test]
    fn write_private_creates_parents_and_replaces_contents() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("a").join("b").join("file");
        write_private(&path, b"first").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");
        write_private(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn write_private_leaves_no_temporary_file_behind() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file");
        write_private(&path, b"x").unwrap();
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![OsString::from("file")]);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_uses_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret");
        write_private(&path, b"x").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn write_private_rejects_a_path_without_a_file_name() {
        let error = write_private(Path::new("/"), b"x").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
