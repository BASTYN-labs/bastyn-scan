//! The first-run notice and the marker that records it was shown.

use std::io;
use std::path::{Path, PathBuf};

use super::state;

/// The text printed to standard error before the first summary is sent. One
/// line, no trailing newline: the caller adds its own.
pub const NOTICE: &str = "bastyn: each completed scan sends an anonymous summary (counts only: no file paths, no code, no finding text, no repository name). Turn it off with --no-reporting, --offline, or DO_NOT_TRACK=1. Details: https://github.com/BASTYN-labs/bastyn-scan#reporting";

/// File name of the marker, inside the state directory.
const MARKER: &str = "reporting-notice-shown";

fn marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join(MARKER)
}

/// Whether the notice has been shown before, judged by the marker file.
#[must_use]
pub fn already_shown(state_dir: &Path) -> bool {
    marker_path(state_dir).exists()
}

/// Records that the notice was shown, by writing the marker file (private to
/// the current user, parent directories created).
pub fn record_shown(state_dir: &Path) -> io::Result<()> {
    state::write_private(&marker_path(state_dir), b"shown\n")
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    #[test]
    fn notice_is_one_line() {
        assert!(!NOTICE.contains('\n'));
        assert!(NOTICE.contains("--no-reporting"));
        assert!(NOTICE.contains("DO_NOT_TRACK=1"));
    }

    #[test]
    fn marker_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("nested").join("bastyn");
        assert!(!already_shown(&state));
        record_shown(&state).unwrap();
        assert!(already_shown(&state));
        assert!(state.join("reporting-notice-shown").is_file());
        record_shown(&state).unwrap();
        assert!(already_shown(&state));
    }
}
