//! Whether a scan may send its anonymous summary.
//!
//! The decision has exactly three inputs, checked in a fixed order: the
//! `--no-reporting` flag, the `--offline` flag, and the `DO_NOT_TRACK`
//! environment variable. Nothing else can turn reporting off, and nothing can
//! turn it on beyond the absence of those three. In particular nothing read
//! from the scanned tree is an input, so a repository cannot opt a user in or
//! out.

use std::ffi::OsString;

/// Which of the three inputs turned reporting off. When several apply, the
/// first in this order is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledBy {
    /// The `--no-reporting` flag.
    NoReportingFlag,
    /// The `--offline` flag: an offline scan makes no network calls at all.
    OfflineFlag,
    /// The `DO_NOT_TRACK` environment variable.
    DoNotTrack,
}

/// Whether reporting is allowed for this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// None of the three inputs turned reporting off.
    Enabled,
    /// Reporting is off, for the stated reason.
    Disabled(DisabledBy),
}

/// Decides whether this run may report.
///
/// Precedence: `no_reporting`, then `offline`, then `DO_NOT_TRACK`.
/// `DO_NOT_TRACK` disables reporting when its value, after trimming ASCII
/// whitespace, is non-empty and not `0`; an unset, empty or `0` value leaves
/// it enabled. The environment is passed in as a lookup function so tests
/// never touch the real process environment.
#[must_use]
pub fn decide(
    no_reporting: bool,
    offline: bool,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Decision {
    if no_reporting {
        return Decision::Disabled(DisabledBy::NoReportingFlag);
    }
    if offline {
        return Decision::Disabled(DisabledBy::OfflineFlag);
    }
    if env("DO_NOT_TRACK").is_some_and(|value| do_not_track_set(&value)) {
        return Decision::Disabled(DisabledBy::DoNotTrack);
    }
    Decision::Enabled
}

/// Whether a `DO_NOT_TRACK` value asks for tracking to be off. A value that
/// is not valid Unicode still counts as set: it is non-empty and cannot be
/// the single character `0`.
fn do_not_track_set(value: &OsString) -> bool {
    value.to_str().map_or(!value.is_empty(), |text| {
        let trimmed = text.trim_matches(|c: char| c.is_ascii_whitespace());
        !trimmed.is_empty() && trimmed != "0"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(value: Option<&'static str>) -> impl Fn(&str) -> Option<OsString> {
        move |name| {
            (name == "DO_NOT_TRACK")
                .then(|| value.map(OsString::from))
                .flatten()
        }
    }

    #[test]
    fn full_table_over_the_three_inputs() {
        for no_reporting in [false, true] {
            for offline in [false, true] {
                for dnt in [None, Some("1")] {
                    let expected = if no_reporting {
                        Decision::Disabled(DisabledBy::NoReportingFlag)
                    } else if offline {
                        Decision::Disabled(DisabledBy::OfflineFlag)
                    } else if dnt.is_some() {
                        Decision::Disabled(DisabledBy::DoNotTrack)
                    } else {
                        Decision::Enabled
                    };
                    assert_eq!(
                        decide(no_reporting, offline, &env_with(dnt)),
                        expected,
                        "no_reporting={no_reporting} offline={offline} dnt={dnt:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn do_not_track_values_that_do_not_disable() {
        for value in ["", "0", " 0 ", "  ", "\t0\n"] {
            assert_eq!(
                decide(false, false, &env_with(Some(value))),
                Decision::Enabled,
                "value {value:?}"
            );
        }
    }

    #[test]
    fn do_not_track_values_that_disable() {
        for value in ["1", "true", "yes", " 1 ", "00", "off"] {
            assert_eq!(
                decide(false, false, &env_with(Some(value))),
                Decision::Disabled(DisabledBy::DoNotTrack),
                "value {value:?}"
            );
        }
    }

    #[test]
    fn unrelated_variables_change_nothing() {
        let env = |name: &str| (name == "CI").then(|| OsString::from("1"));
        assert_eq!(decide(false, false, &env), Decision::Enabled);
    }
}
