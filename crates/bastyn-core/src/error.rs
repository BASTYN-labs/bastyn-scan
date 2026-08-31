//! Error types shared across the core engine.

use std::path::PathBuf;

/// A specialised [`std::result::Result`] for core operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Anything that can go wrong while inspecting a source tree.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The requested path does not exist, or is not readable.
    #[error("path not found: {path}")]
    PathNotFound {
        /// The path that could not be resolved.
        path: PathBuf,
    },

    /// The requested path exists but is not a directory.
    #[error("not a directory: {path}")]
    NotADirectory {
        /// The path that was expected to be a directory.
        path: PathBuf,
    },

    /// Traversal failed part-way through.
    #[error("failed to walk {path}")]
    Walk {
        /// The root the walk started from.
        path: PathBuf,
        /// The underlying traversal failure.
        #[source]
        source: ignore::Error,
    },

    /// An exclude pattern is not valid.
    ///
    /// Fatal on purpose. A pattern that does not compile excludes nothing, so
    /// carrying on would scan more than the caller asked for while saying
    /// nothing about it — the one outcome worse than refusing to start.
    #[error("invalid exclude pattern: {pattern}")]
    ExcludePattern {
        /// The pattern as the caller wrote it.
        pattern: String,
        /// Why it could not be compiled.
        #[source]
        source: ignore::Error,
    },

    /// The embedded rule set could not be loaded.
    ///
    /// This is a build-time defect rather than a user error: the rules ship
    /// inside the binary, so a failure here means we shipped a broken one.
    #[error("could not load the embedded rules")]
    Rules {
        /// The underlying rule-loading failure.
        #[source]
        source: Box<crate::rules::RuleError>,
    },

    /// An I/O operation failed.
    #[error("i/o error at {path}")]
    Io {
        /// The path being operated on when the failure occurred.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
}
