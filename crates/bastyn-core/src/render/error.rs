//! Errors specific to rendering a [`crate::report::Report`].
//!
//! Rendering only fails if serialisation itself fails, which does not happen
//! for the data this crate produces — [`Report`](crate::report::Report) is
//! plain owned data with no non-string map keys or cyclic structure. The
//! return type stays honest about the possibility rather than reaching for
//! `unwrap`.

use thiserror::Error;

/// A specialised [`std::result::Result`] for rendering operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong turning a [`crate::report::Report`] into text.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Serialising the report to JSON — directly, or as part of SARIF —
    /// failed.
    #[error("failed to serialise report")]
    Serialize(#[from] serde_json::Error),
}
