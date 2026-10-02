//! Anonymous reporting support: the pieces that decide *which* project a scan
//! belongs to, without ever sending or storing the repository's identity in
//! clear.
//!
//! This module has no terminal code, and its only network code is the summary
//! uploader in [`upload`], behind a trait. It holds the testable building
//! blocks the CLI composes:
//!
//! - [`project_id`] derives a stable, opaque project identifier so scans of
//!   the same repository from different machines or CI runners group
//!   together.
//! - [`state`] locates (and writes files into) the per-user directory where
//!   Bastyn keeps small state such as a locally generated random identifier.
//!
//! - [`summary`] builds the anonymous, counts-only scan summary from a
//!   finished report, under a hard allowlist of what may leave the machine.
//!
//! - [`consent`], [`notice`], [`upload`] and [`session`] decide whether to
//!   report, show the first-run notice, post the summary with bounded
//!   retries, and run those steps in a fixed order. The network and the clock
//!   sit behind traits, so all of it is tested with fakes. The core scan
//!   pipeline never calls this module; the CLI does, after a scan.
//!
//! Everything here treats the scanned tree as untrusted data: nothing from it
//! selects a hashing algorithm or prefix, and no subprocess is ever started.

pub mod consent;
pub mod notice;
pub mod project_id;
pub mod session;
pub mod state;
pub mod summary;
pub mod upload;
