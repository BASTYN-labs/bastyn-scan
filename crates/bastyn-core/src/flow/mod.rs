//! Tier 2: a deterministic, per-file dataflow graph.
//!
//! Tier 1 (`crate::rules`) asks *what shape is this code*. This module asks
//! *where did this value come from*, which is the question a rule about
//! untrusted data actually needs answered. The difference is measurable: a
//! rule that gates `eval($ARG)` on `$ARG`'s **name** matching
//! `response|completion|output|...` survived 0 of its 10 realistic renamings
//! of the same bug; after migrating to a `flow:` provenance gate it survives
//! all 10 (`crates/bastyn-core/tests/brittleness_gate.rs`, which pools 119
//! synonym samples across 14 gated targets -- the 10 here are this rule's own
//! row). The name is a guess about intent; provenance is a fact about the
//! program, and renaming a variable does not change what produced its value.
//!
//! # Scope, deliberately small
//!
//! - **Python only.** The graph is written against `tree-sitter-python`'s
//!   node kinds. A rule with a `flow:` clause in any other language is a
//!   *load error* ([`crate::rules::RuleError::FlowUnsupportedLanguage`]),
//!   never a rule that silently never matches.
//! - **One file.** No project-wide index: it would not fit the pre-commit
//!   budget this tier is bound by.
//! - **Depth one, for calls.** A local function that returns a source is a
//!   source for its callers; a local function that feeds a parameter to a
//!   sink is a sink for its callers. Neither relation chains -- see
//!   [`graph`]'s docs for why the bound is enforced rather than incidental.
//!
//! # Determinism
//!
//! Every answer is a function of the parsed tree alone. Where the graph
//! cannot prove a single origin -- a name assigned differently in two
//! branches, a value from a construct the resolver does not model -- it
//! answers [`Origin::Unknown`] rather than picking one. `Unknown` never
//! satisfies a `flow: source:` gate, so an unresolvable value produces
//! silence, not a guess.
//!
//! # Cost
//!
//! The graph is built lazily, per file, and only when a rule with a `flow:`
//! clause has already produced a structural candidate on that file. A
//! repository with no `eval`/`exec` call therefore pays nothing at all for
//! this tier.

pub(crate) mod catalogue;
pub(crate) mod graph;
pub(crate) mod guards;

pub(crate) use catalogue::{SinkKind, SourceKind};
pub(crate) use graph::{FlowGraph, FlowLanguage};
