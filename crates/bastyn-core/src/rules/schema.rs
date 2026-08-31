//! The on-disk shape of a rule file, deserialised as written.
//!
//! `#[serde(deny_unknown_fields)]` throughout: a typo in a rule file is a load
//! error, not a silently ignored field.

use std::collections::HashMap;

use serde::Deserialize;

use crate::category::Category;
use crate::finding::{Confidence, Kind, Severity};
use crate::flow::{SinkKind, SourceKind};

/// The language a rule's patterns are written against.
///
/// The variant list is deliberately narrow so that a rule authored for a
/// language we cannot yet parse fails to load instead of silently never
/// matching.
///
/// There is no `Tsx` variant. `.tsx` files are still scanned -- see
/// [`super::engine`]'s module docs -- but a rule author writes `language:
/// typescript` once and the engine compiles it against both the TypeScript
/// and Tsx grammars internally, so the schema does not need a rule author to
/// pick between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RuleLanguage {
    /// Python source, matched via `tree-sitter-python`.
    Python,
    /// TypeScript source, matched via `tree-sitter-typescript`. Also
    /// compiled against the Tsx grammar to cover `.tsx` files.
    Typescript,
    /// JavaScript source, matched via `tree-sitter-javascript`. The same
    /// grammar parses JSX (`.jsx`), so there is no separate variant for it.
    ///
    /// Because JavaScript is a syntactic subset of TypeScript, a rule
    /// declaring this language is also compiled against the TypeScript and
    /// Tsx grammars, so it applies to `.ts` and `.tsx` files too. Declare
    /// [`Self::Typescript`] instead only when a pattern needs syntax
    /// JavaScript does not have.
    Javascript,
}

/// What a rule wants done with a match that lands in a test path.
///
/// The default is [`Self::Downgrade`], deliberately: it is the safe direction
/// for a scanner whose whole claim is precision, and a rule author who has a
/// reason to report through a fixture has to say so. See
/// [`crate::test_path`] for the measurement that motivated it and for what
/// counts as a test path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TestPathPolicy {
    /// Report the match as a [`Kind::Observation`] instead of whatever the
    /// rule's own `kind` says, so it stays out of the default report.
    #[default]
    Downgrade,
    /// Report the match unchanged. For the findings that are worth reading
    /// even in a fixture — a live provider key is leaked wherever it sits.
    Report,
}

/// The top-level shape of a rule YAML document: a list of rules.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleFile {
    /// The rules defined in this document.
    pub(crate) rules: Vec<RuleDef>,
}

/// One rule, exactly as written in YAML.
///
/// `Clone` is needed because a `language: typescript` rule is compiled twice
/// -- once against the TypeScript grammar, once against the Tsx grammar (see
/// [`super::engine`]'s module docs) -- and each compile consumes its own
/// `RuleDef`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleDef {
    /// Stable rule identifier, e.g. `"BAS-LLM10-001"`.
    pub(crate) id: String,
    /// One line, imperative, no hedging.
    pub(crate) title: String,
    /// Defect or observation.
    pub(crate) kind: Kind,
    /// Severity, if real.
    pub(crate) severity: Severity,
    /// How sure we are.
    pub(crate) confidence: Confidence,
    /// Framework categories this maps to. Must be non-empty.
    pub(crate) categories: Vec<Category>,
    /// The language the patterns below are written against.
    pub(crate) language: RuleLanguage,
    /// What to do with a match inside a test path. Defaults to
    /// [`TestPathPolicy::Downgrade`].
    #[serde(default)]
    pub(crate) in_test_paths: TestPathPolicy,
    /// Match if any of these patterns match. Must be non-empty.
    pub(crate) any: Vec<String>,
    /// Suppress a match if any of these match the same node.
    #[serde(default)]
    pub(crate) none: Vec<String>,
    /// Only match when nested inside one of these patterns.
    #[serde(default)]
    pub(crate) inside: Vec<String>,
    /// Captured metavariable name to the regex its text must match.
    #[serde(default)]
    pub(crate) metavariable_matches: HashMap<String, String>,
    /// Captured metavariable name to a regex its text must *not* match.
    ///
    /// The inverse of `metavariable_matches`, and a separate field rather
    /// than a negation syntax inside the same map: this engine's regex
    /// backend (the `regex` crate) has no lookaround and no backreferences,
    /// so a single regex cannot both require a shape (a credential-looking
    /// value) and reject specific content within it (a known placeholder
    /// word, or two captures being equal). A rule with no evidence for a
    /// variable here -- an `any` pattern that never binds it -- treats that
    /// as nothing to exclude, not as a failure; see
    /// [`super::engine::CompiledRule::metavariable_exclusions_clear`].
    #[serde(default)]
    pub(crate) metavariable_not_matches: HashMap<String, String>,
    /// Where a captured value must have come from, and whether a guard may
    /// already cover it.
    ///
    /// The provenance gate. `metavariable_matches` asks what a variable is
    /// *called*; this asks what produced its value, which is the question a
    /// rule about untrusted data actually needs answered. The two coexist so
    /// that rules can migrate from the first to the second one at a time
    /// rather than in a single sweep, and when both are present both apply.
    #[serde(default)]
    pub(crate) flow: Option<FlowDef>,
    /// What is wrong and why it matters. Two sentences at most.
    pub(crate) description: String,
    /// What to do about it. Actionable, specific to this code.
    pub(crate) remediation: String,
}

/// A rule's `flow:` clause, exactly as written in YAML.
///
/// ```yaml
/// flow:
///   variable: ARG          # whose provenance to test; defaults to ARG
///   source: model_output   # one kind, or a list of them
///   unguarded: true        # and no guard may already dominate the sink
///   sink: code_execution   # also match calls to local wrappers of this sink
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FlowDef {
    /// The captured metavariable whose provenance is tested.
    ///
    /// Defaults to `ARG`, which is what every sink pattern in this corpus
    /// names its interesting capture. Naming it explicitly is still
    /// preferable in a rule whose patterns bind more than one.
    #[serde(default = "default_flow_variable")]
    pub(crate) variable: String,
    /// The source kinds the captured value must have come from. Written as a
    /// single kind or a list of them.
    pub(crate) source: SourceSpec,
    /// Require that no guard dominates the sink.
    ///
    /// Off by default, because a rule that has not thought about guards
    /// should not silently start suppressing findings.
    #[serde(default)]
    pub(crate) unguarded: bool,
    /// Also report calls to a function *in the same file* that forwards the
    /// captured value into a sink of this kind.
    ///
    /// This is what lets `def run(x): exec(x)` called with a model reply be
    /// reported at the `run(...)` call site, which no `any:` pattern can
    /// describe. Bounded at one hop -- see [`crate::flow::graph`].
    #[serde(default)]
    pub(crate) sink: Option<SinkKind>,
}

/// One source kind or several, so a rule author writes `source: model_output`
/// when one will do and `source: [model_output, file_read]` when it will not.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum SourceSpec {
    /// A single kind.
    One(SourceKind),
    /// Several kinds; the value must have come from any one of them.
    Many(Vec<SourceKind>),
}

impl SourceSpec {
    /// The kinds this clause accepts.
    pub(crate) fn kinds(&self) -> Vec<SourceKind> {
        match self {
            Self::One(kind) => vec![*kind],
            Self::Many(kinds) => kinds.clone(),
        }
    }
}

/// The metavariable a `flow:` clause tests when it does not name one.
fn default_flow_variable() -> String {
    "ARG".to_owned()
}
