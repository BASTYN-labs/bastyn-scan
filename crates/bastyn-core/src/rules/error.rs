//! Errors that can occur while loading or compiling a rule set.
//!
//! Kept local to this module rather than folded into [`crate::error::Error`]:
//! that type belongs to the traversal layer and this crate's contract forbids
//! changing it, so rule loading gets its own narrow error type instead.

use ast_grep_core::matcher::{PatternError, RegexMatcherError};

/// A specialised [`std::result::Result`] for rule loading and compilation.
pub type Result<T, E = RuleError> = std::result::Result<T, E>;

/// Anything that can go wrong while parsing or compiling rule YAML.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RuleError {
    /// The YAML text could not be parsed, or used a field the schema does not
    /// define.
    #[error("malformed rule YAML: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),

    /// A rule declared an `any` list with no patterns in it.
    #[error("rule `{id}`: `any` must contain at least one pattern")]
    EmptyAny {
        /// The offending rule's id.
        id: String,
    },

    /// A rule declared a `categories` list with no categories in it.
    #[error("rule `{id}`: `categories` must contain at least one category")]
    EmptyCategories {
        /// The offending rule's id.
        id: String,
    },

    /// Two rules in the same set declared the same id.
    #[error("rule `{id}`: duplicate rule id")]
    DuplicateId {
        /// The id shared by two rules.
        id: String,
    },

    /// A `kind: defect` rule mapped to a category whose absence cannot be
    /// judged from the repository alone. Only observations may carry those.
    #[error(
        "rule `{id}`: kind is `defect` but category `{category}` is context-dependent; \
         context-dependent categories may only be observations"
    )]
    ContextDependentDefect {
        /// The offending rule's id.
        id: String,
        /// The context-dependent category that triggered the rejection.
        category: String,
    },

    /// One of a rule's `any`, `none`, or `inside` patterns failed to compile
    /// against the grammar its language implies.
    ///
    /// `language` names the grammar the pattern was compiled against, not
    /// just the schema-level `RuleLanguage`: a `language: typescript` rule
    /// compiles separately against the TypeScript and Tsx grammars (see
    /// `crate::rules::engine`'s module docs), and the two can disagree --
    /// TypeScript's angle-bracket cast syntax (`<Foo>bar`), for example, does
    /// not parse under the Tsx grammar at all. Naming the grammar, not just
    /// the rule id, tells the author which of the two compiles actually
    /// failed.
    #[error("rule `{id}`: invalid {language} pattern `{pattern}`: {source}")]
    InvalidPattern {
        /// The offending rule's id.
        id: String,
        /// The grammar the pattern was compiled against (e.g. `"python"`,
        /// `"typescript"`, `"tsx"`, `"javascript"`).
        language: String,
        /// The pattern text that failed to compile.
        pattern: String,
        /// The underlying pattern-compilation failure.
        #[source]
        source: PatternError,
    },

    /// A `metavariable_matches` regular expression failed to compile.
    #[error("rule `{id}`: invalid metavariable_matches regex for `{var}`: {source}")]
    InvalidRegex {
        /// The offending rule's id.
        id: String,
        /// The metavariable name the regex was attached to.
        var: String,
        /// The underlying regex-compilation failure.
        #[source]
        source: RegexMatcherError,
    },

    /// A rule declared a `flow:` clause in a language the dataflow graph
    /// cannot be built for.
    ///
    /// A load error rather than a rule that silently never matches: the
    /// graph is Python-only today (see the crate-internal `flow` module), and a `flow:`
    /// clause compiled against any other grammar would be a matcher that can
    /// never fire, with nothing in the report to say so.
    #[error(
        "rule `{id}`: `flow` is only supported for `language: python`, not `{language}`; \
         the dataflow graph has no other grammar"
    )]
    FlowUnsupportedLanguage {
        /// The offending rule's id.
        id: String,
        /// The language the rule declared.
        language: String,
    },

    /// A rule declared a `flow:` clause with no source kinds in it.
    ///
    /// Such a rule can never match, because no origin satisfies an empty set.
    #[error("rule `{id}`: `flow.source` must name at least one source kind")]
    EmptyFlowSources {
        /// The offending rule's id.
        id: String,
    },

    /// A `metavariable_not_matches` regular expression failed to compile.
    ///
    /// Kept distinct from [`Self::InvalidRegex`] rather than sharing one
    /// variant: the two fields are opposite gates (must match / must not
    /// match), and a rule author staring at a compile error benefits from
    /// the message naming which one they got wrong.
    #[error("rule `{id}`: invalid metavariable_not_matches regex for `{var}`: {source}")]
    InvalidNotRegex {
        /// The offending rule's id.
        id: String,
        /// The metavariable name the regex was attached to.
        var: String,
        /// The underlying regex-compilation failure.
        #[source]
        source: RegexMatcherError,
    },
}
