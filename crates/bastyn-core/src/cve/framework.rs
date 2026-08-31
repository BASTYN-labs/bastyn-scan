//! `BAS-LLM04-001` — a wildcard-version pin on a known agent/MCP-ecosystem
//! package.
//!
//! Scope, deliberately narrow, on two axes:
//!
//! 1. **Which packages.** Only a curated list of agent frameworks, the MCP
//!    SDK, and the major model-provider SDKs — not every unpinned dependency
//!    in the manifest. `flask>=2.0` says nothing about agent supply-chain
//!    risk; `langchain>=0.1.0` does, because an MCP server or agent process
//!    holding whatever `LangChain` ships next is exactly the risk this rule
//!    describes.
//! 2. **Which constraints.** Only a genuine wildcard (`*`, `latest`, no
//!    version at all) or a range with no upper bound (`>=1.0.0` and nothing
//!    else). A caret or tilde range (`^1.2.3`, `~1.2.3`) is the default,
//!    bounded output of `npm install`/Poetry and is not this finding — see
//!    [`is_wildcard_or_unbounded`] for the exact line.
//!
//! Dev/test-only dependencies are excluded via
//! [`UnresolvedDependency::dev`](super::manifest::UnresolvedDependency::dev):
//! a wildcard on a lint or test package is not the same finding as one on
//! the framework the agent actually runs.

use crate::{Category, Confidence, Finding, Kind, Location, Severity};

use super::manifest::UnresolvedDependency;

/// Package names, and name prefixes, recognised as part of the agent/MCP
/// ecosystem across the manifests this crate parses (npm's `@scope/name`
/// convention and `PyPI`'s `dashed-name` convention).
///
/// Curated from the rule catalogue's own examples (`langchain`, `autogen`,
/// `mcp`, `openai-agents`) plus the packages actually observed carrying an
/// unbounded version constraint in the calibration corpus. Not exhaustive —
/// a missed framework is a false negative, which this rule accepts in
/// exchange for not guessing at names that were never measured.
const EXACT_PACKAGES: &[&str] = &[
    // Cross-framework / protocol
    "mcp",
    "fastmcp",
    "@modelcontextprotocol/sdk",
    // LangChain family, exact top-level names not covered by the prefix
    // match below
    "langgraph",
    "@langchain/langgraph",
    // Multi-agent frameworks
    "autogen",
    "pyautogen",
    "ag2",
    "crewai",
    "crewai-tools",
    "smolagents",
    // RAG / orchestration frameworks
    "llama-index",
    "llama_index",
    "haystack-ai",
    "guidance",
    "dspy",
    "dspy-ai",
    "pydantic-ai",
    // Microsoft's agent framework
    "semantic-kernel",
    // OpenAI's agent framework, distinct from the plain SDK below
    "openai-agents",
    "@openai/agents",
    // Model-provider SDKs — not agent frameworks themselves, but the
    // catalogue's own "etc." and an unpinned model SDK is the same supply
    // chain shape: whatever the registry serves runs inside the agent's
    // trust boundary with no review.
    "openai",
    "anthropic",
    "@anthropic-ai/sdk",
];

/// True if `name` is recognised as an agent/MCP-ecosystem package.
fn is_agent_framework_package(name: &str) -> bool {
    if EXACT_PACKAGES.contains(&name) {
        return true;
    }
    name.starts_with("langchain-")
        || name.starts_with("langchain_")
        || name == "langchain"
        || name.starts_with("@langchain/")
        || name == "mastra"
        || name.starts_with("@mastra/")
}

/// True for a constraint with no upper bound: a bare wildcard (`*`, `x`,
/// `X`), the string `latest`, no version at all (already normalised to `*`
/// by the manifest parsers), or a single `>=`/`>` constraint with nothing
/// else narrowing it.
///
/// Deliberately excludes caret/tilde ranges (`^1.2.3`, `~1.2.3`,
/// `~=1.2.3`), compound constraints with an upper bound
/// (`>=1.0.0,<2.0.0`), and exclusion-only constraints (`!=1.2.3`) — all of
/// those are a real, bounded compatibility decision, not a wildcard.
fn is_wildcard_or_unbounded(constraint: &str) -> bool {
    let trimmed = constraint.trim();
    if trimmed.is_empty()
        || trimmed == "*"
        || trimmed == "x"
        || trimmed == "X"
        || trimmed.eq_ignore_ascii_case("latest")
    {
        return true;
    }
    let Some(rest) = trimmed
        .strip_prefix(">=")
        .or_else(|| trimmed.strip_prefix('>'))
    else {
        return false;
    };
    let rest = rest.trim();
    !rest.is_empty()
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// Run `BAS-LLM04-001` over every unresolved dependency a manifest scan
/// turned up. Called once per scan, over the whole tree's worth of
/// manifests — not per file — because a defensible list of agent frameworks
/// is short and cheap to check against every entry directly.
#[must_use]
pub(crate) fn check(unresolved: &[UnresolvedDependency]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = unresolved
        .iter()
        .filter(|dep| !dep.dev)
        .filter(|dep| is_agent_framework_package(&dep.name))
        .filter(|dep| is_wildcard_or_unbounded(&dep.constraint))
        .map(|dep| Finding {
            rule_id: "BAS-LLM04-001".to_string(),
            title: format!("`{}` has no upper-bounded version pin", dep.name),
            kind: Kind::Observation,
            severity: Severity::Low,
            confidence: Confidence::High,
            categories: vec![Category::Llm04],
            location: Location {
                file: dep.file.clone(),
                line: dep.line,
                column: 1,
            },
            snippet: format!("{}{}", dep.name, dep.constraint),
            description: format!(
                "`{}` is declared as `{}`, with no upper bound. An MCP server or agent \
                 process built against this framework runs whatever version the registry \
                 serves at install time, with no review of what changed.",
                dep.name, dep.constraint
            ),
            remediation: format!(
                "Pin `{}` to a specific version or a bounded range (e.g. `^1.4.0`), and \
                 raise it deliberately.",
                dep.name
            ),
            secondary_rule_ids: Vec::new(),
            references: Vec::new(),
        })
        .collect();

    // Deterministic order: file, then line. `unresolved`'s own order follows
    // whatever order `collect_files` walked the tree in, which is stable
    // within a run but not a property callers should rely on directly.
    findings.sort_by(|a, b| {
        (&a.location.file, a.location.line).cmp(&(&b.location.file, b.location.line))
    });
    findings
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn unresolved(name: &str, constraint: &str, dev: bool) -> UnresolvedDependency {
        UnresolvedDependency {
            name: name.to_string(),
            constraint: constraint.to_string(),
            file: PathBuf::from("requirements.txt"),
            line: 1,
            dev,
        }
    }

    #[test]
    fn flags_a_bare_wildcard_on_a_known_framework() {
        let deps = [unresolved("langchain", "*", false)];
        let findings = check(&deps);
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_id, "BAS-LLM04-001");
        assert_eq!(findings[0].kind, Kind::Observation);
    }

    #[test]
    fn flags_an_unbounded_lower_range_on_a_known_framework() {
        let deps = [unresolved("langchain-community", ">=0.0.10", false)];
        assert_eq!(check(&deps).len(), 1);
    }

    #[test]
    fn flags_no_version_at_all_normalised_to_a_wildcard() {
        // The Python manifest parsers hand a bare, unconstrained dependency
        // back as constraint "*" — the same value a real `"*"` literal
        // produces, and the same effective risk.
        let deps = [unresolved("openai", "*", false)];
        assert_eq!(check(&deps).len(), 1);
    }

    #[test]
    fn does_not_flag_a_bounded_caret_or_tilde_range() {
        let deps = [
            unresolved("langchain", "^0.3.0", false),
            unresolved("langchain-core", "~1.2.0", false),
            unresolved("openai", "~=1.35", false),
        ];
        assert!(check(&deps).is_empty(), "{:#?}", check(&deps));
    }

    #[test]
    fn does_not_flag_a_compound_constraint_with_an_upper_bound() {
        let deps = [unresolved("langchain", ">=0.1.0,<0.2.0", false)];
        assert!(check(&deps).is_empty());
    }

    #[test]
    fn does_not_flag_an_unrecognised_package() {
        let deps = [
            unresolved("flask", "*", false),
            unresolved("requests", ">=2.0", false),
        ];
        assert!(check(&deps).is_empty(), "{:#?}", check(&deps));
    }

    #[test]
    fn does_not_flag_a_dev_only_dependency_even_on_a_known_framework_name() {
        // A wildcard on a lint/test tool is not the same finding as one on
        // the framework itself — this is the scoping the task explicitly
        // calls for.
        let deps = [unresolved("openai", "*", true)];
        assert!(check(&deps).is_empty());
    }

    #[test]
    fn recognises_the_langchain_family_by_prefix_and_scope() {
        assert!(is_agent_framework_package("langchain"));
        assert!(is_agent_framework_package("langchain-community"));
        assert!(is_agent_framework_package("langchain_community"));
        assert!(is_agent_framework_package("@langchain/core"));
        assert!(!is_agent_framework_package("langchainhub-lookalike"));
    }

    #[test]
    fn does_not_mistake_an_unrelated_package_for_a_framework_by_substring() {
        // "openai-helper" is not the "openai" SDK; substring matching on the
        // curated list would be exactly the kind of overfire this module
        // exists to avoid.
        assert!(!is_agent_framework_package("openai-helper"));
        assert!(!is_agent_framework_package("my-langchain-fork"));
    }

    #[test]
    fn wildcard_detection_matches_the_documented_shapes() {
        for constraint in ["*", "x", "X", "latest", "LATEST", "", ">=1.0.0", ">2.0"] {
            assert!(
                is_wildcard_or_unbounded(constraint),
                "{constraint:?} should be a wildcard"
            );
        }
        for constraint in [
            "^1.2.3",
            "~1.2.3",
            "~=1.2",
            ">=1.0.0,<2.0.0",
            "==1.2.3",
            "!=1.2.3",
        ] {
            assert!(
                !is_wildcard_or_unbounded(constraint),
                "{constraint:?} should not be a wildcard"
            );
        }
    }

    #[test]
    fn findings_are_ordered_by_file_then_line() {
        let deps = [
            UnresolvedDependency {
                name: "openai".to_string(),
                constraint: "*".to_string(),
                file: PathBuf::from("b/requirements.txt"),
                line: 5,
                dev: false,
            },
            UnresolvedDependency {
                name: "langchain".to_string(),
                constraint: "*".to_string(),
                file: PathBuf::from("a/requirements.txt"),
                line: 9,
                dev: false,
            },
        ];
        let findings = check(&deps);
        assert_eq!(findings.len(), 2);
        assert_eq!(
            findings[0].location.file,
            PathBuf::from("a/requirements.txt")
        );
    }
}
