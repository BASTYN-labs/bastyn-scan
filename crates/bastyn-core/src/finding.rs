//! The finding model. Every analyser in the engine produces these.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::category::Category;

/// How bad the problem is, if it is real.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing, not worth blocking.
    Low,
    /// Should be fixed.
    Medium,
    /// Should be fixed before shipping.
    High,
    /// Exploitable as written.
    Critical,
}

/// How sure we are that the finding is real.
///
/// A first-class field, not a comment. The cross-file pass lowers it, and the
/// report filters on it — this is the mechanism that keeps default output
/// believable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Plausible, but the repository does not settle it.
    Low,
    /// Consistent with the code, with a reading that would make it benign.
    Medium,
    /// The code says so. No further context could make this acceptable.
    High,
}

/// Whether a finding is a defect or an observation.
///
/// Observations are hidden unless explicitly asked for. This distinction is the
/// product's central promise: we do not call a missing control a bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Wrong regardless of how the application is deployed.
    Defect,
    /// A control is absent, and whether that is wrong depends on context the
    /// repository cannot show.
    Observation,
}

/// Where in the tree a finding sits.
///
/// Equality on this type is what deduplication uses, so it deliberately
/// excludes the message text: two rules describing one problem differently are
/// still one problem.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Location {
    /// Path relative to the scanned root.
    pub file: PathBuf,
    /// 1-indexed line.
    pub line: usize,
    /// 1-indexed column.
    pub column: usize,
}

/// One problem, at one place, from one rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier, e.g. `"BAS-LLM10-001"`.
    pub rule_id: String,
    /// One line, imperative, no hedging.
    pub title: String,
    /// Defect or observation.
    pub kind: Kind,
    /// Severity, if real.
    pub severity: Severity,
    /// How sure we are.
    pub confidence: Confidence,
    /// Framework categories this maps to. Never empty.
    pub categories: Vec<Category>,
    /// Where it is.
    pub location: Location,
    /// The offending source line, trimmed.
    pub snippet: String,
    /// What is wrong and why it matters. Two sentences at most.
    pub description: String,
    /// What to do about it. Actionable, specific to this code.
    pub remediation: String,
    /// Other rules that matched the same location, kept for traceability
    /// rather than reported as separate findings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secondary_rule_ids: Vec<String>,

    /// External identifiers this finding covers, such as the CVE and GHSA ids
    /// behind one vulnerable dependency.
    ///
    /// A dependency with eleven published advisories is one thing to fix and
    /// one finding to read, but a consumer still needs every identifier. They
    /// live here rather than in the prose so a machine can use them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

impl Finding {
    /// The deduplication key: rule, location, and title.
    ///
    /// The title is part of the identity because one rule can legitimately
    /// report distinct problems at one location — a dependency line with two
    /// published advisories against it is two findings, not one. Collapsing
    /// them would drop a real vulnerability, and which one survived would
    /// depend on iteration order.
    ///
    /// Findings from *different* rules never collide here, because `rule_id`
    /// leads the key; merging those is the rule engine's job, where the
    /// higher-severity rule wins and the other is kept as a secondary match.
    #[must_use]
    pub fn dedupe_key(&self) -> (&str, &PathBuf, usize, usize, &str) {
        (
            &self.rule_id,
            &self.location.file,
            self.location.line,
            self.location.column,
            &self.title,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, title: &str, line: usize) -> Finding {
        Finding {
            rule_id: rule.to_owned(),
            title: title.to_owned(),
            kind: Kind::Defect,
            severity: Severity::High,
            confidence: Confidence::High,
            categories: vec![crate::Category::Llm04],
            location: Location {
                file: PathBuf::from("requirements.txt"),
                line,
                column: 1,
            },
            snippet: "requests==2.19.1".to_owned(),
            description: String::new(),
            remediation: String::new(),
            secondary_rule_ids: Vec::new(),
            references: Vec::new(),
        }
    }

    #[test]
    fn two_advisories_on_one_line_are_two_findings() {
        // A dependency with more than one published advisory is more than one
        // finding. Collapsing them dropped real vulnerabilities, and which one
        // survived depended on hash iteration order.
        let a = finding(
            "BAS-CVE-001",
            "requests 2.19.1 is affected by CVE-2018-18074",
            1,
        );
        let b = finding(
            "BAS-CVE-001",
            "requests 2.19.1 is affected by GHSA-x4qr-2fvf-3mr5",
            1,
        );

        assert_ne!(a.dedupe_key(), b.dedupe_key());
    }

    #[test]
    fn the_same_finding_twice_is_one_finding() {
        let a = finding(
            "BAS-CVE-001",
            "requests 2.19.1 is affected by CVE-2018-18074",
            1,
        );
        let b = a.clone();

        assert_eq!(a.dedupe_key(), b.dedupe_key());
    }
}
