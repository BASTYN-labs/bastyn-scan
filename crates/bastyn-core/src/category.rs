//! Framework categories every finding is mapped to.
//!
//! Two frameworks, nineteen categories: the OWASP Top 10 for `GenAI` (08/2026)
//! and Anthropic's Zero Trust guidance for agents (05/2026). Five of the
//! nineteen carry no signal in source code — they are process and lifecycle
//! guidance — and are deliberately absent from this enum. A rule that wants to
//! claim one of them is a rule that should not exist.
//!
//! The two frameworks are not two flat lists of equals. The OWASP categories
//! name *threats*, and those threats sit in concentric rings: an attacker gets
//! in through an entry vector, the foothold is magnified by the agent's own
//! machinery, and it lands as an impact. The Zero Trust categories name the
//! *defenses* that break that chain, in rings of their own. [`Layer`] is that
//! structure, and it is what lets a report argue an order of work instead of
//! only listing what is wrong: close the entry vector and the impacts
//! downstream of it never happen.

use serde::{Deserialize, Serialize};

/// Which ring of the defensive model a Zero Trust category belongs to.
///
/// Declaration order is outermost first, matching [`Layer`]'s: a control at
/// the perimeter fails before one in the machinery ever gets tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Ring {
    /// The boundary between the agent and everything it does not trust:
    /// sandboxing, and the separation of instructions from data.
    Perimeter,
    /// The agent's own workings — who it is, what it may reach, what it
    /// remembers.
    Machinery,
    /// Controls that do not stop the attack but bound what it costs, chiefly
    /// by making it visible after the fact.
    ImpactMitigation,
}

/// Where a [`Category`] sits in the threat model.
///
/// Threat layers come first and in causal order, because the order the
/// variants are declared in is the order the report prioritises them: the
/// renderer files a finding under the *smallest* layer among its categories,
/// so `Entry` preceding `Impact` is the statement that an entry vector is the
/// more useful thing to fix. `Defense` comes last for the same reason — a
/// finding that names both a threat and the defense it defeats is filed as the
/// threat, because the threat is what actually goes wrong.
///
/// `CrossLayer` is not a hedge. It is for threats that genuinely appear at
/// more than one ring: excessive agency is both how an attacker moves and what
/// they move with, and improper output handling is both an entry vector for
/// the next component and an impact on this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Layer {
    /// How an attack gets in.
    Entry,
    /// What turns a foothold into leverage.
    Amplifier,
    /// What the attack finally costs.
    Impact,
    /// Present at more than one ring at once.
    CrossLayer,
    /// A control that would have broken the chain, and is absent.
    Defense(Ring),
}

/// A framework category a finding maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum Category {
    /// LLM01 — untrusted input reaching a prompt.
    Llm01,
    /// LLM02 — secrets or personal data leaving through the model.
    Llm02,
    /// LLM03 — the model given more authority than the task needs.
    Llm03,
    /// LLM04 — vulnerable or unpinned dependencies, untrusted model sources.
    Llm04,
    /// LLM06 — no ceiling on tokens, calls, or cost. Context-dependent.
    Llm06,
    /// LLM08 — secrets or internal detail inside a system prompt.
    Llm08,
    /// LLM09 — vector store queried without tenant isolation. Context-dependent.
    Llm09,
    /// LLM10 — model output used as code, SQL, a shell command, or markup.
    Llm10,
    /// ZT1 — static, long-lived, or hardcoded credentials.
    Zt1,
    /// ZT2 — wildcard tool grants, unscoped permissions.
    Zt2,
    /// ZT3 — no sandbox boundary; unrestricted filesystem or network reach.
    Zt3,
    /// ZT4 — untrusted data mixed into instructions without separation.
    Zt4,
    /// ZT5 — memory or session state shared across users. Context-dependent.
    Zt5,
    /// ZT6 — tool calls that leave no audit trail. Context-dependent.
    Zt6,
}

impl Category {
    /// The stable identifier used in reports, e.g. `"LLM01"`.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Llm01 => "LLM01",
            Self::Llm02 => "LLM02",
            Self::Llm03 => "LLM03",
            Self::Llm04 => "LLM04",
            Self::Llm06 => "LLM06",
            Self::Llm08 => "LLM08",
            Self::Llm09 => "LLM09",
            Self::Llm10 => "LLM10",
            Self::Zt1 => "ZT1",
            Self::Zt2 => "ZT2",
            Self::Zt3 => "ZT3",
            Self::Zt4 => "ZT4",
            Self::Zt5 => "ZT5",
            Self::Zt6 => "ZT6",
        }
    }

    /// The human-readable name of the category.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Llm01 => "Prompt Injection",
            Self::Llm02 => "Sensitive Information Disclosure",
            Self::Llm03 => "Excessive Agency",
            Self::Llm04 => "Supply Chain",
            Self::Llm06 => "Unbounded Consumption",
            Self::Llm08 => "Hidden Context Exposure",
            Self::Llm09 => "Vector and Embedding Weaknesses",
            Self::Llm10 => "Improper Output Handling",
            Self::Zt1 => "Identity and Credentials",
            Self::Zt2 => "Least Agency and Access",
            Self::Zt3 => "Isolation and Runtime",
            Self::Zt4 => "I/O and Prompt Defenses",
            Self::Zt5 => "Memory and Context",
            Self::Zt6 => "Observability and Logging",
        }
    }

    /// Whether this category can only ever be reported as an observation.
    ///
    /// These describe a control the repository shows to be absent, without
    /// showing that its absence is wrong — the limiter may be at the edge, the
    /// chatbot may be deliberately public. Reporting them as defects is the
    /// single largest source of noise in the tools we measured.
    #[must_use]
    pub const fn is_context_dependent(self) -> bool {
        matches!(self, Self::Llm06 | Self::Llm09 | Self::Zt5 | Self::Zt6)
    }

    /// The external framework families this category's *risk* is discussed
    /// in, per the OWASP `GenAI` mapping table maintained alongside this
    /// enum's source of truth (see `docs/frameworks/owasp-genai-top10.md`).
    ///
    /// This is deliberately coarse: it names families such as "NIST AI RMF"
    /// or "MITRE ATLAS", never a specific control or technique ID, because
    /// the source mapping only goes that far. It says the category is
    /// *discussed* in that framework family — not that a Bastyn finding
    /// satisfies, violates, or maps to any control inside it. Nothing here
    /// is a compliance claim, and nothing here belongs in a finding, a rule
    /// tag, or SARIF output: those are per-rule, and this is per-category
    /// taxonomy coverage, a different and much weaker claim.
    ///
    /// Zero Trust categories (`Zt*`) return an empty slice. Their source
    /// table has no framework-family column at all — its third column is a
    /// governing *principle* Anthropic wrote for its own guidance, not a
    /// citation to an external framework, and the two must never be
    /// conflated.
    #[must_use]
    pub const fn framework_families(self) -> &'static [&'static str] {
        match self {
            Self::Llm01 => &[
                "NIST AI RMF",
                "NIST GenAI",
                "MITRE ATLAS",
                "CWE",
                "OWASP Agentic",
                "OWASP GenAI",
            ],
            Self::Llm02 => &[
                "NIST AI RMF",
                "NIST GenAI",
                "MITRE ATLAS",
                "CWE",
                "CSA AI",
                "OWASP GenAI",
            ],
            Self::Llm03 => &[
                "NIST AI RMF",
                "MITRE ATLAS",
                "CWE",
                "CSA AI",
                "OWASP Agentic",
            ],
            Self::Llm04 => &[
                "NIST AI RMF",
                "MITRE ATLAS",
                "MITRE ATT&CK",
                "CWE",
                "CSA AI",
                "OWASP AppSec",
            ],
            Self::Llm06 => &["NIST AI RMF", "MITRE ATLAS", "CWE", "CSA AI"],
            Self::Llm08 => &["NIST AI RMF", "MITRE ATLAS", "CWE", "OWASP Agentic"],
            Self::Llm09 => &["NIST AI RMF", "MITRE ATLAS", "CWE", "CSA AI", "OWASP GenAI"],
            Self::Llm10 => &[
                "NIST AI RMF",
                "MITRE ATLAS",
                "CWE",
                "CSA AI",
                "OWASP Top 10",
            ],
            Self::Zt1 | Self::Zt2 | Self::Zt3 | Self::Zt4 | Self::Zt5 | Self::Zt6 => &[],
        }
    }

    /// Where this category sits in the threat model — see [`Layer`].
    ///
    /// Written as an exhaustive match rather than a `matches!` chain with a
    /// fallback, so that adding a category without deciding where it belongs
    /// is a compile error. A silently unclassified category would drop out of
    /// the grouped report, and a finding that is never printed is worse than
    /// one printed in the wrong place.
    #[must_use]
    pub const fn layer(self) -> Layer {
        match self {
            // The two ways in: text the attacker wrote, and code someone else
            // wrote that the build pulled in.
            Self::Llm01 | Self::Llm04 => Layer::Entry,
            // Both are the context window working against its owner — a
            // foothold reads more, or reaches further, than it should.
            Self::Llm08 | Self::Llm09 => Layer::Amplifier,
            // What the attacker leaves with: data, or someone else's bill.
            Self::Llm02 | Self::Llm06 => Layer::Impact,
            Self::Llm03 | Self::Llm10 => Layer::CrossLayer,
            // The boundary controls: keep the agent in, keep instructions and
            // data apart.
            Self::Zt3 | Self::Zt4 => Layer::Defense(Ring::Perimeter),
            // Identity, authority, and memory: the agent's own workings.
            Self::Zt1 | Self::Zt2 | Self::Zt5 => Layer::Defense(Ring::Machinery),
            // Logging stops nothing. It bounds how long the damage runs.
            Self::Zt6 => Layer::Defense(Ring::ImpactMitigation),
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::{Category, Layer, Ring};

    /// Every category, with the two strings the outside world sees.
    ///
    /// `id()` is what the terminal prints and what SARIF puts in `tags`; the
    /// serialised form is what lands in the JSON report's `categories` array.
    /// They happen to be identical today, and this table exists so that they
    /// stay that way by decision rather than by accident.
    const CONTRACT: [(Category, &str); 14] = [
        (Category::Llm01, "LLM01"),
        (Category::Llm02, "LLM02"),
        (Category::Llm03, "LLM03"),
        (Category::Llm04, "LLM04"),
        (Category::Llm06, "LLM06"),
        (Category::Llm08, "LLM08"),
        (Category::Llm09, "LLM09"),
        (Category::Llm10, "LLM10"),
        (Category::Zt1, "ZT1"),
        (Category::Zt2, "ZT2"),
        (Category::Zt3, "ZT3"),
        (Category::Zt4, "ZT4"),
        (Category::Zt5, "ZT5"),
        (Category::Zt6, "ZT6"),
    ];

    #[test]
    fn ids_and_serialised_forms_are_a_stable_contract() {
        for (category, id) in CONTRACT {
            assert_eq!(category.id(), id);
            assert_eq!(category.to_string(), id);
            assert_eq!(
                serde_json::to_string(&category).unwrap(),
                format!("\"{id}\"")
            );
            assert_eq!(
                serde_json::from_str::<Category>(&format!("\"{id}\"")).unwrap(),
                category,
                "{id} must still deserialise back to the category it names"
            );
        }
    }

    /// The product team's threat model, transcribed.
    ///
    /// Every category, so that this is a statement about the whole mapping and
    /// not a spot check: a category quietly moving ring is exactly the kind of
    /// change that would reorder the report without anyone noticing.
    #[test]
    fn every_category_sits_where_the_threat_model_puts_it() {
        let expected = [
            (Category::Llm01, Layer::Entry),
            (Category::Llm04, Layer::Entry),
            (Category::Llm08, Layer::Amplifier),
            (Category::Llm09, Layer::Amplifier),
            (Category::Llm02, Layer::Impact),
            (Category::Llm06, Layer::Impact),
            (Category::Llm03, Layer::CrossLayer),
            (Category::Llm10, Layer::CrossLayer),
            (Category::Zt3, Layer::Defense(Ring::Perimeter)),
            (Category::Zt4, Layer::Defense(Ring::Perimeter)),
            (Category::Zt1, Layer::Defense(Ring::Machinery)),
            (Category::Zt2, Layer::Defense(Ring::Machinery)),
            (Category::Zt5, Layer::Defense(Ring::Machinery)),
            (Category::Zt6, Layer::Defense(Ring::ImpactMitigation)),
        ];

        assert_eq!(
            expected.len(),
            CONTRACT.len(),
            "every category needs a layer, or a finding could be silently unfiled"
        );
        for (category, layer) in expected {
            assert_eq!(category.layer(), layer, "{category} is on the wrong layer");
        }
    }

    /// OWASP categories name at least one framework family; Zero Trust
    /// categories name none, because their source table maps to a governing
    /// principle instead — not an external framework — and that distinction
    /// must survive here, not just in the doc file.
    #[test]
    fn framework_families_are_owasp_only_and_never_empty_for_owasp() {
        for (category, id) in CONTRACT {
            let families = category.framework_families();
            if id.starts_with("LLM") {
                assert!(
                    !families.is_empty(),
                    "{id} is an OWASP category and must name at least one framework family"
                );
            } else {
                assert!(
                    families.is_empty(),
                    "{id} is a Zero Trust category and must not claim an external framework family"
                );
            }
        }
    }

    /// The product team's framework-family mapping, transcribed verbatim so
    /// a drifted family name or a silently dropped one fails a test instead
    /// of only being visible in a doc diff.
    #[test]
    fn framework_families_match_the_source_mapping() {
        assert_eq!(
            Category::Llm01.framework_families(),
            [
                "NIST AI RMF",
                "NIST GenAI",
                "MITRE ATLAS",
                "CWE",
                "OWASP Agentic",
                "OWASP GenAI",
            ]
        );
        assert_eq!(
            Category::Llm02.framework_families(),
            [
                "NIST AI RMF",
                "NIST GenAI",
                "MITRE ATLAS",
                "CWE",
                "CSA AI",
                "OWASP GenAI",
            ]
        );
        assert_eq!(
            Category::Llm03.framework_families(),
            [
                "NIST AI RMF",
                "MITRE ATLAS",
                "CWE",
                "CSA AI",
                "OWASP Agentic"
            ]
        );
        assert_eq!(
            Category::Llm04.framework_families(),
            [
                "NIST AI RMF",
                "MITRE ATLAS",
                "MITRE ATT&CK",
                "CWE",
                "CSA AI",
                "OWASP AppSec",
            ]
        );
        assert_eq!(
            Category::Llm06.framework_families(),
            ["NIST AI RMF", "MITRE ATLAS", "CWE", "CSA AI"]
        );
        assert_eq!(
            Category::Llm08.framework_families(),
            ["NIST AI RMF", "MITRE ATLAS", "CWE", "OWASP Agentic"]
        );
        assert_eq!(
            Category::Llm09.framework_families(),
            ["NIST AI RMF", "MITRE ATLAS", "CWE", "CSA AI", "OWASP GenAI"]
        );
        assert_eq!(
            Category::Llm10.framework_families(),
            [
                "NIST AI RMF",
                "MITRE ATLAS",
                "CWE",
                "CSA AI",
                "OWASP Top 10"
            ]
        );
        for zt in [
            Category::Zt1,
            Category::Zt2,
            Category::Zt3,
            Category::Zt4,
            Category::Zt5,
            Category::Zt6,
        ] {
            assert!(zt.framework_families().is_empty());
        }
    }

    /// The ordering is load-bearing, not incidental.
    ///
    /// The renderer files a multi-category finding under the smallest layer
    /// among its categories, so this ordering *is* the tie-break rule. Reorder
    /// the variants and the report silently reprioritises.
    #[test]
    fn layers_are_ordered_by_where_a_fix_has_the_most_leverage() {
        let mut ordered = [
            Layer::Defense(Ring::ImpactMitigation),
            Layer::Impact,
            Layer::Defense(Ring::Perimeter),
            Layer::Entry,
            Layer::CrossLayer,
            Layer::Defense(Ring::Machinery),
            Layer::Amplifier,
        ];
        ordered.sort_unstable();

        assert_eq!(
            ordered,
            [
                Layer::Entry,
                Layer::Amplifier,
                Layer::Impact,
                Layer::CrossLayer,
                Layer::Defense(Ring::Perimeter),
                Layer::Defense(Ring::Machinery),
                Layer::Defense(Ring::ImpactMitigation),
            ]
        );
    }
}
