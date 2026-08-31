//! Crosswalk from [`Category`] to the EU AI Act and the two NIST AI documents.
//!
//! A crosswalk, never a verdict. The strongest claim anything in this module
//! makes is that a finding is *relevant to* a named article or subcategory.
//! Bastyn cannot determine regulatory compliance: that turns on the deployment
//! context, the system's risk classification, and the organisation's
//! documentation and processes, none of which are in a source tree. [`
//! DISCLAIMER`] says exactly that, and every renderer that emits a crosswalk
//! emits it too, so the caveat travels with the data instead of living only in
//! a document nobody opens.
//!
//! Every identifier and every quoted string in this file was transcribed from
//! a primary source fetched on 2026-08-28; the URLs, access dates, the
//! reasoning behind each row, and the reasoning behind each deliberately empty
//! cell are in `docs/frameworks/compliance-crosswalk.md`. Nothing here was
//! written from memory, and a mapping that cannot be quoted from a source does
//! not belong here.
//!
//! This is per *category*, exactly like [`Category::framework_families`], and
//! for the same reason: per-rule identifiers are a separate and much stronger
//! claim that Bastyn's rule schema does not yet support.

use serde::{Deserialize, Serialize};

use crate::category::Category;
use crate::finding::Kind;
use crate::report::Report;

/// The one sentence that must never be got wrong.
///
/// Printed by the terminal renderer and carried in the JSON whenever a
/// crosswalk is produced. Stated once, plainly, and not buried.
pub const DISCLAIMER: &str = "This is a crosswalk, not a compliance assessment. It says which \
regulatory areas these findings are relevant to. Bastyn cannot determine compliance: that \
depends on the deployment context, the system's risk classification, and the organisation's \
documentation and processes, none of which are in the source code. Finding nothing does not mean \
an obligation is met.";

/// Words that must never appear anywhere a crosswalk is printed.
///
/// A verdict, in any of its spellings. These are checked against every string
/// this module holds — including the article headings and subcategory
/// sentences transcribed from the source documents, none of which contains
/// one — and against the bytes every renderer emits.
///
/// Public because the same filter has to be applied in three places — the
/// mapping's own strings, the terminal renderer's prose, and the CLI's
/// end-to-end output — and three copies of a list like this drift apart.
pub const FORBIDDEN_CLAIMS: &[&str] = &[
    "complies",
    "compliant",
    "satisfied",
    "satisfies",
    "certified",
    "audit passed",
    "conformant",
    "meets the requirement",
];

/// Words that must never appear in prose Bastyn wrote itself.
///
/// Weaker than a verdict and more dangerous for it. A draft of the terminal
/// layout described findings as "potential technical gaps", which asserts that
/// a framework area was examined and found short — far more than any word in
/// [`FORBIDDEN_CLAIMS`] — while sailing straight through that filter. A
/// crosswalk says which areas findings are relevant to. It never says an area
/// was measured, scored, aligned with, or left short.
///
/// Applied only to what Bastyn authors, never to transcribed source text. NIST
/// AI 100-1's MAP 3.5 reads "Processes for human oversight are defined,
/// assessed, and documented"; that is NIST describing an outcome in its own
/// words, and altering a citation to satisfy a word list would be the worse
/// failure by a distance.
///
/// Matched as substrings against lowercased text, so "gap" covers "gaps".
/// "Coverage gaps" is a legitimate heading in the report — this list applies
/// to the crosswalk, not to the whole document.
pub const FORBIDDEN_CHARACTERISATIONS: &[&str] = &["gap", "assessed", "scored", "aligned"];

/// The one line that opens the crosswalk section of a terminal report.
///
/// It has to do two jobs in one line: say what the section is, and say what it
/// is not, before the reader has seen a single framework name.
pub const CROSSWALK_INTRO: &str =
    "Which framework areas these findings touch. Not a compliance assessment.";

/// The paragraph that closes the crosswalk section of a terminal report.
///
/// Says what [`DISCLAIMER`] says. They are two strings rather than one because
/// [`DISCLAIMER`] is a published contract — JSON and SARIF carry it verbatim,
/// and rewording it would change bytes other tools already parse — while this
/// is the terminal's own prose, laid out for a reader who is looking at a
/// table and about to draw a conclusion from it.
///
/// Both go through the same anti-overclaim filter, and both end on the
/// sentence that carries the most weight: an empty table is not a clean bill
/// of health.
pub const TERMINAL_CAVEAT: &str = "A source scan cannot determine legal compliance. It does not \
establish applicability, system classification, or the presence of organizational and deployment \
controls. Finding nothing does not mean an obligation is met.";

/// A framework Bastyn's categories are crosswalked to.
///
/// Each variant is renamed explicitly rather than by a `rename_all` rule, so
/// that the serialised form is the same string [`Framework::id`] returns and
/// the same one `--group-by` accepts. A derived rule got this wrong once:
/// `kebab-case` spells `NistGenAi` as `nist-gen-ai`, which would have made a
/// pipeline filter on a value the command line will not take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Framework {
    /// Regulation (EU) 2024/1689, the Artificial Intelligence Act.
    #[serde(rename = "eu-ai-act")]
    EuAiAct,
    /// NIST AI 100-1, the AI Risk Management Framework 1.0.
    #[serde(rename = "nist-ai-rmf")]
    NistAiRmf,
    /// NIST AI 600-1, the Generative AI Profile.
    #[serde(rename = "nist-genai")]
    NistGenAi,
}

/// One identifier inside a framework, with text quoted from its source.
///
/// `title` is transcribed, not paraphrased. An article heading or a
/// subcategory sentence read in the words the framework itself uses is the
/// only kind of citation an auditor can check.
///
/// This is the static mapping table's own type, and deliberately not a
/// serialised one: it borrows `'static` text, whereas a [`Group`] read back
/// out of a JSON report owns its strings. Keeping the two apart is what lets
/// the table stay allocation-free without forcing that choice on every
/// consumer of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Control {
    /// The identifier as the framework spells it, e.g. `"Art. 15"` or
    /// `"MEASURE 2.7"`.
    pub id: &'static str,
    /// The heading or subcategory text, quoted from the source document.
    pub title: &'static str,
}

// ---------------------------------------------------------------------------
// EU AI Act — Regulation (EU) 2024/1689. Headings quoted from the OJ text.
// ---------------------------------------------------------------------------

/// Article 12, quoted from Regulation (EU) 2024/1689.
const EU_ART_12: Control = Control {
    id: "Art. 12",
    title: "Record-keeping",
};
/// Article 14, quoted from Regulation (EU) 2024/1689.
const EU_ART_14: Control = Control {
    id: "Art. 14",
    title: "Human oversight",
};
/// Article 15, quoted from Regulation (EU) 2024/1689.
const EU_ART_15: Control = Control {
    id: "Art. 15",
    title: "Accuracy, robustness and cybersecurity",
};

// ---------------------------------------------------------------------------
// NIST AI RMF 1.0 — subcategory text quoted from AI 100-1, Tables 2 to 4.
// ---------------------------------------------------------------------------

/// MAP 3.5, quoted from NIST AI 100-1 Table 2.
const RMF_MAP_3_5: Control = Control {
    id: "MAP 3.5",
    title: "Processes for human oversight are defined, assessed, and documented in accordance \
with organizational policies from the GOVERN function.",
};
/// MAP 4.1, quoted from NIST AI 100-1 Table 2.
const RMF_MAP_4_1: Control = Control {
    id: "MAP 4.1",
    title: "Approaches for mapping AI technology and legal risks of its components \u{2013} \
including the use of third-party data or software \u{2013} are in place, followed, and \
documented, as are risks of infringement of a third party's intellectual property or other \
rights.",
};
/// MEASURE 2.4, quoted from NIST AI 100-1 Table 3.
const RMF_MEASURE_2_4: Control = Control {
    id: "MEASURE 2.4",
    title: "The functionality and behavior of the AI system and its components \u{2013} as \
identified in the MAP function \u{2013} are monitored when in production.",
};
/// MEASURE 2.7, quoted from NIST AI 100-1 Table 3.
const RMF_MEASURE_2_7: Control = Control {
    id: "MEASURE 2.7",
    title: "AI system security and resilience \u{2013} as identified in the MAP function \u{2013} \
are evaluated and documented.",
};
/// MEASURE 2.10, quoted from NIST AI 100-1 Table 3.
const RMF_MEASURE_2_10: Control = Control {
    id: "MEASURE 2.10",
    title: "Privacy risk of the AI system \u{2013} as identified in the MAP function \u{2013} is \
examined and documented.",
};
/// MANAGE 3.1, quoted from NIST AI 100-1 Table 4.
const RMF_MANAGE_3_1: Control = Control {
    id: "MANAGE 3.1",
    title: "AI risks and benefits from third-party resources are regularly monitored, and risk \
controls are applied and documented.",
};
/// MANAGE 4.1, quoted from NIST AI 100-1 Table 4.
const RMF_MANAGE_4_1: Control = Control {
    id: "MANAGE 4.1",
    title: "Post-deployment AI system monitoring plans are implemented, including mechanisms for \
capturing and evaluating input from users and other relevant AI actors, appeal and override, \
decommissioning, incident response, recovery, and change management.",
};

// ---------------------------------------------------------------------------
// NIST Generative AI Profile — risk definitions quoted from AI 600-1 §2.
// ---------------------------------------------------------------------------

/// Risk 4, quoted from NIST AI 600-1 §2.
const GENAI_DATA_PRIVACY: Control = Control {
    id: "Data Privacy",
    title: "Impacts due to leakage and unauthorized use, disclosure, or de-anonymization of \
biometric, health, location, or other personally identifiable information or sensitive data.",
};
/// Risk 9, quoted from NIST AI 600-1 §2.
const GENAI_INFORMATION_SECURITY: Control = Control {
    id: "Information Security",
    title: "Lowered barriers for offensive cyber capabilities, including via automated discovery \
and exploitation of vulnerabilities to ease hacking, malware, phishing, offensive cyber \
operations, or other cyberattacks; increased attack surface for targeted cyberattacks, which may \
compromise a system's availability or the confidentiality or integrity of training data, code, or \
model weights.",
};
/// Risk 12, quoted from NIST AI 600-1 §2.
const GENAI_VALUE_CHAIN: Control = Control {
    id: "Value Chain and Component Integration",
    title: "Non-transparent or untraceable integration of upstream third-party components, \
including data that has been improperly obtained or not processed and cleaned due to increased \
automation from GAI; improper supplier vetting across the AI lifecycle; or other issues that \
diminish transparency or accountability for downstream users.",
};

impl Framework {
    /// Every framework, in the order a report presents them.
    pub const ALL: [Self; 3] = [Self::EuAiAct, Self::NistAiRmf, Self::NistGenAi];

    /// The stable identifier used on the command line and in JSON.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::EuAiAct => "eu-ai-act",
            Self::NistAiRmf => "nist-ai-rmf",
            Self::NistGenAi => "nist-genai",
        }
    }

    /// The short name a heading uses.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EuAiAct => "EU AI Act",
            Self::NistAiRmf => "NIST AI RMF 1.0",
            Self::NistGenAi => "NIST Generative AI Profile",
        }
    }

    /// The full citation of the document the identifiers come from.
    #[must_use]
    pub const fn citation(self) -> &'static str {
        match self {
            Self::EuAiAct => "Regulation (EU) 2024/1689, as amended by Regulation (EU) 2026/1744",
            Self::NistAiRmf => {
                "NIST AI 100-1, Artificial Intelligence Risk Management Framework (AI RMF 1.0)"
            }
            Self::NistGenAi => {
                "NIST AI 600-1, Artificial Intelligence Risk Management Framework: Generative \
Artificial Intelligence Profile"
            }
        }
    }

    /// The document's identifier, without its title.
    ///
    /// What a terminal table names the source as. [`Self::citation`] is the
    /// full reference and is what JSON and SARIF carry, but the identifier is
    /// the checkable half — it is the string a reader types into a search box
    /// — and the title is what pushes the heading past the width of the
    /// screen. `Regulation (EU) 2024/1689` fits on one line; the same string
    /// with `, as amended by Regulation (EU) 2026/1744` after it does not, and
    /// the amendment is named in the standing footnote directly below anyway.
    #[must_use]
    pub const fn document_id(self) -> &'static str {
        match self {
            Self::EuAiAct => "Regulation (EU) 2024/1689",
            Self::NistAiRmf => "NIST AI 100-1",
            Self::NistGenAi => "NIST AI 600-1",
        }
    }

    /// Where the identifiers were read from.
    #[must_use]
    pub const fn source_url(self) -> &'static str {
        match self {
            Self::EuAiAct => {
                "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02024R1689-20260727"
            }
            Self::NistAiRmf => "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf",
            Self::NistGenAi => "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf",
        }
    }

    /// What a reader must know about this framework's standing before using
    /// the grouping.
    ///
    /// For the EU AI Act that is the application date, because it moved: the
    /// articles this crosswalk names do not bind anyone yet, and a compliance
    /// reader who assumes otherwise is planning against the wrong deadline.
    /// For the NIST documents it is that they are voluntary guidance, so that
    /// nobody reads a group heading as a legal duty.
    #[must_use]
    pub const fn standing(self) -> &'static str {
        match self {
            Self::EuAiAct => {
                "Articles 12, 14 and 15 sit in Chapter III, Sections 1 to 3, which apply from \
2 December 2027 for AI systems classified as high-risk under Article 6(2) and Annex III, and \
from 2 August 2028 under Article 6(1) and Annex I \u{2014} Article 113 as amended by Regulation \
(EU) 2026/1744. They bind high-risk AI systems only, and nothing in a source tree says whether \
this system is one."
            }
            Self::NistAiRmf | Self::NistGenAi => {
                "Voluntary guidance, not a regulation. Its subcategories describe outcomes an \
organisation works towards, not conditions a repository can be measured against."
            }
        }
    }

    /// Every control this framework contributes, in the order groups print.
    ///
    /// The canonical order lives here and nowhere else, so a group can never
    /// appear in one output format and be missing from another, and the order
    /// cannot drift between the terminal and the JSON.
    #[must_use]
    pub const fn controls(self) -> &'static [Control] {
        match self {
            Self::EuAiAct => &[EU_ART_12, EU_ART_14, EU_ART_15],
            Self::NistAiRmf => &[
                RMF_MAP_3_5,
                RMF_MAP_4_1,
                RMF_MEASURE_2_4,
                RMF_MEASURE_2_7,
                RMF_MEASURE_2_10,
                RMF_MANAGE_3_1,
                RMF_MANAGE_4_1,
            ],
            Self::NistGenAi => &[
                GENAI_DATA_PRIVACY,
                GENAI_INFORMATION_SECURITY,
                GENAI_VALUE_CHAIN,
            ],
        }
    }
}

impl Category {
    /// The controls in `framework` this category's risk is *relevant to*.
    ///
    /// Never "satisfies", never "violates". A finding under this category
    /// touches the area the control governs; whether the obligation is met is
    /// a question about the deployment, not about the code.
    ///
    /// An empty slice is a real answer and appears twice on purpose:
    /// [`Category::Llm06`] has no EU AI Act mapping because no article
    /// addresses cost or token ceilings, and [`Category::Zt6`] has no NIST
    /// Generative AI Profile mapping because none of that document's twelve
    /// risks is about audit trails. Stretching either to fill the table would
    /// be the overclaim this whole module exists to avoid.
    #[must_use]
    pub const fn controls(self, framework: Framework) -> &'static [Control] {
        match framework {
            Framework::EuAiAct => self.eu_ai_act_controls(),
            Framework::NistAiRmf => self.nist_ai_rmf_controls(),
            Framework::NistGenAi => self.nist_genai_controls(),
        }
    }

    /// EU AI Act articles, per `docs/frameworks/compliance-crosswalk.md`.
    ///
    /// Article 15(5) carries most of this: it names data poisoning, poisoning
    /// of "pre-trained components used in training", "inputs designed to cause
    /// the AI model to make a mistake", and confidentiality attacks. Article
    /// 14(4)(d) and (e) — the ability to override output and interrupt the
    /// system — is where excessive agency and unscoped grants land. Article
    /// 12(1) is the obligation to record events, which is what ZT6 is about.
    const fn eu_ai_act_controls(self) -> &'static [Control] {
        match self {
            Self::Llm03 | Self::Zt2 => &[EU_ART_14],
            Self::Llm01
            | Self::Llm02
            | Self::Llm04
            | Self::Llm08
            | Self::Llm09
            | Self::Llm10
            | Self::Zt1
            | Self::Zt3
            | Self::Zt4
            | Self::Zt5 => &[EU_ART_15],
            Self::Zt6 => &[EU_ART_12],
            // No article addresses cost, token, or call ceilings. Article
            // 15(4) is about resilience to "errors, faults or
            // inconsistencies"; a missing token ceiling is neither.
            Self::Llm06 => &[],
        }
    }

    /// NIST AI RMF 1.0 subcategories, per
    /// `docs/frameworks/compliance-crosswalk.md`.
    ///
    /// `MEASURE 2.7` carries thirteen of the fourteen because it is the
    /// framework's security-and-resilience subcategory and Bastyn is a
    /// security scanner. Spreading findings across GOVERN subcategories to
    /// make the table look richer would claim coverage of policy and process
    /// that no scan can see.
    const fn nist_ai_rmf_controls(self) -> &'static [Control] {
        match self {
            Self::Llm01
            | Self::Llm06
            | Self::Llm08
            | Self::Llm10
            | Self::Zt1
            | Self::Zt3
            | Self::Zt4 => &[RMF_MEASURE_2_7],
            Self::Llm02 | Self::Llm09 | Self::Zt5 => &[RMF_MEASURE_2_7, RMF_MEASURE_2_10],
            Self::Llm03 | Self::Zt2 => &[RMF_MAP_3_5, RMF_MEASURE_2_7],
            Self::Llm04 => &[RMF_MAP_4_1, RMF_MEASURE_2_7, RMF_MANAGE_3_1],
            Self::Zt6 => &[RMF_MEASURE_2_4, RMF_MANAGE_4_1],
        }
    }

    /// NIST Generative AI Profile risks, per
    /// `docs/frameworks/compliance-crosswalk.md`.
    ///
    /// The mapping is to the twelve named risks in §2, not to the suggested
    /// actions in §3. A suggested action is something an organisation does; a
    /// finding does not show that it was skipped, so putting an action id on
    /// one would assert more than the code supports. The actions are quoted in
    /// the crosswalk document as the evidence for these rows instead.
    const fn nist_genai_controls(self) -> &'static [Control] {
        match self {
            Self::Llm01
            | Self::Llm03
            | Self::Llm06
            | Self::Llm08
            | Self::Llm10
            | Self::Zt1
            | Self::Zt2
            | Self::Zt3
            | Self::Zt4 => &[GENAI_INFORMATION_SECURITY],
            Self::Llm02 | Self::Llm09 | Self::Zt5 => {
                &[GENAI_DATA_PRIVACY, GENAI_INFORMATION_SECURITY]
            }
            Self::Llm04 => &[GENAI_INFORMATION_SECURITY, GENAI_VALUE_CHAIN],
            // None of the twelve risks in AI 600-1 §2 is about traceability or
            // audit trails. Information Security is about attack surface and
            // offensive capability, not whether a tool call was recorded.
            Self::Zt6 => &[],
        }
    }
}

/// The findings relevant to one control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    /// The control's identifier as its framework spells it, e.g. `"Art. 15"`.
    pub id: String,
    /// The control's heading or subcategory text, quoted from the source.
    pub title: String,
    /// Indices into [`Report::findings`], ascending.
    ///
    /// Indices rather than copies: the findings are already in the document,
    /// and a finding relevant to three articles would otherwise be serialised
    /// three times.
    pub findings: Vec<usize>,
    /// How many of those are defects.
    pub defects: usize,
    /// How many of those are observations.
    pub observations: usize,
}

/// Findings the framework has nothing to say about.
///
/// Present even when empty, because a finding silently vanishing from a
/// compliance view is worse than one shown as unmapped. `LLM06` under the EU
/// AI Act is the case this exists for.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Unmapped {
    /// Indices into [`Report::findings`], ascending.
    pub findings: Vec<usize>,
    /// How many of those are defects.
    pub defects: usize,
    /// How many of those are observations.
    pub observations: usize,
}

/// A report's findings, grouped by the areas of one framework they touch.
///
/// Not a compliance assessment; see [`DISCLAIMER`], which this struct carries
/// so that no consumer can read the grouping without it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Crosswalk {
    /// Which framework.
    pub framework: Framework,
    /// Its short name.
    pub name: String,
    /// The document the identifiers were read from.
    pub citation: String,
    /// Where that document was read.
    pub source_url: String,
    /// What a reader must know before using this grouping — application dates
    /// for the EU AI Act, voluntariness for the NIST documents.
    pub standing: String,
    /// [`DISCLAIMER`], verbatim.
    pub disclaimer: String,
    /// One entry per control that has at least one relevant finding, in the
    /// framework's canonical order.
    ///
    /// A finding relevant to more than one control appears under each of them,
    /// so these counts deliberately sum to more than the report's total. A
    /// crosswalk answers "which areas does this touch", not "where does this
    /// belong".
    pub groups: Vec<Group>,
    /// Findings no control in this framework covers.
    pub unmapped: Unmapped,
}

/// Group `report`'s findings by the areas of `framework` they are relevant to.
///
/// Controls with no relevant finding are omitted rather than listed empty. An
/// empty group would read as "this area is clear", and it never means that:
/// four of the fourteen categories have no production detector at all, so a
/// silent area is at least as likely to mean "nothing inspects this" as
/// "nothing is wrong here".
#[must_use]
pub fn crosswalk(report: &Report, framework: Framework) -> Crosswalk {
    let mut groups: Vec<Group> = framework
        .controls()
        .iter()
        .map(|control| Group {
            id: control.id.to_owned(),
            title: control.title.to_owned(),
            findings: Vec::new(),
            defects: 0,
            observations: 0,
        })
        .collect();
    let mut unmapped = Unmapped::default();

    for (index, finding) in report.findings.iter().enumerate() {
        let mut placed = false;
        for group in &mut groups {
            let relevant = finding.categories.iter().any(|category| {
                category
                    .controls(framework)
                    .iter()
                    .any(|control| control.id == group.id)
            });
            if relevant {
                group.findings.push(index);
                tally(finding.kind, &mut group.defects, &mut group.observations);
                placed = true;
            }
        }
        if !placed {
            unmapped.findings.push(index);
            tally(
                finding.kind,
                &mut unmapped.defects,
                &mut unmapped.observations,
            );
        }
    }

    groups.retain(|group| !group.findings.is_empty());

    Crosswalk {
        framework,
        name: framework.name().to_owned(),
        citation: framework.citation().to_owned(),
        source_url: framework.source_url().to_owned(),
        standing: framework.standing().to_owned(),
        disclaimer: DISCLAIMER.to_owned(),
        groups,
        unmapped,
    }
}

fn tally(kind: Kind, defects: &mut usize, observations: &mut usize) {
    match kind {
        Kind::Defect => *defects += 1,
        Kind::Observation => *observations += 1,
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::{
        CROSSWALK_INTRO, Category, Crosswalk, DISCLAIMER, FORBIDDEN_CHARACTERISATIONS,
        FORBIDDEN_CLAIMS, Framework, TERMINAL_CAVEAT, crosswalk,
    };
    use crate::render::test_support::{empty_report, layered_report};
    use crate::report::CveStatus;

    /// Every category, so the assertions below are about the whole mapping.
    const EVERY_CATEGORY: [Category; 14] = [
        Category::Llm01,
        Category::Llm02,
        Category::Llm03,
        Category::Llm04,
        Category::Llm06,
        Category::Llm08,
        Category::Llm09,
        Category::Llm10,
        Category::Zt1,
        Category::Zt2,
        Category::Zt3,
        Category::Zt4,
        Category::Zt5,
        Category::Zt6,
    ];

    /// The mapping, transcribed from `docs/frameworks/compliance-crosswalk.md`.
    ///
    /// Pinned in full rather than spot-checked because a compliance mapping
    /// that silently drifts is worse than one that never existed: a wrong
    /// article number in front of an auditor is the failure mode this whole
    /// feature has to avoid. A diff here is the fastest way to see that the
    /// code and the sourced document have parted company.
    #[test]
    fn the_mapping_is_exactly_what_the_sourced_document_says() {
        let eu: Vec<(Category, Vec<&str>)> = EVERY_CATEGORY
            .iter()
            .map(|category| {
                (
                    *category,
                    category
                        .controls(Framework::EuAiAct)
                        .iter()
                        .map(|control| control.id)
                        .collect(),
                )
            })
            .collect();

        assert_eq!(
            eu,
            vec![
                (Category::Llm01, vec!["Art. 15"]),
                (Category::Llm02, vec!["Art. 15"]),
                (Category::Llm03, vec!["Art. 14"]),
                (Category::Llm04, vec!["Art. 15"]),
                (Category::Llm06, vec![]),
                (Category::Llm08, vec!["Art. 15"]),
                (Category::Llm09, vec!["Art. 15"]),
                (Category::Llm10, vec!["Art. 15"]),
                (Category::Zt1, vec!["Art. 15"]),
                (Category::Zt2, vec!["Art. 14"]),
                (Category::Zt3, vec!["Art. 15"]),
                (Category::Zt4, vec!["Art. 15"]),
                (Category::Zt5, vec!["Art. 15"]),
                (Category::Zt6, vec!["Art. 12"]),
            ]
        );

        let rmf: Vec<Vec<&str>> = EVERY_CATEGORY
            .iter()
            .map(|category| {
                category
                    .controls(Framework::NistAiRmf)
                    .iter()
                    .map(|control| control.id)
                    .collect()
            })
            .collect();

        assert_eq!(
            rmf,
            vec![
                vec!["MEASURE 2.7"],
                vec!["MEASURE 2.7", "MEASURE 2.10"],
                vec!["MAP 3.5", "MEASURE 2.7"],
                vec!["MAP 4.1", "MEASURE 2.7", "MANAGE 3.1"],
                vec!["MEASURE 2.7"],
                vec!["MEASURE 2.7"],
                vec!["MEASURE 2.7", "MEASURE 2.10"],
                vec!["MEASURE 2.7"],
                vec!["MEASURE 2.7"],
                vec!["MAP 3.5", "MEASURE 2.7"],
                vec!["MEASURE 2.7"],
                vec!["MEASURE 2.7"],
                vec!["MEASURE 2.7", "MEASURE 2.10"],
                vec!["MEASURE 2.4", "MANAGE 4.1"],
            ]
        );

        let genai: Vec<Vec<&str>> = EVERY_CATEGORY
            .iter()
            .map(|category| {
                category
                    .controls(Framework::NistGenAi)
                    .iter()
                    .map(|control| control.id)
                    .collect()
            })
            .collect();

        assert_eq!(
            genai,
            vec![
                vec!["Information Security"],
                vec!["Data Privacy", "Information Security"],
                vec!["Information Security"],
                vec![
                    "Information Security",
                    "Value Chain and Component Integration"
                ],
                vec!["Information Security"],
                vec!["Information Security"],
                vec!["Data Privacy", "Information Security"],
                vec!["Information Security"],
                vec!["Information Security"],
                vec!["Information Security"],
                vec!["Information Security"],
                vec!["Information Security"],
                vec!["Data Privacy", "Information Security"],
                vec![],
            ]
        );
    }

    /// The two empty cells are decisions, not oversights.
    ///
    /// Asserted on their own so that filling either one — the tempting way to
    /// make a table look complete — fails a test that says in words why it
    /// must not be filled.
    #[test]
    fn the_two_empty_cells_stay_empty() {
        assert!(
            Category::Llm06.controls(Framework::EuAiAct).is_empty(),
            "no EU AI Act article addresses cost or token ceilings; Art. 15(4) is about \
resilience to errors, faults or inconsistencies, which a missing token ceiling is not"
        );
        assert!(
            Category::Zt6.controls(Framework::NistGenAi).is_empty(),
            "none of the twelve risks in NIST AI 600-1 section 2 is about traceability or audit \
trails"
        );
    }

    /// Every control a category names must be one the framework declares.
    ///
    /// The framework's own list is what orders the groups, so a control that
    /// only a category knows about would map findings into a group that is
    /// never rendered — a finding silently dropped from a compliance view.
    #[test]
    fn no_category_names_a_control_its_framework_does_not_declare() {
        for framework in Framework::ALL {
            let declared: Vec<&str> = framework
                .controls()
                .iter()
                .map(|control| control.id)
                .collect();
            for category in EVERY_CATEGORY {
                for control in category.controls(framework) {
                    assert!(
                        declared.contains(&control.id),
                        "{category} names {} in {}, which the framework does not declare",
                        control.id,
                        framework.name()
                    );
                }
            }
        }
    }

    /// Every control a framework declares must be reachable from a category.
    ///
    /// An unreachable control is dead data pretending to be coverage.
    #[test]
    fn every_declared_control_is_reachable_from_some_category() {
        for framework in Framework::ALL {
            for control in framework.controls() {
                assert!(
                    EVERY_CATEGORY.iter().any(|category| category
                        .controls(framework)
                        .iter()
                        .any(|mapped| mapped.id == control.id)),
                    "{} in {} maps from no category",
                    control.id,
                    framework.name()
                );
            }
        }
    }

    /// The identifiers a category names are unique and in the framework's own
    /// order, so a group's membership never depends on iteration order.
    #[test]
    fn a_category_never_names_the_same_control_twice() {
        for framework in Framework::ALL {
            let order: Vec<&str> = framework
                .controls()
                .iter()
                .map(|control| control.id)
                .collect();
            for category in EVERY_CATEGORY {
                let ids: Vec<&str> = category
                    .controls(framework)
                    .iter()
                    .map(|control| control.id)
                    .collect();
                let mut sorted = ids.clone();
                sorted.sort_unstable();
                sorted.dedup();
                assert_eq!(sorted.len(), ids.len(), "{category} repeats a control");

                let positions: Vec<usize> = ids
                    .iter()
                    .map(|id| order.iter().position(|other| other == id).unwrap())
                    .collect();
                let mut ascending = positions.clone();
                ascending.sort_unstable();
                assert_eq!(
                    positions,
                    ascending,
                    "{category} lists {} out of the framework's canonical order",
                    framework.name()
                );
            }
        }
    }

    /// Every identifier carries text quoted from its source.
    ///
    /// Length is not the test — "Record-keeping" is the whole of Article 12's
    /// heading, and a real citation. What must hold is that the title says
    /// something the identifier does not: an id echoed back as its own title
    /// is a row nobody transcribed.
    #[test]
    fn every_control_carries_quoted_text() {
        for framework in Framework::ALL {
            for control in framework.controls() {
                assert!(!control.id.is_empty());
                assert!(
                    !control.title.is_empty(),
                    "{} has no quoted text",
                    control.id
                );
                assert_ne!(
                    control.title, control.id,
                    "{} repeats its own id instead of quoting its source",
                    control.id
                );
            }
        }
    }

    /// A finding relevant to two articles is counted under both.
    ///
    /// `BAS-ZT4-001` maps to `[LLM01, ZT4]`, both of which are Art. 15, so it
    /// must appear once there and not be double-counted within one group.
    /// `BAS-LLM10-001` maps to `[LLM10, ZT4]` — the same article again.
    #[test]
    fn a_finding_appears_under_every_area_it_touches_and_once_per_area() {
        let report = layered_report();
        let walk = crosswalk(&report, Framework::EuAiAct);

        let article_15 = walk
            .groups
            .iter()
            .find(|group| group.id == "Art. 15")
            .unwrap();

        let mut deduped = article_15.findings.clone();
        deduped.dedup();
        assert_eq!(
            deduped, article_15.findings,
            "a finding whose categories both map to one article must be listed once"
        );

        // Ascending, so a consumer can index straight into report.findings.
        let mut sorted = article_15.findings.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, article_15.findings);

        for index in &article_15.findings {
            assert!(*index < report.findings.len());
        }
    }

    /// Counts per group are the counts of that group's own findings.
    #[test]
    fn group_counts_match_the_findings_they_list() {
        let report = layered_report();
        for framework in Framework::ALL {
            let walk = crosswalk(&report, framework);
            for group in &walk.groups {
                let defects = group
                    .findings
                    .iter()
                    .filter(|index| report.findings[**index].kind == crate::finding::Kind::Defect)
                    .count();
                assert_eq!(group.defects, defects, "{}", group.id);
                assert_eq!(
                    group.observations,
                    group.findings.len() - defects,
                    "{}",
                    group.id
                );
            }
        }
    }

    /// Nothing is lost: every finding is in a group or in `unmapped`.
    ///
    /// The whole risk of a compliance view is a finding that quietly does not
    /// appear in it.
    #[test]
    fn every_finding_is_either_grouped_or_explicitly_unmapped() {
        let report = layered_report();
        for framework in Framework::ALL {
            let walk = crosswalk(&report, framework);
            for index in 0..report.findings.len() {
                let grouped = walk
                    .groups
                    .iter()
                    .any(|group| group.findings.contains(&index));
                let unmapped = walk.unmapped.findings.contains(&index);
                assert!(
                    grouped ^ unmapped,
                    "finding {index} is {} under {}",
                    if grouped { "in both places" } else { "nowhere" },
                    framework.name()
                );
            }
        }
    }

    /// The `LLM06` observation is the reason `unmapped` exists: under the EU
    /// AI Act it maps to nothing, and it must still be visible.
    #[test]
    fn an_unmappable_finding_is_surfaced_rather_than_dropped() {
        let report = layered_report();
        let walk = crosswalk(&report, Framework::EuAiAct);

        assert_eq!(walk.unmapped.findings.len(), 1);
        assert_eq!(walk.unmapped.observations, 1);
        assert_eq!(walk.unmapped.defects, 0);

        let index = walk.unmapped.findings[0];
        assert_eq!(report.findings[index].categories, vec![Category::Llm06]);

        // The same finding is mapped under NIST, so this is a property of the
        // framework and not of the finding.
        let nist = crosswalk(&report, Framework::NistAiRmf);
        assert!(nist.unmapped.findings.is_empty());
    }

    /// A control with no relevant finding is omitted, never listed empty.
    #[test]
    fn controls_with_no_findings_are_omitted() {
        let walk = crosswalk(&empty_report(), Framework::EuAiAct);
        assert!(walk.groups.is_empty());
        assert!(walk.unmapped.findings.is_empty());

        // Art. 12 has no detector behind ZT6 at all, so it must not appear
        // even on a report that does have findings.
        let walk = crosswalk(&layered_report(), Framework::EuAiAct);
        assert!(
            walk.groups.iter().all(|group| group.id != "Art. 12"),
            "an empty group would read as 'this area is clear', which it never means"
        );
    }

    /// The disclaimer is carried on the value itself, not left to a renderer
    /// to remember.
    #[test]
    fn every_crosswalk_carries_the_disclaimer_and_its_provenance() {
        for framework in Framework::ALL {
            let walk = crosswalk(&empty_report(), framework);
            assert_eq!(walk.disclaimer, DISCLAIMER);
            assert_eq!(walk.framework, framework);
            assert!(walk.source_url.starts_with("https://"));
            assert!(!walk.citation.is_empty());
            assert!(!walk.standing.is_empty());
        }
    }

    /// The wording constraint, enforced.
    ///
    /// Every string this module can put in front of a reader is checked for
    /// the vocabulary of a verdict. A static scanner cannot determine
    /// compliance, so it must never use a word that says it did.
    #[test]
    fn no_string_ever_claims_compliance() {
        // What Bastyn wrote, held to both lists.
        let mut authored: Vec<&str> = vec![DISCLAIMER, CROSSWALK_INTRO, TERMINAL_CAVEAT];
        // What a source document wrote, held to the verdict list only: a
        // citation altered to satisfy a word filter is no longer a citation.
        let mut transcribed: Vec<&str> = Vec::new();

        for framework in Framework::ALL {
            authored.push(framework.name());
            authored.push(framework.standing());
            transcribed.push(framework.citation());
            for control in framework.controls() {
                transcribed.push(control.id);
                transcribed.push(control.title);
            }
        }

        for text in authored.iter().chain(&transcribed) {
            let lowered = text.to_lowercase();
            for word in FORBIDDEN_CLAIMS {
                assert!(
                    !lowered.contains(word),
                    "{word:?} appears in {text:?}: a crosswalk states relevance, never a verdict"
                );
            }
        }

        for text in authored {
            let lowered = text.to_lowercase();
            for word in FORBIDDEN_CHARACTERISATIONS {
                assert!(
                    !lowered.contains(word),
                    "{word:?} appears in {text:?}: a crosswalk states what maps where, never \
what it means"
                );
            }
        }
    }

    /// One framework, one spelling.
    ///
    /// `id()` is what `--group-by` accepts; the serialised form is what a
    /// pipeline filters on. They must be the same string, and a derived
    /// `rename_all` rule made them differ once — `nist-genai` on the command
    /// line against `nist-gen-ai` in the JSON — which would have sent anyone
    /// filtering the output to a value the CLI rejects.
    #[test]
    fn the_command_line_spelling_and_the_serialised_spelling_are_one_string() {
        for framework in Framework::ALL {
            assert_eq!(
                serde_json::to_string(&framework).unwrap(),
                format!("\"{}\"", framework.id())
            );
            assert_eq!(
                serde_json::from_str::<Framework>(&format!("\"{}\"", framework.id())).unwrap(),
                framework,
                "{} must deserialise back to the framework it names",
                framework.id()
            );
        }
    }

    /// The disclaimer says the four things it has to say.
    #[test]
    fn the_disclaimer_names_what_a_scan_cannot_see() {
        assert!(DISCLAIMER.contains("not a compliance assessment"));
        assert!(DISCLAIMER.contains("relevant to"));
        assert!(DISCLAIMER.contains("cannot determine compliance"));
        assert!(DISCLAIMER.contains("Finding nothing does not mean an obligation is met"));
    }

    /// The serialised form round-trips, because a compliance report generator
    /// reading the JSON back is the whole point of putting it there.
    #[test]
    fn a_crosswalk_round_trips_through_json() {
        let walk = crosswalk(&layered_report(), Framework::EuAiAct);
        let text = serde_json::to_string(&walk).unwrap();
        let back: Crosswalk = serde_json::from_str(&text).unwrap();
        assert_eq!(back, walk);
        assert!(text.contains("\"framework\":\"eu-ai-act\""));
    }

    /// The report the CVE status came from does not change the crosswalk —
    /// it groups findings, and nothing else.
    #[test]
    fn cve_status_does_not_reach_the_crosswalk() {
        let mut report = layered_report();
        let first = crosswalk(&report, Framework::NistGenAi);
        report.cve = CveStatus::Checked { dependencies: 9 };
        assert_eq!(crosswalk(&report, Framework::NistGenAi), first);
    }
}
