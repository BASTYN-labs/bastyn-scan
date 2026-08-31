//! SARIF 2.1.0 rendering, for GitHub Advanced Security and GitLab.
//!
//! Spec: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>.
//!
//! Two things are the easiest way to get hand-written SARIF wrong, and both
//! are covered by tests here: `rules` must be deduplicated by rule id with
//! every result's `ruleIndex` pointing at the matching entry, and an
//! [`Kind::Observation`] must always report level `"note"` regardless of its
//! severity, so a context-dependent finding can never make a code-scanning
//! gate block a pull request the way a defect does.
//!
//! Each compliance crosswalk the report carries is emitted as a
//! `toolComponent` in `run.taxonomies` (§3.19.3) with each rule pointing at it
//! through a `reportingDescriptorRelationship` of kind `relevant` (§3.53). A
//! default scan carries all three, so a rule whose categories reach areas in
//! every framework carries one relationship per area per framework, each
//! naming the taxonomy its area came from.
//! Never through `tags`: `tags` is how GitHub and GitLab index and filter a
//! rule, so a framework name there would make their interfaces present a
//! finding as a regulatory violation — a claim a static scan cannot support,
//! and the reason `rule_tags_are_the_category_ids_and_only_those` exists.
//! `taxonomies` degrades the right way instead: a consumer that does not
//! implement it sees nothing rather than something wrong, and the taxonomy
//! component's `fullDescription` carries the disclaimer, so the caveat reaches
//! whoever opens the file.

use std::collections::HashMap;

use serde::Serialize;

use crate::category::Category;
use crate::compliance::Framework;
use crate::finding::{Confidence, Finding, Kind, Severity};
use crate::report::Report;

use super::error::Result;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const INFORMATION_URI: &str = "https://bastyn.ai";

/// Render `report` as a SARIF 2.1.0 log.
pub(crate) fn render(report: &Report) -> Result<String> {
    let mut rule_indices: HashMap<&str, usize> = HashMap::new();
    let mut rules: Vec<Rule> = Vec::new();

    for finding in &report.findings {
        if !rule_indices.contains_key(finding.rule_id.as_str()) {
            rule_indices.insert(finding.rule_id.as_str(), rules.len());
            rules.push(build_rule(finding));
        }
    }

    let results = report
        .findings
        .iter()
        .map(|finding| build_result(finding, &rule_indices))
        .collect();

    let taxonomies = build_taxonomies(report, &mut rules);

    let log = Log {
        schema: SCHEMA,
        version: SARIF_VERSION,
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "Bastyn",
                    version: report.bastyn_version.as_str(),
                    information_uri: INFORMATION_URI,
                    rules,
                },
            },
            results,
            taxonomies,
        }],
    };

    Ok(serde_json::to_string_pretty(&log)?)
}

/// A stable `guid` for each framework's taxonomy component.
///
/// SARIF requires a `guid` to identify the same component across runs, so
/// these are fixed constants rather than generated per invocation: a guid that
/// moved would make a consumer treat every run's taxonomy as a new one.
const fn taxonomy_guid(framework: Framework) -> &'static str {
    match framework {
        Framework::EuAiAct => "6a1c8b2e-9f4d-4c73-8a5b-2e7d1f4a9c30",
        Framework::NistAiRmf => "b3d9e740-5c81-4a26-9f13-7e0a6b8c2d54",
        Framework::NistGenAi => "cf2740a8-16b3-4e59-8d07-3a9c5b1e6f82",
    }
}

/// Build the run's taxonomies from `report`'s crosswalks, and attach each
/// rule's relationships to them.
///
/// The crosswalks belong here, in SARIF's own `taxonomies` mechanism (§3.19.3)
/// with `reportingDescriptorRelationship` (§3.53) pointing at them — never in
/// `tags`. `tags` is what GitHub and GitLab index and filter a rule by, so a
/// framework name there would make their UI present a finding as a regulatory
/// violation, which is a claim no static scan can make. A consumer that does
/// not implement `taxonomies` sees no change at all, which is the right
/// failure mode for a caveated mapping: silence rather than a wrong headline.
///
/// The relationship kind is `relevant`, the SARIF vocabulary's term for
/// descriptors that are meaningfully connected without implying equivalence.
/// That is precisely the strength of this mapping, and the reason it is not
/// `equal`, `superset` or `subset`.
///
/// Each relationship is derived from the rule's own category ids — the same
/// ids already in its `tags` — so it asserts exactly "this rule's categories
/// are relevant to these areas", and nothing stronger than the per-category
/// mapping supports.
///
/// With three frameworks in the run, one rule carries one relationship per
/// area per framework, and each `target.toolComponent` names the taxonomy that
/// area came from. §3.52.3 resolves such a reference by `guid` when one is
/// present, so the taxonomies stay addressable however the array is ordered —
/// which is why these references carry a `guid` and never a bare `index`.
fn build_taxonomies(report: &Report, rules: &mut [Rule]) -> Vec<Taxonomy> {
    let mut taxonomies = Vec::new();

    for walk in &report.crosswalks {
        let framework = walk.framework;
        let guid = taxonomy_guid(framework);

        // Only the controls this run actually reached. A taxon nobody points
        // at would suggest the run examined an area it never looked at.
        for rule in rules.iter_mut() {
            for group in &walk.groups {
                let relevant = rule.categories.iter().any(|category| {
                    category
                        .controls(framework)
                        .iter()
                        .any(|control| control.id == group.id)
                });
                if relevant {
                    rule.relationships.push(Relationship {
                        target: DescriptorReference {
                            id: group.id.clone(),
                            tool_component: ComponentReference {
                                name: walk.name.clone(),
                                guid,
                            },
                        },
                        kinds: vec!["relevant"],
                    });
                }
            }
        }

        taxonomies.push(Taxonomy {
            name: walk.name.clone(),
            guid,
            information_uri: walk.source_url.clone(),
            short_description: Text {
                text: walk.citation.clone(),
            },
            // Where the caveat lives. A SARIF file is read a long way from the
            // terminal that produced it, so the disclaimer travels with the
            // data rather than being left behind in a console nobody kept.
            full_description: Text {
                text: format!("{} {}", walk.disclaimer, walk.standing),
            },
            taxa: walk
                .groups
                .iter()
                .map(|group| Taxon {
                    id: group.id.clone(),
                    name: group.id.clone(),
                    short_description: Text {
                        text: group.title.clone(),
                    },
                })
                .collect(),
        });
    }

    taxonomies
}

/// SARIF `level` for one finding.
///
/// Observations always render as `"note"`, whatever their severity: they
/// describe a control the repository cannot show is actually missing, and
/// must never be strong enough to fail a code-scanning gate the way a defect
/// does.
fn level_for(finding: &Finding) -> &'static str {
    if finding.kind == Kind::Observation {
        return "note";
    }
    match finding.severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Forward-slash URI for a finding's file, regardless of host platform.
fn uri_for(finding: &Finding) -> String {
    finding.location.file.to_string_lossy().replace('\\', "/")
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Defect => "defect",
        Kind::Observation => "observation",
    }
}

fn build_rule(finding: &Finding) -> Rule {
    let level = level_for(finding);
    Rule {
        id: finding.rule_id.clone(),
        name: finding.title.clone(),
        short_description: Text {
            text: finding.title.clone(),
        },
        full_description: Text {
            text: finding.description.clone(),
        },
        default_configuration: DefaultConfiguration {
            level: level.to_string(),
        },
        properties: RuleProperties {
            tags: finding
                .categories
                .iter()
                .map(|category| category.id().to_string())
                .collect(),
            problem_severity: level.to_string(),
        },
        relationships: Vec::new(),
        categories: finding.categories.clone(),
    }
}

fn build_result(finding: &Finding, rule_indices: &HashMap<&str, usize>) -> SarifResult {
    // Every rule id present in `report.findings` was inserted into
    // `rule_indices` before any result is built, so this always resolves;
    // `unwrap_or_default` is a non-panicking belt-and-braces fallback, not a
    // sign this can actually miss.
    let rule_index = rule_indices
        .get(finding.rule_id.as_str())
        .copied()
        .unwrap_or_default();
    SarifResult {
        rule_id: finding.rule_id.clone(),
        rule_index,
        level: level_for(finding).to_string(),
        message: Text {
            text: finding.description.clone(),
        },
        locations: vec![SarifLocation {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: uri_for(finding),
                },
                region: Region {
                    start_line: finding.location.line,
                    start_column: finding.location.column,
                    snippet: Text {
                        text: finding.snippet.clone(),
                    },
                },
            },
        }],
        partial_fingerprints: Fingerprints {
            primary_location_line_hash: fingerprint(finding),
        },
        properties: ResultProperties {
            confidence: confidence_label(finding.confidence).to_string(),
            kind: kind_label(finding.kind).to_string(),
            references: finding.references.clone(),
        },
    }
}

/// A stable fingerprint for `finding`.
///
/// Built from the rule, the file, the offending snippet and the title — but not
/// the line number, so a finding that moves with the code stays the same alert.
///
/// FNV-1a rather than `DefaultHasher`: `std`'s hasher makes no stability
/// guarantee across Rust versions, and a fingerprint that changes on a
/// toolchain bump would silently duplicate every alert in a consumer's
/// dashboard.
fn fingerprint(finding: &Finding) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET;
    let mut feed = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
    };

    feed(finding.rule_id.as_bytes());
    feed(b"\0");
    feed(finding.location.file.to_string_lossy().as_bytes());
    feed(b"\0");
    feed(finding.snippet.trim().as_bytes());
    feed(b"\0");
    feed(finding.title.as_bytes());

    format!("{hash:016x}")
}

#[derive(Serialize)]
struct Log<'a> {
    #[serde(rename = "$schema")]
    schema: &'a str,
    version: &'a str,
    runs: Vec<Run<'a>>,
}

#[derive(Serialize)]
struct Run<'a> {
    tool: Tool<'a>,
    results: Vec<SarifResult>,
    /// SARIF 2.1.0 §3.14.8. One entry per crosswalk the report carries, in
    /// [`crate::compliance::Framework::ALL`] order; absent entirely when it
    /// carries none, so a report with nothing to say says nothing.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    taxonomies: Vec<Taxonomy>,
}

/// A `toolComponent` acting as a taxonomy, per SARIF 2.1.0 §3.19.3.
#[derive(Serialize)]
struct Taxonomy {
    name: String,
    /// Stable across runs, as §3.19.5 requires.
    guid: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: String,
    #[serde(rename = "shortDescription")]
    short_description: Text,
    #[serde(rename = "fullDescription")]
    full_description: Text,
    taxa: Vec<Taxon>,
}

/// One `reportingDescriptor` inside a taxonomy, per SARIF 2.1.0 §3.19.25.
#[derive(Serialize)]
struct Taxon {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: Text,
}

/// A `reportingDescriptorRelationship`, per SARIF 2.1.0 §3.53.
#[derive(Serialize)]
struct Relationship {
    target: DescriptorReference,
    /// Always `["relevant"]`: the descriptors are meaningfully connected
    /// without implying equivalence, which is exactly what a crosswalk claims.
    kinds: Vec<&'static str>,
}

/// A `reportingDescriptorReference`, per SARIF 2.1.0 §3.52.
#[derive(Serialize)]
struct DescriptorReference {
    id: String,
    #[serde(rename = "toolComponent")]
    tool_component: ComponentReference,
}

/// A `toolComponentReference`, per SARIF 2.1.0 §3.54.
///
/// Identified by `name` and `guid` rather than by `index`, because an index
/// means a different thing depending on which array is being referenced and
/// the two named properties are unambiguous. With three taxonomies in one run
/// that stops mattering only in theory: §3.52.3 resolves a descriptor
/// reference through this component, so a reference that guessed at an index
/// would attach a finding to the wrong framework's area.
#[derive(Serialize)]
struct ComponentReference {
    name: String,
    guid: &'static str,
}

#[derive(Serialize)]
struct Tool<'a> {
    driver: Driver<'a>,
}

#[derive(Serialize)]
struct Driver<'a> {
    name: &'static str,
    version: &'a str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
struct Rule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: Text,
    #[serde(rename = "fullDescription")]
    full_description: Text,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: DefaultConfiguration,
    properties: RuleProperties,
    /// SARIF 2.1.0 §3.49.15. One entry per area of per framework this rule's
    /// categories reach; empty when the report carries no crosswalk.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    relationships: Vec<Relationship>,
    /// The categories this rule claimed, kept so the taxonomy can be built
    /// after deduplication without walking the findings again.
    ///
    /// Never serialised: the categories already reach the output as `tags`,
    /// and a second copy under a different name would be two places for one
    /// fact to disagree with itself.
    #[serde(skip)]
    categories: Vec<Category>,
}

#[derive(Serialize)]
struct Text {
    text: String,
}

#[derive(Serialize)]
struct DefaultConfiguration {
    level: String,
}

#[derive(Serialize)]
struct RuleProperties {
    tags: Vec<String>,
    #[serde(rename = "problem.severity")]
    problem_severity: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    #[serde(rename = "ruleIndex")]
    rule_index: usize,
    level: String,
    message: Text,
    locations: Vec<SarifLocation>,
    /// How a consumer recognises this finding across runs. Without it, GitHub
    /// code scanning raises a fresh alert on every push.
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: Fingerprints,
    properties: ResultProperties,
}

/// Stable identity for a finding, per the SARIF `partialFingerprints` contract.
#[derive(Serialize)]
struct Fingerprints {
    /// GitHub's conventional key. Deliberately excludes the line number: code
    /// moves, and a finding that shifts down a line is the same finding, not a
    /// new one.
    #[serde(rename = "primaryLocationLineHash")]
    primary_location_line_hash: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: usize,
    #[serde(rename = "startColumn")]
    start_column: usize,
    snippet: Text,
}

#[derive(Serialize)]
struct ResultProperties {
    confidence: String,
    kind: String,
    /// External identifiers this finding covers, such as the CVE ids behind one
    /// vulnerable dependency. Present so a consumer can act on them without
    /// parsing the message prose.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    references: Vec<String>,
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use std::collections::HashMap;

    use super::{fingerprint, render};
    use crate::compliance::{DISCLAIMER, Framework, crosswalk};
    use crate::render::test_support::{
        defect, duplicate_rule_report, empty_report, observation, report_with, windows_path_defect,
    };
    use crate::report::CveStatus;

    fn parse(report: &crate::report::Report) -> serde_json::Value {
        let text = render(report).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    /// The standard two-finding report, grouped by `framework`.
    fn grouped(framework: Framework) -> crate::report::Report {
        let mut report = report_with(CveStatus::NoManifest);
        report.crosswalks = vec![crosswalk(&report, framework)];
        report
    }

    /// The standard two-finding report as a default scan produces it: every
    /// framework crosswalked at once.
    fn grouped_by_all() -> crate::report::Report {
        let mut report = report_with(CveStatus::NoManifest);
        report.crosswalks = Framework::ALL
            .iter()
            .map(|framework| crosswalk(&report, *framework))
            .collect();
        report
    }

    #[test]
    fn fingerprints_are_stable_across_line_moves() {
        // A finding that shifts down when someone adds an import is the same
        // finding. If the fingerprint changed, GitHub would raise a duplicate
        // alert on every such push.
        let mut a = defect();
        let mut b = defect();
        b.location.line = a.location.line + 40;

        assert_eq!(
            fingerprint(&a),
            fingerprint(&b),
            "the line number must not be part of the identity"
        );

        // But a different problem in the same place is a different finding.
        a.title = "One thing".to_owned();
        let mut c = defect();
        c.title = "A different thing".to_owned();
        assert_ne!(fingerprint(&a), fingerprint(&c));
    }

    #[test]
    fn fingerprint_is_a_fixed_width_hex_digest() {
        let value = fingerprint(&defect());
        assert_eq!(value.len(), 16, "got {value}");
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()), "got {value}");
    }

    #[test]
    fn every_result_carries_a_fingerprint() {
        let report = report_with(CveStatus::SkippedOffline);
        let sarif = parse(&report);

        for result in sarif["runs"][0]["results"].as_array().unwrap() {
            let hash = result["partialFingerprints"]["primaryLocationLineHash"].as_str();
            assert!(
                hash.is_some_and(|value| value.len() == 16),
                "every result needs a 16-hex fingerprint for cross-run matching, got {hash:?}"
            );
        }
    }

    #[test]
    fn rules_are_deduplicated_and_rule_indices_resolve() {
        let report = duplicate_rule_report();
        let value = parse(&report);

        let rules = value["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let results = value["runs"][0]["results"].as_array().unwrap();

        // Two distinct rule ids among the findings (see duplicate_rule_report).
        assert_eq!(rules.len(), 2);
        assert_eq!(results.len(), report.findings.len());

        for result in results {
            let rule_id = result["ruleId"].as_str().unwrap();
            let rule_index = usize::try_from(result["ruleIndex"].as_u64().unwrap()).unwrap();
            assert!(rule_index < rules.len(), "ruleIndex out of bounds");
            assert_eq!(
                rules[rule_index]["id"].as_str(),
                Some(rule_id),
                "ruleIndex points at the wrong rule"
            );
        }
    }

    #[test]
    fn observation_with_high_severity_still_maps_to_note() {
        let report = report_with(CveStatus::NoManifest);
        let value = parse(&report);
        let obs = observation();

        let results = value["runs"][0]["results"].as_array().unwrap();
        let result = results
            .iter()
            .find(|r| r["ruleId"].as_str() == Some(obs.rule_id.as_str()))
            .unwrap();

        assert_eq!(obs.severity, crate::finding::Severity::High);
        assert_eq!(result["level"].as_str(), Some("note"));
        assert_eq!(result["properties"]["kind"].as_str(), Some("observation"));
    }

    #[test]
    fn windows_style_path_renders_with_forward_slashes() {
        let windows = windows_path_defect();
        let mut report = report_with(CveStatus::NoManifest);
        report.findings.push(windows.clone());
        let value = parse(&report);

        let results = value["runs"][0]["results"].as_array().unwrap();
        let result = results
            .iter()
            .find(|r| r["ruleId"].as_str() == Some(windows.rule_id.as_str()))
            .unwrap();

        let uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert!(!uri.contains('\\'), "uri still contains a backslash: {uri}");
        assert_eq!(uri, "src/windows/creds.rs");
    }

    #[test]
    fn defect_severity_maps_to_expected_levels() {
        let mut d = defect();
        d.severity = crate::finding::Severity::Medium;
        let mut report = empty_report();
        report.findings.push(d);
        let value = parse(&report);
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["level"].as_str(), Some("warning"));
    }

    /// Grouping the terminal report by threat layer must not reach the tags.
    ///
    /// `tags` is how GitHub and GitLab index a rule, so the values there are
    /// the framework category ids and nothing else — never a layer name, never
    /// a ring. How Bastyn arranges its own output is not a fact about the
    /// finding.
    #[test]
    fn rule_tags_are_the_category_ids_and_only_those() {
        let value = parse(&report_with(CveStatus::NoManifest));
        let rules = value["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();

        let tags_for = |rule_id: &str| -> Vec<String> {
            rules
                .iter()
                .find(|rule| rule["id"].as_str() == Some(rule_id))
                .unwrap()["properties"]["tags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tag| tag.as_str().unwrap().to_owned())
                .collect()
        };

        assert_eq!(tags_for("BAS-LLM10-001"), ["LLM10", "ZT4"]);
        assert_eq!(tags_for("BAS-LLM06-001"), ["LLM06"]);
    }

    /// Without `--group-by`, SARIF is exactly what it always was.
    ///
    /// A code-scanning integration that has never heard of the crosswalk must
    /// not see a byte change, so the taxonomy is opt-in rather than always
    /// present-but-empty.
    #[test]
    fn a_report_without_a_crosswalk_emits_no_taxonomy() {
        let value = parse(&report_with(CveStatus::NoManifest));
        assert!(value["runs"][0].get("taxonomies").is_none());
        for rule in value["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
        {
            assert!(rule.get("relationships").is_none());
        }
    }

    /// The crosswalk goes in `taxonomies`, per SARIF 2.1.0 §3.19.3, and never
    /// in `tags`.
    ///
    /// `tags` is how GitHub and GitLab index and filter a rule; a framework
    /// name there would make their UI read a finding as a regulatory
    /// violation. `taxonomies` is the mechanism the specification provides for
    /// exactly this, and a consumer that does not understand it simply sees
    /// nothing rather than seeing something wrong.
    #[test]
    fn the_crosswalk_is_a_taxonomy_and_never_a_tag() {
        let value = parse(&grouped(Framework::EuAiAct));

        let taxonomies = value["runs"][0]["taxonomies"].as_array().unwrap();
        assert_eq!(taxonomies.len(), 1);
        let taxonomy = &taxonomies[0];
        assert_eq!(taxonomy["name"].as_str(), Some("EU AI Act"));

        let taxa: Vec<&str> = taxonomy["taxa"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_str().unwrap())
            .collect();
        assert_eq!(taxa, ["Art. 15"]);

        // Tags stay exactly the category ids. This is the guardrail the
        // existing rule_tags_are_the_category_ids_and_only_those test pins,
        // asserted again with a taxonomy present so the two cannot drift.
        for rule in value["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
        {
            for tag in rule["properties"]["tags"].as_array().unwrap() {
                let tag = tag.as_str().unwrap();
                assert!(
                    tag.starts_with("LLM") || tag.starts_with("ZT"),
                    "{tag} is not a category id"
                );
            }
        }
    }

    /// Rules point at taxa through `relationships`, with kind `relevant`.
    ///
    /// SARIF's own vocabulary has the word this crosswalk needs. `relevant`
    /// means the descriptors are meaningfully connected without implying
    /// equivalence — which is the exact strength of the claim, and the reason
    /// this is `relevant` and never `equal` or `superset`.
    #[test]
    fn rules_relate_to_taxa_as_relevant_and_resolve_to_a_real_taxon() {
        let value = parse(&grouped(Framework::NistAiRmf));
        let run = &value["runs"][0];
        let taxonomy = &run["taxonomies"][0];
        let taxa: Vec<&str> = taxonomy["taxa"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_str().unwrap())
            .collect();

        let mut related = 0;
        for rule in run["tool"]["driver"]["rules"].as_array().unwrap() {
            for relationship in rule["relationships"].as_array().unwrap() {
                related += 1;
                assert_eq!(
                    relationship["kinds"].as_array().unwrap(),
                    &vec![serde_json::json!("relevant")],
                    "a crosswalk is a relevance relation, never an equivalence"
                );
                let target = &relationship["target"];
                let id = target["id"].as_str().unwrap();
                assert!(taxa.contains(&id), "{id} is not a taxon in the taxonomy");
                assert_eq!(
                    target["toolComponent"]["guid"].as_str(),
                    taxonomy["guid"].as_str(),
                    "the reference must resolve to the taxonomy it came from"
                );
                assert_eq!(
                    target["toolComponent"]["name"].as_str(),
                    taxonomy["name"].as_str()
                );
            }
        }
        assert!(related > 0, "no rule was related to any taxon");
    }

    /// The caveat travels with the data.
    ///
    /// A SARIF file is read far from the terminal that produced it, so the
    /// disclaimer is on the taxonomy component itself rather than left behind.
    #[test]
    fn the_taxonomy_carries_the_disclaimer_and_its_provenance() {
        for framework in Framework::ALL {
            let value = parse(&grouped(framework));
            let taxonomy = &value["runs"][0]["taxonomies"][0];

            let full = taxonomy["fullDescription"]["text"].as_str().unwrap();
            assert!(
                full.contains(DISCLAIMER),
                "{} does not carry the disclaimer",
                framework.name()
            );
            assert!(full.contains(framework.standing()));
            assert_eq!(
                taxonomy["shortDescription"]["text"].as_str(),
                Some(framework.citation())
            );
            assert_eq!(
                taxonomy["informationUri"].as_str(),
                Some(framework.source_url())
            );
        }
    }

    /// Taxonomy GUIDs are stable across runs, as SARIF requires of a `guid`,
    /// and distinct between frameworks.
    #[test]
    fn taxonomy_guids_are_stable_and_distinct() {
        let mut seen = Vec::new();
        for framework in Framework::ALL {
            let first = parse(&grouped(framework))["runs"][0]["taxonomies"][0]["guid"]
                .as_str()
                .unwrap()
                .to_owned();
            let second = parse(&grouped(framework))["runs"][0]["taxonomies"][0]["guid"]
                .as_str()
                .unwrap()
                .to_owned();
            assert_eq!(first, second, "a guid that moves duplicates every alert");
            assert_eq!(first.len(), 36, "not a UUID: {first}");
            assert!(!seen.contains(&first), "two frameworks share a guid");
            seen.push(first);
        }
    }

    /// A taxon is emitted only when a rule actually relates to it, so the
    /// taxonomy never implies coverage of an area nothing inspected.
    #[test]
    fn only_taxa_with_a_relationship_are_emitted() {
        let value = parse(&grouped(Framework::EuAiAct));
        let taxa = value["runs"][0]["taxonomies"][0]["taxa"]
            .as_array()
            .unwrap();
        for taxon in taxa {
            let id = taxon["id"].as_str().unwrap();
            let related = value["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|rule| {
                    rule["relationships"]
                        .as_array()
                        .is_some_and(|relationships| {
                            relationships
                                .iter()
                                .any(|r| r["target"]["id"].as_str() == Some(id))
                        })
                });
            assert!(related, "{id} is a taxon nothing points at");
        }
    }

    /// Three frameworks, three taxonomies, and every relationship resolving
    /// to the one its area actually came from.
    ///
    /// This is the failure the multi-taxonomy shape invites: `Art. 15` and
    /// `MEASURE 2.7` are areas of different documents, and a relationship that
    /// named the wrong `toolComponent` would file a finding under a framework
    /// that never mentioned it. §3.52.3 resolves the reference through the
    /// component's `guid`, so the guid is what this checks.
    #[test]
    fn every_framework_becomes_its_own_taxonomy_and_relationships_resolve_to_it() {
        let value = parse(&grouped_by_all());
        let run = &value["runs"][0];
        let taxonomies = run["taxonomies"].as_array().unwrap();

        assert_eq!(taxonomies.len(), 3);
        let names: Vec<&str> = taxonomies
            .iter()
            .map(|taxonomy| taxonomy["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            ["EU AI Act", "NIST AI RMF 1.0", "NIST Generative AI Profile"]
        );

        // Which taxa each guid owns, so a mis-targeted relationship is a
        // lookup failure rather than something that quietly passes.
        let owner: HashMap<&str, Vec<&str>> = taxonomies
            .iter()
            .map(|taxonomy| {
                (
                    taxonomy["guid"].as_str().unwrap(),
                    taxonomy["taxa"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|taxon| taxon["id"].as_str().unwrap())
                        .collect(),
                )
            })
            .collect();

        let mut related = 0;
        for rule in run["tool"]["driver"]["rules"].as_array().unwrap() {
            for relationship in rule["relationships"].as_array().unwrap() {
                related += 1;
                assert_eq!(
                    relationship["kinds"].as_array().unwrap(),
                    &vec![serde_json::json!("relevant")],
                    "a crosswalk is a relevance relation, never an equivalence"
                );
                let target = &relationship["target"];
                let guid = target["toolComponent"]["guid"].as_str().unwrap();
                let id = target["id"].as_str().unwrap();
                assert!(
                    owner.get(guid).is_some_and(|taxa| taxa.contains(&id)),
                    "{id} is not a taxon of the taxonomy {guid} it points at"
                );
            }
        }

        // BAS-LLM10-001 is [LLM10, ZT4]: Art. 15 under the EU AI Act,
        // MEASURE 2.7 under the AI RMF, Information Security under the GenAI
        // profile — three, so all three frameworks are reached from one rule.
        // BAS-LLM06-001 is [LLM06], which no EU AI Act article addresses, so
        // it adds two rather than three. Five is the whole of what these two
        // rules can claim, and a number that moved would mean a relationship
        // was invented or lost.
        assert_eq!(related, 5);
    }

    /// Tags stay the category ids with three taxonomies present.
    ///
    /// The guardrail `rule_tags_are_the_category_ids_and_only_those` pins, but
    /// asserted again in the shape a default scan now produces: `tags` is what
    /// GitHub and GitLab index a rule by, and three framework names there
    /// would make their UI read every finding as three regulatory violations.
    #[test]
    fn three_taxonomies_still_reach_no_tag() {
        let value = parse(&grouped_by_all());
        for rule in value["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
        {
            for tag in rule["properties"]["tags"].as_array().unwrap() {
                let tag = tag.as_str().unwrap();
                assert!(
                    tag.starts_with("LLM") || tag.starts_with("ZT"),
                    "{tag} is not a category id"
                );
            }
        }
    }

    /// Every taxonomy carries the caveat, whichever one a consumer opens.
    #[test]
    fn each_of_the_default_taxonomies_carries_the_disclaimer() {
        let value = parse(&grouped_by_all());
        for taxonomy in value["runs"][0]["taxonomies"].as_array().unwrap() {
            let full = taxonomy["fullDescription"]["text"].as_str().unwrap();
            assert!(
                full.contains(DISCLAIMER),
                "{} does not carry the disclaimer",
                taxonomy["name"]
            );
        }
    }

    #[test]
    fn empty_report_renders_cleanly() {
        let value = parse(&empty_report());
        assert_eq!(value["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    /// SARIF has never carried the coverage-gap listing, and still does not.
    ///
    /// A code-scanning upload is a list of results; what a scan did not reach
    /// has no result to attach to. Structuring the skip reasons for the
    /// terminal must therefore change nothing here at all, and the cheapest
    /// way to know that is to render with and without them and compare bytes.
    #[test]
    fn coverage_gaps_change_no_byte_of_the_sarif() {
        let plain = report_with(CveStatus::NoManifest);
        let mut skipped = plain.clone();
        skipped.skipped = crate::render::test_support::every_skip_reason();
        skipped.summary.files_skipped = skipped.skipped.len();

        assert_eq!(
            render(&plain).unwrap(),
            render(&skipped).unwrap(),
            "a skip reason reached the SARIF log"
        );
    }
}
