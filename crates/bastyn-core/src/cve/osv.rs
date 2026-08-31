//! The `OSV.dev` lookup: batch-query dependencies, hydrate the matches, and
//! turn them into [`Finding`]s.
//!
//! The network call sits behind [`OsvTransport`] so the unit test suite never
//! makes a real request — [`check`] wires up the real `ureq`-backed
//! transport; tests substitute a fake that returns canned JSON.
//!
//! Nothing here ever returns an `Err` for a network problem. A DNS failure,
//! a timeout, or a non-2xx response all become
//! [`CveStatus::Unreachable`](crate::CveStatus::Unreachable) — see
//! [`check`] for why that matters.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::manifest::Dependency;
use crate::{Category, Confidence, CveStatus, Finding, Kind, Location, Severity};

/// `OSV.dev`'s batch-query endpoint.
const QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
/// `OSV.dev`'s per-advisory detail endpoint; `{id}` is appended.
const VULNS_URL: &str = "https://api.osv.dev/v1/vulns";
/// Hard cap on pagination rounds, so a misbehaving API handing back an
/// endless `next_page_token` cannot loop forever.
const MAX_PAGINATION_ROUNDS: u32 = 50;
/// Connect timeout for an OSV request: DNS, TCP, and TLS handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Overall timeout for one OSV request, covering connect, write, and read.
/// Chosen to comfortably cover a batch of a few hundred packages while still
/// failing fast enough that a hung request does not stall the whole scan.
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(15);
/// The rule every CVE finding is reported under.
const RULE_ID: &str = "BAS-CVE-001";

/// Abstraction over the network transport used to talk to `OSV.dev`, so
/// tests can substitute canned responses without touching the network.
trait OsvTransport {
    /// POST `body` (JSON) to `url`, returning the raw response body.
    ///
    /// # Errors
    /// A human-readable reason on any network failure, timeout, or non-2xx
    /// response.
    fn post(&self, url: &str, body: &str) -> Result<String, String>;

    /// GET `url`, returning the raw response body.
    ///
    /// # Errors
    /// A human-readable reason on any network failure, timeout, or non-2xx
    /// response.
    fn get(&self, url: &str) -> Result<String, String>;
}

/// The real transport: blocking HTTPS via `ureq`, over rustls.
struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(GLOBAL_TIMEOUT))
            .build();
        Self {
            agent: config.into(),
        }
    }
}

impl OsvTransport for UreqTransport {
    fn post(&self, url: &str, body: &str) -> Result<String, String> {
        self.agent
            .post(url)
            .header("Content-Type", "application/json")
            .send(body.to_string())
            .map_err(|error| error.to_string())?
            .body_mut()
            .read_to_string()
            .map_err(|error| error.to_string())
    }

    fn get(&self, url: &str) -> Result<String, String> {
        self.agent
            .get(url)
            .call()
            .map_err(|error| error.to_string())?
            .body_mut()
            .read_to_string()
            .map_err(|error| error.to_string())
    }
}

// ---------------------------------------------------------------------
// Request/response shapes
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct QueryBatchRequest<'a> {
    queries: &'a [Query<'a>],
}

#[derive(Serialize)]
struct Query<'a> {
    package: PackageQuery<'a>,
    #[serde(skip_serializing_if = "str::is_empty")]
    version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<&'a str>,
}

#[derive(Serialize)]
struct PackageQuery<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Debug, Deserialize)]
struct QueryBatchResponse {
    #[serde(default)]
    results: Vec<QueryResult>,
}

#[derive(Debug, Deserialize)]
struct QueryResult {
    #[serde(default)]
    vulns: Vec<VulnStub>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VulnStub {
    id: String,
}

#[derive(Debug, Deserialize)]
struct VulnDetail {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<SeverityEntry>,
    database_specific: Option<DatabaseSpecific>,
    #[serde(default)]
    affected: Vec<Affected>,
}

#[derive(Debug, Deserialize)]
struct SeverityEntry {
    score: String,
}

#[derive(Debug, Deserialize)]
struct DatabaseSpecific {
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Affected {
    package: Option<AffectedPackage>,
    #[serde(default)]
    ranges: Vec<Range>,
}

#[derive(Debug, Deserialize)]
struct AffectedPackage {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Range {
    /// `ECOSYSTEM`, `SEMVER`, or `GIT`. Absent on some older entries.
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    events: Vec<RangeEvent>,
}

#[derive(Debug, Deserialize)]
struct RangeEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

// ---------------------------------------------------------------------
// Affected-range → fixed-version resolution
// ---------------------------------------------------------------------

/// One `(introduced, fixed)` window from an OSV affected range.
struct Segment {
    introduced: Option<String>,
    fixed: Option<String>,
}

/// Pair a range's ordered events into `(introduced, fixed)` segments.
fn segments_for(range: &Range) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut intro: Option<String> = None;
    for event in &range.events {
        if let Some(i) = &event.introduced {
            intro = Some(i.clone());
        } else if let Some(f) = &event.fixed {
            out.push(Segment {
                introduced: intro.take(),
                fixed: Some(f.clone()),
            });
        } else if event.last_affected.is_some() {
            out.push(Segment {
                introduced: intro.take(),
                fixed: None,
            });
        }
    }
    if let Some(i) = intro {
        out.push(Segment {
            introduced: Some(i),
            fixed: None,
        });
    }
    out
}

/// All `(introduced, fixed)` segments across affected entries for `package`.
fn package_segments(vuln: &VulnDetail, package: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    for affected in &vuln.affected {
        let Some(pkg) = &affected.package else {
            continue;
        };
        let Some(name) = &pkg.name else { continue };
        if !name.eq_ignore_ascii_case(package) {
            continue;
        }
        for range in &affected.ranges {
            // GIT ranges publish commit SHAs as the fix. "Upgrade to
            // 97d23167..." is not advice a developer can act on, and a SHA
            // sorts above any real version lexically, so it must never reach
            // the upgrade hint.
            if range
                .kind
                .as_deref()
                .is_some_and(|kind| kind.eq_ignore_ascii_case("GIT"))
            {
                continue;
            }
            out.extend(segments_for(range));
        }
    }
    out
}

/// Best-effort dotted-numeric version → digit sequence, for range
/// comparison. Takes the leading numeric components (`"4.4.1"` →
/// `[4, 4, 1]`); ignores pre-release/build suffixes. `None` if nothing
/// numeric is found. Not full semver — enough to pick which advisory range
/// contains a version, and it never *drops* an advisory (OSV already
/// confirmed the version is affected).
/// True if `version` is a plain release number: every dot-separated segment is
/// digits, and nothing else.
///
/// This is stricter than hunting for known prerelease markers, and correct for
/// the cases that matter. `1.0.10rc1`, `2.0.0b3`, `1.2.3.post1` and
/// `4.0.0-alpha` all fail it, because a marker can sit inside a segment rather
/// than at its start. A security tool should not push someone onto an
/// unreleased build to escape a vulnerability.
fn is_plain_release(version: &str) -> bool {
    let trimmed = version.trim();
    !trimmed.is_empty()
        && trimmed
            .split('.')
            .all(|segment| !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()))
}

fn version_digits(v: &str) -> Option<Vec<u64>> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let digits: Vec<u64> = v
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    (!digits.is_empty()).then_some(digits)
}

/// True if `installed` falls in `[introduced, fixed)` using dotted-numeric
/// comparison.
fn segment_contains(installed: &str, introduced: Option<&str>, fixed: Option<&str>) -> bool {
    let Some(installed_digits) = version_digits(installed) else {
        return false;
    };
    if let Some(intro) = introduced
        && intro != "0"
        && let Some(lo) = version_digits(intro)
        && installed_digits < lo
    {
        return false;
    }
    if let Some(fx) = fixed
        && let Some(hi) = version_digits(fx)
        && installed_digits >= hi
    {
        return false;
    }
    true
}

/// The fixed version for the range that contains `installed_version`.
///
/// An advisory can carry several ranges (e.g. a 4.x line and a 5.x line).
/// When the installed version is known, this returns the `fixed` of the
/// segment that actually contains it, so the upgrade hint is correct for the
/// version in use. Falls back to the first published `fixed` if no segment
/// matches.
fn extract_fix_version(
    vuln: &VulnDetail,
    package: &str,
    installed_version: &str,
) -> Option<String> {
    let segments = package_segments(vuln, package);
    for segment in &segments {
        if let Some(fixed) = &segment.fixed
            && segment_contains(
                installed_version,
                segment.introduced.as_deref(),
                Some(fixed),
            )
        {
            return Some(fixed.clone());
        }
    }
    segments.into_iter().find_map(|segment| segment.fixed)
}

// ---------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------

/// Derive a severity rank from a CVSS vector string without computing the
/// full score. OSV's `severity[].score` for `CVSS_V3`/`CVSS_V4` is a vector
/// string — the numeric base score is not embedded; it must be computed from
/// the metrics. Rather than add a CVSS parser dependency, this maps the
/// worst-case impact triad to a conservative rank:
///
/// - all `H`            → critical (4)
/// - any `H`             → high (3)
/// - any `L`/`M` (no `H`) → medium (2)
/// - all `N`             → low (1)
///
/// This errs toward invalidating rather than silently missing a real
/// vulnerability. CVSS v3 uses `C`/`I`/`A`; CVSS v4 uses `VC`/`VI`/`VA` (and
/// falls back to `SC`/`SI`/`SA` if none of those are present).
fn rank_from_cvss_vector(vector: &str) -> u8 {
    let mut metrics: HashMap<&str, &str> = HashMap::new();
    for part in vector.split('/') {
        if part.starts_with("CVSS:") {
            continue;
        }
        if let Some((k, v)) = part.split_once(':') {
            metrics.insert(k, v);
        }
    }

    let primary = ["C", "I", "A", "VC", "VI", "VA"];
    let mut impact: std::collections::HashSet<&str> = primary
        .iter()
        .filter_map(|k| metrics.get(k).copied())
        .collect();
    if impact.is_empty() {
        let secondary = ["SC", "SI", "SA"];
        impact = secondary
            .iter()
            .filter_map(|k| metrics.get(k).copied())
            .collect();
        if impact.is_empty() {
            impact.insert("N");
        }
    }

    if impact.len() == 1 && impact.contains("H") {
        return 4;
    }
    if impact.contains("H") {
        return 3;
    }
    if impact.contains("L") || impact.contains("M") {
        return 2;
    }
    1
}

/// Rank one `severity[]` entry: a CVSS vector string, or a legacy numeric
/// base score.
fn rank_from_severity_entry(score: &str) -> u8 {
    if score.starts_with("CVSS:") {
        return rank_from_cvss_vector(score);
    }
    match score.trim().parse::<f64>() {
        Ok(base) if base >= 9.0 => 4,
        Ok(base) if base >= 7.0 => 3,
        Ok(base) if base >= 4.0 => 2,
        Ok(base) if base > 0.0 => 1,
        _ => 0,
    }
}

fn severity_from_rank(rank: u8) -> Severity {
    match rank {
        4 => Severity::Critical,
        3 => Severity::High,
        2 => Severity::Medium,
        _ => Severity::Low,
    }
}

/// The highest severity `vuln` carries, preferring the database's own
/// normalised label (`database_specific.severity`) over deriving one from a
/// CVSS vector.
fn severity_for(vuln: &VulnDetail) -> Severity {
    if let Some(label) = vuln
        .database_specific
        .as_ref()
        .and_then(|d| d.severity.as_deref())
    {
        let rank = match label.to_uppercase().as_str() {
            "CRITICAL" => Some(4),
            "HIGH" => Some(3),
            "MEDIUM" | "MODERATE" => Some(2),
            "LOW" => Some(1),
            "NONE" => Some(0),
            _ => None,
        };
        if let Some(rank) = rank {
            return severity_from_rank(rank);
        }
    }

    let best = vuln
        .severity
        .iter()
        .map(|entry| rank_from_severity_entry(&entry.score))
        .max()
        .unwrap_or(0);
    severity_from_rank(best)
}

/// The first CVE alias on `vuln`, if it has one. Many advisories are
/// `GHSA`-only with no CVE assigned.
fn first_cve(vuln: &VulnDetail) -> Option<&str> {
    vuln.aliases
        .iter()
        .map(String::as_str)
        .find(|alias| alias.starts_with("CVE-"))
}

// ---------------------------------------------------------------------
// Query + hydrate
// ---------------------------------------------------------------------

/// POST the initial batch, then follow `next_page_token` until every query
/// has yielded all its pages or the round cap is hit. Returns each matched
/// advisory id mapped to the indices (into `deps`) of every dependency it
/// affects.
fn query_osv(
    deps: &[Dependency],
    transport: &dyn OsvTransport,
) -> Result<HashMap<String, Vec<usize>>, String> {
    let queries: Vec<Query<'_>> = deps
        .iter()
        .map(|d| Query {
            package: PackageQuery {
                name: &d.name,
                ecosystem: d.ecosystem.osv_name(),
            },
            version: &d.version,
            page_token: None,
        })
        .collect();

    let body = serde_json::to_string(&QueryBatchRequest { queries: &queries })
        .map_err(|error| format!("could not encode OSV request: {error}"))?;
    let response_text = transport
        .post(QUERYBATCH_URL, &body)
        .map_err(|reason| format!("OSV querybatch request failed: {reason}"))?;
    let response: QueryBatchResponse = serde_json::from_str(&response_text)
        .map_err(|error| format!("OSV querybatch returned an unparseable response: {error}"))?;

    let mut id_to_indices: HashMap<String, Vec<usize>> = HashMap::new();
    let mut pending: Vec<(usize, String)> = Vec::new();

    for (i, result) in response.results.iter().enumerate() {
        if i >= deps.len() {
            break;
        }
        record_result(result, i, &mut id_to_indices, &mut pending);
    }

    let mut round = 0;
    while !pending.is_empty() && round < MAX_PAGINATION_ROUNDS {
        round += 1;
        let paged_queries: Vec<Query<'_>> = pending
            .iter()
            .map(|(i, token)| Query {
                package: PackageQuery {
                    name: &deps[*i].name,
                    ecosystem: deps[*i].ecosystem.osv_name(),
                },
                version: &deps[*i].version,
                page_token: Some(token.as_str()),
            })
            .collect();

        let Ok(body) = serde_json::to_string(&QueryBatchRequest {
            queries: &paged_queries,
        }) else {
            break;
        };
        // A pagination round that fails, or comes back unparseable, is not
        // treated as a total lookup failure: the initial batch already
        // succeeded, so the API is reachable. The tail of results for the
        // still-pending packages is simply missing from this run.
        let Ok(response_text) = transport.post(QUERYBATCH_URL, &body) else {
            break;
        };
        let Ok(page): Result<QueryBatchResponse, _> = serde_json::from_str(&response_text) else {
            break;
        };

        let mut next_pending = Vec::new();
        for (j, result) in page.results.iter().enumerate() {
            if j >= pending.len() {
                break;
            }
            let (i, _) = pending[j];
            record_result(result, i, &mut id_to_indices, &mut next_pending);
        }
        pending = next_pending;
    }

    Ok(id_to_indices)
}

fn record_result(
    result: &QueryResult,
    dep_index: usize,
    id_to_indices: &mut HashMap<String, Vec<usize>>,
    pending: &mut Vec<(usize, String)>,
) {
    if let Some(token) = &result.next_page_token
        && !token.is_empty()
    {
        pending.push((dep_index, token.clone()));
    }
    for stub in &result.vulns {
        id_to_indices
            .entry(stub.id.clone())
            .or_default()
            .push(dep_index);
    }
}

/// One advisory against one dependency.
struct Advisory {
    /// The CVE id where OSV publishes one, otherwise the OSV id.
    identifier: String,
    severity: Severity,
    /// The version that resolves this advisory, when one is published.
    fix_version: Option<String>,
    /// OSV's own one-line description of the vulnerability.
    summary: String,
}

/// Turn matched advisories into **one [`Finding`] per vulnerable dependency**.
///
/// Grouping is deliberate. `cryptography 38.0.4` carries eleven published
/// advisories; as eleven findings it buries every other result in the report,
/// which is the presentation failure this tool exists to avoid. It is also one
/// thing to do about it — a single upgrade — so it reads as one finding, with
/// every identifier preserved in [`Finding::references`] for machines.
fn build_findings(
    deps: &[Dependency],
    id_to_indices: &HashMap<String, Vec<usize>>,
    transport: &dyn OsvTransport,
) -> Vec<Finding> {
    // Sorted, not `HashMap` order. Advisory ids reached in a random order
    // produce findings in a random order, and a scan whose output changes
    // between identical runs cannot be used to verify a fix.
    let mut osv_ids: Vec<&String> = id_to_indices.keys().collect();
    osv_ids.sort_unstable();

    // Dependency index -> its advisories, in the order the sorted ids give.
    let mut by_dependency: BTreeMap<usize, Vec<Advisory>> = BTreeMap::new();

    for osv_id in osv_ids {
        let Some(indices) = id_to_indices.get(osv_id) else {
            continue;
        };
        let url = format!("{VULNS_URL}/{osv_id}");
        // One un-hydratable advisory should not sink the whole batch.
        let Ok(body) = transport.get(&url) else {
            continue;
        };
        let Ok(vuln) = serde_json::from_str::<VulnDetail>(&body) else {
            continue;
        };

        let severity = severity_for(&vuln);
        let identifier = first_cve(&vuln).unwrap_or(vuln.id.as_str()).to_owned();

        for &i in indices {
            let dep = &deps[i];
            by_dependency.entry(i).or_default().push(Advisory {
                identifier: identifier.clone(),
                severity,
                fix_version: extract_fix_version(&vuln, &dep.name, &dep.version),
                summary: vuln.summary.clone(),
            });
        }
    }

    let mut findings: Vec<Finding> = by_dependency
        .into_iter()
        .filter_map(|(index, advisories)| {
            deps.get(index).map(|dep| group_finding(dep, &advisories))
        })
        .collect();

    findings.sort_by(|a, b| {
        a.location
            .file
            .cmp(&b.location.file)
            .then(a.location.line.cmp(&b.location.line))
            .then(a.title.cmp(&b.title))
    });
    findings
}

/// Collapse one dependency's advisories into a single finding.
fn group_finding(dep: &Dependency, advisories: &[Advisory]) -> Finding {
    let severity = advisories
        .iter()
        .map(|advisory| advisory.severity)
        .max()
        .unwrap_or(Severity::Low);

    let mut identifiers: Vec<String> = advisories
        .iter()
        .map(|advisory| advisory.identifier.clone())
        .collect();
    identifiers.sort();
    identifiers.dedup();

    // The highest published fix clears every advisory below it, so it is the
    // one version worth naming. If any advisory has no published fix, the
    // upgrade cannot be claimed to resolve everything and the text says so.
    // An advisory counts as unfixed when it offers no version we can name — no
    // published fix, or only a commit SHA or prerelease.
    let unfixed = advisories.iter().any(|advisory| {
        advisory
            .fix_version
            .as_deref()
            .is_none_or(|version| !is_plain_release(version))
    });
    // Candidates must parse as a release number. GIT ranges are already
    // dropped upstream in `package_segments`; this is the guard that keeps any
    // other unparseable value out of an upgrade hint.
    let mut candidates: Vec<(&str, Vec<u64>)> = advisories
        .iter()
        .filter_map(|advisory| advisory.fix_version.as_deref())
        .filter(|version| is_plain_release(version))
        .filter_map(|version| version_digits(version).map(|digits| (version, digits)))
        .collect();
    candidates.sort_by(|(a_text, a_digits), (b_text, b_digits)| {
        a_digits.cmp(b_digits).then_with(|| a_text.cmp(b_text))
    });
    let target = candidates.last().map(|(version, _)| (*version).to_owned());

    let count = identifiers.len();
    let title = if count == 1 {
        format!(
            "{} {} is affected by {}",
            dep.name, dep.version, identifiers[0]
        )
    } else {
        format!(
            "{} {} \u{2014} {count} known vulnerabilities",
            dep.name, dep.version
        )
    };

    Finding {
        rule_id: RULE_ID.to_string(),
        title,
        kind: Kind::Defect,
        severity,
        confidence: Confidence::High,
        categories: vec![Category::Llm04],
        location: Location {
            file: dep.file.clone(),
            line: dep.line,
            column: 1,
        },
        snippet: dep.declaration.clone(),
        description: group_description(dep, advisories, count),
        remediation: group_remediation(dep, target.as_deref(), count, unfixed),
        secondary_rule_ids: Vec::new(),
        references: identifiers,
    }
}

/// The severity spread, so a reader can see what the group is made of without
/// expanding it.
fn group_description(dep: &Dependency, advisories: &[Advisory], count: usize) -> String {
    if count == 1 {
        // With one advisory there is room for OSV's own description, which is
        // more useful than anything we could restate.
        let summary = advisories
            .first()
            .map(|advisory| advisory.summary.trim())
            .filter(|summary| !summary.is_empty());
        return match summary {
            Some(text) => format!("{} {}: {text}", dep.name, dep.version),
            None => format!(
                "{} {} is affected by a published advisory.",
                dep.name, dep.version
            ),
        };
    }

    let mut counts = [0_usize; 4];
    for advisory in advisories {
        let slot = match advisory.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
        };
        counts[slot] += 1;
    }

    let spread: Vec<String> = ["critical", "high", "medium", "low"]
        .iter()
        .zip(counts)
        .filter(|(_, n)| *n > 0)
        .map(|(label, n)| format!("{n} {label}"))
        .collect();

    format!(
        "{} {} has {count} published advisories against it ({}).",
        dep.name,
        dep.version,
        spread.join(", ")
    )
}

/// Name the single upgrade that clears the group, when there is one.
fn group_remediation(
    dep: &Dependency,
    target: Option<&str>,
    count: usize,
    unfixed: bool,
) -> String {
    match (target, unfixed) {
        (Some(version), false) if count == 1 => {
            format!("Upgrade {} to {version} or later.", dep.name)
        }
        (Some(version), false) => format!(
            "Upgrade {} to {version} or later, which resolves all {count}.",
            dep.name
        ),
        (Some(version), true) => format!(
            "Upgrade {} to {version} or later. At least one advisory has no published fix \
             yet, so track it and upgrade again when one lands.",
            dep.name
        ),
        (None, _) => format!(
            "No fixed version is published yet; track the advisories and upgrade {} once one \
             lands.",
            dep.name
        ),
    }
}

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

/// Look up `deps` against `OSV.dev` and turn any match into a [`Finding`].
///
/// This never fails the scan on a network problem: a DNS failure, a
/// timeout, or a non-2xx response all come back as
/// [`CveStatus::Unreachable`] with a one-line reason, and zero findings — not
/// an `Err`, and not a silent "no vulnerabilities found". A CVE section that
/// reports nothing because the lookup could not run reads as "clean", which
/// is the worst possible failure for a security tool.
///
/// `deps` is expected to be every dependency resolved across every manifest
/// found in the scanned tree — [`check`] reports a single [`CveStatus`] for
/// the whole scan, not one per manifest. An empty slice returns
/// [`CveStatus::NoManifest`]: with nothing to look up there is no observable
/// difference between "no manifest existed" and "a manifest existed but had
/// nothing pinned to check", and reporting a network round trip that never
/// happened as `Checked { dependencies: 0 }` would be misleading.
///
/// When `offline` is `true`, this makes no network call at all — not even to
/// build the underlying HTTP client — and returns
/// [`CveStatus::SkippedOffline`].
#[must_use]
pub fn check(deps: &[Dependency], offline: bool) -> (Vec<Finding>, CveStatus) {
    if offline {
        return (Vec::new(), CveStatus::SkippedOffline);
    }
    check_with_transport(deps, false, &UreqTransport::new())
}

/// The injectable core behind [`check`]: same contract, but the transport is
/// substitutable so tests never touch the network.
fn check_with_transport(
    deps: &[Dependency],
    offline: bool,
    transport: &dyn OsvTransport,
) -> (Vec<Finding>, CveStatus) {
    if offline {
        return (Vec::new(), CveStatus::SkippedOffline);
    }
    if deps.is_empty() {
        return (Vec::new(), CveStatus::NoManifest);
    }

    match query_osv(deps, transport) {
        Ok(id_to_indices) => {
            let findings = build_findings(deps, &id_to_indices, transport);
            (
                findings,
                CveStatus::Checked {
                    dependencies: deps.len(),
                },
            )
        }
        Err(reason) => (Vec::new(), CveStatus::Unreachable { reason }),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::PathBuf;

    use super::*;
    use crate::cve::manifest::Ecosystem;

    fn dependency(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem: Ecosystem::PyPi,
            file: PathBuf::from("requirements.txt"),
            line: 1,
            declaration: format!("{name}=={version}"),
        }
    }

    /// A fake transport driven by canned responses, so tests never touch the
    /// network. POST responses are consumed in order; GET responses are
    /// looked up by URL.
    struct FakeTransport {
        post_calls: RefCell<u32>,
        post_responses: RefCell<VecDeque<Result<String, String>>>,
        get_responses: RefCell<HashMap<String, Result<String, String>>>,
    }

    impl FakeTransport {
        fn new() -> Self {
            Self {
                post_calls: RefCell::new(0),
                post_responses: RefCell::new(VecDeque::new()),
                get_responses: RefCell::new(HashMap::new()),
            }
        }

        fn with_post_response(self, response: Result<String, String>) -> Self {
            self.post_responses.borrow_mut().push_back(response);
            self
        }

        fn with_get_response(self, url: &str, response: Result<String, String>) -> Self {
            self.get_responses
                .borrow_mut()
                .insert(url.to_string(), response);
            self
        }

        fn post_call_count(&self) -> u32 {
            *self.post_calls.borrow()
        }
    }

    impl OsvTransport for FakeTransport {
        fn post(&self, _url: &str, _body: &str) -> Result<String, String> {
            *self.post_calls.borrow_mut() += 1;
            self.post_responses
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Err("no canned response left".to_string()))
        }

        fn get(&self, url: &str) -> Result<String, String> {
            self.get_responses
                .borrow()
                .get(url)
                .cloned()
                .unwrap_or_else(|| Err(format!("no canned response for {url}")))
        }
    }

    #[test]
    fn only_plain_release_versions_are_recommended() {
        // A commit SHA or a release candidate must never be the upgrade target.
        assert!(is_plain_release("2.33.0"));
        assert!(is_plain_release("2024.7.4"));
        assert!(is_plain_release("49"));
        assert!(!is_plain_release("1.0.10rc1"), "rc inside a segment");
        assert!(!is_plain_release("2.0.0b3"));
        assert!(!is_plain_release("1.2.3.post1"));
        assert!(!is_plain_release("4.0.0-alpha"));
        assert!(
            !is_plain_release("97d231672763cdb5959a3b191e692a362f1b9e55"),
            "a git SHA is not a version"
        );
        assert!(!is_plain_release(""));
    }

    #[test]
    fn advisories_on_one_dependency_group_into_one_finding() {
        // The behaviour that turns a 44-row wall into something readable: one
        // dependency is one thing to fix, so it is one finding.
        let deps = vec![dependency("cryptography", "38.0.4")];
        let mut ids = HashMap::new();
        ids.insert("OSV-A".to_owned(), vec![0]);
        ids.insert("OSV-B".to_owned(), vec![0]);
        ids.insert("OSV-C".to_owned(), vec![0]);

        let detail = |id: &str, cve: &str, sev: &str, fixed: &str| {
            format!(
                r#"{{"id":"{id}","summary":"Example advisory.","aliases":["{cve}"],
                    "database_specific":{{"severity":"{sev}"}},
                    "affected":[{{"package":{{"name":"cryptography","ecosystem":"PyPI"}},
                    "ranges":[{{"events":[{{"introduced":"0"}},{{"fixed":"{fixed}"}}]}}]}}]}}"#
            )
        };

        let transport = FakeTransport::new()
            .with_get_response(
                &format!("{VULNS_URL}/OSV-A"),
                Ok(detail("OSV-A", "CVE-1111-0001", "MODERATE", "39.0.1")),
            )
            .with_get_response(
                &format!("{VULNS_URL}/OSV-B"),
                Ok(detail("OSV-B", "CVE-1111-0002", "HIGH", "42.0.4")),
            )
            .with_get_response(
                &format!("{VULNS_URL}/OSV-C"),
                Ok(detail("OSV-C", "CVE-1111-0003", "LOW", "41.0.0")),
            );

        let findings = build_findings(&deps, &ids, &transport);

        assert_eq!(
            findings.len(),
            1,
            "expected one grouped finding: {findings:#?}"
        );
        let finding = &findings[0];
        assert_eq!(
            finding.severity,
            Severity::High,
            "severity must be the maximum across the group"
        );
        assert_eq!(finding.references.len(), 3, "every identifier is kept");
        assert!(
            finding.title.contains("3 known vulnerabilities"),
            "title should count them: {}",
            finding.title
        );
        assert!(
            finding.remediation.contains("42.0.4"),
            "the highest fix clears the group: {}",
            finding.remediation
        );
        assert!(
            finding.remediation.contains("all 3"),
            "and should say so: {}",
            finding.remediation
        );
    }

    #[test]
    fn matched_vuln_produces_a_finding_with_severity_and_fix_version() {
        let deps = vec![dependency("requests", "2.19.1")];

        let querybatch = r#"{"results":[{"vulns":[{"id":"GHSA-x84v-xcm2-53pg"}]}]}"#;
        let vuln_detail = r#"{
            "id": "GHSA-x84v-xcm2-53pg",
            "summary": "Requests leaks Proxy-Authorization header.",
            "aliases": ["CVE-2023-32681"],
            "database_specific": {"severity": "MODERATE"},
            "affected": [{
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"events": [
                    {"introduced": "0"},
                    {"fixed": "2.31.0"}
                ]}]
            }]
        }"#;

        let transport = FakeTransport::new()
            .with_post_response(Ok(querybatch.to_string()))
            .with_get_response(
                "https://api.osv.dev/v1/vulns/GHSA-x84v-xcm2-53pg",
                Ok(vuln_detail.to_string()),
            );

        let (findings, status) = check_with_transport(&deps, false, &transport);

        assert_eq!(status, CveStatus::Checked { dependencies: 1 });
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.rule_id, "BAS-CVE-001");
        assert_eq!(
            finding.title,
            "requests 2.19.1 is affected by CVE-2023-32681"
        );
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(finding.categories, vec![Category::Llm04]);
        assert_eq!(finding.location.line, 1);
        assert!(finding.remediation.contains("2.31.0"));
    }

    #[test]
    fn transport_failure_is_unreachable_not_an_error() {
        let deps = vec![dependency("requests", "2.19.1")];
        let transport =
            FakeTransport::new().with_post_response(Err("connection refused".to_string()));

        let (findings, status) = check_with_transport(&deps, false, &transport);

        assert!(findings.is_empty());
        assert!(
            matches!(&status, CveStatus::Unreachable { reason } if reason.contains("connection refused")),
            "status: {status:?}"
        );
    }

    #[test]
    fn offline_skips_without_calling_the_transport() {
        let deps = vec![dependency("requests", "2.19.1")];
        let transport = FakeTransport::new();

        let (findings, status) = check_with_transport(&deps, true, &transport);

        assert!(findings.is_empty());
        assert_eq!(status, CveStatus::SkippedOffline);
        assert_eq!(
            transport.post_call_count(),
            0,
            "offline must not touch the network"
        );
    }

    #[test]
    fn empty_dependency_list_is_no_manifest() {
        let transport = FakeTransport::new();

        let (findings, status) = check_with_transport(&[], false, &transport);

        assert!(findings.is_empty());
        assert_eq!(status, CveStatus::NoManifest);
        assert_eq!(transport.post_call_count(), 0);
    }

    #[test]
    fn no_match_still_reports_checked() {
        let deps = vec![dependency("requests", "2.19.1")];
        let transport = FakeTransport::new()
            .with_post_response(Ok(r#"{"results":[{"vulns":[]}]}"#.to_string()));

        let (findings, status) = check_with_transport(&deps, false, &transport);

        assert!(findings.is_empty());
        assert_eq!(status, CveStatus::Checked { dependencies: 1 });
    }

    /// A transport whose every POST response carries another
    /// `next_page_token`, to prove pagination is bounded rather than
    /// infinite.
    struct AlwaysPagingTransport {
        calls: RefCell<u32>,
    }

    impl OsvTransport for AlwaysPagingTransport {
        fn post(&self, _url: &str, _body: &str) -> Result<String, String> {
            *self.calls.borrow_mut() += 1;
            Ok(r#"{"results":[{"vulns":[],"next_page_token":"more"}]}"#.to_string())
        }

        fn get(&self, _url: &str) -> Result<String, String> {
            Err("unused in this test".to_string())
        }
    }

    #[test]
    fn pagination_is_followed_and_bounded_by_the_round_cap() {
        let deps = vec![dependency("requests", "2.19.1")];
        let transport = AlwaysPagingTransport {
            calls: RefCell::new(0),
        };

        let (findings, status) = check_with_transport(&deps, false, &transport);

        assert!(findings.is_empty());
        assert_eq!(status, CveStatus::Checked { dependencies: 1 });
        // One initial call, then MAX_PAGINATION_ROUNDS more before the round
        // cap stops the loop.
        assert_eq!(*transport.calls.borrow(), 1 + MAX_PAGINATION_ROUNDS);
    }

    #[test]
    fn rank_from_cvss_vector_reads_the_impact_triad() {
        assert_eq!(
            rank_from_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            4
        );
        assert_eq!(
            rank_from_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            3
        );
        assert_eq!(
            rank_from_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            2
        );
        assert_eq!(
            rank_from_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            1
        );
    }

    #[test]
    fn extract_fix_version_picks_the_segment_containing_the_installed_version() {
        let vuln: VulnDetail = serde_json::from_str(
            r#"{
                "id": "GHSA-test",
                "affected": [{
                    "package": {"name": "demo"},
                    "ranges": [
                        {"events": [{"introduced": "0"}, {"fixed": "1.5.0"}]},
                        {"events": [{"introduced": "2.0.0"}, {"fixed": "2.3.0"}]}
                    ]
                }]
            }"#,
        )
        .unwrap();

        assert_eq!(
            extract_fix_version(&vuln, "demo", "1.2.0").as_deref(),
            Some("1.5.0")
        );
        assert_eq!(
            extract_fix_version(&vuln, "demo", "2.1.0").as_deref(),
            Some("2.3.0")
        );
    }

    #[test]
    #[ignore = "hits the real OSV.dev API; run explicitly with `cargo test -- --ignored`"]
    fn real_osv_lookup_finds_a_known_vulnerable_dependency() {
        let deps = vec![dependency("requests", "2.19.1")];

        let (findings, status) = check(&deps, false);

        assert!(
            matches!(status, CveStatus::Checked { .. }),
            "status: {status:?}"
        );
        assert!(
            !findings.is_empty(),
            "expected at least one known CVE for requests 2.19.1"
        );
    }
}
