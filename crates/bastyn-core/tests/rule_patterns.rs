//! Verifies `rules/bastyn.yml` without the rule engine, which is being built
//! by a different task in parallel (`src/rules/mod.rs` is still a
//! placeholder). This test drives `ast-grep-core` directly and implements
//! just enough of the documented schema semantics to prove the YAML is
//! sound:
//!
//! - `any`: a rule fires wherever any of its patterns match.
//! - `none`: a match is suppressed when a `none` pattern matches the exact
//!   same AST node (identical byte range) — the same relationship the given
//!   `BAS-LLM10-001` example relies on (`eval($ARG)` / `eval("$LIT")` both
//!   anchor on the same call node).
//! - `inside`: a match must be a descendant of at least one `inside`
//!   pattern's match.
//! - `metavariable_matches`: a named capture's text must satisfy the
//!   corresponding regex.
//!
//! `metavariable_matches` regexes are re-implemented here as small, named
//! Rust predicates (see [`eval_metavariable`]) rather than compiled as real
//! regexes, because the `regex` crate is not a dependency of `bastyn-core`
//! and this test file is not allowed to add one (`Cargo.toml` is owned by a
//! different task). Each predicate is a direct, hand-checked translation of
//! its rule's YAML pattern; keep them in sync if the YAML changes.
//!
//! ## Rules considered and dropped
//!
//! - A ZT2/ZT3 ("no auth", "no rate limiting") observation: rejected outright.
//!   Both are unprovable from source alone — the control is normally at the
//!   edge — which is exactly the class of noise `clean_agent/app.py` exists
//!   to prove this rule set does not produce.
//! - A ZT6 ("tool call with no audit log") observation, structured the same
//!   way as `BAS-LLM06-001`'s `none`-based `max_tokens` check: the log call can
//!   land at any position in the body, which needed as many `none` position
//!   variants as the token-ceiling check for a category the scope doc ranks
//!   below the eight rules actually shipped here. Dropped rather than shipped
//!   half-verified.
//! - A single-statement-body heuristic for "no permission check" (matching a
//!   lone non-`$$$` metavariable as the function body): measured directly
//!   against `ast-grep-core` and found to match multi-statement bodies too
//!   (a block's sole child metavariable behaves like a multi-capture), so it
//!   cannot distinguish a guarded tool from an unguarded one. Replaced with
//!   the `none`-guard-shape approach `BAS-LLM03-001` uses instead.

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use ast_grep_core::{AstGrep, Pattern};
use ast_grep_language::Python;
use bastyn_core::{Category, Confidence, Kind, Severity};
use serde::Deserialize;

const RULES_YAML: &str = include_str!("../rules/bastyn.yml");

// ---------------------------------------------------------------------
// Schema (mirrors the rule schema's own definition, reusing the
// engine's own Kind/Severity/Confidence/Category types so a rule that does
// not deserialize against the real finding model fails this test).
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RuleFile {
    rules: Vec<RuleDef>,
}

#[derive(Debug, Deserialize)]
struct RuleDef {
    id: String,
    title: String,
    kind: Kind,
    severity: Severity,
    confidence: Confidence,
    categories: Vec<Category>,
    language: String,
    #[serde(default)]
    any: Vec<String>,
    #[serde(default)]
    none: Vec<String>,
    #[serde(default)]
    inside: Vec<String>,
    #[serde(default)]
    metavariable_matches: BTreeMap<String, String>,
    description: String,
    remediation: String,
}

fn load_rules() -> Vec<RuleDef> {
    // `.unwrap()`: a rules file that doesn't parse against the schema should
    // fail every test in this file, loudly.
    let file: RuleFile = serde_yaml_ng::from_str(RULES_YAML).unwrap();
    file.rules
}

/// `load_rules()`, filtered to `language: python`.
///
/// This file drives `ast-grep-core` directly against a single hardcoded
/// grammar (`ast_grep_language::Python`, see the module docs) because it
/// predates the real rule engine (`bastyn_core::rules`), which was "being
/// built by a different task in parallel" when this file was written. That
/// engine is now real, multi-language, and the source of truth: it compiles
/// each rule against the grammar its own `language` field names (see
/// `crates/bastyn-core/src/rules/engine.rs`'s module docs for why that
/// matters), and its own precision is verified in
/// `crates/bastyn-core/src/rules/tests.rs` and the corpus gate
/// (`crates/bastyn-core/tests/corpus_gate.rs`), which do cover the
/// TypeScript and JavaScript rules this function excludes.
///
/// Compiling a TypeScript or JavaScript rule's patterns against the Python
/// grammar here would not exercise anything real -- tree-sitter is
/// error-tolerant, so an unrelated-language pattern often still "compiles"
/// into a structurally meaningless matcher instead of failing loudly. Rather
/// than teach this Python-only, no-`regex`-crate harness a second grammar,
/// pattern-level checks here stay scoped to what it was built to verify.
fn python_rules() -> Vec<RuleDef> {
    load_rules()
        .into_iter()
        .filter(|rule| rule.language == "python")
        .collect()
}

fn fixture_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn python_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "py"))
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no .py fixtures found under {}",
        dir.display()
    );
    files
}

// ---------------------------------------------------------------------
// Rust stand-ins for each rule's `metavariable_matches` regex. See the
// module doc for why these are hand-written rather than a real regex.
// ---------------------------------------------------------------------

fn contains_ci(text: &str, words: &[&str]) -> bool {
    let lower = text.to_lowercase();
    words.iter().any(|w| lower.contains(w))
}

/// Mirrors `^sk-[A-Za-z0-9_-]{16,}$` (BAS-ZT1-001's `SECRET`): the captured
/// text, in full, must be an `sk-`-prefixed token of at least 16 further
/// alphanumeric/`_`/`-` characters.
fn looks_like_openai_key(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("sk-") else {
        return false;
    };
    rest.len() >= 16
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Mirrors `(?i)sk-[A-Za-z0-9_-]{16,}` (BAS-LLM08-001's `CONTENT`): an
/// `sk-`-shaped token appearing *anywhere* in the text, unanchored.
fn contains_openai_key_shape(text: &str) -> bool {
    text.match_indices("sk-").any(|(idx, _)| {
        text[idx + 3..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .count()
            >= 16
    })
}

/// Mirrors BAS-ZT1-002's `VALUE` regex's first alternative
/// (`:\/\/[^\s/:@]+:[^\s/@]+@`): a `://user:pass@` connection-string shape
/// appearing anywhere in the text.
fn looks_like_creds_url(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    for i in 0..n {
        if chars[i] == ':' && chars.get(i + 1) == Some(&'/') && chars.get(i + 2) == Some(&'/') {
            let mut j = i + 3;
            let user_start = j;
            while j < n && !matches!(chars[j], ' ' | '\t' | '\n' | '/' | ':' | '@') {
                j += 1;
            }
            if j == user_start || j >= n || chars[j] != ':' {
                continue;
            }
            j += 1;
            let pass_start = j;
            while j < n && !matches!(chars[j], ' ' | '\t' | '\n' | '/' | '@') {
                j += 1;
            }
            if j != pass_start && j < n && chars[j] == '@' {
                return true;
            }
        }
    }
    false
}

/// Mirrors BAS-ZT1-002's `VALUE` regex's second alternative
/// (`(?i:secret|token|password|api[_-]?key|private[_-]?key)[-_][0-9a-f]{12,}`):
/// a secret-ish keyword immediately followed by `-`/`_` and 12+ hex chars.
fn looks_like_secret_token(text: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "secret",
        "token",
        "password",
        "apikey",
        "api_key",
        "api-key",
        "privatekey",
        "private_key",
        "private-key",
    ];
    let lower = text.to_lowercase();
    for kw in KEYWORDS {
        let mut start = 0;
        while let Some(pos) = lower[start..].find(kw) {
            let end = start + pos + kw.len();
            let rest = &lower[end..];
            let mut rest_chars = rest.chars();
            if let Some(sep) = rest_chars.next()
                && (sep == '-' || sep == '_')
            {
                let hex_len = rest_chars.take_while(char::is_ascii_hexdigit).count();
                if hex_len >= 12 {
                    return true;
                }
            }
            start = end;
        }
    }
    false
}

/// Mirrors BAS-ZT1-002's `VALUE` regex as a whole (either alternative).
fn looks_like_credential_value(text: &str) -> bool {
    looks_like_creds_url(text) || looks_like_secret_token(text)
}

/// Mirrors BAS-LLM03-001's `FN` regex: a destructive verb at the start of
/// the function name.
fn is_destructive_tool_name(text: &str) -> bool {
    const VERBS: &[&str] = &[
        "delete",
        "drop",
        "remove",
        "transfer",
        "withdraw",
        "wire",
        "drain",
        "revoke",
        "terminate",
        "shutdown",
        "sell_all",
        "liquidate",
        "send_funds",
        "execute_trade",
        "purge",
        "wipe",
    ];
    let lower = text.to_lowercase();
    VERBS.iter().any(|v| lower.starts_with(v))
}

const LLM_OUTPUT_WORDS: &[&str] = &[
    "response",
    "reply",
    "completion",
    "message",
    "content",
    "choices",
    "output",
    "generated",
];

/// Dispatches a captured metavariable's text to the predicate that mirrors
/// its rule's YAML regex. Panics on an unrecognised (rule, var) pair so a
/// rule that adds a new `metavariable_matches` key cannot silently skip
/// verification.
fn eval_metavariable(rule_id: &str, var: &str, text: &str) -> bool {
    match (rule_id, var) {
        ("BAS-LLM10-001" | "BAS-LLM10-002" | "BAS-LLM10-003", "ARG") => {
            contains_ci(text, LLM_OUTPUT_WORDS)
        }
        ("BAS-LLM10-003", "CUR") => {
            contains_ci(text, &["cursor", "cur", "db", "conn", "connection"])
        }
        ("BAS-ZT4-001" | "BAS-ZT4-002", "SYS") => contains_ci(
            text,
            &["system", "prompt", "instruction", "persona", "template"],
        ),
        ("BAS-ZT4-001", "VAR") => contains_ci(
            text,
            &["user", "request", "query", "input", "raw", "message"],
        ),
        ("BAS-ZT1-001", "SECRET") => looks_like_openai_key(text),
        ("BAS-LLM08-001", "VAR") => contains_ci(
            text,
            &["prompt", "template", "system", "instruction", "persona"],
        ),
        ("BAS-LLM08-001", "CONTENT") => contains_openai_key_shape(text),
        ("BAS-LLM03-001", "FN") => is_destructive_tool_name(text),
        ("BAS-LLM06-001", "CLIENT") => contains_ci(text, &["client", "llm", "openai", "gpt"]),
        ("BAS-ZT1-002", "VALUE") => looks_like_credential_value(text),
        ("BAS-ZT4-002", "OVERRIDE") => contains_ci(
            text,
            &[
                "override",
                "overridden",
                "custom_instructions",
                "force_prompt",
            ],
        ),
        _ => unreachable!(
            "no verification predicate wired up for {rule_id}.{var} -- \
             add one in eval_metavariable alongside the YAML regex"
        ),
    }
}

// ---------------------------------------------------------------------
// The mini rule engine used only by this test.
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Finding {
    rule_id: String,
    file: PathBuf,
    line: usize,
}

fn compile_all<'a>(patterns: impl Iterator<Item = &'a String>) -> Vec<Pattern> {
    patterns
        .map(|p| Pattern::try_new(p.as_str(), Python).unwrap())
        .collect()
}

/// Runs one rule over one file's source, returning the (`start_byte`, line) of
/// each surviving match.
fn run_rule_on_source(rule: &RuleDef, source: &str) -> Vec<(usize, usize)> {
    let grep = AstGrep::new(source, Python);
    let root = grep.root();
    let any_patterns = compile_all(rule.any.iter());
    let none_patterns = compile_all(rule.none.iter());
    let inside_patterns = compile_all(rule.inside.iter());

    let none_ranges: HashSet<(usize, usize)> = none_patterns
        .iter()
        .flat_map(|p| root.find_all(p))
        .map(|m| (m.range().start, m.range().end))
        .collect();

    let mut hits = Vec::new();
    for pat in &any_patterns {
        for m in root.find_all(pat) {
            let range = (m.range().start, m.range().end);
            if none_ranges.contains(&range) {
                continue;
            }
            if !inside_patterns.is_empty() && !inside_patterns.iter().any(|ip| m.inside(ip)) {
                continue;
            }
            let satisfies_metavars = rule.metavariable_matches.keys().all(|var| {
                m.get_env()
                    .get_match(var)
                    .is_some_and(|node| eval_metavariable(&rule.id, var, &node.text()))
            });
            if !satisfies_metavars {
                continue;
            }
            hits.push((range.0, m.start_pos().line() + 1));
        }
    }
    hits.sort_unstable();
    hits.dedup();
    hits
}

fn scan_dir(rules: &[RuleDef], dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in python_files(dir) {
        let source = fs::read_to_string(&file).unwrap();
        for rule in rules {
            for (_start, line) in run_rule_on_source(rule, &source) {
                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    file: file.clone(),
                    line,
                });
            }
        }
    }
    findings
}

fn counts_by_rule(findings: &[Finding]) -> HashMap<&str, usize> {
    let mut counts = HashMap::new();
    for f in findings {
        *counts.entry(f.rule_id.as_str()).or_insert(0) += 1;
    }
    counts
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

/// Every rule deserializes against the real finding model, has a non-empty
/// `any`, a valid category, and context-dependent categories only ever
/// appear on `kind: observation` — the constraint the engine enforces per
/// `Category::is_context_dependent`.
#[test]
fn yaml_schema_is_valid() {
    let rules = load_rules();
    assert!(
        !rules.is_empty(),
        "bastyn.yml must declare at least one rule"
    );
    let python_count = rules.iter().filter(|r| r.language == "python").count();
    assert!(
        python_count <= 12,
        "aim for 8-12 python rules; {python_count} is more than the brief asks for"
    );
    // TypeScript/JavaScript support came later (see `python_rules`'s doc
    // comment); those rules get their own budget rather than sharing the
    // python-era cap.
    let ts_js_count = rules.len() - python_count;
    assert!(
        ts_js_count <= 10,
        "aim for 6-10 TS/JS rules; {ts_js_count} is more than asked for"
    );

    let mut seen_ids = HashSet::new();
    for rule in &rules {
        assert!(!rule.any.is_empty(), "{}: `any` must be non-empty", rule.id);
        assert!(
            !rule.categories.is_empty(),
            "{}: must map to at least one category",
            rule.id
        );
        assert!(
            seen_ids.insert(rule.id.clone()),
            "duplicate rule id {}",
            rule.id
        );
        assert!(
            matches!(
                rule.language.as_str(),
                "python" | "typescript" | "javascript"
            ),
            "{}: unknown language {:?}",
            rule.id,
            rule.language
        );
        assert!(
            !rule.title.is_empty(),
            "{}: title must not be empty",
            rule.id
        );
        assert!(
            !rule.description.is_empty(),
            "{}: description must not be empty",
            rule.id
        );
        assert!(
            !rule.remediation.is_empty(),
            "{}: remediation must not be empty",
            rule.id
        );

        let context_dependent = rule.categories.iter().any(|c| c.is_context_dependent());
        if context_dependent {
            assert_eq!(
                rule.kind,
                Kind::Observation,
                "{}: maps to a context-dependent category ({:?}) and must be kind: observation",
                rule.id,
                rule.categories
            );
        }
    }

    // BAS-LLM10-001 must exist with the shape the brief pins down explicitly
    // -- another task depends on this id existing in this shape.
    let anchor = rules.iter().find(|r| r.id == "BAS-LLM10-001").unwrap();
    assert_eq!(anchor.title, "Model output executed as code");
    assert_eq!(anchor.kind, Kind::Defect);
    assert_eq!(anchor.severity, Severity::Critical);
    assert_eq!(anchor.confidence, Confidence::High);
    assert_eq!(anchor.categories, vec![Category::Llm10, Category::Zt4]);
    assert_eq!(
        anchor.any,
        vec!["eval($ARG)".to_string(), "exec($ARG)".to_string()]
    );
    assert_eq!(anchor.none, vec!["eval(\"$LIT\")".to_string()]);
}

/// Every `any`/`none`/`inside` pattern across every `language: python` rule
/// compiles as a valid ast-grep Python pattern. TypeScript/JavaScript rules
/// are excluded -- see `python_rules`'s doc comment -- and are instead
/// compiled against their own grammar by the real engine, verified in
/// `crates/bastyn-core/src/rules/tests.rs`.
#[test]
fn all_patterns_compile() {
    let rules = python_rules();
    for rule in &rules {
        for pat in rule
            .any
            .iter()
            .chain(rule.none.iter())
            .chain(rule.inside.iter())
        {
            Pattern::try_new(pat.as_str(), Python).unwrap();
        }
    }
}

/// Each rule fires on the specific line of `vulnerable_agent/` documented in
/// `tests/fixtures/README.md`, and fires there exactly once (proving the
/// rule is not accidentally over-broad even on its own positive fixture).
#[test]
fn vulnerable_fixture_produces_expected_findings() {
    let rules = python_rules();
    let dir = fixture_dir("vulnerable_agent");
    let findings = scan_dir(&rules, &dir);
    let counts = counts_by_rule(&findings);

    let expected: &[(&str, usize)] = &[
        ("BAS-ZT1-001", 1),
        ("BAS-ZT4-001", 1),
        ("BAS-LLM08-001", 1),
        ("BAS-LLM03-001", 1),
        ("BAS-LLM10-001", 1),
        ("BAS-LLM10-002", 1),
        ("BAS-LLM10-003", 1),
        ("BAS-LLM06-001", 1),
    ];
    for (rule_id, expected_count) in expected {
        assert_eq!(
            counts.get(rule_id).copied().unwrap_or(0),
            *expected_count,
            "{rule_id}: expected {expected_count} match(es) on vulnerable_agent, findings were: {findings:#?}"
        );
    }

    // get_wallet_balance is not destructive and must never trip BAS-LLM03-001,
    // guard or no guard -- the count above (exactly 1, for delete_wallet)
    // already proves this, but assert the specific file too.
    let llm03_files: Vec<&Path> = findings
        .iter()
        .filter(|f| f.rule_id == "BAS-LLM03-001")
        .map(|f| f.file.as_path())
        .collect();
    assert!(llm03_files.iter().all(|f| f.ends_with("tools.py")));

    // Cross-check the exact (rule, file, line) triples against the
    // documented spec in tests/fixtures/README.md.
    let expected_locations: &[(&str, &str, usize)] = &[
        ("BAS-ZT1-001", "config.py", 6),
        ("BAS-ZT4-001", "prompts.py", 10),
        ("BAS-LLM08-001", "prompts.py", 17),
        ("BAS-LLM03-001", "tools.py", 9),
        ("BAS-LLM10-001", "agent.py", 39),
        ("BAS-LLM10-002", "agent.py", 49),
        ("BAS-LLM10-003", "agent.py", 58),
        ("BAS-LLM06-001", "agent.py", 23),
    ];
    for (rule_id, file_name, line) in expected_locations {
        let found = findings
            .iter()
            .any(|f| f.rule_id == *rule_id && f.file.ends_with(file_name) && f.line == *line);
        assert!(
            found,
            "expected {rule_id} to fire at {file_name}:{line}, findings were: {findings:#?}"
        );
    }
}

/// The headline test: the safe app, containing every near-miss called out in
/// the scope doc (a literal `eval()`, `approx_tokens`-style names, correct
/// `os.environ` usage, a properly delimited prompt template, a public
/// no-login endpoint, no rate limiting), produces zero findings from any
/// rule. This is how precision is proven rather than claimed.
#[test]
fn clean_fixture_produces_no_findings() {
    let rules = python_rules();
    let dir = fixture_dir("clean_agent");
    let findings = scan_dir(&rules, &dir);
    assert!(
        findings.is_empty(),
        "clean_agent must produce zero findings; got: {findings:#?}"
    );
}
