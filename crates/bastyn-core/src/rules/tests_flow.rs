//! Unit tests for the `flow:` clause: a rule that fires on where a value came
//! from rather than on what it was called.

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::path::Path;

use super::{RuleError, RuleSet, scan_source};

/// The `flow:`-gated form of `BAS-LLM10-001`: no name gate anywhere in it.
const FLOW_RULE_YAML: &str = r"
rules:
  - id: BAS-FLOW-001
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
      - exec($ARG)
    flow:
      variable: ARG
      source: model_output
      unguarded: true
    description: Model output reaches eval().
    remediation: Do not execute model output.
";

fn flow_ruleset() -> RuleSet {
    RuleSet::from_yaml(FLOW_RULE_YAML).unwrap()
}

fn fires(ruleset: &RuleSet, source: &str) -> bool {
    scan_source(ruleset, Path::new("app/handler.py"), source)
        .iter()
        .any(|finding| finding.rule_id.starts_with("BAS-FLOW"))
}

/// The measurement this whole tier exists to move: the variable is named
/// something no keyword list contains, and the rule fires anyway.
#[test]
fn a_flow_gated_rule_fires_regardless_of_the_variable_name() {
    let ruleset = flow_ruleset();
    for name in ["response", "runbookText", "suggestion", "x", "config_path"] {
        let source = format!(
            "def handle(ticket):\n    \
             {name} = client.chat.completions.create(prompt=ticket).choices[0].message.content\n    \
             eval({name})\n"
        );
        assert!(fires(&ruleset, &source), "did not fire for `{name}`");
    }
}

/// And the other direction: a gate-shaped name over a value that did not come
/// from a model stays silent, which the name gate could never do.
#[test]
fn a_flow_gated_rule_stays_silent_on_a_value_from_elsewhere() {
    let ruleset = flow_ruleset();
    for name in ["response", "completion", "output"] {
        let source =
            format!("def handle(path):\n    {name} = json.load(open(path))\n    eval({name})\n");
        assert!(!fires(&ruleset, &source), "fired for `{name}`");
    }
}

#[test]
fn a_flow_gated_rule_stays_silent_on_a_literal() {
    assert!(!fires(
        &flow_ruleset(),
        "def handle():\n    eval(\"1 + 1\")\n"
    ));
}

/// A value whose origin the graph cannot prove is not a value the rule may
/// claim. Silence, not a guess.
#[test]
fn a_flow_gated_rule_stays_silent_when_the_origin_is_unprovable() {
    assert!(!fires(
        &flow_ruleset(),
        "def handle():\n    eval(mystery)\n"
    ));
}

/// `unguarded: true` means what it says: a model reply that has been checked
/// against a fixed set before reaching the sink is not reported.
#[test]
fn an_unguarded_flow_rule_skips_a_guarded_sink() {
    let source = "\
ALLOWED = (\"a\", \"b\")


def handle(ticket):
    plan = client.chat.completions.create(prompt=ticket).choices[0].message.content
    if plan not in ALLOWED:
        raise ValueError(plan)
    eval(plan)
";
    assert!(!fires(&flow_ruleset(), source));
}

/// Task 4's payoff, reachable from a rule: the sink is one call away.
#[test]
fn a_sink_flow_rule_reports_a_call_to_a_local_wrapper() {
    let yaml = r"
rules:
  - id: BAS-FLOW-002
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      variable: ARG
      source: model_output
      sink: code_execution
    description: Model output reaches eval().
    remediation: Do not execute model output.
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let source = "\
def run_snippet(code):
    exec(code)


def handle(ticket):
    plan = client.chat.completions.create(prompt=ticket).choices[0].message.content
    run_snippet(plan)
";
    let findings = scan_source(&ruleset, Path::new("app/handler.py"), source);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].location.line, 7);
}

/// A wrapper call carrying something the graph cannot attribute to a model is
/// not reported, so the extra reach does not cost precision.
#[test]
fn a_sink_flow_rule_ignores_a_wrapper_call_with_an_unproven_argument() {
    let yaml = r"
rules:
  - id: BAS-FLOW-002
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      source: model_output
      sink: code_execution
    description: Model output reaches eval().
    remediation: Do not execute model output.
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let source = "\
def run_snippet(code):
    exec(code)


def handle(path):
    run_snippet(open(path).read())
";
    assert!(scan_source(&ruleset, Path::new("app/handler.py"), source).is_empty());
}

/// Migration has to be possible one rule at a time, so the two gates must be
/// able to sit on the same rule. Both apply.
#[test]
fn flow_and_metavariable_matches_both_apply() {
    let yaml = r#"
rules:
  - id: BAS-FLOW-003
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    metavariable_matches:
      ARG: "(?i)plan"
    flow:
      source: model_output
    description: Model output reaches eval().
    remediation: Do not execute model output.
"#;
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let model = "plan = client.chat.completions.create(prompt=t).choices[0].message.content\n";

    // Both gates satisfied.
    assert!(fires(
        &ruleset,
        &format!("def handle(t):\n    {model}    eval(plan)\n")
    ));
    // Flow satisfied, name gate not.
    assert!(!fires(
        &ruleset,
        &format!(
            "def handle(t):\n    {}    eval(other)\n",
            model.replace("plan", "other")
        )
    ));
    // Name gate satisfied, flow not.
    assert!(!fires(
        &ruleset,
        "def handle(p):\n    plan = json.load(open(p))\n    eval(plan)\n"
    ));
}

/// A `flow:` gate on a metavariable the matching pattern never bound has no
/// evidence, and fails closed -- the same direction `metavariable_matches`
/// takes, and for the same reason.
#[test]
fn a_flow_gate_on_an_unbound_metavariable_fails_closed() {
    let yaml = r"
rules:
  - id: BAS-FLOW-004
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      variable: NEVER_BOUND
      source: model_output
    description: Model output reaches eval().
    remediation: Do not execute model output.
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let source = "def handle(t):\n    \
                  plan = client.chat.completions.create(prompt=t).choices[0].message.content\n    \
                  eval(plan)\n";
    assert!(scan_source(&ruleset, Path::new("app/handler.py"), source).is_empty());
}

/// The graph is Python-only. A `flow:` rule in a language it cannot analyse is
/// a load error, not a rule that quietly never matches.
#[test]
fn a_flow_rule_in_an_unsupported_language_fails_to_load() {
    let yaml = r"
rules:
  - id: BAS-FLOW-005
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: typescript
    any:
      - eval($ARG)
    flow:
      source: model_output
    description: Model output reaches eval().
    remediation: Do not execute model output.
";
    let error = RuleSet::from_yaml(yaml).unwrap_err();
    assert!(
        matches!(error, RuleError::FlowUnsupportedLanguage { .. }),
        "{error:?}"
    );
}

#[test]
fn a_flow_clause_accepts_a_list_of_sources() {
    let yaml = r"
rules:
  - id: BAS-FLOW-006
    title: Untrusted content executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      source: [model_output, file_read]
    description: Untrusted content reaches eval().
    remediation: Do not execute untrusted content.
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    assert!(fires(
        &ruleset,
        "def handle(p):\n    rows = json.load(open(p))\n    eval(rows)\n"
    ));
    assert!(!fires(
        &ruleset,
        "def handle(p):\n    rows = requests.get(p)\n    eval(rows)\n"
    ));
}

#[test]
fn a_flow_clause_with_an_empty_source_list_fails_to_load() {
    let yaml = r"
rules:
  - id: BAS-FLOW-007
    title: Untrusted content executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      source: []
    description: Untrusted content reaches eval().
    remediation: Do not execute untrusted content.
";
    let error = RuleSet::from_yaml(yaml).unwrap_err();
    assert!(
        matches!(error, RuleError::EmptyFlowSources { .. }),
        "{error:?}"
    );
}

#[test]
fn an_unknown_flow_field_is_a_load_error() {
    let yaml = r"
rules:
  - id: BAS-FLOW-008
    title: Untrusted content executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      source: model_output
      sanitiser: html_escape
    description: Untrusted content reaches eval().
    remediation: Do not execute untrusted content.
";
    assert!(matches!(
        RuleSet::from_yaml(yaml).unwrap_err(),
        RuleError::Yaml(_)
    ));
}

/// The cost guard in front of the wrapper walk must never hide a real
/// wrapper, whatever the file looks like around it. These are the shapes a
/// plain substring test, or a `name(` test, would get wrong.
#[test]
fn the_wrapper_cost_guard_does_not_hide_a_wrapper() {
    let yaml = r"
rules:
  - id: BAS-FLOW-009
    title: Model output executed as code
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - eval($ARG)
    flow:
      source: model_output
      sink: code_execution
    description: Model output reaches eval().
    remediation: Do not execute model output.
";
    let ruleset = RuleSet::from_yaml(yaml).unwrap();
    let call = "plan = client.chat.completions.create(prompt=t).choices[0].message.content\n    run_snippet(plan)\n";

    // Whitespace between the callee and its arguments.
    let spaced = format!("def run_snippet(code):\n    exec (code)\n\n\ndef handle(t):\n    {call}");
    assert!(fires(&ruleset, &spaced), "missed a spaced `exec (code)`");

    // The file's other mention of the name is inside a longer word.
    let shadowed = format!(
        "def execute_all(rows):\n    return rows\n\n\ndef run_snippet(code):\n    exec(code)\n\n\ndef handle(t):\n    {call}"
    );
    assert!(
        fires(&ruleset, &shadowed),
        "missed a wrapper next to `execute_all`"
    );
}
