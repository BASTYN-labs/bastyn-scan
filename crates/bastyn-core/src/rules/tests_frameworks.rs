//! Unit tests for the agent-framework rules in `rules/frameworks.yml`
//! (`BAS-LLM03-01x` / `BAS-LLM10-01x`).
//!
//! Each rule gets its own single-rule YAML fragment (mirroring the style of
//! `tests.rs`) rather than loading the real `frameworks.yml`, so a test
//! failure points at exactly one rule. The YAML fragments here are kept in
//! sync by hand with `rules/frameworks.yml` -- when a rule's patterns change
//! there, the matching fragment here must change too.

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::path::Path;

use super::*;
use crate::finding::Kind;

fn ruleset(yaml: &str) -> RuleSet {
    RuleSet::from_yaml(yaml).unwrap()
}

fn findings_for(yaml: &str, path: &str, source: &str) -> Vec<crate::finding::Finding> {
    let rs = ruleset(yaml);
    scan_source(&rs, Path::new(path), source)
}

// ---------------------------------------------------------------------
// BAS-LLM03-010 -- allow_dangerous_code=True on a LangChain data-agent
// factory.
// ---------------------------------------------------------------------

const LLM03_010_YAML: &str = r"
rules:
  - id: BAS-LLM03-010
    title: allow_dangerous_code=True on a LangChain data-agent factory
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM03]
    language: python
    any:
      - create_pandas_dataframe_agent(allow_dangerous_code=True)
      - create_pandas_dataframe_agent(allow_dangerous_code=True, $$$B)
      - create_pandas_dataframe_agent($$$A, allow_dangerous_code=True)
      - create_pandas_dataframe_agent($$$A, allow_dangerous_code=True, $$$B)
      - create_csv_agent(allow_dangerous_code=True)
      - create_csv_agent(allow_dangerous_code=True, $$$B)
      - create_csv_agent($$$A, allow_dangerous_code=True)
      - create_csv_agent($$$A, allow_dangerous_code=True, $$$B)
    description: test
    remediation: test
";

#[test]
fn allow_dangerous_code_true_is_flagged() {
    let findings = findings_for(
        LLM03_010_YAML,
        "agent.py",
        "agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-LLM03-010");
}

#[test]
fn allow_dangerous_code_true_leading_kwarg_is_flagged() {
    let findings = findings_for(
        LLM03_010_YAML,
        "agent.py",
        "agent = create_csv_agent(allow_dangerous_code=True, llm=llm, path=path)\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn allow_dangerous_code_absent_is_not_flagged() {
    let findings = findings_for(
        LLM03_010_YAML,
        "agent.py",
        "agent = create_pandas_dataframe_agent(llm, df)\n",
    );

    assert!(findings.is_empty(), "findings: {findings:?}");
}

#[test]
fn allow_dangerous_code_false_is_not_flagged() {
    let findings = findings_for(
        LLM03_010_YAML,
        "agent.py",
        "agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=False)\n",
    );

    assert!(findings.is_empty(), "findings: {findings:?}");
}

// ---------------------------------------------------------------------
// BAS-LLM03-011 -- allow_dangerous_deserialization=True on a vectorstore
// loader.
// ---------------------------------------------------------------------

const LLM03_011_YAML: &str = r"
rules:
  - id: BAS-LLM03-011
    title: allow_dangerous_deserialization=True on a vectorstore loader
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM03]
    language: python
    any:
      - $STORE.load_local(allow_dangerous_deserialization=True)
      - $STORE.load_local(allow_dangerous_deserialization=True, $$$B)
      - $STORE.load_local($$$A, allow_dangerous_deserialization=True)
      - $STORE.load_local($$$A, allow_dangerous_deserialization=True, $$$B)
    description: test
    remediation: test
";

#[test]
fn allow_dangerous_deserialization_true_is_flagged() {
    let findings = findings_for(
        LLM03_011_YAML,
        "store.py",
        "db = FAISS.load_local(path, embeddings, allow_dangerous_deserialization=True)\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-LLM03-011");
}

#[test]
fn allow_dangerous_deserialization_absent_is_not_flagged() {
    let findings = findings_for(
        LLM03_011_YAML,
        "store.py",
        "db = FAISS.load_local(path, embeddings)\n",
    );

    assert!(findings.is_empty(), "findings: {findings:?}");
}

// ---------------------------------------------------------------------
// BAS-LLM03-012 -- allow_dangerous_requests=True on a LangChain
// graph/HTTP tool.
// ---------------------------------------------------------------------

const LLM03_012_YAML: &str = r"
rules:
  - id: BAS-LLM03-012
    title: allow_dangerous_requests=True on a LangChain graph/HTTP tool
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM03]
    language: python
    any:
      - GraphCypherQAChain.from_llm(allow_dangerous_requests=True)
      - GraphCypherQAChain.from_llm(allow_dangerous_requests=True, $$$B)
      - GraphCypherQAChain.from_llm($$$A, allow_dangerous_requests=True)
      - GraphCypherQAChain.from_llm($$$A, allow_dangerous_requests=True, $$$B)
      - RequestsToolkit(allow_dangerous_requests=True)
      - RequestsToolkit(allow_dangerous_requests=True, $$$B)
      - RequestsToolkit($$$A, allow_dangerous_requests=True)
      - RequestsToolkit($$$A, allow_dangerous_requests=True, $$$B)
      - RequestsGetTool(allow_dangerous_requests=True)
      - RequestsGetTool(allow_dangerous_requests=True, $$$B)
      - RequestsGetTool($$$A, allow_dangerous_requests=True)
      - RequestsGetTool($$$A, allow_dangerous_requests=True, $$$B)
      - RequestsPostTool(allow_dangerous_requests=True)
      - RequestsPostTool(allow_dangerous_requests=True, $$$B)
      - RequestsPostTool($$$A, allow_dangerous_requests=True)
      - RequestsPostTool($$$A, allow_dangerous_requests=True, $$$B)
    description: test
    remediation: test
";

#[test]
fn allow_dangerous_requests_true_on_graph_chain_is_flagged() {
    let findings = findings_for(
        LLM03_012_YAML,
        "graph.py",
        "chain = GraphCypherQAChain.from_llm(graph=graph, llm=llm, allow_dangerous_requests=True)\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-LLM03-012");
}

#[test]
fn allow_dangerous_requests_true_on_requests_toolkit_is_flagged() {
    let findings = findings_for(
        LLM03_012_YAML,
        "graph.py",
        "toolkit = RequestsToolkit(requests_wrapper=w, allow_dangerous_requests=True)\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn allow_dangerous_requests_absent_is_not_flagged() {
    let findings = findings_for(
        LLM03_012_YAML,
        "graph.py",
        "chain = GraphCypherQAChain.from_llm(graph=graph, llm=llm)\n",
    );

    assert!(findings.is_empty(), "findings: {findings:?}");
}

// ---------------------------------------------------------------------
// BAS-LLM10-010 -- torch.load without weights_only=True.
// ---------------------------------------------------------------------

const LLM10_010_YAML: &str = r"
rules:
  - id: BAS-LLM10-010
    title: torch.load without weights_only=True
    kind: defect
    severity: high
    confidence: medium
    categories: [LLM10]
    language: python
    any:
      - torch.load($$$A)
    none:
      - torch.load(weights_only=True)
      - torch.load(weights_only=True, $$$B)
      - torch.load($$$A, weights_only=True)
      - torch.load($$$A, weights_only=True, $$$B)
    description: test
    remediation: test
";

#[test]
fn torch_load_without_weights_only_is_flagged() {
    let findings = findings_for(
        LLM10_010_YAML,
        "model.py",
        "model = torch.load(\"checkpoint.pth\")\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-LLM10-010");
}

#[test]
fn torch_load_with_weights_only_true_is_not_flagged() {
    let findings = findings_for(
        LLM10_010_YAML,
        "model.py",
        "model = torch.load(path, weights_only=True)\n",
    );

    assert!(findings.is_empty(), "findings: {findings:?}");
}

#[test]
fn torch_load_with_weights_only_true_leading_is_not_flagged() {
    let findings = findings_for(
        LLM10_010_YAML,
        "model.py",
        "model = torch.load(weights_only=True, f=path)\n",
    );

    assert!(findings.is_empty(), "findings: {findings:?}");
}

// ---------------------------------------------------------------------
// BAS-LLM10-011 -- yaml.load without a safe loader.
// ---------------------------------------------------------------------

const LLM10_011_YAML: &str = r#"
rules:
  - id: BAS-LLM10-011
    title: yaml.load without a safe loader
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - yaml.load($$$A, Loader=yaml.UnsafeLoader, $$$B)
      - yaml.load($$$A, Loader=yaml.UnsafeLoader)
      - yaml.load(Loader=yaml.UnsafeLoader, $$$B)
      - yaml.load(Loader=yaml.UnsafeLoader)
      - yaml.load($$$A, Loader=UnsafeLoader, $$$B)
      - yaml.load($$$A, Loader=UnsafeLoader)
      - yaml.load(Loader=UnsafeLoader, $$$B)
      - yaml.load(Loader=UnsafeLoader)
      - yaml.load($$$A, Loader=$L, $$$B)
      - yaml.load($$$A, Loader=$L)
      - yaml.load(Loader=$L, $$$B)
      - yaml.load(Loader=$L)
      - yaml.load($$$A)
    metavariable_not_matches:
      L: "(?i)safe"
    description: test
    remediation: test
"#;

#[test]
fn yaml_load_without_safe_loader_is_flagged() {
    let findings = findings_for(
        LLM10_011_YAML,
        "config.py",
        "config = yaml.load(open(\"agent_config.yaml\"))\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-LLM10-011");
}

#[test]
fn yaml_load_with_explicit_unsafe_loader_is_flagged() {
    let findings = findings_for(
        LLM10_011_YAML,
        "config.py",
        "config = yaml.load(f, Loader=yaml.UnsafeLoader)\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn yaml_load_with_safe_loader_is_not_flagged() {
    let findings = findings_for(
        LLM10_011_YAML,
        "config.py",
        "config = yaml.load(f, Loader=yaml.SafeLoader)\n",
    );

    assert!(findings.is_empty(), "findings: {findings:?}");
}

#[test]
fn yaml_safe_load_is_not_flagged() {
    let findings = findings_for(LLM10_011_YAML, "config.py", "config = yaml.safe_load(f)\n");

    assert!(findings.is_empty(), "findings: {findings:?}");
}

/// Regression test for a real false positive measured on the calibration
/// corpus 2026-08-28: a custom `Loader` subclass whose
/// own name says it is safe (`YAMLNoDateSafeLoader(yaml.SafeLoader)`) must
/// not be flagged, even though its name is neither `SafeLoader` nor
/// `yaml.SafeLoader` verbatim.
#[test]
fn yaml_load_with_custom_safe_named_loader_is_not_flagged() {
    let findings = findings_for(
        LLM10_011_YAML,
        "config.py",
        "spec = yaml.load(spec, Loader=YAMLNoDateSafeLoader)\n",
    );

    assert!(findings.is_empty(), "findings: {findings:?}");
}

#[test]
fn yaml_load_with_custom_unsafe_named_loader_is_flagged() {
    let findings = findings_for(
        LLM10_011_YAML,
        "config.py",
        "spec = yaml.load(spec, Loader=CustomFullLoader)\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

// No BAS-LLM10-012 here: the "code-execution tool shells out via
// subprocess/child_process as its sandbox" draft was measured against the
// calibration corpus and dropped rather than shipped -- see the DROPPED
// comment in rules/frameworks.yml for the full reasoning (zero corpus
// matches to adjudicate, plus a real structural ambiguity the `none:`
// exclusion cannot close). Nothing to test for a rule that does not exist.

// ---------------------------------------------------------------------
// BAS-LLM10-013 -- import/use of LLMMathChain / LLMSymbolicMathChain.
// ---------------------------------------------------------------------

const LLM10_013_YAML: &str = r#"
rules:
  - id: BAS-LLM10-013
    title: Import/use of LLMMathChain or LLMSymbolicMathChain
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - "from $MOD import LLMMathChain"
      - "from $MOD import $$$A, LLMMathChain"
      - "from $MOD import LLMMathChain, $$$B"
      - "from $MOD import $$$A, LLMMathChain, $$$B"
      - "from $MOD import LLMSymbolicMathChain"
      - "from $MOD import $$$A, LLMSymbolicMathChain"
      - "from $MOD import LLMSymbolicMathChain, $$$B"
      - "from $MOD import $$$A, LLMSymbolicMathChain, $$$B"
      - LLMMathChain.from_llm($$$A)
      - LLMMathChain($$$A)
      - LLMSymbolicMathChain.from_llm($$$A)
      - LLMSymbolicMathChain($$$A)
    description: test
    remediation: test
"#;

#[test]
fn llm_math_chain_import_is_flagged() {
    let findings = findings_for(
        LLM10_013_YAML,
        "math_agent.py",
        "from langchain.chains import LLMMathChain\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-LLM10-013");
}

#[test]
fn llm_math_chain_instantiation_is_flagged() {
    let findings = findings_for(
        LLM10_013_YAML,
        "math_agent.py",
        "chain = LLMMathChain.from_llm(llm)\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn llm_symbolic_math_chain_import_is_flagged() {
    let findings = findings_for(
        LLM10_013_YAML,
        "math_agent.py",
        "from langchain_experimental.chains import LLMSymbolicMathChain\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn unrelated_chain_import_is_not_flagged() {
    let findings = findings_for(
        LLM10_013_YAML,
        "math_agent.py",
        "from langchain.chains import LLMChain\n",
    );

    assert!(findings.is_empty(), "findings: {findings:?}");
}

// ---------------------------------------------------------------------
// BAS-LLM10-014 -- import/use of PandasQueryEngine / PandasAstREPLTool.
// ---------------------------------------------------------------------

const LLM10_014_YAML: &str = r#"
rules:
  - id: BAS-LLM10-014
    title: Import/use of PandasQueryEngine or PandasAstREPLTool
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - "from $MOD import PandasQueryEngine"
      - "from $MOD import $$$A, PandasQueryEngine"
      - "from $MOD import PandasQueryEngine, $$$B"
      - "from $MOD import $$$A, PandasQueryEngine, $$$B"
      - "from $MOD import PandasAstREPLTool"
      - "from $MOD import $$$A, PandasAstREPLTool"
      - "from $MOD import PandasAstREPLTool, $$$B"
      - "from $MOD import $$$A, PandasAstREPLTool, $$$B"
      - PandasQueryEngine($$$A)
      - PandasAstREPLTool($$$A)
    description: test
    remediation: test
"#;

#[test]
fn pandas_query_engine_import_is_flagged() {
    let findings = findings_for(
        LLM10_014_YAML,
        "analysis.py",
        "from llama_index.experimental.query_engine import PandasQueryEngine\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-LLM10-014");
}

#[test]
fn pandas_query_engine_instantiation_is_flagged() {
    let findings = findings_for(
        LLM10_014_YAML,
        "analysis.py",
        "engine = PandasQueryEngine(df=df)\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn unrelated_pandas_import_is_not_flagged() {
    let findings = findings_for(LLM10_014_YAML, "analysis.py", "import pandas as pd\n");

    assert!(findings.is_empty(), "findings: {findings:?}");
}

// ---------------------------------------------------------------------
// BAS-LLM10-015 -- import/use of PALChain.
// ---------------------------------------------------------------------

const LLM10_015_YAML: &str = r#"
rules:
  - id: BAS-LLM10-015
    title: Import/use of PALChain
    kind: defect
    severity: critical
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - "from $MOD import PALChain"
      - "from $MOD import $$$A, PALChain"
      - "from $MOD import PALChain, $$$B"
      - "from $MOD import $$$A, PALChain, $$$B"
      - PALChain.from_math_prompt($$$A)
      - PALChain.from_colored_object_prompt($$$A)
      - PALChain($$$A)
    description: test
    remediation: test
"#;

#[test]
fn pal_chain_import_is_flagged() {
    let findings = findings_for(
        LLM10_015_YAML,
        "pal_agent.py",
        "from langchain_experimental.pal_chain import PALChain\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-LLM10-015");
}

#[test]
fn pal_chain_instantiation_is_flagged() {
    let findings = findings_for(
        LLM10_015_YAML,
        "pal_agent.py",
        "chain = PALChain.from_math_prompt(llm=llm)\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn unrelated_chain_is_not_flagged_by_pal_rule() {
    let findings = findings_for(
        LLM10_015_YAML,
        "pal_agent.py",
        "from langchain.chains import LLMChain\n",
    );

    assert!(findings.is_empty(), "findings: {findings:?}");
}

// ---------------------------------------------------------------------
// BAS-LLM10-016 -- LangGraph checkpoint/cache serializer with
// pickle_fallback=True.
// ---------------------------------------------------------------------

const LLM10_016_YAML: &str = r"
rules:
  - id: BAS-LLM10-016
    title: LangGraph checkpoint/cache serializer with pickle_fallback=True
    kind: defect
    severity: high
    confidence: high
    categories: [LLM10]
    language: python
    any:
      - JsonPlusSerializer(pickle_fallback=True)
      - JsonPlusSerializer(pickle_fallback=True, $$$B)
      - JsonPlusSerializer($$$A, pickle_fallback=True)
      - JsonPlusSerializer($$$A, pickle_fallback=True, $$$B)
    description: test
    remediation: test
";

#[test]
fn pickle_fallback_true_is_flagged() {
    let findings = findings_for(
        LLM10_016_YAML,
        "checkpoint.py",
        "serde = JsonPlusSerializer(pickle_fallback=True)\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].rule_id, "BAS-LLM10-016");
}

#[test]
fn pickle_fallback_false_is_not_flagged() {
    let findings = findings_for(
        LLM10_016_YAML,
        "checkpoint.py",
        "serde = JsonPlusSerializer(pickle_fallback=False)\n",
    );

    assert!(findings.is_empty(), "findings: {findings:?}");
}

#[test]
fn json_plus_serializer_default_is_not_flagged() {
    let findings = findings_for(
        LLM10_016_YAML,
        "checkpoint.py",
        "serde = JsonPlusSerializer()\n",
    );

    assert!(findings.is_empty(), "findings: {findings:?}");
}

/// Sanity check that `in_test_paths` defaults hold for these rules too --
/// none of them declare `in_test_paths: report`, so a match inside a test
/// path is downgraded to an observation, same as the rest of the corpus.
#[test]
fn allow_dangerous_code_in_test_path_is_downgraded() {
    let findings = findings_for(
        LLM03_010_YAML,
        "tests/test_agent.py",
        "agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)\n",
    );

    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].kind, Kind::Observation);
}
