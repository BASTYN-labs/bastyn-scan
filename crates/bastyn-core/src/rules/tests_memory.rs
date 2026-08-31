//! Unit tests for the conversation-memory / session-isolation / agent-loop
//! rules shipped in `rules/memory.yml`.
//!
//! Every test loads the real embedded rule set (`RuleSet::embedded()`), not
//! an inline copy of the YAML, so these tests fail the moment the shipped
//! rule drifts from what is asserted here.

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::path::Path;

use super::*;

fn embedded() -> RuleSet {
    RuleSet::embedded().unwrap()
}

/// Findings for one rule id only, from scanning `source` as `path`.
fn findings_for(rule_id: &str, path: &str, source: &str) -> Vec<crate::finding::Finding> {
    let ruleset = embedded();
    scan_source(&ruleset, Path::new(path), source)
        .into_iter()
        .filter(|f| f.rule_id == rule_id)
        .collect()
}

// ---------------------------------------------------------------------
// BAS-ZT5-001 -- module-level chat history mutated inside a handler.
// ---------------------------------------------------------------------

#[test]
fn zt5_001_fires_on_module_scope_history_in_a_fastapi_handler() {
    let source = r#"
from fastapi import FastAPI
app = FastAPI()

chat_history = []

@app.post("/chat")
def handler(msg: str):
    chat_history.append(msg)
    return chat_history
"#;
    let findings = findings_for("BAS-ZT5-001", "app.py", source);
    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].kind, crate::finding::Kind::Observation);
}

#[test]
fn zt5_001_does_not_fire_on_a_per_request_local_list() {
    let source = r#"
from fastapi import FastAPI
app = FastAPI()

@app.post("/chat")
def handler(msg: str):
    chat_history = []
    chat_history.append(msg)
    return chat_history
"#;
    let findings = findings_for("BAS-ZT5-001", "app.py", source);
    assert!(findings.is_empty(), "findings: {findings:?}");
}

#[test]
fn zt5_001_does_not_fire_without_a_route_decorator() {
    let source = r"
chat_history = []

def handler(msg: str):
    chat_history.append(msg)
    return chat_history
";
    let findings = findings_for("BAS-ZT5-001", "cli.py", source);
    assert!(findings.is_empty(), "findings: {findings:?}");
}

#[test]
fn zt5_001_does_not_fire_on_a_session_keyed_store() {
    let source = r#"
from fastapi import FastAPI
app = FastAPI()

store = {}

@app.post("/chat")
def handler(session_id: str, msg: str):
    store.setdefault(session_id, []).append(msg)
"#;
    let findings = findings_for("BAS-ZT5-001", "app.py", source);
    assert!(findings.is_empty(), "findings: {findings:?}");
}

#[test]
fn zt5_001_does_not_fire_on_a_per_request_local_list_with_nothing_after_append() {
    let source = r#"
from fastapi import FastAPI
app = FastAPI()

@app.post("/chat")
def handler(msg: str):
    chat_history = []
    chat_history.append(msg)
"#;
    let findings = findings_for("BAS-ZT5-001", "app.py", source);
    assert!(findings.is_empty(), "findings: {findings:?}");
}

#[test]
fn zt5_001_does_not_fire_on_an_unrelated_accumulator_name() {
    let source = r#"
from fastapi import FastAPI
app = FastAPI()

@app.post("/items")
def handler():
    results = []
    results.append(1)
    return results
"#;
    let findings = findings_for("BAS-ZT5-001", "app.py", source);
    assert!(findings.is_empty(), "findings: {findings:?}");
}

// ---------------------------------------------------------------------
// BAS-ZT5-003 -- singleton conversation memory referenced in a handler.
// ---------------------------------------------------------------------

#[test]
fn zt5_003_fires_on_shared_memory_used_without_local_construction() {
    let source = r#"
from fastapi import FastAPI
from langchain.chains import ConversationChain

app = FastAPI()
memory = ConversationBufferMemory()
conversation = ConversationChain(llm=llm, memory=memory)

@app.post("/chat")
def handler(msg: str):
    return conversation.predict(input=msg)
"#;
    let findings = findings_for("BAS-ZT5-003", "app.py", source);
    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn zt5_003_does_not_fire_when_the_handler_builds_its_own_memory() {
    let source = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/chat")
def handler(msg: str):
    memory = ConversationBufferMemory()
    memory.save_context({"input": msg}, {"output": "ok"})
    return "ok"
"#;
    let findings = findings_for("BAS-ZT5-003", "app.py", source);
    assert!(findings.is_empty(), "findings: {findings:?}");
}

#[test]
fn zt5_003_does_not_fire_without_a_route_decorator() {
    let source = r"
memory = ConversationBufferMemory()
conversation = ConversationChain(llm=llm, memory=memory)

def handler(msg: str):
    return conversation.predict(input=msg)
";
    let findings = findings_for("BAS-ZT5-003", "cli.py", source);
    assert!(findings.is_empty(), "findings: {findings:?}");
}

// ---------------------------------------------------------------------
// BAS-ZT5-004 -- LangGraph invoked with a hardcoded literal thread_id.
// ---------------------------------------------------------------------

#[test]
fn zt5_004_fires_on_a_literal_thread_id() {
    let source = r#"
result = graph.invoke({"messages": [m]}, config={"configurable": {"thread_id": "1"}})
"#;
    let findings = findings_for("BAS-ZT5-004", "app.py", source);
    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn zt5_004_fires_on_a_literal_thread_id_single_quoted() {
    let source = r"
result = graph.invoke({'messages': [m]}, config={'configurable': {'thread_id': '1'}})
";
    let findings = findings_for("BAS-ZT5-004", "app.py", source);
    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn zt5_004_fires_on_a_positional_literal_thread_id() {
    // Real shape found in the calibration corpus: the config dict is
    // passed positionally, with no `config=` keyword.
    let source = "response = await graph.ainvoke(initial_state, {\"configurable\": {\"thread_id\": \"1\"}})\n";
    let findings = findings_for("BAS-ZT5-004", "app.py", source);
    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn zt5_004_does_not_fire_when_thread_id_comes_from_the_request() {
    let source = r#"
result = graph.invoke({"messages": [m]}, config={"configurable": {"thread_id": session_id}})
"#;
    let findings = findings_for("BAS-ZT5-004", "app.py", source);
    assert!(findings.is_empty(), "findings: {findings:?}");
}

// ---------------------------------------------------------------------
// BAS-ZT2-010 -- ShellToolMiddleware with no execution policy.
// ---------------------------------------------------------------------

#[test]
fn zt2_010_fires_on_default_construction() {
    let source = "mw = ShellToolMiddleware()\n";
    let findings = findings_for("BAS-ZT2-010", "agent.py", source);
    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn zt2_010_does_not_fire_when_a_policy_is_passed() {
    let source = "mw = ShellToolMiddleware(execution_policy=SandboxExecutionPolicy())\n";
    let findings = findings_for("BAS-ZT2-010", "agent.py", source);
    assert!(findings.is_empty(), "findings: {findings:?}");
}

// ---------------------------------------------------------------------
// BAS-LLM03-030 -- destructive MCP tool with no confirmation guard.
// ---------------------------------------------------------------------

#[test]
fn llm03_030_fires_on_destructive_tool_with_no_guard() {
    let source = r#"
@mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
def delete_record(record_id: str):
    db.delete(record_id)
    return "deleted"
"#;
    let findings = findings_for("BAS-LLM03-030", "server.py", source);
    assert_eq!(findings.len(), 1, "findings: {findings:?}");
    assert_eq!(findings[0].kind, crate::finding::Kind::Defect);
}

#[test]
fn llm03_030_fires_on_dict_annotation_form() {
    let source = r#"
@mcp.tool(annotations={"destructiveHint": True})
def delete_record(record_id: str):
    db.delete(record_id)
    return "deleted"
"#;
    let findings = findings_for("BAS-LLM03-030", "server.py", source);
    assert_eq!(findings.len(), 1, "findings: {findings:?}");
}

#[test]
fn llm03_030_does_not_fire_with_a_guard_clause() {
    let source = r#"
@mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
def delete_record(record_id: str, confirmed: bool):
    if not confirmed:
        raise ValueError("confirmation required")
    db.delete(record_id)
    return "deleted"
"#;
    let findings = findings_for("BAS-LLM03-030", "server.py", source);
    assert!(findings.is_empty(), "findings: {findings:?}");
}

#[test]
fn llm03_030_does_not_fire_without_the_destructive_annotation() {
    let source = r#"
@mcp.tool()
def delete_record(record_id: str):
    db.delete(record_id)
    return "deleted"
"#;
    let findings = findings_for("BAS-LLM03-030", "server.py", source);
    assert!(findings.is_empty(), "findings: {findings:?}");
}
