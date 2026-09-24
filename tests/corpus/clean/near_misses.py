"""Every near-miss called out in the corpus spec, in one file, deliberately.

Each of these is a shape that a naive scanner (or a naive rule) gets wrong.
Bastyn's rules are precise enough that none of them should fire here. This
file, and this file alone, is what proves precision rather than asserting
it: `expect_none` on the whole file.
"""

import os
import shlex
import subprocess
import sys

from langchain.tools import tool

# eval() on a literal: the `none:` exclusion and the ARG regex both keep
# BAS-LLM10-001 quiet.
literal_result = eval("2 + 2")

# exec() on a literal with an explicit globals dict: the 2-arg `none:`
# exclusion added for BAS-LLM10-004's globals/locals widening must keep this
# quiet too, exactly as the single-arg literal case above does.
literal_exec_result = exec("2 + 2", {})

# Variable names that look secret-ish or token-ish by substring alone.
approx_tokens = 1500
token_count = 0
api_key_name = "OPENAI_API_KEY"
max_tokens = 500

# Correct credential handling: subscript / getenv, never a string literal.
openai_key = os.environ["OPENAI_API_KEY"]
anthropic_key = os.getenv("ANTHROPIC_API_KEY")

# Scaffolding for run_playbook_fully_quoted() below -- mirrored in
# tests/corpus/vulnerable/llm10_shell_injection_tool.py's
# run_playbook_partially_quoted() must-still-fire counterpart.
SAFE_PLAYBOOKS = ("deploy", "rollback")
SAFE_HOSTS = ("prod-1", "prod-2")
RUNNER_PATH = "/opt/opsbot/run_playbook.py"


def build_greeting(name: str) -> str:
    """An f-string with one interpolation, but neither side is
    prompt/instruction-shaped or user-input-shaped -- BAS-ZT4-001's two
    metavariable regexes both need to match, and neither does here."""
    greeting = f"Hello, {name}! How can OpsBot help today?"
    return greeting


# Self-concatenation, but the LHS/RHS variable name is not prompt-shaped --
# BAS-ZT4-002's SYS metavariable-match regex needs the same name on both
# sides of the `+` to also look like a system/prompt/instruction/persona/
# template variable, and `unrelated_var` doesn't.
unrelated_var = "base value"
unrelated_var = unrelated_var + "something"

# Self-concatenation onto a prompt-shaped variable, but the appended value's
# name isn't override-shaped -- BAS-ZT4-002's OVERRIDE metavariable-match
# regex needs "override", "overridden", "custom_instructions", or
# "force_prompt" in the name, and "user_note" doesn't qualify.
system_prompt = "You are OpsBot."
user_note = "please be concise"
system_prompt = system_prompt + user_note


def safe_query(cursor, incident_id: str) -> None:
    """A cursor.execute() call, but parameterized -- the query text is a
    literal, and the untrusted value is a bind parameter, never
    interpolated into the SQL string itself."""
    cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))


# A live-looking "Bearer <token>" that is actually unexpanded template
# syntax, substituted by the application's own templating layer at
# execution time -- no secret is embedded. Measured 2026-08-31 against a
# real DAST tool's request executor.
dast_auth_headers = {"Authorization": "Bearer {{env.DAST_AUTH_TOKEN}}"}

# A value scrubbed *before* being persisted, not a leaked one. Measured
# 2026-08-31 against a real repository-intake pipeline.
private_repo = {}
private_repo["accessToken"] = "[REDACTED]"


def log_spend(cur) -> None:
    """A fully static audit query split across more literal segments than
    BAS-LLM10-003's `none:` exclusion used to cover (previously capped at
    5), where one segment -- `completion_tokens`, a real LiteLLM_SpendLogs
    column -- happens to contain an ARG trigger word for a reason that has
    nothing to do with model output. The last segment switches to single
    quotes (to hold the double-quoted table name without escaping), which
    the original report's own shape also did -- the exclusion regex has to
    cover a mix of quote styles across adjacent segments, not just one
    style repeated. Measured 2026-08-31."""
    cur.execute(
        "SELECT model, "
        "prompt_tokens, "
        "completion_tokens, "
        "startTime, "
        "endTime "
        'FROM "LiteLLM_SpendLogs"'
    )


def literal_sql_through_local_variable(cursor) -> None:
    """BAS-LLM10-008's flow gate resolves this local variable back to a
    plain string literal, not a model call -- Origin::Literal is not
    source: model_output, so this must not fire even though the shape
    (assign to a local, then execute()) matches BAS-LLM10-008's
    structural pattern exactly."""
    sql = "SELECT id, title, body FROM kb_articles WHERE title = 'widget'"
    cursor.execute(sql)


def restart_known_service() -> None:
    """A shell command built entirely from fixed literals, never from a
    caller-supplied value -- BAS-LLM10-009's `none:` exclusion for a bare
    string-literal argument covers exactly this."""
    subprocess.run("systemctl restart opsbot-worker", shell=True)


def run_backup_script(target_dir: str) -> None:
    """The same kind of operation as the vulnerable fixture's ping tool,
    but built as an argv list with shell=False -- no shell ever parses
    target_dir, so there is nothing to inject into."""
    subprocess.run(["tar", "-czf", "backup.tar.gz", target_dir], shell=False)


def read_runbook_resolved(filename: str) -> str:
    """The same lookup as the vulnerable fixture, but the joined path is
    wrapped in os.path.realpath() before open() ever sees it -- the
    `none:` exclusion for open(os.path.realpath(...)) must keep this
    quiet even though the shape (os.path.join then open) is identical."""
    with open(os.path.realpath(os.path.join("/srv/opsbot/runbooks", filename))) as handle:
        return handle.read()


def jwt_algorithm_config() -> dict:
    """A string that merely mentions JWT/algorithm config, not a token
    shape itself -- BAS-ZT1-018's VALUE regex requires the exact
    eyJ.<payload>.<signature> three-segment structure, which this does
    not have."""
    return {"jwt_algorithm": "HS256"}


def storage_backend_setting() -> str:
    """BAS-ZT1-020: STORAGE_TYPE is read via os.environ.get with a
    default, but the KEY itself never matches the
    password/secret/token/api_key/... gate -- this is the exact false
    positive BAS-INFRA-006 produced against a real Docker Compose file
    (STORAGE_TYPE: local); the equivalent Python-source shape must not
    repeat it."""
    return os.environ.get("STORAGE_TYPE", "local")


def all_literal_join_is_not_flagged() -> str:
    """BAS-LLM10-012's ARG-shape gate's first alternative used to be a bare
    substring test for `os.path.join(` -- true even when every argument
    inside the call is a fixed string literal, contradicting the rule's own
    title ("...built by joining or interpolating a non-literal value"). The
    metavariable_not_matches exclusion added 2026-09-23 anchors the whole
    ARG text end-to-end and must keep this quiet."""
    with open(os.path.join("/etc/opsbot", "settings.ini")) as handle:
        return handle.read()


def restart_service_single_quoted() -> None:
    """The same fixed-literal shell command as restart_known_service()
    above, but single-quoted -- BAS-LLM10-009's `none:` list used to only
    spell the exclusion with double-quoted "$LIT", so this single-quoted
    form produced an incorrect critical finding until the 2026-09-23 fix
    added the '$LIT' variant for all twelve sink shapes. Kept as a sibling
    function rather than editing restart_known_service() itself, so that
    function's own regression proof (the double-quoted case) stays intact."""
    subprocess.run('systemctl restart opsbot-worker', shell=True)


def search_articles_parameterized(cursor, keyword: str) -> list:
    """The same search, parameterized correctly -- BAS-LLM10-017's ARG
    regex requires an f-string/concat/%-format shape, and a plain
    literal query string with a bind parameter has none of those."""
    return cursor.execute(
        "SELECT id, title FROM kb_articles WHERE title LIKE ?", (f"%{keyword}%",)
    ).fetchall()


@tool
def get_current_time() -> str:
    """Return the current server time in UTC.

    Always confirm with the user before changing the system clock.
    """
    return "12:00:00 UTC"


def restart_worker_via_variable() -> None:
    """Confirmed safe (LLM10): moved here from
    vulnerable/real_misses/shell_command_via_local_variable.py on
    2026-09-24, where it had been recorded as a known_false_positive --
    cmd is a fixed literal, but assigned one line above the
    subprocess.run() call rather than passed inline, so BAS-LLM10-009's
    same-node `none:` exclusion (which can only match alternate shapes of
    the matched node itself, never a prior sibling statement) could not
    see it and reported an incorrect critical finding. The Tier-2
    dataflow graph added 2026-09-24 resolves $ARG back through the local
    assignment to the literal it holds, so BAS-LLM10-009's new
    `exclude_if: closed_value` clause now proves cmd is closed and
    correctly suppresses this."""
    cmd = "systemctl restart opsbot-worker"
    subprocess.run(cmd, shell=True)


def restart_component(component: str) -> str:
    """near_miss (LLM10): the shell command is looked up in a dict of
    literal commands after a membership check that returns on failure --
    `command` can only ever be one of the dict's own literal values, so
    BAS-LLM10-009's exclude_if: closed_value clause suppresses this."""
    commands = {
        "worker": "systemctl restart opsbot-worker",
        "scheduler": "systemctl restart opsbot-scheduler",
    }
    if component not in commands:
        return f"unknown component: {component}"
    command = commands[component]
    return subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode()


def run_playbook_fully_quoted(playbook: str, target_host: str, extra_args: str) -> dict:
    """near_miss (LLM10): every interpolated value is wrapped in
    shlex.quote(), so the shell sees each one as a single argument no
    matter what it contains -- BAS-LLM10-009's exclude_if: shell_quoted
    clause suppresses this."""
    if playbook not in SAFE_PLAYBOOKS or target_host not in SAFE_HOSTS:
        return {"ok": False, "error": "not allowed"}
    command = (
        f"{shlex.quote(sys.executable)} {shlex.quote(RUNNER_PATH)} "
        f"{shlex.quote(playbook)} --target {shlex.quote(target_host)} {shlex.quote(extra_args)}"
    )
    completed = subprocess.run(command, shell=True, capture_output=True)
    return {"ok": completed.returncode == 0}


HERE = os.path.dirname(__file__)


def read_bundled_config() -> str:
    """Confirmed safe (LLM10): moved here from
    vulnerable/real_misses/path_traversal_safe_local_constant.py on
    2026-09-24, where it had been recorded as a known_false_positive --
    HERE is a bare identifier, a genuine non-literal by BAS-LLM10-012's own
    ARG-shape gate, but same-node regex matching (metavariable_matches /
    metavariable_not_matches) had no way to see how HERE was assigned, so
    it could not tell this apart from a real attacker-controlled variable.
    The Tier-2 dataflow graph added 2026-09-24 resolves HERE back through
    its module-level assignment and proves it is a constant_path: built
    only from __file__ (fixed at import time, never attacker-influenced)
    and a call to os.path.dirname, one of the whitelisted pure
    path-construction functions. BAS-LLM10-012's new
    exclude_if: constant_path clause now suppresses this correctly."""
    with open(os.path.join(HERE, "data.json")) as handle:
        return handle.read()
