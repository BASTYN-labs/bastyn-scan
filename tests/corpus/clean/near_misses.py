"""Every near-miss called out in the corpus spec, in one file, deliberately.

Each of these is a shape that a naive scanner (or a naive rule) gets wrong.
Bastyn's rules are precise enough that none of them should fire here. This
file, and this file alone, is what proves precision rather than asserting
it: `expect_none` on the whole file.
"""

import os
import subprocess

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
