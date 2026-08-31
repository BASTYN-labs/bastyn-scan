# Bastyn test corpus

This is the release gate. `expected.toml` (see `FORMAT.md` for the exact
contract) says what Bastyn must find, must not find, and is known not to
find yet. A harness — built separately — runs the scanner over this tree
and diffs its output against that manifest.

It exists because the previous fixtures (`tests/fixtures/`) were written by
the same process as the rules: every fixture line was chosen because a rule
already matched it. Measured against a real production agentic app, that
scanner found **1 of 5** real issues. This corpus is written the other way
around — from real failure modes first — so a category with no working
detection is recorded as a `known_gap`, not quietly left out.

> **This document's per-file tables and "Measured results" numbers were
> written against the original Python-only corpus** and have not been kept
> in lockstep with every addition since (TypeScript/JavaScript support, new
> `real_misses/` fixtures, rule renumbering). Where a specific line number,
> rule id, or count below might be stale, [`expected.toml`](expected.toml)
> and the corpus gate's own printed output
> (`cargo test -p bastyn-core --test corpus_gate -- --nocapture`) are the
> authoritative, always-current source — this file explains the *shape* of
> the corpus, not a live count of it.

## Structure

```
vulnerable/    one realistic instance of each detectable category, as a
               small coherent app ("OpsBot", an internal on-call assistant)
               split across files named after the category it demonstrates
vulnerable/real_misses/
               specific misses measured against code written without this
               scanner in mind — four against a production app, two more
               against a 65-repository calibration corpus — shapes the rules
               structurally could not match when each was recorded
vulnerable/NOT_DETECTABLE.md
               why LLM05, LLM07, ZT7, ZT8, ZT9 have no rule and never should
mcp/           MCP server configuration shapes: auth on streamable HTTP,
               filesystem scope on stdio servers, JSON/YAML/TOML parity
clean/         the same OpsBot app, done safely, plus every near-miss shape
               that is known to fool naive rules
```

## Running the gate

The automated gate (`crates/bastyn-core/tests/corpus_gate.rs`) scans
`tests/corpus/` exactly once, as a whole, and diffs the result against
`expected.toml`:

```
cargo test -p bastyn-core --test corpus_gate -- --nocapture
```

To reproduce the same scan manually instead, e.g. to eyeball the JSON:

```
$HOME/.cargo/bin/cargo build --release
./target/release/bastyn scan tests/corpus --offline --show-observations --format json
```

Two flags matter for reproducing the numbers exactly:

- **`--offline`** — `BAS-CVE-001` (the LLM04 dependency check) calls
  `OSV.dev` over the network. `--offline` makes zero network calls by
  design (`CveStatus::SkippedOffline`) and therefore finds nothing there
  regardless of what is pinned. This corpus's `requirements.txt` cases are
  recorded as `known_gap` for exactly this reason — see the `llm04_*`
  entries in `expected.toml`.
- **`--show-observations`** — without it, `kind = "observation"`
  findings (LLM06, LLM09, ZT5, ZT6) are filtered out of the default report
  entirely. The `expect` entries of `kind = "observation"` in
  `expected.toml` only appear with this flag set.

## What's in each file

### `vulnerable/`

| File | Line | Rule | Category | Kind | Why |
| --- | --- | --- | --- | --- | --- |
| `llm01_prompt_injection.py` | 26 | `BAS-ZT4-001` | LLM01 | expect | Untrusted wiki runbook text folded straight into agent instructions, no delimiter |
| `llm02_sensitive_info_disclosure.py` | 29 | — | LLM02 | **known_gap** | Full customer PII serialized into a model message, no redaction — no rule inspects message content |
| `llm03_excessive_agency.py` | 9 | `BAS-LLM03-001` | LLM03 | expect | `shutdown_server`, a destructive `@tool`, has no confirmation guard |
| `llm04_supply_chain/requirements.txt` | 12–15 | — | LLM04 | **known_gap** (×4) | `requests==2.19.1`, `cryptography==38.0.4`, `urllib3==1.26.14`, `certifi==2022.12.7` — real advisories, but `BAS-CVE-001` needs network `--offline` denies |
| `llm06_unbounded_consumption.py` | 19 | `BAS-LLM06-001` | LLM06 | expect (observation) | No `max_tokens` on the ticket-summarization call |
| `llm08_hidden_context_exposure.py` | 8 | `BAS-LLM08-001` | LLM08 | expect | A webhook signing secret embedded in the system prompt text |
| `llm09_vector_embedding_weaknesses.py` | 21 | — | LLM09 | **known_gap** (observation) | Vector search with no tenant/namespace filter, multi-tenant deployment |
| `llm10_eval_on_model_reply.py` | 40 / 50 / 59 | `BAS-LLM10-001/002/003` | LLM10 | expect (×3) | Model reply run through `eval()`, `subprocess.run(shell=True)`, and interpolated into SQL |
| `zt1_static_credentials.py` | 13 | `BAS-ZT1-001` | ZT1 | expect | Hardcoded `sk-`-shaped OpenAI key |
| `zt2_wildcard_tool_grant.py` | 29 | `BAS-ZT2-001` | ZT2 | expect | `allowed_tools="*"` in Python agent-construction code. Was a `known_gap` when this table was first written (only `BAS-MCP-003`, MCP-config-only, existed); `BAS-ZT2-001` closed it |
| `zt3_isolation/mcp.json` | 5 | `BAS-MCP-001` | ZT3 | expect | MCP server launched with root filesystem access |
| `zt4_no_delimiter.py` | 14 | `BAS-ZT4-001` | ZT4 | expect | Raw customer ticket text concatenated into persona instructions, no delimiter |
| `zt5_memory_and_context.py` | 15 | — | ZT5 | **known_gap** (observation) | Conversation memory keyed globally by ticket ID in a multi-tenant deployment |
| `zt6_observability_and_logging.py` | 22 | — | ZT6 | **known_gap** (observation) | A tool call that bypasses the audited path, no record of who/why |
| `tests/test_settings_fixture.py` | 19, 26 | `BAS-ZT1-002` | ZT1 | expect (observation ×2) | Throwaway DSNs in a test fixture. Still found, still critical, but reported as observations because the path says fixture — the shape behind 23 of 32 measured false positives |
| `latest/config.py` | 16 | `BAS-ZT1-002` | ZT1 | expect | The same credential in a directory that merely *contains* "test". Stays a defect: a substring check for "test" would silently demote real shipped configuration |

### `vulnerable/real_misses/` — misses measured against code nobody wrote for this scanner

| File | Line | Category | Why the current pattern misses it |
| --- | --- | --- | --- |
| `eval_compile_rce.py` | 37 | LLM10 | `eval(compile(model_reply))` — the taint is one variable hop from the reply; `BAS-LLM10-001`'s metavariable regex reads the literal text of the `eval()` argument (`compiled`), which contains no response/reply/... word |
| `overridable_system_prompt.py` | 19 | LLM01 | `f"System: {override}{context}\n\nUser: {user_input}"` — two interpolations; `BAS-ZT4-001`'s pattern requires exactly one, so it never structurally matches |
| `hardcoded_dict_secrets.py` | 15, 16 | ZT1 | A DB URL with an inline password and an admin token, both dict-literal values — `BAS-ZT1-001` only matches a direct `$VAR = "$SECRET"` assignment |
| `autonomous_action_from_model_text.py` | 29 | LLM03 | The model emits `EXECUTE_SIGNAL{...}`; the app `re.search()`es for it and dispatches the JSON with no confirmation — there is no `@tool` function at all, so `BAS-LLM03-001` cannot apply |
| `override_or_fallback_prompt.py` | 28 | LLM01 | `system_prompt = system_override or self._build_system_prompt(...)` — the caller's override replaces the instructions outright. The only caller-supplied prompt override in 65 real repositories, and not the f-string shape `BAS-ZT4-002` was written against |
| `eval_expression_tool.js` | 26, 34 | LLM10 | `eval(expression)` in an agent tool and `new Function(\`return ${resolved}\`)`. Every real JS/TS instance names the variable for what the value is, never `response`/`reply`, which is why the old name gate on `BAS-LLM10-005` never fired |

### `mcp/`

| File | Line | Rule | Category | Kind |
| --- | --- | --- | --- | --- |
| `streamable_http/mcp.json` | 4 | `BAS-MCP-002` | ZT1 | expect — `http://`, no auth header |
| `streamable_http/claude_desktop_config.json` | — | — | — | expect_none — same server, `https://` + `Authorization: Bearer` |
| `stdio_two/mcp.json` | 5 | `BAS-MCP-001` | ZT3 | expect — one server scoped to `/`, one to `/srv/opsbot/runbooks` (not flagged) |
| `stdio_two/mcp.yaml` | 6 | `BAS-MCP-001` | ZT3 | expect — same config, YAML |
| `stdio_two/mcp.toml` | 3 | `BAS-MCP-001` | ZT3 | expect — same config, TOML |

The two recognisable-name workarounds above are deliberate: `mcp::is_mcp_config`
(`crates/bastyn-core/src/mcp/mod.rs`) only recognises an exact filename
allowlist (`mcp.json`, `.mcp.json`, `mcp_config.json`,
`claude_desktop_config.json`, and the `.yaml`/`.toml` variants), regardless
of directory. A file literally named `streamable_http.json` is invisible to
the scanner — not inspected, not even reported as malformed. So each
scenario lives in its own descriptively-named *directory*, using two
different recognised filenames (`mcp.json` + `claude_desktop_config.json`)
to keep the good/bad pair in one place. This is a real, if minor, product
gap worth knowing about: a config file named anything outside that
allowlist is silently unscanned. See "Findings for the crates/ task" below.

### `clean/`

| File | Near-misses it must survive |
| --- | --- |
| `config.py` | `os.environ["OPENAI_API_KEY"]` (subscript, not a literal); `api_key_name = "OPENAI_API_KEY"` (secret-shaped name, boring value); `approx_tokens_per_word`, `token_count`, `max_tokens_per_call` |
| `prompts.py` | A prompt-named variable with no `sk-`-shaped content; untrusted input kept in a `ChatPromptTemplate` slot, never f-string-interpolated into instructions |
| `tools.py` | A destructive tool guarded by a decorator, and one guarded by `assert` — see the confirmed precision bug below |
| `agent.py` | `eval("2 + 2")` on a literal inside an `assert`; an LLM call with `max_tokens=500` |
| `app.py` | A public, unauthenticated `/chat` endpoint (correct for a public chatbot); no rate limiting (unprovable from a repo — it lives at the edge) |
| `near_misses.py` | All of the above near-misses collected in one file, plus a parameterized SQL query and a non-prompt-shaped f-string |
| `mcp/mcp.json` | A narrowly-scoped stdio server and an authenticated `https://` remote server with an explicit `allowedTools` list |

## Measured results

Reconciled by running the corpus gate, which scans the whole `tests/corpus/`
tree once and diffs the result against `expected.toml` — see the disclaimer
at the top of this file for how to reproduce the current numbers yourself
rather than trust the ones printed here:

```
cargo test -p bastyn-core --test corpus_gate -- --nocapture
```

As of this commit (21 `bastyn.yml` rules, 5 `BAS-MCP-*` checks, `BAS-CVE-001`,
and the infra/`ZT3` analysers, across Python, TypeScript, and JavaScript):

- **`expect`: 41/41 present.** Every finding a detector is designed to catch,
  on a realistic instance, is actually produced — a self-authored upper
  bound, not an independent recall measurement; see the main
  [`README.md`](../../README.md#measured-coverage) for why that distinction
  matters.
- **`known_gap`: 12 confirmed still uncaught (+8 reachable only with a
  network connection).** LLM02, LLM09, ZT5, and ZT6 have no detector at all
  today, in either language. The rest are specific misses — in `real_misses/`
  and in the JS/TS corpus — where a detector exists but the pattern
  structurally cannot reach the shape yet.
- **`known_false_positive`: 2.** Both in
  `real_misses/eval_guarded_by_local_check.py`: `BAS-LLM10-004` flags an
  `eval()` call that is provably safe by reading a sibling statement (a
  prior assignment or guard clause) the rule engine's `none:`/`inside:`
  cannot reach. This is a precision debt, tracked separately from
  `known_gap` — see `corpus_gate.rs`'s `MAX_KNOWN_FALSE_POSITIVES` for why
  the two are not counted together.
- **`expect_none`: 16/16 files clean.** The `clean/tools.py` `assert`-guard
  false positive this section used to describe as confirmed and open (an
  `assert`-guarded destructive tool tripping `BAS-LLM03-001`) has since been
  fixed: `BAS-LLM03-001`'s `none:` exclusion now recognises the `assert`
  guard shape alongside `if not X: raise/return` (see `bastyn.yml`'s
  `BAS-LLM03-001` comment). If a future change reopens a precision bug in
  `clean/`, record it here the way this one used to be recorded — not by
  deleting the fixture.

## Findings for the `crates/` task

Written when this corpus was first measured; kept as a record of what was
outstanding then, with status notes added rather than deleted.

1. ~~**Confirmed precision bug**: `BAS-LLM03-001`'s guard-shape `none:`
   exclusion does not recognise an `assert`-based guard, only
   `if not X: raise/return`. Reproduces at `clean/tools.py:35`.~~ **Fixed.**
   `BAS-LLM03-001`'s `none:` now includes the `assert`-guard shape; see
   "Measured results" above.
2. **MCP config filename allowlist is exact-match only**: any MCP config
   not named exactly `mcp.json` / `.mcp.json` / `mcp_config.json` /
   `claude_desktop_config.json` (or their `.yaml`/`.toml` twins) is
   invisible to `mcp::is_mcp_config`, in any directory, with no
   fallback and no "unrecognised config" signal. Worth a decision on
   whether that allowlist should widen (e.g. any `*mcp*.{json,yaml,toml}`)
   or stay exact. Still true as of this commit.
3. ~~Nine categories (LLM02, LLM04-under-`--offline`, LLM09, ZT2, ZT5, ZT6,
   plus the four `real_misses/`) have no working detection today.~~
   **Partially closed.** ZT2 and LLM04 (via `BAS-CVE-001`, still
   network-gated under `--offline`) now have detectors. LLM02, LLM09, ZT5,
   and ZT6 still have none, in either language — see "Measured results"
   above and the main [`README.md`](../../README.md#measured-coverage) for
   the current count. All are tracked as `known_gap`, ready to become
   `expect` the moment a detector catches them.

## Everything not covered

`vulnerable/NOT_DETECTABLE.md` explains, per category, why LLM05, LLM07,
ZT7, ZT8, and ZT9 have no code file and never should: each is a property of
a process, a dataset, or a judgment call over time, not of a source-code
shape a static rule could anchor to.
