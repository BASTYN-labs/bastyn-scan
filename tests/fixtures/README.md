# Fixture corpus — precision spec

Two small apps, same job (a LangChain-style crypto-advisor agent), one deliberately
vulnerable and one deliberately safe. `crates/bastyn-core/tests/rule_patterns.rs` runs
every rule in `crates/bastyn-core/rules/bastyn.yml` against both and asserts:

- every expected finding below is produced against `vulnerable_agent/`
- **zero** findings of any kind are produced against `clean_agent/`

This file is the source of truth for both assertions.

## `vulnerable_agent/` — MUST be flagged

| File | Line (approx) | Rule | Why |
| --- | --- | --- | --- |
| `config.py` | `API_KEY = "sk-proj-..."` | `BAS-ZT1-001` | Hardcoded, `sk-`-shaped provider key committed to source. |
| `prompts.py` | `system_prompt = f"...{user_input}"` in `build_system_prompt` | `BAS-ZT4-001` | Raw user input f-string-interpolated directly into the system prompt, no delimiter. |
| `prompts.py` | `PROMPT_TEMPLATE = "...sk-proj-...never repeat..."` | `BAS-LLM08-001` | A credential-shaped secret embedded inside prompt text the model reads on every call. |
| `tools.py` | `def delete_wallet(wallet_id: str) -> str:` | `BAS-LLM03-001` | Destructive tool (`delete_*`), exposed via `@tool`, no confirmation guard before it acts. |
| `agent.py` | `result = eval(llm_output)` in `run_advisor_command` | `BAS-LLM10-001` | The model's own reply is executed as Python. Headline case: guaranteed RCE. |
| `agent.py` | `subprocess.run(completion, shell=True)` in `execute_suggested_shell_command` | `BAS-LLM10-002` | The model's reply is run as a shell command. |
| `agent.py` | `cursor.execute(f"...{model_reply}...")` in `log_query_to_db` | `BAS-LLM10-003` | The model's reply is concatenated into a SQL statement. |
| `agent.py` | `client.chat.completions.create(model="gpt-4", messages=[...])` in `ask_advisor` (no `max_tokens`) | `BAS-LLM06-001` (observation) | No token ceiling on the call. |

Every other line in `vulnerable_agent/` — imports, the Flask routes in `app.py`,
`get_wallet_balance` in `tools.py`, `MODEL_NAME`, `db.commit()` — is not expected to match
any rule.

## `clean_agent/` — MUST NOT be flagged (zero findings, of any kind)

This is the more important half of the corpus: it is how precision gets proven, not just
claimed. It deliberately includes every near-miss called out in the scope doc.

| File | Line | Near-miss | Why it must stay clean |
| --- | --- | --- | --- |
| `config.py` | `API_KEY = os.environ["OPENAI_API_KEY"]` | Looks like credential handling | Correct practice — read from the environment, not a string literal. `BAS-ZT1-001`'s pattern requires a string-literal RHS; a subscript expression never matches it. |
| `config.py` | `api_key_name = "OPENAI_API_KEY"` | Variable named like a secret | The *value* isn't `sk-`-shaped, and the *name* isn't prompt-shaped. Neither `BAS-ZT1-001` nor `BAS-LLM08-001` fire on name alone — this is exactly the `approx_tokens` mistake the scope doc calls out, done deliberately so the test proves we don't repeat it. |
| `config.py` | `approx_tokens_per_word = 1.3`, `token_count = 0` | Variable names containing "token"/"count" | Not strings, not secrets, not flagged by anything. |
| `prompts.py` | `SYSTEM_PROMPT = "You are CryptoAdvisor..."` | Prompt-named variable, matches `BAS-LLM08-001`'s name constraint | No `sk-`-shaped substring anywhere in the text, so the content constraint never fires. Name alone is never sufficient. |
| `prompts.py` | `chat_prompt = ChatPromptTemplate.from_messages([("system", SYSTEM_PROMPT), ("human", "{sanitized_input}")])` | Prompt built with user data in it | Proper delimiters: the untrusted value sits in its own templated slot via LangChain's message list, never string-interpolated into the instruction text. Not an f-string at all, so `BAS-ZT4-001` cannot structurally match it. |
| `prompts.py` | `assert eval("2 + 2") == 4` in `_sanity_check` | `eval()` call | Literal argument, not model output. Both the `none:` exclusion (`eval("$LIT")`) and the `metavariable_matches` regex on `ARG` independently prevent `BAS-LLM10-001` from firing here. |
| `agent.py` | `delete_wallet(wallet_id, confirmed=False)` | Destructive tool name | Guarded: `if not confirmed: raise PermissionError(...)` is the function's first statement, matching `BAS-LLM03-001`'s `none:` guard shape, so the match is suppressed. |
| `agent.py` | `get_wallet_balance` | Also has no guard | Not destructive — the name never matches `BAS-LLM03-001`'s verb regex, guard or no guard. |
| `agent.py` | `client.chat.completions.create(..., max_tokens=500)` | LLM call | Explicit token ceiling present, matching `BAS-LLM06-001`'s `none:` exclusion. |
| `app.py` | `/chat` route has no login/auth check | Public, unauthenticated endpoint | Correct for a public chatbot with nothing sensitive behind it. `bastyn.yml` has no rule that infers "missing auth" as a defect from source alone — that is exactly the "no rate limiting is not a bug" class of noise the scope doc calls out. |
| `app.py` | No rate limiting anywhere in the file | Missing control | Unprovable from the repository — the limiter is normally at the edge (proxy/gateway). No rule claims this category, so nothing can fire. |

## Why some plausible rules are absent

`bastyn.yml` does not attempt LLM05, LLM07, ZT7, ZT8, ZT9 (no signal in source, per
`category::Category` — they simply aren't in the enum) or ZT2/ZT3/LLM02/LLM04/LLM09/ZT5
(in scope for the product eventually, but no pattern for them cleared the precision bar in
this pass — see the module doc at the top of `crates/bastyn-core/tests/rule_patterns.rs`
for what was tried and dropped).
