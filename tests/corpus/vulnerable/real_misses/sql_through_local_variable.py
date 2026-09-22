"""Real miss #9: model output reaching SQL through a local variable.

Found via an external security-gap report run against a benchmark repo
called opsdesk-agent (not part of this file's own 65-real-repository
measurement corpus). BAS-LLM10-003 matches $CUR.execute($ARG) gated by
`metavariable_matches` on $CUR's and $ARG's own *text* -- but here the
model's reply is assigned to a local variable (`sql`) one f-string
reassignment before the execute() call, so $ARG's captured text is just
`sql`. No response/reply/... trigger word appears in that text, so the
old rule's name-gate can never fire, even though the value is exactly the
same model-controlled SQL text BAS-LLM10-003 already catches when it is
inlined directly into the execute() call.

BAS-LLM10-008 catches this: it asks the flow graph whether $ARG traces
back to a model call, instead of guessing from $ARG's own text. The flow
graph already resolves `sql`'s f-string interpolation back through its
local binding to `client.chat.completions.create` without any engine
changes -- see the comment above BAS-LLM10-008 in
crates/bastyn-core/rules/bastyn.yml.
"""

from openai import OpenAI

from zt1_static_credentials import OPENAI_API_KEY, MODEL_NAME

client = OpenAI(api_key=OPENAI_API_KEY)


def search_knowledge_base(query: str, cursor) -> list[dict]:
    """Real miss (LLM10): the model's own reply is folded into a SQL
    filter via one local variable -- previously missed because
    BAS-LLM10-003's name-gate never sees a variable named `sql`, now
    caught by BAS-LLM10-008's flow-based gate."""
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": "user", "content": f"Rewrite this search query: {query}"}],
        max_tokens=50,
    )
    refined_query = response.choices[0].message.content
    sql = f"SELECT id, title, body FROM kb_articles WHERE title LIKE '%{refined_query}%'"
    cursor.execute(sql)
    return cursor.fetchall()
