"""OpsBot's knowledge-base search tool."""


def search_articles_inline(cursor, keyword: str) -> list:
    """BAS-LLM10-017: the query is f-string interpolated directly into
    the execute() call -- no bind parameter, and no variable-name gate
    is needed to see it, unlike BAS-LLM10-003 which only fires when the
    argument's own text looks like a model reply."""
    return cursor.execute(f"SELECT id, title FROM kb_articles WHERE title LIKE '%{keyword}%'").fetchall()


def archive_stale_ticket(cursor, ticket_id: str) -> None:
    """BAS-LLM10-018: the same local-variable-then-execute() shape as
    real_misses/sql_through_local_variable.py, but execute() is the
    function's literal LAST statement -- a fire-and-forget UPDATE with
    nothing returned or run afterward, the most common real shape for a
    write query. Regression fixture for a 2026-09-23 review finding: the
    def-wrapped BAS-LLM10-018 pattern's trailing `$$$REST` capture
    required at least one statement after execute() to bind, so this
    exact shape produced no finding until the rule gained a sibling
    `any:` variant with no `$$$REST` tail (see bastyn.yml's comment on
    BAS-LLM10-018 for the full explanation)."""
    sql = f"UPDATE tickets SET status = 'archived' WHERE id = {ticket_id}"
    cursor.execute(sql)


def plain_parameter_sql_through_local_variable(cursor, query: str) -> None:
    """A local variable built from an ordinary, non-tool function
    parameter -- not a model call -- interpolated into SQL and executed,
    with execute() as the function's last statement. Moved here from
    clean/near_misses.py on 2026-09-23: it was originally written to
    prove BAS-LLM10-008 stays silent (a bare parameter resolves to
    Origin::Parameter in the flow graph, never Origin::Call{...}, so it
    cannot classify as model_output regardless of whether the enclosing
    function happens to be a decorated tool -- and that is still true;
    BAS-LLM10-008 does not fire here). But BAS-LLM10-018 has no such
    provenance gate: it fires on the interpolate-then-execute *shape*
    alone, exactly like BAS-LLM10-017 and BAS-LLM10-009 do, regardless
    of where the value came from. Once the last-statement parsing gap
    above was fixed, this shape became a genuine, correct BAS-LLM10-018
    true positive, so it no longer belongs in a file whose whole point
    is that nothing in it should fire -- it now demonstrates the two
    rules' behavior diverging correctly: -008 silent (no model-output
    provenance), -018 firing (the interpolation shape alone is enough)."""
    sql = f"SELECT id, title, body FROM kb_articles WHERE title LIKE '%{query}%'"
    cursor.execute(sql)


def find_ticket_by_customer(conn, customer_email: str):
    """LLM10 (BAS-LLM10-017): customer_email is interpolated as a query
    *value* in a WHERE clause, not a schema identifier -- the DDL-keyword
    exclusion does not apply here, and this must still fire."""
    return conn.execute(f"SELECT * FROM tickets WHERE customer_email = '{customer_email}'").fetchall()


def materialize_filtered_table(conn, name: str, user_filter: str) -> None:
    """LLM10 (BAS-LLM10-017): opens with CREATE TABLE, a DDL keyword the
    exclusion's opening check alone would have swallowed -- but the rest
    of the string also interpolates user_filter as a real query *value*,
    quoted with the opposite quote character. Regression fixture for a
    2026-09-24 final-review finding: the DDL exclusion originally only
    checked the opening keyword, not whether a quoted value literal
    appeared anywhere in the remainder, so this was wrongly excluded.
    Must still fire."""
    conn.execute(f"CREATE TABLE {name} AS SELECT * FROM src WHERE owner = '{user_filter}'")


def add_column_with_default(conn, table: str, column: str, user_filter: str) -> None:
    """LLM10 (BAS-LLM10-017): opens with ALTER TABLE, but DEFAULT
    '{user_filter}' interpolates a real query value, not a schema
    identifier -- same 2026-09-24 regression as materialize_filtered_table()
    above, the ADD COLUMN counterpart. Must still fire."""
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT DEFAULT '{user_filter}'")
