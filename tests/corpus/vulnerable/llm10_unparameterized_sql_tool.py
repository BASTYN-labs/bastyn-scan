"""OpsBot's knowledge-base search tool."""


def search_articles_inline(cursor, keyword: str) -> list:
    """BAS-LLM10-017: the query is f-string interpolated directly into
    the execute() call -- no bind parameter, and no variable-name gate
    is needed to see it, unlike BAS-LLM10-003 which only fires when the
    argument's own text looks like a model reply."""
    return cursor.execute(f"SELECT id, title FROM kb_articles WHERE title LIKE '%{keyword}%'").fetchall()
