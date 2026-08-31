"""Runbook retrieval from OpsBot's shared vector store.

known_gap (LLM09, observation): no rule inspects a vector-store query call
for a tenant or namespace filter. This category is context-dependent -- a
single-tenant deployment needs no such filter -- so even a future rule
could only ever report it as an observation, never a defect. None exists
today.
"""

from vector_client import vector_client


def search_runbooks(query_embedding: list[float], top_k: int = 5) -> list[dict]:
    """Search the shared runbook index for the closest matching passages.

    OpsBot is deployed multi-tenant: every customer org's private runbooks
    live in the same index. This query has no namespace or tenant_id
    filter, so a query embedding similar enough to another org's internal
    runbook content can surface it in the results.
    """
    return vector_client.query(vector=query_embedding, top_k=top_k)
