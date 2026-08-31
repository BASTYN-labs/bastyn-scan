"""Static configuration and credentials for OpsBot, the internal infra agent.

OpsBot is a small on-call assistant: it reads incident tickets, drafts
replies, consults a runbook vector store, and can call infrastructure tools
directly (restart a service, delete a stale resource, shut a host down).
"""

import os

# BAS-ZT1-001: a real-looking provider key, committed straight into source
# instead of coming from an environment variable or secret manager. It ships
# with every clone of this repo and every fork.
OPENAI_API_KEY = "sk-proj-7f3a9c1e5d8b2a6f4c0e9d7b3a5f8c1e"

MODEL_NAME = "gpt-4o"
VECTOR_DB_HOST = os.environ.get("VECTOR_DB_HOST", "vector.internal.opsbot.example.com")
TICKET_QUEUE_URL = "https://tickets.internal.example.com/api/v1"
