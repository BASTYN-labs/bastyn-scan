"""Prompt construction for OpsBot (safe)."""

from langchain.prompts import ChatPromptTemplate

# Prompt-named variable, matches BAS-LLM08-001's name constraint -- but no
# sk-shaped substring anywhere in the text, so the content constraint never
# fires. Name alone is never sufficient.
SYSTEM_PROMPT = "You are OpsBot, an internal infrastructure assistant. Help the engineer triage the incident described below."

# Proper delimiters: the untrusted value sits in its own templated slot via
# LangChain's message list, never string-interpolated into the instruction
# text. Not an f-string at all, so BAS-ZT4-001 cannot structurally match it.
chat_prompt = ChatPromptTemplate.from_messages(
    [("system", SYSTEM_PROMPT), ("human", "{sanitized_incident_summary}")]
)
