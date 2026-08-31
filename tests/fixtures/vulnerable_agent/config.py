"""Configuration for the crypto advisor agent."""

import os

# BAS-ZT1-001: a real-looking provider key, committed straight into source.
API_KEY = "sk-proj-1a2b3c4d5e6f7g8h9i0jklmnopqrstuv"

MODEL_NAME = os.environ.get("ADVISOR_MODEL", "gpt-4")
