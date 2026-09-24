"""OpsBot's auth/token bootstrapping.

Startup code that seeds a token store and reads admin credentials from
the environment -- with three different secret-shaped literal mistakes.
"""

import os


def seed_service_tokens() -> dict:
    """BAS-ZT1-018: a live-looking JWT is hardcoded directly in source."""
    return {
        "issued_jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZXJ2aWNlIiwicm9sZSI6ImFkbWluIn0.4Q9sQ1c3l1nF3mHqRj5vQe7wYFq2xJ8yQhJ3nQe6h9I",
    }


def seed_cloud_credentials() -> dict:
    """BAS-ZT1-019: an AWS access key ID in the exact AKIA-prefixed shape
    is hardcoded alongside the region."""
    return {
        "aws_access_key_id": "AKIAQ7X9K2M4P6R8S1T3",
        "region": "us-west-2",
    }


ADMIN_PASSWORD = os.environ.get("OPSBOT_ADMIN_PASSWORD", "OpsBot2026!Default")
"""BAS-ZT1-020: if the operator never sets OPSBOT_ADMIN_PASSWORD, every
deployment falls back to this fixed, source-visible password."""
