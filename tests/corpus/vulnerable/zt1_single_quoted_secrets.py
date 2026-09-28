"""Regression fixture: BAS-ZT1-018/019's `any:` list only matched a
double-quoted string literal ('"$VALUE"'), so the exact same JWT or AWS
access key ID, spelled with single quotes instead, produced no finding at
all even though the double-quoted form fired correctly.
"""


def seed_single_quoted_jwt() -> dict:
    """BAS-ZT1-018: identical JWT shape to zt1_secret_shapes.py, but
    single-quoted -- must still fire."""
    return {
        "issued_jwt": 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZXJ2aWNlIiwicm9sZSI6ImFkbWluIn0.4Q9sQ1c3l1nF3mHqRj5vQe7wYFq2xJ8yQhJ3nQe6h9I',
    }


def seed_single_quoted_access_key() -> dict:
    """BAS-ZT1-019: a real-looking AKIA-prefixed access key ID,
    single-quoted -- must still fire."""
    return {
        "aws_access_key_id": 'AKIAT3M8K1Q9X2R7N4V6',
        "region": "eu-central-1",
    }
