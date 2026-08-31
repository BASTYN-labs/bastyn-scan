"""Real miss #3: credentials hardcoded inside a dict literal.

Measured against a production agentic app: BAS-ZT1-001 only matches direct
assignment of a string literal to a variable ($VAR = "$SECRET"). A secret
that is instead a value inside a dict literal -- the ordinary shape for an
app's runtime settings object -- has no assignment target of its own, so
the pattern never anchors to it.
"""


def load_runtime_settings() -> dict:
    """known_gap (ZT1): a live DB password and an admin token, both inside
    a dict literal rather than a direct string-literal assignment."""
    return {
        "database_url": "postgresql://admin:password123@db.internal.example.com:5432/opsbot",
        "admin_secret": "SUPER-SECRET-TOKEN-9f2b7d41c6a8e35019bd4471aa",
        "region": "us-east-1",
    }


def load_legacy_settings() -> dict:
    """known_gap (ZT1): the same defect with a token shape BAS-ZT1-002 misses.

    The token above contains a long hex run, which is what the rule's value
    gate keys on. This one is uppercase-and-dashes with a year — the shape a
    real application actually used — and carries no hex at all. Widening the
    gate to accept any long string would also flag `api_key_name` in the clean
    corpus, so recall here costs precision. Recorded rather than fixed.
    """
    return {
        "database_url": "postgresql://svc:hunter2@legacy.internal.example.com:5432/ops",
        "admin_secret": "SUPER-SECRET-ADMIN-TOKEN-2025",
        "region": "eu-west-1",
    }
