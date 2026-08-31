"""A test fixture's own throwaway credentials, in a test path.

Paraphrased from the shape that dominated the 2026-08-28 calibration run:
23 of BAS-ZT1-002's 32 findings across 65 real repositories were placeholder
DSNs exactly like these, sitting in `tests/`. A password invented so a suite
can reach a disposable container is not a credential anybody can use.

Everything here is still *found* — it is a credential-shaped literal and the
rule is right about that — but it is reported as an observation, out of the
default report, because the path says it is a fixture. Deleting the finding
outright is what would be wrong: a genuinely leaked secret does sometimes sit
in a test file, and this file is what proves it is still reachable with
--show-observations.

Deliberately not a `localhost`/`127.0.0.1` host: that shape is now excluded
outright by BAS-ZT1-002's `metavariable_not_matches` (see clean/config.py's
`AUDIT_DB_PATH` near-miss and bastyn.yml's comment on the rule) because a DSN
that can only ever reach the local machine is not a credential an attacker
can use no matter where the source file sits — a stronger, value-based signal
than the path-based downgrade this file exists to pin. Using a non-localhost
host here keeps this file testing what it says it tests: the test-path
downgrade, not the placeholder-value exclusion.
"""

import os

# Downgraded (ZT1): the throwaway DSN every integration suite has, pointed at
# a disposable CI database container rather than localhost.
TEST_DATABASE_URL = "postgresql://test_user:test_password@postgres-test.ci.internal:5432/test_db"


def make_settings() -> dict:
    """Downgraded (ZT1): the same shape as a dict value, which is what the
    real repositories mostly did."""
    return {
        "database_url": "mysql+pymysql://user:password@mysql-test.ci.internal/app_test",
        "region": "us-east-1",
    }


def real_settings() -> dict:
    """Not a finding: the suite reads the real value from the environment,
    same as the application does."""
    return {"database_url": os.environ["DATABASE_URL"]}
