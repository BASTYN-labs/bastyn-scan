"""The same defect in a directory that merely *contains* the word "test".

`latest/` is what a substring check for "test" gets wrong, and getting it
wrong here would be the expensive direction: it would quietly demote a real
hardcoded credential in shipped configuration to an observation nobody sees
by default. This file exists so that mistake fails the release gate.

Real shape, paraphrased: a versioned settings module (`latest/` next to
`v1/`) whose database URL carries an inline password as its default.
"""

import os

# A defect, not a downgrade: `latest` is not a test directory.
DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://appsvc:s3cr3tpassword@db.internal.example.com:5432/app"
)
