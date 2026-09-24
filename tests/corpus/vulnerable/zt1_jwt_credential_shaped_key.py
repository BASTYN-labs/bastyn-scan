"""Regression fixture: a realistically-named JWT assignment legitimately
co-fires two independent, correct rules at the same location.

The Task 3 fixture (zt1_secret_shapes.py) names its JWT-holding dict key
`issued_jwt` rather than a more realistic name like `service_token`. That
rename was made specifically to dodge a genuine interaction:
`service_token` -- a completely ordinary variable name -- matches
BAS-ZT1-010's credential-shaped-name gate
((?i)(password|passwd|secret|token|...)) at the same time its value
matches BAS-ZT1-018's JWT-shape gate (the eyJ... three-segment structure).
Both are correct, independent true positives at the same source location:
BAS-ZT1-010 flags "a credential-shaped name holds a high-entropy literal"
and BAS-ZT1-018 flags "this literal has the exact shape of a JWT" -- two
different, both-valid signals about the same line, not a duplicate. This
file documents that co-firing as intentional, expected behavior rather
than reshaping the fixture (as zt1_secret_shapes.py was) to hide it.
"""


def issue_session_token() -> str:
    """BAS-ZT1-010 + BAS-ZT1-018: session_token is a realistic,
    credential-shaped variable name (matches BAS-ZT1-010's KEY gate)
    assigned a value that also has the exact eyJ.<payload>.<signature>
    JWT shape (matches BAS-ZT1-018's VALUE gate) -- both rules correctly
    fire at this same assignment line."""
    session_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJvcHNib3QtYWdlbnQiLCJyb2xlIjoiYWRtaW4ifQ.8Fq3nR1sQ9c2l0mHqTj6vRe8wZFq3xK9zRiK4nRe7i0J"
    return session_token
