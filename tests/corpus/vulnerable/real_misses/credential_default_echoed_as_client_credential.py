"""Known false positive (low confidence -- borderline): a credential-shaped
environment default used as a client credential sent to a server, not
compared against or stored.

BAS-ZT1-020 cannot distinguish "this default is the actual secret this
program defends" from "this default is a client script logging in with
the server's own known default password" -- both are
os.environ.get(CREDENTIAL_KEY, "real-looking-default"). The server-side
default (the actual weak secret a deployment would run with) must still
fire; this file's own docstring is what tells them apart, not anything
Bastyn's engine can see. Recorded as a known_false_positive rather than
adding call-context analysis (is this value used as a *sent* value or a
*compared/stored* one), which the report itself calls borderline and low
priority -- another reviewer could reasonably call this a true positive.
"""

import os


def login_as_default_admin(session) -> dict:
    """known_false_positive (ZT1, low confidence): this is a verification
    script logging in AS the server's own documented default account, not
    a program defending a secret -- but BAS-ZT1-020 has no way to tell a
    client-side credential echo apart from a server-side default without
    understanding what the value is used for."""
    return session.post(
        "/login",
        json={
            "username": os.environ.get("DEMO_ADMIN_USERNAME", "admin"),
            "password": os.environ.get("DEMO_ADMIN_PASSWORD", "Winter2026RootPass!"),
        },
    ).json()
