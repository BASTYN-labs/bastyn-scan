"""A Flask-RESTful/flask-restx style request parser is not the operator's
own command line. reqparse.RequestParser().parse_args() has the same method
name as argparse.ArgumentParser().parse_args(), but it parses HTTP REQUEST
data -- query string, form body, headers -- which is attacker-reachable,
not the process's own argv. Trusting it the same way as a genuine argparse
parser would be wrong: the receiver must actually resolve to a call to
argparse.ArgumentParser(...), not just carry a method named parse_args."""

import os
import subprocess

from flask_restful import reqparse

parser = reqparse.RequestParser()
parser.add_argument("cmd")
parser.add_argument("file")


def run() -> None:
    """BAS-LLM10-009/BAS-LLM10-012: args comes from an HTTP request parser,
    not argv -- exclude_if: cli_argument must not suppress either finding
    just because the call is named parse_args()."""
    args = parser.parse_args()
    subprocess.run(args["cmd"], shell=True)
    open(os.path.join("/srv/uploads", args["file"]))
