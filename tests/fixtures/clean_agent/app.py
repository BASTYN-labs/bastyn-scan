"""Public entrypoint for the crypto advisor agent (safe)."""

from flask import Flask, jsonify, request

from agent import ask_advisor

app = Flask(__name__)


@app.route("/chat", methods=["POST"])
def chat():
    """Public, no-login chat endpoint.

    Correct practice for this app: the assistant only answers general
    questions about crypto prices and trading concepts, so it is
    deliberately open to anonymous visitors. No rule should treat "no
    authentication" as a defect here -- bastyn.yml intentionally has no rule
    that infers a missing control from source code alone.

    Rate limiting, if it is needed, belongs at the edge (reverse proxy or API
    gateway) -- the repository cannot see it either way, so it is not
    something bastyn.yml claims to check.
    """
    user_input = request.json.get("message", "")
    sanitized_input = user_input.strip()[:2000]
    return jsonify({"reply": ask_advisor(sanitized_input)})
