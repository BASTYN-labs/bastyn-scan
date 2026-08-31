"""HTTP surface for OpsBot (safe)."""

from flask import Flask, request

from agent import ask_model

app = Flask(__name__)


@app.route("/chat", methods=["POST"])
def chat():
    """Public, unauthenticated endpoint.

    Correct for a public chatbot with nothing sensitive behind it. No rule
    in bastyn.yml infers "missing auth" as a defect from source alone --
    that is exactly the "no rate limiting is not a bug" class of noise the
    scope doc calls out. There is also no rate limiting anywhere in this
    file: unprovable from the repository, since the limiter normally lives
    at the edge (a proxy or gateway), so nothing here should flag it.
    """
    incident_summary = request.json.get("message", "")
    reply = ask_model(incident_summary)
    return {"reply": reply}
