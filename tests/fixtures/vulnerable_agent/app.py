"""Public entrypoint for the crypto advisor agent."""

from flask import Flask, jsonify, request

from agent import execute_suggested_shell_command, log_query_to_db, run_advisor_command

app = Flask(__name__)


@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message", "")
    log_query_to_db(user_input)
    return jsonify({"reply": run_advisor_command(user_input)})


@app.route("/prices/refresh", methods=["POST"])
def refresh_prices():
    user_input = request.json.get("message", "")
    execute_suggested_shell_command(user_input)
    return jsonify({"status": "ok"})
