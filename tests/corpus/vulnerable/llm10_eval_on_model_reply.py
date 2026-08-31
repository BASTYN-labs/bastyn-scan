"""OpsBot's model-suggested-action pipeline.

OpsBot asks the model for a suggested remediation, then several downstream
helpers act on that reply directly. This is the highest-value category:
running, shelling out with, or querying with model output is wrong in every
deployment, with no mitigating circumstances.
"""

import subprocess
import sqlite3

from openai import OpenAI

from zt1_static_credentials import OPENAI_API_KEY, MODEL_NAME

client = OpenAI(api_key=OPENAI_API_KEY)
db = sqlite3.connect("opsbot_audit.db")
cursor = db.cursor()


def ask_model(incident_summary: str) -> str:
    """Ask the model for a suggested remediation action."""
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "Suggest a one-line Python fix."},
            {"role": "user", "content": incident_summary},
        ],
        max_tokens=200,
    )
    return response.choices[0].message.content


def run_suggested_python(incident_summary: str) -> str:
    """Let the model decide what Python expression to run to remediate.

    BAS-LLM10-001: the model's own reply is passed straight to eval().
    """
    llm_output = ask_model(incident_summary)
    result = eval(llm_output)
    return str(result)


def execute_suggested_shell_command(incident_summary: str) -> None:
    """The model sometimes suggests a shell one-liner to restart a service.

    BAS-LLM10-002: the model's reply is run as a shell command.
    """
    completion = ask_model(incident_summary)
    subprocess.run(completion, shell=True)


def log_suggestion_to_db(incident_summary: str) -> None:
    """Store the model's suggested action alongside the incident for audit.

    BAS-LLM10-003: the model's reply is concatenated straight into SQL.
    """
    model_reply = ask_model(incident_summary)
    cursor.execute(f"INSERT INTO suggestions (incident, action) VALUES ('{incident_summary}', '{model_reply}')")
    db.commit()
