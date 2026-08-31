"""Core chat and command logic for the crypto advisor agent."""

import subprocess
import sqlite3

from openai import OpenAI

from config import API_KEY
from prompts import build_system_prompt

client = OpenAI(api_key=API_KEY)
db = sqlite3.connect("advisor.db")
cursor = db.cursor()


def ask_advisor(user_input: str) -> str:
    """Ask the model a crypto question.

    BAS-LLM06-001: no max_tokens on the completion call, so nothing here
    bounds the cost or length of a single response.
    """
    system_prompt = build_system_prompt(user_input)
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input},
        ],
    )
    return response.choices[0].message.content


def run_advisor_command(user_input: str) -> str:
    """Let the model decide what Python expression to run for a calculation.

    BAS-LLM10-001: the model's own reply is passed straight to eval().
    """
    llm_output = ask_advisor(user_input)
    result = eval(llm_output)
    return str(result)


def execute_suggested_shell_command(user_input: str) -> None:
    """The model sometimes suggests a shell command to fetch live prices.

    BAS-LLM10-002: the model's reply is run as a shell command.
    """
    completion = ask_advisor(user_input)
    subprocess.run(completion, shell=True)


def log_query_to_db(user_input: str) -> None:
    """Store the model's answer alongside the question for audit.

    BAS-LLM10-003: the model's reply is concatenated straight into SQL.
    """
    model_reply = ask_advisor(user_input)
    cursor.execute(f"INSERT INTO queries (question, answer) VALUES ('{user_input}', '{model_reply}')")
    db.commit()
