import sqlite3
import subprocess


def run_fixed_query():
    cursor = sqlite3.connect(":memory:").cursor()
    response = "SELECT 1"
    cursor.execute(response)
    statement = "SELECT 1"
    cursor.execute(statement)


def run_fixed_command():
    response = "printf hello"
    subprocess.run(response, shell=True)
    command = "printf hello"
    subprocess.run(command, shell=True)


def evaluate_fixed_expression():
    expression = "1 + 1"
    return eval(expression)
