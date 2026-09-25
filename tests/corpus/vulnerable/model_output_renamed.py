import subprocess


def run_command(client):
    command = client.responses.create(model="gpt-4o-mini", input="Generate a shell command", max_output_tokens=64).output_text
    subprocess.run(command, shell=True)


def run_statement(client, cursor):
    statement = client.responses.create(model="gpt-4o-mini", input="Generate SQL", max_output_tokens=64).output_text
    cursor.execute(statement)


def run_formatted(client, cursor):
    reply = client.responses.create(model="gpt-4o-mini", input="Pick a table", max_output_tokens=64).output_text
    cursor.execute("SELECT * FROM {}".format(reply))
