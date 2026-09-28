"""Minimal reproduction of a hook / skill-runner's own command-dispatch shape:
the whole point of this file is to run a command its own parent process
handed it over stdin -- the same trust boundary as argv, not user input."""
import json
import subprocess
import sys


def run_hook() -> None:
    event = json.load(sys.stdin)
    command = event["command"]
    subprocess.run(command, shell=True, check=True)


if __name__ == "__main__":
    run_hook()
