"""A command built from a config file read, not a direct stdin read --
BAS-LLM10-009 must still fire here. Guards against the stdin_dispatch
fact being implemented too broadly."""
import subprocess


def run_from_config(config_path: str) -> None:
    with open(config_path) as handle:
        command = handle.readline().strip()
    subprocess.run(command, shell=True, check=True)
