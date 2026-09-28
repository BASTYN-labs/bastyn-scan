"""Values traced entirely to the operator's own command line -- sys.argv,
argparse's parse_args()/parse_known_args(), and click/typer command
parameters -- are trusted the same way stdin_dispatch already trusts a
hook's stdin read: not attacker-reachable input."""

import argparse, os, subprocess, sys


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--eval-dir", required=True)
    args = p.parse_args()
    with open(os.path.join(args.eval_dir, "output.jsonl")) as f:
        print(f.readline())
    subprocess.run(f"ls {sys.argv[1]}", shell=True)


if __name__ == "__main__":
    main()


import click


@click.command()
@click.option("--eval-dir", required=True)
def cli(eval_dir: str) -> None:
    """A click command's own option value is populated by click from the
    operator's own command line, the same click.command/click.option
    decorator shape exclude_if: cli_argument's third source recognizes."""
    subprocess.run(f"ls {eval_dir}", shell=True)


import typer

app = typer.Typer()


@app.command()
def run(eval_dir: str) -> None:
    """A typer command's own parameter value is populated by typer from the
    operator's own command line -- the @app.command() shape where app is a
    name this file's module scope bound to typer.Typer()."""
    subprocess.run(f"ls {eval_dir}", shell=True)
