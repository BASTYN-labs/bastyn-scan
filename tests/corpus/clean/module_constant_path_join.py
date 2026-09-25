"""A path built from a module-level string constant plus a literal
filename, joined directly at the open() call site. BAS-LLM10-012 should
not fire: DATA_DIR is fixed by this file's own source, not caller-
supplied, even though it isn't derived via os.path.dirname/__file__."""
import os

DATA_DIR = "/opt/app/data"


def load_config():
    with open(os.path.join(DATA_DIR, "config.json")) as handle:
        return handle.read()
