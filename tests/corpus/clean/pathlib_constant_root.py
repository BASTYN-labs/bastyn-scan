"""Path roots built with pathlib instead of os.path. BAS-LLM10-012 should
not fire in any of these: HERE and ASSETS both trace back to __file__
through nothing but pathlib's own pure, argument-only methods (.parent,
.resolve(), .parents[...]), the / operator, and str(), so constant_path
must recognize this shape the same way it already recognizes the
os.path.dirname/__file__ one."""

from pathlib import Path

HERE = Path(__file__).parent.parent
ASSETS = HERE / "assets"


def load_overlay() -> str:
    return open(f"{HERE}/js/overlay.js", "r").read()


def load_schema() -> str:
    with open(ASSETS / "schema.json") as fh:
        return fh.read()


def load_readme() -> str:
    return open(str(Path(__file__).resolve().parents[1]) + "/README.md").read()
