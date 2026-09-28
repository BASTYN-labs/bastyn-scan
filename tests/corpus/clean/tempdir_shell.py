"""Values derived from Python's `tempfile` module: an OS-generated
temp-file/temp-directory path, fixed by the operating system at call time,
never attacker-influenced. BAS-LLM10-009's exclude_if: closed_value and
BAS-LLM10-012's exclude_if: constant_path must both recognize this trust
boundary. See tests/corpus/vulnerable/llm10_shell_injection_tool.py's
unpack() for the must-still-fire sibling that mixes a tempfile-derived
value with a real caller-supplied parameter.
"""

import os
import tempfile
from pathlib import Path


def sync_repo() -> None:
    """workspace is Path(tmpdir), where tmpdir is the as-target of a `with
    tempfile.TemporaryDirectory()` block -- an OS-generated temp directory
    path. BAS-LLM10-009's exclude_if: closed_value must drop the os.system()
    call below, and BAS-LLM10-012's exclude_if: constant_path must drop the
    os.path.join(workspace, ...) path passed to open()."""
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        os.system(f"cd {workspace} && git init --quiet")
        with open(os.path.join(workspace, "README.md"), "w") as handle:
            handle.write("scratch workspace\n")


def collect_diagnostics() -> bytes:
    """scratch is the direct return value of tempfile.mkdtemp() -- also an
    OS-generated temp directory path. Same two exclusions as above, applied
    to a plain tempfile.mkdtemp() value rather than one wrapped in
    Path(...)."""
    scratch = tempfile.mkdtemp()
    os.system(f"tar -czf {scratch}/diagnostics.tar.gz /var/log/opsbot")
    with open(os.path.join(scratch, "diagnostics.tar.gz"), "rb") as handle:
        return handle.read()
