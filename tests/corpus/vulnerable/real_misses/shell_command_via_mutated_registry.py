"""Known gap: a shell-injection sink reachable through a module-level
registry that is genuinely mutated elsewhere in the file, which
BAS-LLM10-009's exclude_if: closed_value clause cannot see.

crates/bastyn-core/src/flow/graph.rs's Analyzer::bind_targets only records
a binding for a plain-identifier assignment target (`target.kind() ==
"identifier"`); a subscript target (`COMMANDS[name] = cmd`) and an
attribute-call receiver (`CMDS.append(x)`) both fall through the `_ => {}`
arm and record no binding at all. That is the right call for the ordinary
case `self.x = ...` (no local name is bound), but it also means the graph
never learns that the module-level dict COMMANDS below is mutated after
its own literal initializer. Resolution then sees only the one binding
made at COMMANDS's own definition -- a dict of literals, `closed: true` --
and has no way to know register() ever runs, so BAS-LLM10-009's
exclude_if: closed_value clause wrongly treats COMMANDS[component] as
forever drawn from that closed initial set. Fixing this needs the graph to
recognise a subscript-assignment or method-call target as a mutation of
the name it is rooted in and fold that into the name's resolved value --
tracking mutated container names through the graph, a materially larger
change than this fix wave's scope. Recorded as a known_gap rather than
attempted here.
"""

import subprocess

COMMANDS = {"restart": "systemctl restart worker"}


def register(name: str, cmd: str) -> None:
    """known_gap (LLM10): COMMANDS[name] = cmd is a subscript assignment
    target -- bind_targets's `_ => {}` fallthrough records nothing for it,
    so the graph never learns COMMANDS holds anything beyond its own
    literal initializer."""
    COMMANDS[name] = cmd


def run(component: str) -> None:
    """known_gap (LLM10): COMMANDS[component] resolves to `closed: true`
    from COMMANDS's own dict-of-literals initializer alone -- the graph
    has no record of register() ever mutating it -- so BAS-LLM10-009's
    exclude_if: closed_value clause wrongly excludes this shell-injection
    sink even though register() can have populated COMMANDS with an
    attacker-influenced command string by the time this runs."""
    subprocess.run(COMMANDS[component], shell=True)
