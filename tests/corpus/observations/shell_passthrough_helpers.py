"""Fix D (BAS-LLM10-009's flow.passthrough_downgrade): a generic "run this
command" helper whose command is simply its own parameter is reported as an
observation rather than a defect when nothing in this file wires it to a
recognized agent- or web-framework entry point (@mcp.tool()/@app.route()/a
do_GET-style handler). See bastyn.yml's comment on BAS-LLM10-009 and
crate::flow::graph::FlowGraph::is_passthrough_observation_eligible for the
four conditions this relies on.
"""

import subprocess


def run_shell_cmd(cmd: str) -> str:
    """Observation: cmd is a bare pass-through of run_shell_cmd's own
    parameter (condition 1), run_shell_cmd is not itself a recognized entry
    point (condition 2), and nothing in this file forwards an entry point's
    parameter into it (condition 3)."""
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True)
    return process.communicate()[0]


class HookExecutor:
    def execute(self, hook, event_json: str):
        """Observation: command is one plain local alias of hook.command --
        hook is this method's own parameter, and "pure pass-through" follows
        at most one plain local alias between a parameter and the sink."""
        command = hook.command
        if not command:
            return None
        return subprocess.run(command, shell=True, input=event_json,
                               capture_output=True, text=True)
