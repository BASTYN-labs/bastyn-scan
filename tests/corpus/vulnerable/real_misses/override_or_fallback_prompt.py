"""Real miss #6: a system-prompt override as an `or` fallback.

BAS-ZT4-002 was written against the f-string shape -- a caller's override
spliced into the instruction text alongside other content. Across 65 real
third-party AI repositories scanned on 2026-08-28 that shape appeared zero
times, and the rule never fired. The one caller-supplied prompt override the
corpus did contain was written the way Python people actually write an
optional argument:

    system_prompt = system_override or self._build_system_prompt(framework)

Structurally it is the stronger version of the same defect: the override does
not get interpolated *into* the instructions, it replaces them outright. This
file is that shape, paraphrased.
"""


class Orchestrator:
    """An agent orchestrator whose caller may replace the whole persona."""

    def _build_system_prompt(self, framework: str) -> str:
        return f"You are an analyst working within the {framework} framework."

    def run(self, framework: str, system_override: str | None = None) -> str:
        # A defect (LLM01/ZT4): whatever the caller passes as system_override
        # becomes the entire instruction channel. Nothing constrains it to a
        # data slot, and the fixed instructions are simply gone.
        system_prompt = system_override or self._build_system_prompt(framework)
        return system_prompt

    def run_with_slot(self, framework: str, analyst_note: str = "") -> str:
        """Not a finding: the caller's text lands in a delimited data slot and
        the instructions themselves are fixed and caller-invisible."""
        instructions = self._build_system_prompt(framework)
        return instructions + "\n\n<analyst_note>\n" + analyst_note + "\n</analyst_note>"
