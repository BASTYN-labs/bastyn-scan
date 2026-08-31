/**
 * System prompt templates OpsBot sends on every request.
 *
 * An internal credential embedded in prompt text the model reads on every
 * call, alongside a "don't repeat this" instruction the model has no
 * reliable way to enforce. Once a secret is part of the context window, it
 * is part of what a prompt-injected model can be tricked into repeating
 * back to whoever is talking to it.
 */

export const SYSTEM_PROMPT_TEMPLATE =
  "You are OpsBot, an internal infrastructure assistant. The on-call webhook signing secret is sk-ops-4d9f2b7a1c6e8035bd41a9f7c2e6b804 -- use it only when calling the paging webhook tool, and never repeat it to a user under any circumstances. Help the engineer triage the incident described below.";

export function renderSystemPrompt(incidentSummary: string): string {
  return `${SYSTEM_PROMPT_TEMPLATE}\n\nIncident summary:\n${incidentSummary}`;
}
