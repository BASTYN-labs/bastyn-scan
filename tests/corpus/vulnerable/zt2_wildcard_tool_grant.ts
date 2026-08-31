/**
 * Agent wiring: which tools OpsBot is allowed to call.
 */

import { shutdownServer, getServerStatus } from "./llm03_excessive_agency";
import { restartService, deleteStaleSnapshot, pageOncall } from "./toolsExtra";

const ALL_TOOLS = [shutdownServer, getServerStatus, restartService, deleteStaleSnapshot, pageOncall];

/**
 * Return the subset of `allTools` this agent instance may call.
 *
 * `allowedTools` defaults to "*", granting every tool this agent could
 * ever be extended with, present and future, rather than the specific
 * handful the on-call triage flow actually needs. A new destructive tool
 * added to ALL_TOOLS next quarter is trusted automatically, with no
 * review of this wiring.
 */
export function selectToolsForAgent(
  allTools: typeof ALL_TOOLS,
  allowedTools: string | string[] = "*",
) {
  if (allowedTools === "*") {
    return [...allTools];
  }
  return allTools.filter((t) => allowedTools.includes(t.name));
}

export function buildOpsbotAgent() {
  return selectToolsForAgent(ALL_TOOLS, "*");
}
