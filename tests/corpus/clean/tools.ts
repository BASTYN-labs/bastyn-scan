/**
 * Infrastructure tools OpsBot can call (safe).
 */

import { tool } from "ai";
import { z } from "zod";

import { infraClient } from "./infraClient";

class NotConfirmedError extends Error {}

/**
 * Wrapper-based guard: confirmation is enforced by a decorator function,
 * not by an inline `if (!x) throw` at the top of the tool body.
 */
function requireConfirmation<T extends { confirmed?: boolean }, R>(
  execute: (input: T) => Promise<R>,
) {
  return async (input: T): Promise<R> => {
    if (!input.confirmed) {
      throw new NotConfirmedError("This action requires confirmed: true.");
    }
    return execute(input);
  };
}

export const shutdownServer = tool({
  description: "Shut down a production server. Guarded by requireConfirmation.",
  inputSchema: z.object({ hostname: z.string(), confirmed: z.boolean().optional() }),
  execute: requireConfirmation<{ hostname: string; confirmed?: boolean }, string>(async ({ hostname }) => {
    await infraClient.shutdown(hostname);
    return `Server ${hostname} is shutting down.`;
  }),
});

export const deleteStaleSnapshot = tool({
  description: "Delete a stale infrastructure snapshot.",
  inputSchema: z.object({ snapshotId: z.string(), confirmed: z.boolean().optional() }),
  execute: async ({ snapshotId, confirmed }) => {
    if (!confirmed) {
      throw new NotConfirmedError("deleteStaleSnapshot requires confirmed: true");
    }
    await infraClient.deleteSnapshot(snapshotId);
    return `Snapshot ${snapshotId} deleted.`;
  },
});

export const getServerStatus = tool({
  description: "Return the current status of a server. Read-only.",
  inputSchema: z.object({ hostname: z.string() }),
  execute: async ({ hostname }) => infraClient.status(hostname),
});

// Guarded by an inline check -- proves the widened state-changing verb list
// still respects the same guard shapes as the destructive-verb case.
export const updateServerConfig = tool({
  description: "Change a production server's configuration.",
  inputSchema: z.object({ hostname: z.string(), config: z.record(z.unknown()), confirmed: z.boolean().optional() }),
  execute: async ({ hostname, config, confirmed }) => {
    if (!confirmed) {
      throw new NotConfirmedError("updateServerConfig requires confirmed: true");
    }
    await infraClient.updateConfig(hostname, config);
    return `Server ${hostname} reconfigured.`;
  },
});
