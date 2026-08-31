/**
 * Infrastructure tools OpsBot can call directly, no human in the loop.
 *
 * CommonJS on purpose: this is the older half of OpsBot's tool registry,
 * written before the rest of the service moved to ESM/TypeScript, and
 * never migrated.
 */

const { tool } = require("ai");
const { z } = require("zod");

const { infraClient } = require("./infraClient");

/**
 * Shut down a production server.
 *
 * A destructive tool exposed to the agent with no confirmation guard
 * before it acts. If the model decides to call this -- including because
 * a prompt-injected ticket told it to -- the host goes down
 * unconditionally.
 */
const shutdownServer = tool({
  description: "Shut down a production server.",
  inputSchema: z.object({ hostname: z.string() }),
  execute: async ({ hostname }) => {
    await infraClient.shutdown(hostname);
    return `Server ${hostname} is shutting down.`;
  },
});

/**
 * Return the current status of a server. Read-only: not destructive, must
 * not be treated the same as shutdownServer even though it also has no
 * guard.
 */
const getServerStatus = tool({
  description: "Return the current status of a server.",
  inputSchema: z.object({ hostname: z.string() }),
  execute: async ({ hostname }) => infraClient.status(hostname),
});

/**
 * Change a production server's configuration. Not named with a
 * delete/drop/... verb -- the gap the head-to-head benchmark exposed: a
 * state-changing tool (create/update/...) with no guard is just as
 * unauthorized as a destructive one, and BAS-LLM03-002 originally missed
 * this shape entirely.
 */
const updateServerConfig = tool({
  description: "Change a production server's configuration.",
  inputSchema: z.object({ hostname: z.string(), config: z.record(z.unknown()) }),
  execute: async ({ hostname, config }) => {
    await infraClient.updateConfig(hostname, config);
    return `Server ${hostname} reconfigured.`;
  },
});

/**
 * The other way the same SDK is used: a tools *object*, where each tool's
 * name is the property key rather than a `const` binding. Both shapes turn
 * up in real code -- see the 2026-08-28 calibration run -- and neither
 * carries a `name:` property inside the tool({...}) call, which is why the
 * rule reads the binding instead.
 */
function createIncidentTools() {
  return {
    // A destructive tool with no guard, registered as a property key.
    purgeIncidentHistory: tool({
      description: "Delete every stored incident record for a host.",
      inputSchema: z.object({ hostname: z.string() }),
      execute: async ({ hostname }) => {
        await infraClient.purgeHistory(hostname);
        return `History for ${hostname} purged.`;
      },
    }),

    // Same shape, guarded by an inline check as the first statement: must
    // not be flagged.
    removeStaleSnapshot: tool({
      description: "Delete a stale infrastructure snapshot.",
      inputSchema: z.object({ snapshotId: z.string(), confirmed: z.boolean() }),
      execute: async ({ snapshotId, confirmed }) => {
        if (!confirmed) {
          throw new Error("removeStaleSnapshot requires confirmed: true");
        }
        await infraClient.deleteSnapshot(snapshotId);
        return `Snapshot ${snapshotId} deleted.`;
      },
    }),
  };
}

module.exports = { shutdownServer, getServerStatus, createIncidentTools };
