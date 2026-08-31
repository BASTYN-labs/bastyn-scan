/**
 * Static configuration and credentials for OpsBot's Node service.
 *
 * OpsBot is a small on-call assistant: it reads incident tickets, drafts
 * replies, consults a runbook vector store, and can call infrastructure
 * tools directly (restart a service, delete a stale resource, shut a host
 * down). This is the TypeScript sibling of the existing Python fixture --
 * same product, same shape of mistake.
 */

// A real-looking provider key, committed straight into source instead of
// coming from an environment variable or secret manager. It ships with
// every clone of this repo and every fork.
export const OPENAI_API_KEY = "sk-proj-7f3a9c1e5d8b2a6f4c0e9d7b3a5f8c1e";

export const MODEL_NAME = "gpt-4o";
export const VECTOR_DB_HOST = process.env.VECTOR_DB_HOST ?? "vector.internal.opsbot.example.com";
export const TICKET_QUEUE_URL = "https://tickets.internal.example.com/api/v1";
