/**
 * Configuration for OpsBot's Node service (safe): credentials come from
 * the environment.
 */

// Correct practice: read from the environment, never a string literal.
export const OPENAI_API_KEY = process.env.OPENAI_API_KEY as string;

// A variable *named* like a secret, holding the *name* of an env var, not
// a value.
export const apiKeyName = "OPENAI_API_KEY";

export const MODEL_NAME = process.env.OPSBOT_MODEL ?? "gpt-4o";

// Variable names containing "token"/"count". Not strings, not secrets, not
// flagged by anything.
export const approxTokensPerWord = 1.3;
export let tokenCount = 0;
export const maxTokensPerCall = 500;
