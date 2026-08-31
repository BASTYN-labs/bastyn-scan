/**
 * Prompt construction for OpsBot's Node service (safe).
 */

import { ChatPromptTemplate } from "@langchain/core/prompts";

// Prompt-named variable -- no sk--shaped content anywhere in the text.
export const SYSTEM_PROMPT =
  "You are OpsBot, an internal infrastructure assistant. Help the engineer triage the incident described below.";

// Proper delimiters: the untrusted value sits in its own templated slot,
// never string-interpolated into the instruction text.
export const chatPrompt = ChatPromptTemplate.fromMessages([
  ["system", SYSTEM_PROMPT],
  ["human", "{sanitizedIncidentSummary}"],
]);
