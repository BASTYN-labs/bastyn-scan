/**
 * Core chat logic for OpsBot's Node service (safe).
 */

import { generateText } from "ai";
import { createOpenAI } from "@ai-sdk/openai";
import OpenAI from "openai";

import { OPENAI_API_KEY, MODEL_NAME } from "./config";
import { chatPrompt } from "./prompts";

const openaiProvider = createOpenAI({ apiKey: OPENAI_API_KEY });
const openaiClient = new OpenAI({ apiKey: OPENAI_API_KEY });

/**
 * eval() call, but on a literal, not model output.
 */
function sanityCheck(): void {
  console.assert(eval("2 + 2") === 4);
}

/**
 * Ask the model to help triage an incident.
 *
 * The caller has already sanitized and length-capped the input before it
 * reaches this function. Correct practice: maxOutputTokens bounds the
 * response.
 */
export async function askModel(sanitizedIncidentSummary: string): Promise<string> {
  const formatted = await chatPrompt.formatMessages({ sanitizedIncidentSummary });
  const messages = formatted.map((m) => ({ role: m.getType(), content: String(m.content) })) as any;
  const { text } = await generateText({
    model: openaiProvider(MODEL_NAME),
    messages,
    maxOutputTokens: 500,
  });
  return text;
}

/**
 * Same request as askModel(), expressed through the OpenAI Node SDK
 * directly instead of the Vercel AI SDK wrapper. max_tokens caps it.
 *
 * BAS-LLM06-002 carries no receiver-name gate on this call shape (measured:
 * a client|llm|openai|gpt-shaped gate would have missed a real middleware-
 * wrapped client in the corpus this rule was grounded against -- see that
 * rule's comment in bastyn.yml), so this is the negative case that actually
 * exercises the max_tokens exclusion rather than a name gate that never
 * reaches the call at all.
 */
export async function askModelDirect(sanitizedIncidentSummary: string): Promise<string> {
  const completion = await openaiClient.chat.completions.create({
    model: MODEL_NAME,
    messages: [{ role: "user", content: sanitizedIncidentSummary }],
    max_tokens: 500,
  });
  return completion.choices[0]?.message?.content ?? "";
}

/**
 * Tool scoping for the agent this service builds (safe): the granted set is
 * always an explicit list, never the bare wildcard string
 * vulnerable/zt2_wildcard_tool_grant.ts uses.
 */
const ALL_TOOLS = ["getServerStatus", "restartService"];

function selectToolsForAgent(allTools: string[], allowedTools: string[]): string[] {
  return allTools.filter((name) => allowedTools.includes(name));
}

export function buildOpsbotAgent(): string[] {
  return selectToolsForAgent(ALL_TOOLS, ["getServerStatus"]);
}
