/**
 * OpsBot's model-suggested-action pipeline.
 *
 * OpsBot asks the model for a suggested remediation, then several
 * downstream helpers act on that reply directly. This is the
 * highest-value category: running, shelling out with, or querying with
 * model output is wrong in every deployment, with no mitigating
 * circumstances.
 */

import { exec } from "node:child_process";
import * as cp from "node:child_process";

import { Pool } from "pg";
import { generateText } from "ai";
import { createOpenAI } from "@ai-sdk/openai";

import { OPENAI_API_KEY, MODEL_NAME } from "./zt1_static_credentials";

const openaiProvider = createOpenAI({ apiKey: OPENAI_API_KEY });
const db = new Pool({ connectionString: process.env.OPSBOT_AUDIT_DB_URL });

/** Ask the model for a suggested remediation action. */
export async function askModel(incidentSummary: string): Promise<string> {
  const { text } = await generateText({
    model: openaiProvider(MODEL_NAME),
    system: "Suggest a one-line JavaScript fix.",
    prompt: incidentSummary,
    maxOutputTokens: 200,
  });
  return text;
}

/**
 * Let the model decide what JS expression to run to remediate.
 *
 * The model's own reply is passed straight to eval().
 */
export async function runSuggestedExpression(incidentSummary: string) {
  const suggestion = await askModel(incidentSummary);
  const result = eval(suggestion);
  return result;
}

/**
 * The model sometimes suggests a shell one-liner to restart a service.
 *
 * The model's reply is run as a shell command.
 */
export async function executeSuggestedShellCommand(incidentSummary: string): Promise<void> {
  const suggestion = await askModel(incidentSummary);
  exec(suggestion, () => {});
}

/**
 * A second remediation path that imports child_process under a namespace
 * alias (`cp`) rather than destructuring, and runs the reply through
 * `cp.execSync` -- the receiver-qualified shape BAS-LLM10-006's `any` list
 * exists to catch. Proves the rule still fires once its receiver gate is
 * narrowed to `child_process`-shaped names, not just anything with an
 * `.exec` method.
 */
export async function executeSuggestedShellCommandSync(incidentSummary: string): Promise<void> {
  const reply = await askModel(incidentSummary);
  cp.execSync(reply);
}

/**
 * Store the model's suggested action alongside the incident for audit.
 *
 * The model's reply is concatenated straight into SQL.
 */
export async function logSuggestionToDb(incidentSummary: string, assistantNote: string): Promise<void> {
  await db.query(`INSERT INTO suggestions (incident, action) VALUES ('${incidentSummary}', '${assistantNote}')`);
}
