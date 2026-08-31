/**
 * Every near-miss called out in the corpus spec, in one file, deliberately.
 *
 * Each of these is a shape that a naive scanner (or a naive rule) gets
 * wrong. This file, and this file alone, is what proves precision rather
 * than asserting it: `expect_none` on the whole file.
 */

// eval() on a literal.
export const literalResult = eval("2 + 2");

// new Function() on a literal -- the other native "run this as code" sink.
export const literalFn = new Function("return 1");

// Variable names that look secret-ish or token-ish by substring alone.
export const approxTokens = 1500;
export const tokenCount = 0;
export const apiKeyName = "OPENAI_API_KEY";
export const maxTokens = 500;

// Correct credential handling: property access on process.env, never a
// string literal.
export const openaiKey = process.env.OPENAI_API_KEY;
export const anthropicKey = process.env["ANTHROPIC_API_KEY"];

/**
 * A template literal with one interpolation, but neither side is
 * prompt/instruction-shaped or user-input-shaped.
 */
export function buildGreeting(name: string): string {
  const greeting = `Hello, ${name}! How can OpsBot help today?`;
  return greeting;
}

/**
 * A parameterized query -- the query text is a literal, and the untrusted
 * value is a bind parameter, never interpolated into the SQL string
 * itself.
 */
export async function safeQuery(
  pool: { query: (sql: string, params: unknown[]) => Promise<unknown> },
  incidentId: string,
): Promise<void> {
  await pool.query("SELECT * FROM incidents WHERE id = $1", [incidentId]);
}

/**
 * `RegExp.prototype.exec` -- ordinary regex parsing of a model reply, not
 * shell execution. Measured 2026-08-28: BAS-LLM10-006's `any` used a bare
 * `$CP.exec($ARG)` with no gate on the receiver, so any object with an
 * `.exec` method matched. 11 of the rule's 18 false positives on the
 * calibration corpus were exactly this shape.
 */
export function extractIncidentId(pattern: RegExp, response: string): string | null {
  const match = pattern.exec(response);
  return match ? match[0] : null;
}

/**
 * `better-sqlite3`'s `Database.exec` -- synchronous DDL/DML execution on a
 * fixed schema string, not a shell command. Same measured false-positive
 * shape as `pattern.exec` above: 7 of BAS-LLM10-006's 18 false positives
 * were this one. `db` here is not `child_process` under any binding.
 */
export function applyAuditLogSchema(db: { exec: (sql: string) => void }, message: string): void {
  db.exec(message);
}

/**
 * A function whose entire purpose is detecting placeholder API keys --
 * measured 2026-08-28: the sharpest of BAS-ZT1-003's 5 false positives was
 * exactly this, two "leaked keys" flagged inside the detector meant to
 * recognise them as fake. Both literals below are `sk-`-shaped and pass the
 * rule's length gate, so only a placeholder-content exclusion keeps this
 * function from flagging itself.
 */
const KNOWN_PLACEHOLDER_KEYS = [
  "sk-test-0000000000000000",
  "sk-your-key-here-1234567890123",
  // Underscore-separated, not hyphen -- both spellings turn up in real
  // placeholder-detection code, so the exclusion has to survive either one.
  "sk-ant-your_key_here",
];

export function isPlaceholderKey(key: string): boolean {
  return KNOWN_PLACEHOLDER_KEYS.includes(key);
}

/**
 * A local-dev fallback key, chained after the real sources with `||`. Same
 * measured shape as the isPlaceholderKey() literals above -- a placeholder
 * that only exists so the code runs without real credentials configured.
 */
export function resolveOllaBridgeKey(userKey: string | undefined): string {
  return userKey || process.env.OLLABRIDGE_API_KEY || "sk-ollabridge-local";
}
