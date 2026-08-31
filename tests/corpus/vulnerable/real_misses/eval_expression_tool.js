/**
 * Real miss #5: the JavaScript "calculator tool" shape.
 *
 * Measured on 2026-08-28 across 65 real third-party AI repositories: every
 * eval()/new Function() call on model-derived text was reached through a
 * variable named for *what the value is* -- `expression`, `calculation`,
 * `resolved` -- never `response`/`reply`/`completion`. BAS-LLM10-005's
 * metavariable name gate could therefore never fire, and across the whole
 * corpus it never did. Python already learned this lesson once:
 * BAS-LLM10-004 drops the name requirement and keeps only the
 * literal-argument exclusion.
 *
 * Paraphrased, not copied: an agent tool that lets the model hand back an
 * arithmetic expression to evaluate.
 */

const { tool } = require("ai");

/** The model returns an expression string for the tool to evaluate. */
const calculate = tool({
  description: "Evaluate an arithmetic expression",
  execute: async ({ expression }) => {
    // A defect (LLM10): whatever the model put in `expression` runs as
    // JavaScript. No name in this call says "model output"; the danger is
    // the eval, not the noun.
    return eval(expression);
  },
});

/** A resolved template the planner built from model text. */
function runResolvedStep(resolved) {
  // A defect (LLM10): the Function constructor is the other native
  // "run this as code" sink, and a template literal is not a fixed literal.
  return new Function(`return ${resolved}`)();
}

/** Not a finding: a fixed literal is not attacker-influenceable. */
function sanityCheck() {
  return eval("2 + 2");
}

module.exports = { calculate, runResolvedStep, sanityCheck };
