# Corpus manifest format

`expected.toml` is the specification of what Bastyn should find. A test harness
reads it, runs the engine over `tests/corpus/`, and compares. It is the release
gate: **precision and recall are measured against this file, not asserted in
prose.**

Four kinds of entry. The third and fourth are the important ones, and they
are opposites of each other: one tracks what the engine misses, the other
tracks what it wrongly reports.

## `[[expect]]` — this finding must be produced

```toml
[[expect]]
file     = "vulnerable/llm10_eval_on_model_reply.py"
line     = 14
rule     = "BAS-LLM10-001"
category = "LLM10"
kind     = "defect"          # defect | observation
severity = "critical"        # low | medium | high | critical
why      = "eval() on an LLM reply is unconditional RCE"
```

A missing entry is a **recall failure**. `rule` may be omitted when any rule
mapping to `category` at that line is acceptable.

## `[[expect_none]]` — this file must produce nothing

```toml
[[expect_none]]
file = "clean/near_misses.py"
why  = "eval on a literal, approx_tokens, os.environ — the cases that fool naive rules"
```

Any finding here is a **precision failure**, and precision failures are worse
than recall failures: they are what makes developers uninstall a scanner.

## `[[known_gap]]` — we know we miss this, and it is not a regression

```toml
[[known_gap]]
file     = "vulnerable/real_misses/eval_compile_rce.py"
line     = 14
category = "LLM10"
why      = "eval(compile(llm_reply)) — the taint is one hop away; needs dataflow"
```

This is what keeps the gate honest. A gap recorded here does not fail the
build, but the harness **prints the list every run** and the count is expected
to shrink, never grow. Adding a `known_gap` is a deliberate, visible admission
rather than a silently missing test.

When a rule starts catching a gap, its entry moves from `known_gap` to
`expect`. Nothing else changes.

## `[[known_false_positive]]` — we know we wrongly report this, and it is not a regression

```toml
[[known_false_positive]]
file     = "vulnerable/real_misses/eval_guarded_by_local_check.py"
line     = 81
category = "LLM10"
why      = "eval() guarded by a sibling if/raise the engine's none:/inside: cannot see"
```

The mirror image of `known_gap`. A `known_gap` is a **recall** debt: a real
defect the engine misses. A `known_false_positive` is a **precision** debt: a
safe call the engine wrongly flags, because excluding it precisely is beyond
what the rule engine can currently express (usually because the proof of
safety lives in a sibling statement — a prior assignment or guard clause —
that neither `none:` nor `inside:` can see; both only look at the matched
node itself or its ancestors).

Do not model this as a `known_gap`. A `known_gap` entry is promoted to
`expect` the moment a matching finding appears — which is the correct
behaviour for a recall gap, and the *wrong* behaviour for a precision gap,
where the finding already existing is the expected (undesired) steady state,
not news. Filing a false positive as a `known_gap` makes the harness suggest
promoting a false positive to `[[expect]]`, which would assert that
provably-safe code is a defect.

Like `known_gap`, this does not fail the build, but the harness **prints the
list every run**, counts it separately from `known_gap` (a recall debt and a
precision debt are different debts and should not be added together), and
its own count is expected to shrink, never grow. If a rule improves so the
finding stops appearing, the harness flags the entry as stale so it gets
removed rather than silently going out of date.

## What the harness reports

```
corpus: 18/22 expected findings present   (recall 82%)
        0 unexpected findings             (precision 100%)
        4 known gaps
        1 known false positive (precision debt -- tracked separately from known gaps)
```

It fails the build on a missing `expect`, on any finding in an `expect_none`
file, on a `known_gap` count that has grown, or on a `known_false_positive`
count that has grown.
