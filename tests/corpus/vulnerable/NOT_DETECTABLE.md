# Categories with no static rule, and why none should exist

Five of the nineteen framework categories are absent from
`bastyn_core::Category` on purpose (see `crates/bastyn-core/src/category.rs`
and `docs/frameworks/README.md`). No code file exists for them in
`vulnerable/`, and none should ever be added — a rule that claimed one of
these would be a false promise the type system currently prevents.

## LLM05 — Data and Model Poisoning

The checklist is "scan training and RAG data for spam, duplicates, and
anomalies; never train on unfiltered public data; monitor for quality drops
over time." All three are properties of a *dataset and a training/ingestion
pipeline run over time*, not of the application source in front of a
scanner. A single repository snapshot cannot show what data a model was
trained on, whether a RAG corpus was deduplicated, or whether quality
drifted — that requires access to the data itself and to metrics collected
over multiple runs, neither of which is source code.

## LLM07 — Misinformation

The checklist is "force citations, cross-check critical answers against a
real source, require human oversight for high-stakes topics." Whether a
model's output is *factually correct* is a property of the model's
knowledge and the specific query, evaluated at inference time — it is not
observable by reading the code that calls the model. A scanner can check
whether a citation mechanism exists in principle (and even that is a stretch
without deep, project-specific convention-matching), but it cannot tell
whether an answer was actually misinformation.

## ZT7 — Governance and Policy

The checklist is "write security rules as code, treat policies like
production code with PR review, have an incident response plan." This is an
organizational and process property — whether a team reviews changes to its
security policy, whether an incident response plan exists and was
rehearsed — with no corresponding artifact in a source tree that a static
rule could anchor to. A `SECURITY.md` file's existence proves someone wrote
a file, not that a policy is enforced.

## ZT8 — The 8-Phase Rollout

An eight-step *rollout process* (requirements, supply-chain inventory, blast
radius, injection filters, tool allow-lists, short-lived credentials,
session isolation, rogue-agent detection within an hour) describes how a
team should sequence its work over the lifetime of a deployment. Several of
its individual phases already have dedicated detectable categories (supply
chain is LLM04, tool allow-lists are ZT2, short-lived credentials are ZT1).
The category itself is the *process*, not a code shape, so it stays out of
the enum to avoid double-claiming what its component phases already cover.

## ZT9 — The Design Test

"Does this make the attack impossible, or just tedious?" is explicitly a
design *question* to ask of a control, not a control itself — there is
nothing in source code that is "the design test," only controls it might be
applied to. Every category this question would apply to already has its own
entry (or its own documented absence, above). Encoding it as a rule would
mean matching on the *quality of a decision*, which is not a pattern that
exists in a file.
