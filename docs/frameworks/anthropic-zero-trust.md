# Anthropic Zero Trust for agents (05/2026)

Adapts cryptographic identity, ephemeral credentials, and strict sandboxing to
autonomous agents, so that a compromised or tricked agent has the smallest
possible blast radius. Bastyn's detection verdict per category is in the
right-hand column; see [`README.md`](README.md) for what those verdicts mean.
`Bastyn` names the verdict a rule *could* report at, not a promise a rule
exists. A dagger (†) marks a category with no detector implemented yet; see
[`README.md`'s "Detectable is not the same as implemented"](README.md#detectable-is-not-the-same-as-implemented).

Unlike the OWASP GenAI table, there is no "also discussed in" column here.
"Governing principle" names a design principle Anthropic's own guidance
organises itself around. It is not a citation to an external framework, and
none of these categories claim one. Keeping this in its own, differently
named column is deliberate: a reader should never be able to mistake a
Zero Trust principle for the same kind of claim as an OWASP framework-family
citation.

| ID | Category | Developer checklist | Governing principle | Bastyn |
| --- | --- | --- | --- | --- |
| **ZT1** | Identity and Credentials | Give each agent its own cryptographic identity (mTLS), not a config name. No permanent API keys. Use short-lived auto-refreshing tokens. Deny all access by default. | Identity-based zero trust | Defect |
| **ZT2** | Least Agency and Access | Scope permissions to the current task, then revoke. Hardcode which endpoints and tools the agent may call, with no wildcards. Inject credentials at runtime; never let the agent hold or log them. | Least privilege, ephemeral access | Defect |
| **ZT3** | Isolation and Runtime | Sandbox agents in isolated containers with outbound network blocked by default. Quarantine agents that read untrusted external data. Route agent traffic through a gateway, not direct database connections. | Network segmentation and sandboxing | Defect |
| **ZT4** | I/O and Prompt Defenses | Never mix untrusted external data directly with system instructions. Validate input length and schema; redact PII and secrets from output. Require human approval before the agent sends email, moves money, or deletes data. | Data sanitization and human-in-the-loop | Defect |
| **ZT5** | Memory and Context | Ensure an agent cannot use User A's memory to escalate in User B's session. Set strict expiry to purge sensitive context. Sign and version-control RAG data so it cannot be poisoned. | State isolation and data minimization | Observation |
| **ZT6** | Observability and Logging | Record identity, tools used, resources touched, and outcomes in immutable logs. Trace across agents with request IDs. Auto-revoke credentials and kill the session on anomalous behaviour. | Immutable audit trails and active monitoring | Observation † |
| **ZT7** | Governance and Policy | Write security rules as code so they are enforced and auditable. Treat agent policies like production code, with PRs and reviews to change them. Have an incident response plan. | Policy-as-code and change control | Not detectable |
| **ZT8** | The 8-Phase Rollout | 1. Requirements. 2. Supply chain inventory. 3. Define blast radius. 4. Prompt-injection filters. 5. Tool allow-lists. 6. Short-lived credentials. 7. Session isolation and expiry. 8. Detect a rogue agent within one hour. | Secure AI development lifecycle | Not detectable |
| **ZT9** | The Design Test | For every feature ask: does this make the attack impossible, or just tedious? Rate limits and warnings are not enough against automated agents. Enforce hard cryptographic boundaries. | Deterministic security | Not detectable |

`Category::framework_families()` in `bastyn_core` reflects this same
distinction: it returns an empty list for every `Zt*` category, because none
of them has an entry in this table's non-existent "also discussed in"
column. A governing principle is not a framework family, and the method does
not pretend otherwise.

## ZT9 as our own design test

"Does this make the attack impossible, or just tedious?" is also the right
question to ask of a finding. A rule reporting a control whose absence only
makes an attack *tedious*, and whose presence may live somewhere the repository
cannot show, is reporting an observation, not a defect. That is the reasoning
behind ZT5 and ZT6 being observation-only.
