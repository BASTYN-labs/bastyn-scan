# OWASP Top 10 for GenAI (08/2026)

The industry-standard awareness document for security risks specific to building
AI applications. Bastyn's detection verdict per category is in the right-hand
column; see [`README.md`](README.md) for what those verdicts mean.

`Bastyn` names the verdict a rule *could* report at, per
[`README.md`](README.md); it is not a promise a rule exists. A dagger (†)
marks a category with no detector implemented yet. See
[`README.md`'s "Detectable is not the same as implemented"](README.md#detectable-is-not-the-same-as-implemented).

"Also discussed in" names the other framework *families* that write about the
same risk: NIST AI RMF, MITRE ATLAS, CWE, and similar. This is a statement
about the risk taxonomy, not about Bastyn: it says the category is a
recognised risk elsewhere too, not that a Bastyn finding satisfies, violates,
or maps to any specific control inside those frameworks. No control or
technique ID is named because the source mapping does not go that far, and
none is invented here.

| ID | Risk | Developer checklist | Also discussed in | Bastyn |
| --- | --- | --- | --- | --- |
| **LLM01** | Prompt Injection | Treat all inputs (prompts, RAG docs, web scrapes) as malicious. Restrict tools to an explicit whitelist. Require a human in the loop for high-impact actions. Red-team it. | NIST AI RMF, NIST GenAI, MITRE ATLAS, CWE, OWASP Agentic, OWASP GenAI | Defect |
| **LLM02** | Sensitive Info Disclosure | Never put API keys, PII, or internal URLs in a prompt. Pass credentials in backend code, not through the LLM. Filter outputs for sensitive data. Isolate RAG data per user. | NIST AI RMF, NIST GenAI, MITRE ATLAS, CWE, CSA AI, OWASP GenAI | Defect |
| **LLM03** | Excessive Agency | Grant the minimum permissions the task needs. Handle authentication in code, not by instructing the model. Require human approval to delete data, change configs, or make payments. Log which tools are called and why. | NIST AI RMF, MITRE ATLAS, CWE, CSA AI, OWASP Agentic | Defect |
| **LLM04** | Supply Chain | Keep an SBOM of models, plugins, and libraries. Pin versions and verify signatures. Download models only from trusted registries. Have a rollback plan. | NIST AI RMF, MITRE ATLAS, MITRE ATT&CK, CWE, CSA AI, OWASP AppSec | Defect |
| **LLM05** | Data and Model Poisoning | Scan training and RAG data for spam, duplicates, and anomalies. Never train on unfiltered public data. Monitor for quality drops over time. | NIST AI RMF, MITRE ATLAS, CWE, CSA AI, OWASP GenAI | Not detectable |
| **LLM06** | Unbounded Consumption | Cap tokens, API calls, and cost per user and session. Restrict input and output sizes. Auto-throttle on usage spikes. | NIST AI RMF, MITRE ATLAS, CWE, CSA AI | Observation |
| **LLM07** | Misinformation | Force citations. Cross-check critical answers against a real source. Require human oversight for high-stakes topics. | NIST AI RMF, NIST GenAI, MITRE ATLAS, CSA AI | Not detectable |
| **LLM08** | Hidden Context Exposure | Assume users will extract the system prompt. Strip API keys and sensitive URLs from system prompts entirely. Filter internal scaffolding out of responses. | NIST AI RMF, MITRE ATLAS, CWE, OWASP Agentic | Defect |
| **LLM09** | Vector and Embedding Weaknesses | Isolate vector databases per user. Encrypt at rest and in transit. Validate documents before embedding them. | NIST AI RMF, MITRE ATLAS, CWE, CSA AI, OWASP GenAI | Observation † |
| **LLM10** | Improper Output Handling | Never auto-execute model output as code, SQL, or HTML. Force structured output and validate against a schema. Sandbox any code that must run. | NIST AI RMF, MITRE ATLAS, CWE, CSA AI, OWASP Top 10 | Defect |

The eight categories present in `bastyn_core::Category` expose this same list
in code, at `Category::framework_families()`. LLM05 and LLM07 have no code
counterpart, being two of the five categories absent from the enum, so their
"Also discussed in" column is transcribed here for completeness only.

## Why LLM10 is the priority

Running model output as code is wrong in every deployment, in every
architecture, with no mitigating circumstances. `eval()` called on an LLM
reply is an unconditional remote code execution.
