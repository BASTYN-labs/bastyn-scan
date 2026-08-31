# Compliance crosswalk

A crosswalk from `bastyn_core::Category` to the EU AI Act and to the two NIST
AI documents. It exists so a compliance reader can see which regulatory areas
a scan's code-level findings touch, and so an auditor has a defensible
starting map.

## This is a crosswalk, not a compliance assessment

> Bastyn maps its finding categories to the regulatory areas those findings
> are relevant to. It does not determine compliance. Compliance depends on the
> deployment context, the system's risk classification, and the organisation's
> documentation and processes, none of which are in the source code. Finding
> nothing does not mean an obligation is met.

That paragraph is `bastyn_core::compliance::DISCLAIMER`. It is printed in the
terminal report and carried in the JSON output whenever a crosswalk is
requested, so it travels with the data rather than living only here.

Three specific things a reader must not take from this document:

- **It is not a verdict.** "Relevant to Art. 15" is the strongest claim made
  anywhere in this file or in Bastyn's output. Never "complies with",
  "satisfies", "certified", or "passed".
- **Every EU AI Act row is conditional on scope.** Articles 9 to 15 bind
  high-risk AI systems only. Whether a system is high-risk is settled by
  Article 6 and Annexes I and III against the system's intended purpose, which
  is a fact about deployment, not about code. Bastyn cannot see it, does not guess
  it, and the mapping says nothing about whether these articles apply to the
  repository being scanned.
- **A blank cell is an answer.** Where a category has no honest mapping into a
  framework it maps to nothing. The blanks are listed and reasoned below
  rather than filled.

## Sources

Every identifier and every quotation below was taken from a document fetched
on the access date shown. Nothing here is written from memory.

| # | Document | URL | Accessed |
| --- | --- | --- | --- |
| 1 | Regulation (EU) 2024/1689 (Artificial Intelligence Act), OJ L, 2024/1689, 12.7.2024, text as published | <https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401689> | 2026-08-28 |
| 2 | Consolidated text of Regulation (EU) 2024/1689 as applicable from 27.7.2026 (CELEX 02024R1689-20260727) | <https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02024R1689-20260727> | 2026-08-28 |
| 3 | Regulation (EU) 2026/1744 of 8 July 2026 (Digital Omnibus on AI), OJ L, 2026/1744, 24.7.2026, the amending act | <https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32026R1744> | 2026-08-28 |
| 4 | EUR-Lex document record for CELEX 32024R1689, used to enumerate amendments and corrigenda | <https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX:32024R1689> | 2026-08-28 |
| 5 | NIST AI 100-1, *Artificial Intelligence Risk Management Framework (AI RMF 1.0)* | <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf> | 2026-08-28 |
| 6 | NIST AI 600-1, *Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile* | <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf> | 2026-08-28 |
| 7 | SARIF 2.1.0 (OASIS Standard incorporating Errata 01), for the `taxonomies` / `taxa` / `relationships` mechanism | <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html> | 2026-08-28 |

### What was not fetched

- **The NIST AI RMF Playbook** (`airc.nist.gov`) was not retrieved. No Playbook
  content is cited, and no Playbook identifier appears in this crosswalk or in
  the code.
- **Web search was unavailable** for this work (the session's search budget was
  spent). Every source above was reached by direct URL instead, which is why
  the list is short and primary. Nothing was filled in from memory to
  compensate.

## EU AI Act: what is actually in force on 2026-08-28

This matters more than it looks. The Act applies in phases, and those phases
were **changed** two months ago: Regulation (EU) 2026/1744 (source 3), the
Digital Omnibus on AI, was adopted on 8 July 2026, published on 24 July 2026,
and amends Article 113 with effect from 27 July 2026. Reading the 2024 text
alone gives the wrong answer today.

Article 113 of the consolidated text (source 2), quoted in full:

> This Regulation shall enter into force on the twentieth day following that of
> its publication in the *Official Journal of the European Union*.
>
> It shall apply from 2 August 2026.
>
> However:
>
> (a) Chapters I and II shall apply from 2 February 2025, with the exception of
> Article 5(1), first subparagraph, points (ba) and (bb), and Article 5(1a) and
> (1b) which shall apply from 2 December 2026;
>
> (b) Chapter III Section 4, Chapter V, Chapter VII and Chapter XII and Article
> 78 shall apply from 2 August 2025, with the exception of Article 101;
>
> (c) Chapter III, Sections 1, 2, and 3, with the exception of Article 6(5),
> shall apply from:
>
> (i) 2 December 2027 as regards AI systems classified as high-risk pursuant to
> Article 6(2) and Annex III; and
>
> (ii) 2 August 2028 as regards AI systems classified as high-risk pursuant to
> Article 6(1) and Annex I;
>
> (d) Articles 102 to 110 shall apply from 27 July 2026.

Points (a), (c) and (d) are the amended text (EUR-Lex marks them `▼M1`); point
(b) is unchanged from 2024.

The recital in the amending act states the reason for the deferral in (c)
(source 3):

> the delayed availability of standards, common specifications, and alternative
> guidance and the delayed establishment of national competent authorities lead
> to challenges that jeopardise the effective entry into application of those
> obligations

The consequence for this crosswalk:

| Provision | Status on 2026-08-28 |
| --- | --- |
| Chapter III, **Sections 1, 2 and 3** (Articles 6 to 27), which contain **every article this crosswalk maps to** (Art. 12, 14, 15) | **Not yet applicable.** 2 December 2027 for Annex III high-risk systems; 2 August 2028 for Annex I high-risk systems |
| Chapters I and II (definitions, AI literacy, prohibited practices in Art. 5) | Applicable since 2 February 2025; the new Art. 5(1)(ba), (bb), (1a), (1b) from 2 December 2026 |
| Chapter V (general-purpose AI models, Art. 51 to 56) | Applicable since 2 August 2025 |
| Chapter IV (Art. 50, transparency for certain AI systems) | Applicable since 2 August 2026. It is not excepted, so it takes the general date |
| Articles 102 to 110 | Applicable since 27 July 2026 |

So the honest statement is: **the EU AI Act obligations this crosswalk maps to
are not yet in application.** They bind from December 2027 at the earliest, and
only for systems classified as high-risk. The mapping is forward-looking
preparation, and saying so is more useful to a compliance reader than implying
a duty that does not yet bite.

### Article titles and text, quoted

Article headings are quoted verbatim from source 1 and checked against the
consolidated text in source 2. None of Articles 9, 12, 13, 14 or 15 was amended
by Regulation (EU) 2026/1744; Article 10 was (paragraphs 1 and 6 replaced,
paragraph 5 deleted), which is one reason Article 10 is not mapped below.

**Article 12, "Record-keeping"**

> 1. High-risk AI systems shall technically allow for the automatic recording
> of events (logs) over the lifetime of the system.
>
> 2. In order to ensure a level of traceability of the functioning of a
> high-risk AI system that is appropriate to the intended purpose of the
> system, logging capabilities shall enable the recording of events relevant
> for: (a) identifying situations that may result in the high-risk AI system
> presenting a risk within the meaning of Article 79(1) or in a substantial
> modification; (b) facilitating the post-market monitoring referred to in
> Article 72; and (c) monitoring the operation of high-risk AI systems referred
> to in Article 26(5).

**Article 14, "Human oversight"**

> 1. High-risk AI systems shall be designed and developed in such a way,
> including with appropriate human-machine interface tools, that they can be
> effectively overseen by natural persons during the period in which they are
> in use.
>
> 4. […] the high-risk AI system shall be provided to the deployer in such a
> way that natural persons to whom human oversight is assigned are enabled, as
> appropriate and proportionate: […] (d) to decide, in any particular
> situation, not to use the high-risk AI system or to otherwise disregard,
> override or reverse the output of the high-risk AI system; (e) to intervene
> in the operation of the high-risk AI system or interrupt the system through a
> 'stop' button or a similar procedure that allows the system to come to a halt
> in a safe state.

**Article 15, "Accuracy, robustness and cybersecurity"**

> 1. High-risk AI systems shall be designed and developed in such a way that
> they achieve an appropriate level of accuracy, robustness, and cybersecurity,
> and that they perform consistently in those respects throughout their
> lifecycle.
>
> 5. High-risk AI systems shall be resilient against attempts by unauthorised
> third parties to alter their use, outputs or performance by exploiting system
> vulnerabilities.
>
> The technical solutions aiming to ensure the cybersecurity of high-risk AI
> systems shall be appropriate to the relevant circumstances and the risks.
>
> The technical solutions to address AI specific vulnerabilities shall include,
> where appropriate, measures to prevent, detect, respond to, resolve and
> control for attacks trying to manipulate the training data set (data
> poisoning), or pre-trained components used in training (model poisoning),
> inputs designed to cause the AI model to make a mistake (adversarial examples
> or model evasion), confidentiality attacks or model flaws.

Article 15(5) is the sentence that carries most of this crosswalk. It names, in
the Act's own words, four things Bastyn's categories are about: data poisoning,
model poisoning of pre-trained components, "inputs designed to cause the AI
model to make a mistake", and confidentiality attacks.

## NIST AI RMF 1.0 (AI 100-1)

The AI RMF Core has four functions (GOVERN, MAP, MEASURE, MANAGE), each with
numbered categories and subcategories. Subcategory identifiers and text below
are quoted from Tables 1 to 4 of source 5.

| Identifier | Text, quoted from AI 100-1 |
| --- | --- |
| `MAP 3.5` | "Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from the GOVERN function." |
| `MAP 4.1` | "Approaches for mapping AI technology and legal risks of its components – including the use of third-party data or software – are in place, followed, and documented, as are risks of infringement of a third party's intellectual property or other rights." |
| `MEASURE 2.4` | "The functionality and behavior of the AI system and its components – as identified in the MAP function – are monitored when in production." |
| `MEASURE 2.7` | "AI system security and resilience – as identified in the MAP function – are evaluated and documented." |
| `MEASURE 2.10` | "Privacy risk of the AI system – as identified in the MAP function – is examined and documented." |
| `MANAGE 3.1` | "AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented." |
| `MANAGE 4.1` | "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, decommissioning, incident response, recovery, and change management." |

`MEASURE 2.7` carries most of the mapping. That is not laziness: it is the AI
RMF's security subcategory, and Bastyn is a security scanner. Spreading
findings across GOVERN and MANAGE subcategories to make the table look richer
would be inventing coverage the framework does not support. Those
subcategories describe organisational policy and process, which no scan sees.

## NIST Generative AI Profile (AI 600-1)

Section 2 of source 6 enumerates twelve risks "unique to or exacerbated by"
generative AI. The crosswalk maps to those risks, because they are named,
numbered and defined in the document itself. Definitions are quoted verbatim.

| Risk | Definition, quoted from AI 600-1 §2 |
| --- | --- |
| `Data Privacy` | "Impacts due to leakage and unauthorized use, disclosure, or de-anonymization of biometric, health, location, or other personally identifiable information or sensitive data." |
| `Information Security` | "Lowered barriers for offensive cyber capabilities, including via automated discovery and exploitation of vulnerabilities to ease hacking, malware, phishing, offensive cyber operations, or other cyberattacks; increased attack surface for targeted cyberattacks, which may compromise a system's availability or the confidentiality or integrity of training data, code, or model weights." |
| `Value Chain and Component Integration` | "Non-transparent or untraceable integration of upstream third-party components, including data that has been improperly obtained or not processed and cleaned due to increased automation from GAI; improper supplier vetting across the AI lifecycle; or other issues that diminish transparency or accountability for downstream users." |

Section 3 of AI 600-1 lists suggested actions with their own identifiers. Those
are closer to code level than either the AI RMF subcategories or the risk names,
and three of them are quoted here as the evidence for specific rows in the
mapping table. They are **not** part of the machine-readable mapping: an action
is a thing an organisation does, not a property of a finding, and putting an
action id on a finding would assert that the finding tells you the action was
skipped. It does not.

> **`MS-2.7-001`**, "Apply established security measures to: Assess likelihood
> and magnitude of vulnerabilities and threats such as backdoors, compromised
> dependencies, data breaches, eavesdropping, man-in-the-middle attacks,
> reverse engineering, autonomous agents, model theft or exposure of model
> weights, AI inference, bypass, extraction, and other baseline security
> concerns."
>
> **`MS-2.7-007`**, "Perform AI red-teaming to assess resilience against: Abuse
> to facilitate attacks on other systems (e.g., malicious code generation,
> enhanced phishing content), GAI attacks (e.g., prompt injection), ML attacks
> (e.g., adversarial examples/prompts, data poisoning, membership inference,
> model extraction, sponge examples)."
>
> **`MG-3.1-002`**, "Test GAI system value chain risks (e.g., data poisoning,
> malware, other software and hardware vulnerabilities; labor practices; data
> privacy and localization compliance; geopolitical alignment)."

The Profile's §2.9 prose on Information Security is also worth recording,
because it names prompt injection as a first-class risk rather than leaving it
to be inferred:

> GAI itself is vulnerable to attacks like prompt injection or data poisoning
> […] In direct prompt injections, attackers might craft malicious prompts and
> input them directly to a GAI system […] Indirect prompt injection attacks
> occur when adversaries remotely (i.e., without a direct interface) exploit
> LLM-integrated applications by injecting prompts into data likely to be
> retrieved.

## The mapping

Fourteen categories. Read every cell as "relevant to", never as "satisfies".

| Category | EU AI Act | NIST AI RMF 1.0 | NIST GenAI Profile |
| --- | --- | --- | --- |
| **LLM01** Prompt Injection | Art. 15 | `MEASURE 2.7` | `Information Security` |
| **LLM02** Sensitive Information Disclosure | Art. 15 | `MEASURE 2.7`, `MEASURE 2.10` | `Data Privacy`, `Information Security` |
| **LLM03** Excessive Agency | Art. 14 | `MAP 3.5`, `MEASURE 2.7` | `Information Security` |
| **LLM04** Supply Chain | Art. 15 | `MAP 4.1`, `MEASURE 2.7`, `MANAGE 3.1` | `Information Security`, `Value Chain and Component Integration` |
| **LLM06** Unbounded Consumption | *(none)* | `MEASURE 2.7` | `Information Security` |
| **LLM08** Hidden Context Exposure | Art. 15 | `MEASURE 2.7` | `Information Security` |
| **LLM09** Vector and Embedding Weaknesses | Art. 15 | `MEASURE 2.7`, `MEASURE 2.10` | `Data Privacy`, `Information Security` |
| **LLM10** Improper Output Handling | Art. 15 | `MEASURE 2.7` | `Information Security` |
| **ZT1** Identity and Credentials | Art. 15 | `MEASURE 2.7` | `Information Security` |
| **ZT2** Least Agency and Access | Art. 14 | `MAP 3.5`, `MEASURE 2.7` | `Information Security` |
| **ZT3** Isolation and Runtime | Art. 15 | `MEASURE 2.7` | `Information Security` |
| **ZT4** I/O and Prompt Defenses | Art. 15 | `MEASURE 2.7` | `Information Security` |
| **ZT5** Memory and Context | Art. 15 | `MEASURE 2.7`, `MEASURE 2.10` | `Data Privacy`, `Information Security` |
| **ZT6** Observability and Logging | Art. 12 | `MEASURE 2.4`, `MANAGE 4.1` | *(none)* |

### Why each mapping holds

- **Art. 15 for LLM01, LLM04, LLM10, ZT4.** Article 15(5) names "inputs
  designed to cause the AI model to make a mistake" and "attacks trying to
  manipulate the training data set (data poisoning), or pre-trained components
  used in training (model poisoning)". Prompt injection, untrusted model and
  dependency sources, unsafe handling of model output, and the absence of an
  instruction/data boundary all sit inside that sentence.
- **Art. 15 for LLM02, LLM08, LLM09, ZT5.** Article 15(5) names
  "confidentiality attacks". A secret leaving through the model, a secret
  embedded in a system prompt, a vector store queried without tenant isolation,
  and memory shared across users are all confidentiality exposures in the
  system's own design.
- **Art. 15 for ZT1, ZT3.** Article 15(5)'s general clause: "resilient against
  attempts by unauthorised third parties to alter their use, outputs or
  performance by exploiting system vulnerabilities". Static credentials and an
  absent sandbox boundary are the vulnerabilities that make that alteration
  possible.
- **Art. 14 for LLM03, ZT2.** Article 14(4)(d) and (e) require that a person
  can "disregard, override or reverse the output" and "intervene in the
  operation […] or interrupt the system". An agent given more authority than
  its task needs, or a wildcard tool grant, is the code-level shape of an
  oversight path that is not there.
- **Art. 12 for ZT6.** Article 12(1) is the obligation that a system
  "technically allow for the automatic recording of events (logs)". Tool calls
  that leave no audit trail are the direct code-level counterpart.
- **`MEASURE 2.7` for thirteen of the fourteen.** It is the AI RMF's
  security-and-resilience subcategory, and every Bastyn category except ZT6 is
  a security or resilience property. ZT6 is about traceability, so it maps to
  the monitoring subcategories instead.
- **`MEASURE 2.10` for LLM02, LLM09, ZT5.** The privacy subcategory, for the
  three categories whose failure mode is one person's data reaching another.
- **`MAP 3.5` for LLM03, ZT2.** "Processes for human oversight are defined,
  assessed, and documented"; the same argument as Art. 14.
- **`MAP 4.1` and `MANAGE 3.1` for LLM04.** Both are explicitly about
  third-party components and resources, which is what LLM04 is.
- **`MEASURE 2.4` and `MANAGE 4.1` for ZT6.** Production monitoring and
  post-deployment monitoring plans. Neither is satisfied by logging alone, but
  neither is possible without it.
- **`Value Chain and Component Integration` for LLM04**, supported by
  `MG-3.1-002`, which names "other software and hardware vulnerabilities" as a
  value-chain risk to test.
- **`Information Security` for thirteen of the fourteen**, supported by
  `MS-2.7-007` (which names prompt injection and malicious code generation
  outright) and `MS-2.7-001` (which names compromised dependencies, autonomous
  agents, and model theft).

### Deliberately unmapped

| Cell | Why it is empty |
| --- | --- |
| **LLM06 → EU AI Act** | No article addresses cost, token, or call ceilings. Article 15(4) is about resilience to "errors, faults or inconsistencies"; a missing `max_tokens` is neither. Article 15(1)'s "robustness" could be stretched to cover availability, and stretching it is exactly what this document refuses to do. |
| **ZT6 → NIST GenAI Profile** | None of the twelve risks in AI 600-1 §2 is about traceability or audit trails. `Information Security` concerns attack surface and offensive capability, not whether a tool call was recorded. ZT6 maps cleanly in the other two frameworks; the empty cell here is the accurate answer. |
| **Art. 9, 10, 11, 13 → everything** | Risk management systems, training-data governance, technical documentation, and instructions for use are all process and paperwork obligations. Nothing in a source tree evidences them either way. Article 10 was additionally amended by Regulation (EU) 2026/1744. |
| **Art. 50 → everything** | Disclosure that a user is interacting with an AI system, and machine-readable marking of synthetic output. Bastyn has no detector for either. Worth revisiting if one is written. Article 50 is in force now, which would make it the only in-force EU obligation in this table. |
| **Art. 53, 55 → everything** | These bind providers of general-purpose AI models, and Article 55 only providers of models with systemic risk. Article 55(1)(d), which requires providers to "ensure an adequate level of cybersecurity protection for the general-purpose AI model with systemic risk and the physical infrastructure of the model", is tempting because it is in force. But its subject is the model's weights and physical infrastructure, not an application repository's credentials or sandboxing. Mapping every hardcoded key to a systemic-risk GPAI obligation would be the overclaim this document exists to prevent. |
| **GOVERN subcategories → everything** | Every GOVERN subcategory in AI 100-1 Table 1 describes a policy, a role, a training programme, or an accountability structure. A scan cannot see any of them. |
| **The other nine GenAI risks** | CBRN, Confabulation, Dangerous/Violent/Hateful Content, Environmental Impacts, Harmful Bias or Homogenization, Human-AI Configuration, Information Integrity, Intellectual Property, and Obscene/Degrading/Abusive Content have no code signal Bastyn detects. |
| **LLM05, LLM07, ZT7, ZT8, ZT9** | Not in `bastyn_core::Category` at all; see [`README.md`](README.md). A category that cannot be reported cannot be crosswalked. |

## What this is not

Per-rule CWE identifiers remain a separate, unstarted gap; see the last section
of [`README.md`](README.md). This crosswalk is per **category**, exactly like
`Category::framework_families()`, and for the same reason: a category can carry
a crosswalk entry without any rule behind it existing yet. LLM09 and ZT6, two
of the fourteen categories, have no production detector today. They appear in
the table above because the table describes the taxonomy, not Bastyn's
detection surface, and a scan will never produce a finding under them.

That is the sharpest limit on reading a grouped report as coverage: an empty EU
AI Act Art. 12 group does not mean logging is adequate. It means no rule
inspects logging.
