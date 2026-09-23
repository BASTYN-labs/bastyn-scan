# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Pre-1.0, the minor version may carry breaking changes; they will always be listed here.

## [Unreleased]

### Added

- **`BAS-LLM10-009`: non-literal command run through a shell, regardless of any allowlist/denylist
  check.** Flags a `subprocess`/`os.system`/`os.popen` shell call fed a non-literal command even when
  the surrounding code has an allowlist or denylist gate, since neither actually prevents the shell
  from receiving attacker-controlled input. Python only for now — no `child_process` (JS/TS) twin
  ships in this change. Found by measuring Bastyn's rule set against a 5-repository benchmark corpus
  of intentionally-vulnerable MCP/agent applications and closing the recall gap it surfaced.
- **`BAS-LLM10-012`: file opened at an unresolved path built by joining or interpolating a non-literal
  value.** Flags `open()` calls assembled inline via `os.path.join`/f-string/string concatenation with
  no `realpath`/`abspath` resolution — including when the only existing guard is a bypassable
  string-prefix containment check. Python only for now — no JS/TS twin ships in this change. Found via
  the same benchmark-corpus recall pass.
- **`BAS-ZT1-018`/`-019`/`-020`: hardcoded JWT literal, hardcoded AWS access key ID, and a
  credential-shaped default value read from an environment variable.** Three new hardcoded-secret
  shapes the existing `ZT1` rules didn't cover, closing recall gaps the benchmark corpus surfaced.
  Python only for now — no JS/TS twin ships in this change.
- **`BAS-LLM10-017`/`-018`: unparameterized SQL query reaches execution, directly or via a local
  variable.** Flags an interpolation-built query string that reaches `.execute()` either inline or
  after first being assigned to a local variable, closing another benchmark-corpus recall gap. Python
  only for now — no JS/TS twin ships in this change.
- **`BAS-LLM01-002`/`-003`: hidden instruction block and suspicious instruction-override phrase in a
  tool's own description.** Detects MCP "tool poisoning" — an adversarial instruction riding along
  inside a tool's docstring that a human reviewer approving the tool would never read as an
  instruction. Python only for now — no JS/TS twin ships in this change. Found via the same
  benchmark-corpus recall pass.

## [0.1.6] - 2026-09-22

### Added

- **`SKILL.md` manifest scanning (`BAS-SKILL-001` to `-003`).** Bastyn had no `SKILL.md`-specific
  checks at all. Any file named `SKILL.md`, anywhere in the tree, is now checked for: incomplete
  frontmatter (missing `name`, `description`, `version`, or `permissions`); classic
  instruction-override phrasing embedded in the file's own text (a skill's description and body are
  read directly by a host's skill-discovery mechanism, so this is a live prompt-injection surface,
  not documentation); and language telling the agent not to pause for confirmation before a chain of
  consequential actions. Found missing via an external security-gap report benchmarking Bastyn
  against five competitor tools that all had some form of this coverage already.
- **`BAS-LLM10-008`: model output reaching SQL through a local variable.** `BAS-LLM10-003` is a
  structural pattern gated by `metavariable_matches` on the receiver's and argument's own *text*, so
  it never sees a case like `sql = f"...{response}..."; cursor.execute(sql)` — the tainted value's
  own captured text is just the local variable's name, with no trigger word in it. This new,
  complementary, flow-based rule asks the same dataflow graph `BAS-LLM10-001` already uses for
  eval/exec whether the value passed to `.execute()` traces back to a model call, catching the case
  `BAS-LLM10-003`'s name-gate structurally cannot see. `BAS-LLM10-003` is unchanged and keeps
  catching everything it already did; the two overlap on the direct single-line case and report as
  one merged finding there. Does not yet catch the value arriving as a bare function parameter (for
  example, an MCP tool's own incoming argument) with no traceable in-file call to a model — that's a
  known, documented gap, not an oversight; see `tests/corpus/vulnerable/real_misses/
  sql_from_tool_parameter.py`.

### Fixed

- **Security-relevant dot-files were silently unscanned by default.** `bastyn scan` with no flags —
  the documented default usage — never looked at `.env`, `.env.*`, a dot-prefixed MCP manifest
  (`.mcp.json` and friends), `.claude/`, or `.github/workflows/`, because the walker excludes
  dot-files by default and none of those conventions is discoverable without already knowing to pass
  `--hidden`. These four are exactly where the most sensitive material in a modern AI-agent
  repository lives — credentials, MCP server trust boundaries, agent configuration, CI/CD pipeline
  definitions — so the previous default silently missed the files most worth checking. These four
  root-level conventions are now always scanned regardless of `--hidden`; every other dot-file and
  dot-directory keeps the previous default-excluded behavior, and an explicit `--exclude` or a
  respected `.gitignore`/`.bastynignore` still suppresses any of them exactly as before.
- **`exec()`/`eval()` calls with an explicit `globals`/`locals` dict argument.** `BAS-LLM10-004`'s
  `any:` patterns matched only the single-argument shapes `eval($ARG)`/`exec($ARG)`. Python's
  `exec()` and `eval()` both accept optional positional `globals`/`locals` dict arguments — an
  ordinary idiom, often used to sandbox the call — and a call using it, such as
  `exec(manifest["setup_code"], {})`, was silently missed purely because of the extra argument, not
  because of anything about the first argument's own shape. Found via an external security-gap
  report run against a benchmark repo. Now matches the 2- and 3-argument forms of both `eval()` and
  `exec()`, with matching literal-source exclusions so a call with a fixed-literal first argument
  still doesn't fire.
- **A caller-supplied header appended directly onto the system prompt.** `BAS-ZT4-002` matched a
  caller-supplied override only when it was f-string-interpolated or used as an `or` fallback, so
  `system_prompt = system_prompt + x_agent_goal_override` went undetected regardless of whether the
  header was read via `request.headers.get(...)` or FastAPI's `Header(...)` parameter injection —
  the rule has never inspected how the value was sourced, only the shape of the assignment
  statement it lands in. Now also matches the self-concatenation shape (`$SYS = $SYS + $OVERRIDE`)
  and its augmented-assignment form (`$SYS += $OVERRIDE`).
- **`BAS-SKILL-002`/`BAS-SKILL-003` missed a phrase word-wrapped across a line break.** Both checks
  matched their phrase lists (e.g. `"ignore all previous instructions"`) with a literal substring
  search, so Markdown word-wrap splitting a phrase across a line break — or any run of irregular
  whitespace between its words — silently defeated the match, even though the identical phrasing on
  one line was caught correctly. Found via an external tester after the `SKILL.md` checks shipped.
  The shared phrase-matching helper now normalizes whitespace before searching, while still
  reporting an accurate line/column for the match in the original file.

## [0.1.5] - 2026-09-16

### Added

- **`cargo install bastyn`, `brew install bastyn-labs/tap/bastyn`, and a `curl | sh` installer**,
  alongside the existing GitHub Action and GitHub Release binaries. The crates.io package (formerly
  `bastyn-cli`) is renamed to `bastyn` to match; `bastyn-cli` itself is republished as a tiny
  pointer crate so the old name can't be squatted. crates.io publishing uses Trusted Publishing
  (no long-lived token in CI); the Homebrew tap update runs in a separate job from the one that
  executes the downloaded binary, so a GitHub App signing key is never in scope alongside it;
  `install.sh` verifies a checksum before extracting anything and is structured so a truncated
  download can't execute a partial script. See `CONTRIBUTING.md`'s "Releasing" section for what a
  release now touches.

## [0.1.4] - 2026-09-03

### Fixed

- **The Action stopped publishing to the GitHub Marketplace.** `action.yml`'s `description` had
  grown to 188 characters, past an undocumented 125-character limit GitHub enforces before it will
  publish an action's Marketplace listing. Publishing failed silently on every release since: the
  Marketplace page showed no error, it just stopped picking up the new name, description, and
  version, and kept showing whatever the last release under the limit had left there. Shortened the
  description to fit, and added a CI check (`action-metadata` in `ci.yml`, mirrored in
  `release.yml`) so a description that grows past 125 characters again fails the build instead of
  failing silently on the Marketplace.

## [0.1.3] - 2026-09-03

### Added

- **`exclude` input on the GitHub Action.** The `bastyn` CLI already had a repeatable
  `--exclude <GLOB>` flag; the Action had no way to reach it. One gitignore-style glob per line,
  each becoming its own `--exclude` on both the log-format scan and the SARIF one, so a caller can
  suppress specific paths without patching `.bastynignore` into the checked-out tree. Excluded
  paths still show up under the scan's "Coverage gaps" section.

## [0.1.2] - 2026-09-03

Precision fixes. Four false positives found by scanning real third-party repositories, and the three
rules that produced them. No change to what the scanner detects as a genuine defect.

### Fixed

- **A `Bearer` token that was template syntax, not a secret.** `BAS-LLM02-004` and `BAS-LLM02-005`
  reported `"Bearer {{env.DAST_AUTH_TOKEN}}"` and `"Bearer ${VAR}"` as hardcoded credentials. Each is a
  plain string literal whose contents the application substitutes at execution time. `credential.rs`
  already read a leading `{{` or `$` as a placeholder for other rules; these two never got the guard.
- **A credential flagged after it had been scrubbed.** `BAS-ZT1-010` and `BAS-ZT1-011` reported
  `private_repo["accessToken"] = "[REDACTED]"`, which is a redaction routine doing its job rather than a
  leaked secret. `redacted`, `scrubbed` and `masked` were missing from the placeholder word list that
  `credential.rs` and the YAML rules both read from.
- **A fully static SQL query with a model-shaped column name.** `BAS-LLM10-003` reported a literal
  audit query because its column list contains `completion_tokens`. The rule excluded plain-literal
  arguments by enumerating up to five adjacent concatenated literals, and this query had six across
  mixed quote styles. The enumeration is now an end-to-end regex, so the exclusion holds for any
  number of segments rather than the number a corpus run happened to produce.

All four are now `[[expect_none]]` entries in `tests/corpus/clean/near_misses.py` and
`near_misses.ts`, so the corpus gate fails if any of them comes back. The two remaining known false
positives are unchanged and still ratcheted at two.

### Changed

- The README and the Action's Marketplace listing now present the project as BASTYN Community, and
  describe what it checks. No behaviour change.
- `CONTRIBUTING.md` documents how a release is cut: the tag trigger, the version numbers that must
  agree before a tag will build, and what each release job does.
- The JSON example in the README reports `bastyn_version` as `0.1.2`, matching the binary this
  release publishes. It had drifted to `0.1.0` again, the same mismatch 0.1.1 corrected.

## [0.1.1] - 2026-08-31

Action and documentation fixes. The scanner binary is unchanged from 0.1.0.

### Fixed

- **The documented workflow never uploaded its results.** The scan step fails the job when it
  finds anything at or above `fail-on`, so the SARIF upload step after it was skipped in exactly
  the runs that had findings to report, and nothing reached GitHub code scanning. The example now
  guards that step with `if: always() && hashFiles('bastyn.sarif') != ''`.
- **The documented workflow could not have run at all.** It omitted `actions/checkout`, so there
  was no code to scan, and `permissions: security-events: write`, without which the upload is
  rejected. It is now a complete, copy-pasteable workflow. The SARIF upload also moves to
  `github/codeql-action/upload-sarif@v4`; `v3` was a major version behind.
- **Pinning the action did not pin the binary.** `action.yml` defaulted its `version` input to
  `latest`, so `uses: BASTYN-labs/bastyn-scan@v0.1.0` installed whatever the newest release
  happened to be, which is the opposite of what pinning an exact version is for. The default is
  now the release the action was tagged for, and a release job fails if the two drift apart.
  Pass `version: latest` to opt back in to always taking the newest.
- The JSON example in the README reported `bastyn_version` as `0.1.1` while the released binary
  was `0.1.0`.

## [0.1.0] - 2026-08-31

First alpha. `bastyn scan` finds real issues; the embedded classifier does not ship yet.

### Added

- **A GitHub Action**, `BASTYN-labs/bastyn-scan@v0`. It installs the release binary matching
  the runner's operating system *and* architecture, covering x86_64 and arm64 Linux, x86_64
  and arm64 macOS, and x86_64 Windows, and refuses with a named error on any combination
  with no published artifact. It writes SARIF to a file independently of the format written
  to the log, exposes the scan's exit code as an output, and fails the step at the severity
  named by `fail-on`. A manually dispatched smoke test runs it on all five runner
  architectures against the action in the tree rather than the last release.
- `bastyn scan [PATH]` analyses a repository and reports defects, with deterministic,
  byte-identical output across runs so a fix can be verified by re-running.

- **Rules over the Python, TypeScript and JavaScript ASTs**, via `tree-sitter` and `ast-grep`,
  declared as YAML and embedded in the binary. The engine compiles each rule against every grammar
  it declares and keeps one compiled bucket per grammar, so a pattern is never run against a tree
  it was not compiled for. Node-kind ids are meaningful only relative to their own grammar, so
  comparing them across two would silently produce wrong answers rather than an error. TypeScript
  rules compile twice, once against `tree-sitter-typescript` and once against TSX, because the two
  grammars do not agree on every construct, and `.ts`/`.tsx` files are reached by JavaScript rules
  as well.

- **43 rules across five embedded rule files**, split by subject so unrelated rules do not contend
  for one file; ids are globally unique across all of them. `bastyn.yml` (21) carries the core
  threat rules; `frameworks.yml` (9) agent-framework configuration flags and known-unsafe entry
  points (`allow_dangerous_code=True`, `LLMMathChain`, `PALChain` and similar); `secrets.yml` (8)
  credential and secret detection, including the invisible-Unicode inspector; `memory.yml` (5)
  memory scoping, session isolation and agent-loop bounds; and `config.yml` (0), reserved for agent
  and MCP client configuration. The MCP manifest checks, the CVE lookup and the container analysers
  are not `ast-grep` rules and are not counted in that figure.

- **Detectors for twelve of the fourteen modelled categories.** Every category the type system can
  represent has a rule, a CVE check, or an infra/MCP analyser behind it except LLM09 and ZT6;
  [`docs/frameworks/`](docs/frameworks/) records which has which, so the crosswalk cannot present a
  category as covered when nothing looks for it.

- **A deterministic dataflow tier** (`crates/bastyn-core/src/flow/`), which a rule opts into with
  a `flow:` clause. Where the rule engine asks *what shape is this code*, this asks *where did
  this value come from*, which is the question a rule about untrusted data actually needs. The
  difference is measured: a rule gating `eval($ARG)` on `$ARG`'s **name** matching
  `response|completion|output|…` survives 0 of 119 realistic renamings of the same bug; gating on
  its **provenance** survives all 119. The scope is bounded on purpose: Python only, one file,
  and call relations that do not chain past depth one. Every answer is a function of the
  parsed tree alone. Where the graph cannot prove a single origin it answers `Unknown`, which
  never satisfies a `flow: source:` gate, so an unresolvable value produces silence rather than a
  guess. The graph is built lazily and only after a structural candidate already matched, so a
  repository with no `eval`/`exec` call pays nothing for the tier.

- **Container configuration is inspected** (`crates/bastyn-core/src/infra/`). ZT3 (no sandbox
  boundary, unrestricted filesystem or network reach) is close to undetectable in application
  source, because the boundary is not written there. It is written in container config, so
  Dockerfiles and Docker Compose files are parsed directly: `BAS-INFRA-001` (`USER root`, or no
  `USER` at all), `BAS-INFRA-003` (a mounted Docker socket), `BAS-INFRA-004`
  (`privileged: true`), `BAS-INFRA-005` (`network_mode: host`), `BAS-INFRA-010` (`pid: host`),
  and `BAS-INFRA-002`/`BAS-INFRA-006` for provider keys and other credential literals in `ENV`,
  `ARG` or a Compose `environment:` block. Scope stops at those two formats deliberately: 38% of
  65 measured repositories carry a Dockerfile, while Terraform appears in three and Kubernetes
  manifests total 21 files across the whole corpus.

- **MCP manifest inspection** for `mcp.json`, `.mcp.json`, `claude_desktop_config.json` and the
  YAML and TOML equivalents. All formats parse into one model, so checks cannot differ by file
  type: root filesystem grants, unauthenticated plaintext transports, wildcard tool grants, and
  hardcoded credentials.

- **CVE matching** for `requirements.txt`, `pyproject.toml`, `package.json` and `Cargo.toml`
  against OSV.dev. Unpinned ranges are reported as unchecked rather than guessed at. Findings are
  grouped per dependency rather than per advisory. One package with eleven advisories is one
  upgrade and one finding, at the highest severity, with every identifier in `references`. Upgrade
  targets come from `ECOSYSTEM` ranges only: OSV publishes `GIT` ranges beside them, and a hex
  commit SHA sorts above any real version. Release candidates are never recommended.

- **Automatic network kill switch.** No connection means CVEs are skipped and the report says
  so; the scan never hangs, never fails because OSV is down, and never reports zero CVEs as
  though the check had run. `--offline` forces the skip. Dependency names and versions are the
  only thing that leaves the machine.

- **Defect and observation split.** A control the repository shows to be absent (no auth, no
  rate limiting) is an observation, hidden unless `--show-observations` is passed, and never
  able to fail a build at any severity. Enforced by the type system: a rule pairing a
  context-dependent category with `kind: defect` is rejected at load.

- **Findings in test paths are observations, not defects.** Measured over 65 real third-party AI
  repositories: 23 of `BAS-ZT1-002`'s 32 hardcoded-credential findings were placeholder
  connection strings in test fixtures, the single largest source of false positives in the rule
  set. A match in a test path is reported as an observation, so it is out of the default report
  and never fails a build, and `--show-observations` still shows it. Test paths are matched on
  whole path components and known file-naming conventions, never on a substring, so `latest/` and
  `contest/` are unaffected. Rules can opt out with `in_test_paths: report`; the provider-API-key
  rules do, because a live key is leaked wherever it sits.

- **`node_modules` is never scanned**, for the same reason `.git` is not. Nothing inside a vendored
  dependency tree belongs to the repository being scanned, and its remediation is "upgrade the
  package", which is the CVE check's job, not a rule's. Measured: 2 of 65 real repositories
  commit it, and those two produced 5 findings, all inside a vendored compiler's or serialisation
  library's own source.

- **Framework mapping** to the OWASP Top 10 for GenAI and Anthropic Zero Trust. Fourteen
  detectable categories are modelled; the five with no signal in source code are deliberately
  absent from the enum so a rule cannot claim them. Checklists in `docs/frameworks/`.

- **Compliance crosswalks on every scan, no flag required.** Every report ends with a compact
  block for each of the EU AI Act, NIST AI RMF 1.0 and the NIST Generative AI Profile, naming the
  areas the findings are relevant to, the counts under each, and what a reader must know about
  that framework's standing. Every category is crosswalked to named articles and subcategories of
  Regulation (EU) 2024/1689, NIST AI 100-1 and NIST AI 600-1, each identifier quoted from a
  primary source with its URL and access date recorded in
  [`docs/frameworks/compliance-crosswalk.md`](docs/frameworks/compliance-crosswalk.md).

  `--group-by <TAXONOMY>` chooses which one to expand in full: `layer` (the default, which expands
  none and summarises all three), `eu-ai-act`, `nist-ai-rmf`, `nist-genai`. Naming a framework lists
  every finding under each of its areas and leaves the other two out. The summary form carries
  no per-finding lines, so its size does not grow with what the scan found.

  Each framework's heading names its document by identifier (`Regulation (EU) 2024/1689`,
  `NIST AI 100-1`, `NIST AI 600-1`) rather than by full title, so every heading fits on one line
  and the citation does not shout over the counts it introduces. Area titles are cut at a clause
  boundary, never mid-clause: a NIST subcategory written as "heading – elaboration" is cut at the
  dash, so `MEASURE 2.7` reads `AI system security and resilience`. A title with no such boundary
  is dropped entirely. The identifier and the count are what the line is for, and `--group-by`
  quotes every title in full. The complete citation is carried in `--format json` and
  `--format sarif`.

  **It is a crosswalk, not a compliance assessment.** "Relevant to Art. 15" is the strongest
  claim it makes. A static scanner cannot determine regulatory compliance: that depends on the
  deployment context, the system's risk classification, and the organisation's documentation
  and processes, none of which are in the source code. Finding nothing does not mean an
  obligation is met. The report says so before it groups anything, and each machine-format entry
  carries that sentence on itself so a consumer cannot read the grouping without it.

  Two categories map to nothing in one framework each, on purpose: `LLM06` has no EU AI Act
  article about cost or token ceilings, and none of the twelve NIST Generative AI Profile risks
  is about audit trails, so `ZT6` has no entry there.

  The document also records that Regulation (EU) 2026/1744 (the Digital Omnibus on AI, in force
  27 July 2026) deferred Chapter III Sections 1 to 3, which contain every article the
  crosswalk names, to 2 December 2027 for Annex III high-risk systems and 2 August 2028 for
  Annex I.

- **Three output formats from one report model**: JSON, SARIF 2.1.0, and terminal. SARIF maps
  observations to `note` regardless of severity, so an observation can never block a pull
  request in code scanning.

- **A terminal report that reads top to bottom as four answers**: what ran, what the verdict is,
  what to fix, and what the scan did not see. A `RESULT: PASSED`/`FAILED` line and a closing
  `Exit status:` line both come from the value the process actually returns, so neither can
  disagree with `$?`. A checklist above them says which steps ran and which were skipped, with the
  real file, rule and dependency counts, and never a tick for work that did not happen.

  Defects are grouped by threat layer rather than by file. The OWASP categories are threats in
  concentric rings and the Zero Trust ones are the defenses against them, so defects print in the
  order an attack runs (entry vectors, amplifiers, impacts, cross-layer threats), with the
  absent defenses last. The top section is the one whose fixes make the sections below it
  unreachable, which a flat list could not say. A finding that names both a threat and the
  defense it defeats is printed once, as the threat. Inside a section, findings are ordered by
  severity, with `file:line` on the finding's own header line, so a critical is never pushed
  below a high by an alphabetical file name. Each rule's `description` and remediation are
  printed, and no line of the report exceeds eighty columns.

  Coverage gaps are grouped by reason: the reason is stated once with a count, and the entries
  are listed bare underneath, instead of six unpinned dependencies repeating the same sentence
  six times. Every category reaches the reader: excluded, ignore file, generated, unreadable,
  unparseable, unpinned. Observations counted but not collected are reported as
  `N observations hidden — use --show-observations`; `No observations.` is printed only when
  there are none.

  `✓`, `○`, `─` and `†` become `[ok]`, `[--]`, `-` and `*` when stdout is not a terminal or
  `NO_COLOR` is set, so a CI log and an older Windows console get a readable report. Colour is
  disabled on the same condition, so `bastyn scan > report.txt` is a readable file. `--no-color`
  emits no ANSI escape byte and keeps the Unicode.

  The closing severity line on stderr is printed only where stdout is not already carrying the
  verdict: `--format json`, `--format sarif`, or a text report redirected into a file. On an
  interactive text run the report's own `RESULT` block says the same thing three lines above, and
  saying it twice on one screen makes a reader reconcile the two instead of acting on either.
  `--quiet` silences it, because it already prints the summary on stdout.

- **Machine formats carry the crosswalk too.** The JSON report has a `crosswalks` key holding an
  array, one entry per framework, always in the order EU AI Act, NIST AI RMF 1.0, NIST Generative
  AI Profile. It is present on every scan; `--group-by <framework>` narrows it to the single entry
  named. Each crosswalk indexes into the `findings` array rather than reordering or replacing it.

  SARIF likewise has one `taxonomies` entry per framework, three by default, with `relevant`
  `reportingDescriptorRelationship` entries from each rule, each resolving to its own taxonomy by
  `guid` as SARIF 2.1.0 §3.52.3 requires. Framework identifiers stay out of SARIF `tags`, which
  remain exactly the category ids: `tags` is what GitHub and GitLab index and filter a rule by,
  so a framework name there would present a finding as a regulatory violation.

- Stable SARIF `partialFingerprints`, so GitHub code scanning matches an alert to the same
  finding across pushes instead of raising duplicates. The fingerprint deliberately excludes the
  line number. A finding that moves with the code is the same finding.
- CVE and GHSA identifiers in SARIF result properties, so a consumer need not parse prose.
- Live progress output: numbered steps, a spinner, and a one-line summary, each finding attributed
  to the stage that produced it. All on stderr, only when stderr is a terminal, and suppressed by
  `--quiet`, `--no-color`, `NO_COLOR`, or a machine output format.
- **Exit codes**: `0` clean, `1` defects at or above `--fail-on` (default `high`), `2` execution
  error. An execution error outranks findings.
- **GitHub Action** (`action.yml`) that installs the release binary, runs a scan, writes SARIF to
  its own file, and exposes the exit code as an output. Its `show-observations` input maps to the
  flag of the same name.
- A measured corpus and release gate under `tests/corpus/`. Precision and recall are computed in
  CI on every push and printed in the log. The gate fails on a missing expectation, on any
  finding in a file marked as must-stay-silent, or on a known-gap count that grows. Rules measured
  to produce no finding across the 65 repositories record that measurement in their own YAML
  rather than being quietly deleted; `BAS-LLM10-007` is the one where widening was measured and
  *rejected*, because dropping its name gate would have turned 0 findings into 7 false positives
  on interpolated table identifiers.
- CI across Linux, macOS and Windows: formatting, Clippy with `-D warnings`, tests, a
  minimum-supported-Rust-version job, rustdoc, and `cargo deny`.
- Release automation publishing static musl Linux, macOS and Windows binaries on tag.

### Known limitations

- LLM09 and ZT6 are modelled and correctly typed but have no detector yet. Both are recorded as
  `known_gap` entries in `tests/corpus/expected.toml`.
- `BAS-LLM03-001` recognises `if not X: raise`, `if not X: return` and `assert` as permission
  guards, but not a guard that lives in a decorator, in middleware, or in the API the tool calls,
  so such a tool is still flagged. Its confidence is `medium` for that reason.
- `BAS-LLM03-002` reads a tool name from a `const` binding, but not from the property-key form
  that 100 of 122 real registrations use; that shape stays a `known_gap`, because `ast-grep`'s
  JavaScript patterns cannot express it without matching approximately.
- The dataflow tier is Python only, single-file, and does not chain call relations past depth one.
- Container analysis stops at Dockerfiles and Docker Compose files; Terraform and Kubernetes
  manifests are not parsed.
- No `bastyn.yaml` configuration yet; rule severities are fixed.
- No prompt-injection classifier, so injection text sitting in a string literal is not detected.

Detection gaps are recorded in `tests/corpus/expected.toml` with the code shape and the reason
for each, as `known_gap` (a real defect the engine misses) or `known_false_positive` (a rule
reports something it provably should not, and cannot yet be told not to). The two are separate
debts and are counted separately. Both counts are enforced in CI and can only shrink at any
single point in time. This paragraph prints no number, because it drifts every time a language or a rule is
added. See [Measured coverage](README.md#measured-coverage) for the current count, always derived
from the gate rather than typed in here.

[Unreleased]: https://github.com/BASTYN-labs/bastyn-scan/compare/v0.1.6...HEAD
[0.1.6]: https://github.com/BASTYN-labs/bastyn-scan/releases/tag/v0.1.6
[0.1.5]: https://github.com/BASTYN-labs/bastyn-scan/releases/tag/v0.1.5
[0.1.4]: https://github.com/BASTYN-labs/bastyn-scan/releases/tag/v0.1.4
[0.1.3]: https://github.com/BASTYN-labs/bastyn-scan/releases/tag/v0.1.3
[0.1.2]: https://github.com/BASTYN-labs/bastyn-scan/releases/tag/v0.1.2
[0.1.1]: https://github.com/BASTYN-labs/bastyn-scan/releases/tag/v0.1.1
[0.1.0]: https://github.com/BASTYN-labs/bastyn-scan/releases/tag/v0.1.0
