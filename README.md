<h1 align="center">Bastyn</h1>

<p align="center">
  <strong>A single-binary security scanner for AI and agent code.</strong><br>
  Written in Rust. One executable, with no runtime, no JVM and no Python environment to install alongside it.
</p>

<p align="center">
  <a href="https://github.com/BASTYN-labs/bastyn-scan/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BASTYN-labs/bastyn-scan/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <a href="https://github.com/BASTYN-labs/bastyn-scan/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/BASTYN-labs/bastyn-scan?sort=semver&display_name=tag"></a>
  <img alt="MSRV" src="https://img.shields.io/badge/rustc-1.88%2B-orange.svg">
  <img alt="Platforms" src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg">
  <a href="CONTRIBUTING.md"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg"></a>
</p>

---

> **Status: alpha.** `bastyn scan` finds real issues today: 43 AST rules over Python, TypeScript and JavaScript across the OWASP GenAI and Anthropic Zero Trust categories, plus MCP manifest inspection, Dockerfile and Docker Compose inspection, a hidden-Unicode scan of agent instruction files, and CVE matching against OSV. The embedded prompt-injection classifier is not built yet. See [Measured coverage](#measured-coverage) for what the test corpus does and does not prove, and [Roadmap](#roadmap) for what is missing.

## Why Bastyn

Scanners get dropped from a developer's loop for two reasons: installing one is its own project, and the report is mostly things that are not wrong. Bastyn is built against both.

- **One static binary.** `cargo build --release` produces a self-contained executable. No interpreter, no `node_modules`, no container.
- **Defects and observations are separate.** A control the repository merely lacks is not filed as a bug and cannot fail your build. See [Defects and observations](#defects-and-observations).
- **Deterministic offline.** Sorted relative paths and a stable JSON contract, so `--offline` reports diff cleanly across runs and CI jobs. A default online run can differ as OSV's advisory data changes, even over unchanged code.
- **Fails loudly.** An unreadable directory is an error, not a quietly smaller result set. A security tool that under-reports is worse than one that stops.

No wall-clock benchmark has been published, so this README does not claim one.

## Install

Requires Rust 1.88 or newer ([rustup.rs](https://rustup.rs)).

```console
git clone https://github.com/BASTYN-labs/bastyn-scan.git
cd bastyn-scan
cargo build --release
./target/release/bastyn --version
```

`cargo install --path crates/bastyn-cli` puts it on your `PATH`. Tagged releases also publish binaries for Linux, macOS and Windows on the [releases page](https://github.com/BASTYN-labs/bastyn-scan/releases).

## Usage

A complete run, pasted verbatim, over a three-file project: an `agent.py` that passes a model reply to `eval()` and asks for a completion with no token ceiling, a `config.py` holding a provider key as a literal, and a `requirements.txt` of three pinned dependencies.

```console
$ bastyn scan
Bastyn scan: .
Mode: online

[ok] Discovered source tree
[ok] Analysed 3 files with 43 rules
[ok] Parsed 3 dependencies
[ok] OSV vulnerability lookup - 3 dependencies checked

RESULT: FAILED
2 defects found: 2 critical
1 observation hidden - use --show-observations

Findings
--------

CROSS-LAYER - present at more than one ring
-------------------------------------------
CRITICAL  BAS-LLM10-001  agent.py:19
Model output executed as code
Confidence: high | Categories: LLM10, ZT4

  A value that came from a model call is executed as Python, either directly
  by eval()/exec() or by a function in this file that passes it straight
  through to one. A model reply is untrusted input; running it is arbitrary
  remote code execution the moment an attacker can influence what the model
  says.

  Fix:
  Never execute model output. If the agent needs to run model-suggested logic,
  parse it into a constrained, whitelisted set of operations (a small
  interpreter or a JSON tool-call schema) instead of eval/exec.


MISSING DEFENSES - controls that would have broken the chain
------------------------------------------------------------
CRITICAL  BAS-ZT1-001  config.py:1
Hardcoded API key
Confidence: high | Category: ZT1

  A provider API key is a literal in source rather than read from the
  environment or a secret manager. It ships with every clone of the repo,
  every log of the source, and every fork.

  Fix:
  Load the key from an environment variable or secret manager
  (os.environ["OPENAI_API_KEY"]) and rotate the key that leaked into history.


Coverage gaps
-------------
Every file the scan reached was analysed.
3 dependencies were checked against the OSV vulnerability database.


Compliance crosswalk
--------------------
Which framework areas these findings touch. Not a compliance assessment.

EU AI Act *  |  Regulation (EU) 2024/1689
  Art. 15 - Accuracy, robustness and cybersecurity                   2 defects

NIST AI RMF 1.0 **  |  NIST AI 100-1
  MEASURE 2.7 - AI system security and resilience                    2 defects

NIST Generative AI Profile **  |  NIST AI 600-1
  Information Security                                               2 defects

* Articles 12, 14 and 15 sit in Chapter III, Sections 1 to 3, which apply from
  2 December 2027 for AI systems classified as high-risk under Article 6(2)
  and Annex III, and from 2 August 2028 under Article 6(1) and Annex I -
  Article 113 as amended by Regulation (EU) 2026/1744. They bind high-risk AI
  systems only, and nothing in a source tree says whether this system is one.

** Voluntary guidance, not a regulation. Its subcategories describe outcomes
   an organisation works towards, not conditions a repository can be measured
   against.

A source scan cannot determine legal compliance. It does not establish
applicability, system classification, or the presence of organizational and
deployment controls. Finding nothing does not mean an obligation is met.

Scan complete: 2 defects, 1 observation, 0 coverage gaps
Exit status: 1
```

The report reads top to bottom as four answers: what ran, what the verdict is, what to fix, and what the scan did not see. `RESULT` and `Exit status` come from the same value the process returns, so they cannot disagree with `$?`. No line exceeds 78 columns.

That run was captured with stdout redirected to a file, which is why the ticks, rules and daggers are `[ok]`, `-` and `*`. In a terminal they are `✓`, `─` and `†`, and typographic quotes and middots keep their Unicode too. `NO_COLOR` forces the same ASCII fold. `--no-color` is a separate question and only suppresses ANSI escapes.

When stdout is not carrying the text report, because it is redirected or `--format json`/`--format sarif` is in use, a one-line verdict goes to stderr instead:

```console
$ bastyn scan --format json > findings.json
✖ 2 defects found (2 critical)
```

`✓ No defects found` is the other half. `--quiet` suppresses both.

### Defects and observations

A **defect** is wrong however you deploy. Running model output through `eval` is a defect in every architecture, so it is shown by default and it can fail your build.

An **observation** is a control the repository shows to be absent, without showing that its absence is wrong. "No authentication" is not a bug in a public chatbot. "No rate limiting" usually means the limiter is at the edge, where a scanner cannot see it. Observations are hidden unless you ask for them with `--show-observations`, and they never fail a build at any severity. That distinction is the whole design. Scanners that file missing controls as bugs are why developers stop running scanners.

Test code is held to the same rules and reported differently. A password invented so a test suite can reach a throwaway container is not a credential anybody can use, so a finding in a test path is reported as an observation rather than a defect. The exact path list is in `crates/bastyn-core/src/test_path.rs`, and a directory that merely contains the letters "test" (`latest/`, `contest/`) is not one. Nothing is dropped: `--show-observations` still shows every one, because a real secret does sometimes get committed to a fixture. Four rules match a live provider-key literal and opt out of the downgrade, so they keep reporting as defects wherever they fire.

### Flags

| Flag | Effect |
| --- | --- |
| `[PATH]` | Directory to scan (default: `.`) |
| `--fail-on <LEVEL>` | Minimum severity that exits non-zero: `none`, `low`, `medium`, `high` (default), `critical` |
| `--show-observations` | Show context-dependent observations too |
| `--offline` | Skip the CVE lookup, the only step that uses the network |
| `-f`, `--format <FORMAT>` | `text` (default), `json`, or `sarif` |
| `--group-by <TAXONOMY>` | Which framework to expand in full: `layer` (the default, which expands none and summarises all three), `eu-ai-act`, `nist-ai-rmf`, or `nist-genai`. See [Compliance crosswalk](#compliance-crosswalk) |
| `-q`, `--quiet` | Print only the summary line |
| `--no-color` | No ANSI escapes. `NO_COLOR` is honoured too |
| `--exclude <GLOB>` | Do not scan paths matching `GLOB`, in `.gitignore` syntax. Repeatable. Every path it drops is listed under "Coverage gaps" |
| `--no-ignore` | Ignore `.gitignore`, `.ignore`, `.bastynignore` and Git excludes. `.git/` and `node_modules/` are skipped regardless, since neither holds code the repository's authors wrote |
| `--hidden` | Include dot-files and dot-directories |
| `--follow-symlinks` | Follow symbolic links |
| `--max-depth <N>` | Stop descending after `N` directory levels |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Nothing at or above `--fail-on` |
| `1` | Defects at or above `--fail-on` |
| `2` | The scan could not complete: bad path, unreadable tree, invalid usage |

An execution error outranks findings, so a scan that could not run never returns a `1` you might read as "the code merely has issues". Only defects can produce a `1`; observations never can.

### What it checks

**43 rule ids** over the Python, TypeScript and JavaScript ASTs, via [`ast-grep`](https://ast-grep.github.io), loaded from `crates/bastyn-core/rules/*.yml`. A rule written for JavaScript is compiled against the JavaScript, TypeScript and TSX grammars alike, which is what "JS/TS" means below. Each rule's severity, description and remediation text live in those files, which are the reference this table summarises.

| Rule ids | What they match | Languages |
| --- | --- | --- |
| `BAS-LLM10-001` to `-007` | Model output reaching `eval`/`exec`, a shell command, or a SQL string; `eval`/`exec`/`new Function` on any non-literal expression | Python, JS/TS |
| `BAS-LLM10-010`, `-011`, `-013` to `-016`, `BAS-LLM03-010` to `-012` | Named unsafe library APIs: `allow_dangerous_code`, `allow_dangerous_deserialization`, `allow_dangerous_requests`, `torch.load` without `weights_only`, `yaml.load` without a safe loader, `LLMMathChain`, `PandasQueryEngine`, `PALChain`, a LangGraph serializer with `pickle_fallback` | Python |
| `BAS-ZT1-001` to `-003` and `-010` to `-013`, `BAS-LLM02-001`, `-002`, `-004`, `-005`, `BAS-LLM08-001`, `-002` | Credential literals: provider API keys, a key handed to a client constructor, a bearer token in tool or skill code, a secret inside a prompt template, a default admin password seeded by a setup script | Python, JS/TS |
| `BAS-ZT4-001` to `-003` | Raw user input, or a caller-supplied override, folded into a system prompt | Python, JS/TS |
| `BAS-ZT2-001`, `-002`, `BAS-LLM03-001`, `-002`, `-030` | Wildcard tool grants, and destructive agent tools invoked with no confirmation guard | Python, JS/TS |
| `BAS-ZT5-001`, `-003`, `-004`, `BAS-ZT2-010` | Module-level chat history mutated per request, singleton memory, a literal `thread_id`, a shell middleware with no execution policy. Observations, because whether globally-keyed memory is wrong depends on whether the deployment is multi-tenant, and a source tree does not say | Python |
| `BAS-LLM06-001`, `-002` | An LLM call with no token ceiling. Observations | Python, JS/TS |

Not every rule fires equally well in every language yet, and several of the known gaps are JS/TS-specific.

**One rule does not run on shape alone.** `BAS-LLM10-001` claims a value came out of a model, and a pattern over the call site cannot know that. So a structural match on `eval($ARG)`/`exec($ARG)` is handed to a second tier, `crates/bastyn-core/src/flow/`, which builds a per-file dataflow graph and drops the match unless `$ARG` traces back to a model call or to a local function that returns one. The graph is Python-only, single-file, and follows local calls one level deep. Where it cannot prove a single origin it answers "unknown", which never satisfies the gate, so an unresolvable value produces silence rather than a guess. `crates/bastyn-core/tests/brittleness_gate.rs` measures what that bought over the identifier-name gate it replaced: 0 of 10 realistic renamings of the identical bug survived the name gate, 10 of 10 survive the provenance gate, and the eight innocent `json.load`-sourced samples the rule must not fire on stay rejected. Thirteen name gates on other rules have not been migrated.

Four more checks are built into the engine rather than written as rules:

- **MCP manifests** (`BAS-MCP-000` to `-005`, `BAS-LLM03-020`). `mcp.json`, `.mcp.json`, `claude_desktop_config.json` and the YAML and TOML equivalents, all parsed into one model so a check cannot differ by file type. A manifest that does not parse, root or broad filesystem grants, unauthenticated plaintext HTTP, wildcard tool grants, credentials in a server's environment, an `autoApprove`/`alwaysAllow` wildcard, and a server launched from a registry with no version pin. `npx -y @scope/server-x` resolves to whatever the registry serves when the agent starts, so code inside the trust boundary can change with no change to your repository; a pinned server (`npx -y @scope/server@1.2.3`, `uvx server@1.2.3`) is resolved and queried against OSV like any other dependency, though it appears in no `package.json`. Bastyn does not inspect a server's own source.
- **Agent instruction files** (`BAS-LLM01-001`). A byte-level scan of `SKILL.md`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `*.prompt` and every MCP file above, for codepoints that render as nothing: the zero-width characters, the five bidi override and embedding controls, and the Unicode tag block. A human reviewing the diff sees only the visible text while the model reads the hidden payload too. Ordinary non-ASCII text is never flagged, and a `U+FEFF` at the very first byte is read as a byte-order mark.
- **Container configuration** (`BAS-INFRA-001` to `-006`, `-010`). Dockerfiles and Compose files: `USER root` as the effective final user, a provider key or password in `ENV`/`ARG` or a Compose `environment:`, a `/var/run/docker.sock` mount, `privileged: true`, `network_mode: host`, `pid: host`. ZT3, meaning no sandbox boundary, is close to undetectable in application source because the boundary is not expressed there. It is expressed mechanically here. `BAS-INFRA-001` files an explicit root user as a defect and a missing `USER` instruction as an observation: 35 of the 57 Dockerfiles in the calibration corpus carry no `USER` at all, so filing each as a defect would drown the one case that is unambiguous.
- **Dependencies** (`BAS-CVE-001`, `BAS-LLM04-001`). `requirements.txt`, `pyproject.toml`, `package.json` and `Cargo.toml`, matched against [OSV.dev](https://osv.dev) with no API key and no account. One finding per vulnerable dependency rather than per advisory, since a package with eleven advisories is still one upgrade to make; every CVE and GHSA id is kept in the report's `references` field and in the SARIF result properties. An unpinned range is reported as unchecked rather than guessed at. `BAS-LLM04-001` is a separate low-severity observation and the one dependency check that needs no network: an agent framework, the MCP SDK or a model-provider SDK pinned to a genuine wildcard or to a range with no upper bound. A caret or tilde range is the bounded default of `npm install` and Poetry, and is not this finding.

Terraform and Kubernetes are not covered. Across 65 real third-party AI repositories, Terraform appears in three and genuine Kubernetes manifests total 21 files, which is not yet evidence enough to build against.

### What it does not scan

Three things are left out on purpose, and all three are listed in the report's "Coverage gaps" section, or in the `skipped` array under `--format json`. Skipping is an attack surface: "put it in `dist/`" is a real move against a scanner, so nothing is dropped without the report saying so and saying why.

- **Minified bundles.** Committed bundler output is vendor code nobody in the repository wrote, and its remediation is "rebuild it", which no rule can say. It is also where a scan's time and memory go: one calibration-corpus repository commits seven Next.js bundles under `_next/static/`, three of them 20 MB on effectively one line, and parsing them accounted for two thirds of that repository's scan time and 6.5 GB of its peak memory. The verdict comes from the bytes, not the path, as mean line length over a bounded prefix. A directory blocklist was measured and rejected, because 60 of the 417 source files under a `static/` directory in that corpus are handwritten browser JavaScript. See `crates/bastyn-core/src/generated.rs` for the table.
- **`.bastynignore`.** Same syntax as `.gitignore`, and a different statement: "tracked, but not worth scanning". A repository has every reason to commit a vendored bundle and still not want it analysed. Honoured per directory; `--no-ignore` turns it off.
- **`--exclude <GLOB>`.** For a repository you do not own and cannot add a file to. Unlike the ignore files it survives `--no-ignore`, because an instruction typed on the command line is not a file the repository left lying around.

### The network, and the kill switch

The CVE lookup is the only thing that touches the network. It sends dependency names and versions to OSV, never your code and never your findings. This is what `npm audit` and `pip-audit` already do.

With no connection, Bastyn skips CVEs and says so under "Coverage gaps", with the reason on the line. It never hangs, never fails the scan because OSV is down, and never reports zero CVEs as though the check had run. `--offline` forces the skip.

### Output for machines

`--format json` writes one object. Abridged below, with the field names and values from the same three-file project:

```json
{
  "bastyn_version": "0.1.0",
  "root": ".",
  "summary": {
    "files_scanned": 3, "files_skipped": 0,
    "defects": 2, "observations": 1
  },
  "cve": { "status": "checked", "dependencies": 3 },
  "findings": [ ... ],
  "crosswalks": [ ... ]
}
```

`observations` is `1` where the text report said "1 observation hidden": the count is of what the scan found, not of what was printed. `findings` carries observations only under `--show-observations`. A `skipped` array appears alongside them when the scan skipped anything, and is omitted entirely when it did not, so an empty array can never be mistaken for "nothing was checked". Field names are a contract: fields may be added, existing fields keep their names and meanings.

`--format sarif` emits SARIF 2.1.0 for GitHub Advanced Security and GitLab. Observations always map to `note` level, so a context-dependent observation can never block a pull request.

### Compliance crosswalk

Every report ends with the areas of the EU AI Act, NIST AI RMF 1.0 and the NIST Generative AI Profile that its findings touch, with counts and no per-finding lines, as in the run above. No flag is needed. `--group-by <framework>` expands one of the three into the findings under each of its areas, quotes every title in full, and leaves the other two out.

**It is a crosswalk, never a verdict.** "Relevant to Art. 15" is the strongest claim it makes. A static scanner cannot determine regulatory compliance. That turns on the deployment context, the system's risk classification under Article 6, and the organisation's documentation and processes, none of which are in a source tree. A clean scan is not evidence that any obligation is met, and the report says so before it groups anything.

The mapping is per category, not per rule, and every identifier is quoted from a primary source with its URL and access date recorded. Two cells are deliberately empty: `LLM06` has no EU AI Act mapping, and `ZT6` has none in the NIST Generative AI Profile. The full table, the reasoning for each row and each blank, and the current application dates are in [`docs/frameworks/compliance-crosswalk.md`](docs/frameworks/compliance-crosswalk.md).

In `--format json` the grouping is a `crosswalks` array with one entry per framework, always in the order EU AI Act, NIST AI RMF 1.0, NIST Generative AI Profile, each indexing into the existing `findings` array. In `--format sarif` each framework is a `taxonomies` entry with `relevant` relationships from each rule, never a `tags` value, because `tags` is what GitHub and GitLab filter on and a framework name there would present a finding as a regulatory violation. Each entry carries the caveat above on itself, so a consumer cannot read the grouping without it.

### GitHub Actions

```yaml
name: Bastyn security scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  bastyn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - name: Scan AI agent code
        uses: BASTYN-labs/bastyn-scan@v0
        with:
          fail-on: high

      # `always()` matters: the scan step fails the job when it finds
      # something at or above `fail-on`, and without this the upload is
      # skipped in exactly the runs that have findings to report.
      - name: Upload results to code scanning
        if: always() && hashFiles('bastyn.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: bastyn.sarif
          category: bastyn
```

## Measured coverage

A corpus under [`tests/corpus/`](tests/corpus/) specifies what should and should not be found, and a gate measures the engine against it on every push. Its output, verbatim, from `cargo test -p bastyn-core --test corpus_gate -- --nocapture`:

```
corpus: 47/47 planted defects found   (found 100%)
        0 unexpected findings             (precision 100%)
        12 known gaps (+8 reachable only with a network connection)
        2 known false positives (precision debt -- tracked separately from known gaps, see MAX_KNOWN_FALSE_POSITIVES)
```

Every fixture in that corpus is one we wrote, so "47/47" is a regression alarm and not a coverage figure: the engine finds 47 of 47 defects *we planted*, and real-world recall is unmeasured. A more honest single number folds the known gaps back in, at 47/(47+12) ≈ 80% of planted defects, excluding the 8 gaps that are unreachable only because CI runs `--offline`.

The gaps are published rather than hidden. Each one names the code shape we miss and why, in [`tests/corpus/expected.toml`](tests/corpus/expected.toml), and the count fails the build if it grows. The two known false positives are ratcheted on a separate line, because a recall gap and a precision gap are not the same problem.

Of the 19 framework categories Bastyn maps to (see [`docs/frameworks/`](docs/frameworks/)), 12 have a detector behind them: LLM01, LLM02, LLM03, LLM04, LLM06, LLM08, LLM10, ZT1, ZT2, ZT3, ZT4, ZT5. LLM09 and ZT6 are recognised categories with no detector yet, and the remaining five (LLM05, LLM07, ZT7, ZT8, ZT9) are not code-detectable at all, as `tests/corpus/vulnerable/NOT_DETECTABLE.md` sets out. Having a detector for a category is not the same as covering it, and the published gaps sit inside categories that are in this count.

`bastyn scan .` on this repository exits 1, because `tests/` holds the planted fixtures the gate exists to find. Run `bastyn scan . --exclude tests/` instead.

## Architecture

```
bastyn-scan/
├── crates/
│   ├── bastyn-cli/     # Binary: argument parsing, rendering, exit codes
│   └── bastyn-core/    # Library: traversal and analysis
└── .github/workflows/  # CI and release automation
```

Everything that is not tied to a terminal lives in `bastyn-core`, which keeps the engine independently testable and embeddable. The CLI is a presentation layer over a library API, not the other way round.

| Concern | Choice |
| --- | --- |
| CLI | [`clap`](https://docs.rs/clap) (derive) |
| Config and reports | [`serde`](https://serde.rs) / JSON, [SARIF](https://sarifweb.azurewebsites.net) |
| Traversal | [`ignore`](https://docs.rs/ignore), the walker behind ripgrep |
| Parallelism | [`rayon`](https://docs.rs/rayon) |
| Parsing and matching | [`ast-grep`](https://ast-grep.github.io), over [`tree-sitter`](https://tree-sitter.github.io) grammars |
| Manifests | [`serde_json`](https://docs.rs/serde_json), [`serde_yaml_ng`](https://docs.rs/serde_yaml_ng), [`toml`](https://docs.rs/toml) |
| OSV lookup | [`ureq`](https://docs.rs/ureq) |

There is no model and no inference engine in the binary. The prompt-injection classifier on the [Roadmap](#roadmap) is unbuilt. When it lands, the intent is a pure-Rust ONNX runtime so that the single-binary property survives it, with no `libonnxruntime` to ship alongside the executable, but nothing has been added to `Cargo.toml` yet.

## Roadmap

- [x] `bastyn scan`, with deterministic output offline; online runs may vary as OSV's advisory data changes
- [x] AST rules over Python, TypeScript and JavaScript, via tree-sitter and `ast-grep`
- [x] Corpus gate in CI
- [x] MCP manifest inspection: JSON, YAML, TOML
- [x] CVE matching against OSV, with an automatic offline kill switch
- [x] JSON, SARIF 2.1.0 and terminal output from one report model
- [x] GitHub Action
- [ ] `bastyn.yaml` configuration and per-rule severity
- [ ] ONNX-backed classification of prompt-injection text in string literals
- [ ] `bastyn graph`, for cross-file taint analysis

## Development

```console
cargo build                              # compile
cargo test --workspace                   # unit, integration, and doc tests
cargo clippy --all-targets -- -D warnings  # lints
cargo fmt --all --check                  # formatting
cargo deny check                         # licenses and advisories
```

CI runs the same commands on Linux, macOS and Windows, plus a job pinned to the minimum supported Rust version.

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), and note that participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). To report a security issue in Bastyn itself, follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Contributions are accepted under the same terms, per section 5 of the license.
