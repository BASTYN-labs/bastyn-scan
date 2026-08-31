# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report it privately through either channel:

- **Preferred.** [GitHub private vulnerability reporting](https://github.com/BASTYN-labs/bastyn-scan/security/advisories/new), which keeps the discussion attached to the repository.
- **Email.** security@bastyn.ai

Please include:

- The version or commit affected (`bastyn --version`).
- Your platform and Rust version, if you built from source.
- What an attacker gains, and what access they need to get it.
- Steps or a minimal repository that reproduces the issue.

You do not need a working exploit. A clear description of the flaw is enough.

## What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | 3 working days |
| Initial assessment and severity | 10 working days |
| Fix released, or a dated plan if the fix is involved | 90 days |

We will keep you updated as the assessment progresses, credit you in the advisory and release notes unless you ask us not to, and coordinate disclosure timing with you. If we conclude a report is not a vulnerability, we will explain why rather than closing it silently.

## Scope

**In scope:** anything that lets untrusted input compromise the machine running Bastyn, or that causes Bastyn to under-report.

- Arbitrary code execution, path traversal, or file writes outside the scanned tree, triggered by a repository's contents, filenames, or configuration.
- Crashes, hangs, or unbounded memory growth from malformed input. A scanner that dies on a hostile file is a denial of service on the CI job that runs it.
- Silently skipping files that should have been analysed. A scanner that under-reports gives false assurance.
- Leaking scanned source code, credentials, or environment contents anywhere outside the requested output.
- Vulnerabilities in Bastyn's dependency tree that are reachable from Bastyn's own code paths.

**Out of scope:**

- Missed findings from rules that are not implemented yet. Bastyn does not aim to detect every class of vulnerability, and a category with no detector behind it is a coverage gap rather than a flaw in the tool. [`docs/frameworks/README.md`](docs/frameworks/README.md) records which categories currently have one. This covers only the case where no rule inspects the pattern at all. A file an existing rule should have seen and did not is the in-scope under-reporting bug above.
- False positives and false negatives in implemented rules. These are correctness bugs; open a normal issue.
- Vulnerabilities in the code Bastyn is scanning. That is the output, not a flaw in the tool.
- Findings that require an attacker to already have code execution on the machine running Bastyn.

## Supported versions

Bastyn is pre-1.0 and under active development. Security fixes land on `main` and in the next release; there are no long-term support branches yet. Run the latest release.

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |
| Older | No |

## Our own supply chain

`cargo deny` runs in CI against every pull request, checking dependency licenses and the [RustSec advisory database](https://rustsec.org). Dependabot opens pull requests for dependency and GitHub Actions updates. Release binaries are built by GitHub Actions from a tagged commit. The workflow that builds them is [`.github/workflows/release.yml`](.github/workflows/release.yml), so anyone can check what went into an artifact.
