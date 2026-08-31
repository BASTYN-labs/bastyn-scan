## What this changes

<!-- What the change does, and why it is needed. Link the issue if there is one. -->

## How it was verified

<!-- The commands you ran and what they showed. "Should work" is not verification. -->

```console
$ cargo test --workspace

```

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] Behavioural changes have tests covering them
- [ ] User-visible changes are noted in `CHANGELOG.md` under `[Unreleased]`

## Contracts

- [ ] This does **not** change the meaning of exit code `0`, or the `--format json` shape

<!-- If either changes, say so explicitly here. It is a breaking change. -->
