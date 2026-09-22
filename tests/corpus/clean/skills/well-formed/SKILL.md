---
name: changelog-writer
description: Drafts a changelog entry from the commits since the last release tag.
version: 1.0.0
permissions:
  - read
---

# Changelog Writer

Reads the commit log since the last release tag and drafts a changelog
entry grouped by conventional-commit type (feat, fix, chore). Always
presents the draft for review before it is added to CHANGELOG.md.
