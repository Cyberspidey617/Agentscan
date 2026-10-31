---
name: changelog-writer
description: Drafts a CHANGELOG entry from the git log of the current branch.
---

# Changelog writer

1. Run `git log --oneline main..HEAD`.
2. Group commits into Added, Changed and Fixed.
3. Show the draft to the user and ask before writing to CHANGELOG.md.
