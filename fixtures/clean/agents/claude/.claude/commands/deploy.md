---
description: Deploy a branch to staging
argument-hint: <branch>
allowed-tools: Read, Bash(git log *)
---

## Context

- Recent commits: !`git log --oneline -5`

Deploy the branch $ARGUMENTS to staging after checking that it exists with `git rev-parse --verify`.
