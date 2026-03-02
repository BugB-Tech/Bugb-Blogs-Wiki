---
title: "How I Threat Model My Entire Codebase in 5 Minutes With 0 False Positives"
slug: "threat-model-entire-codebase-in-5-minutes"
date: "2026-03-02"
author: "Bugb Security Team"
authorTitle: "Security Researchers"
excerpt: "This is the workflow I use to turn a live codebase into a reviewable, CI-enforced threat model in minutes using GuardLink, with explicit code-local findings instead of noisy scanner guesses."
category: "research"
---

# How I Threat Model My Entire Codebase in 5 Minutes With 0 False Positives

## Summary

Most threat models die as stale documents. The code changes, the architecture changes, the risks change, and the "threat model" becomes a historical artifact nobody trusts.

I wanted the opposite: a threat model that lives in the repo, changes with the code, shows up in diffs, and does not flood me with speculative scanner noise.

That is the workflow I use with GuardLink.

The five-minute claim is real for bootstrapping a codebase into a living model. The "0 false positives" part comes from one key design choice: GuardLink does not try to guess intent from patterns alone. It turns explicit, code-local security annotations into a structured threat model. If an exposure or mitigation appears, it is there because it was intentionally attached to a real code path.

## Why Traditional Threat Modeling Breaks

Most teams still do one of these:

- Run a workshop and draw a diagram.
- Write a document in Confluence or Notion.
- Run a scanner and get hundreds of findings with no context.
- Review security as a separate process after the code is already merged.

All of these create drift.

The root problem is simple: **security knowledge lives outside the code**.

That means:

- Developers do not update it when they change behavior.
- Reviewers do not see it in the diff.
- CI cannot enforce it.
- AI coding tools do not know it exists.

## The Core Idea

GuardLink puts the threat model directly in comments next to the code that matters.

```ts
// @mitigates #api against #sqli using #prepared-stmts -- "Parameterized query blocks SQL injection"
const user = await db.query('SELECT * FROM users WHERE id = $1', [id]);

// @exposes #api to #idor [P1] cwe:CWE-639 -- "[external] Missing ownership check on receipt lookup"
// @audit #api -- "Needs human review for cross-tenant access rules"
app.get('/receipts/:id', getReceipt);
```

Those annotations are parsed into a machine-readable threat model. From there I can:

- validate the model
- check coverage
- generate a report
- generate a dashboard
- export SARIF
- diff threat posture between commits
- fail CI on new unmitigated exposures

That is why the false-positive rate is effectively zero in practice. The system is not inventing findings. It is reading declared security facts attached to specific code.

## What "0 False Positives" Actually Means

This needs precision.

I am not claiming the universe guarantees perfection. If a human writes a bad annotation, the model can still be wrong.

What I mean is:

- GuardLink does not dump speculative findings based on weak pattern matching.
- Every exposure is attached to a specific code location.
- Every mitigation is attached to a specific code location.
- Validation catches malformed syntax and bad references.
- Review happens in the same place as code review.

So the model contains explicit security statements, not scanner guesses.

That changes the workflow from "triage endless noise" to "review concrete security context."

## What I Annotate

I do not annotate everything. I annotate the security boundaries:

- endpoints and request handlers
- authentication and authorization
- database access
- input validation
- file I/O
- external API calls
- crypto operations
- process spawning
- configuration parsing
- trust boundaries
- sensitive data handling

I do **not** annotate pure business logic, formatting helpers, or UI code that never crosses a security boundary.

That keeps the model high-signal.

## Terminal Walkthrough: Starting From Repo Root

This is the exact flow.

You are in the root of your repository:

```bash
pwd
```

```bash
/Users/me/dev/my-app
```

### 1. Initialize GuardLink

```bash
guardlink init
```

What this does:

- creates `.guardlink/`
- creates shared definitions
- adds agent instructions for supported coding agents
- prepares the repo for code-local annotations

At this point, the repo is ready to store a threat model in source comments instead of an external document.

### 2. Start the first annotation pass

From the repo root, I launch annotation with a clear scope:

```bash
guardlink annotate "annotate auth, API handlers, database queries, file I/O, external API calls, and config parsing paths" --codex
```

You can swap `--codex` for another supported agent:

```bash
guardlink annotate "annotate auth, API handlers, database queries, file I/O, external API calls, and config parsing paths" --claude-code
```

Or just copy the prompt if you want to paste it manually:

```bash
guardlink annotate "annotate auth, API handlers, database queries, file I/O, external API calls, and config parsing paths" --clipboard
```

The important part is that the agent is reading the repo and writing annotations next to the code, not producing a disconnected summary.

### 3. Validate the annotations

After the annotation pass finishes:

```bash
guardlink validate .
```

This checks:

- syntax errors
- dangling `#id` references
- duplicate definitions
- general annotation integrity

If validation fails, I fix that immediately before moving on. A broken threat model is worse than none.

### 4. Check posture and coverage

```bash
guardlink status .
```

Typical output is a compact posture summary: assets, threats, controls, mitigations, exposures, and coverage.

Then I check for missing coverage:

```bash
guardlink scan .
```

And I list files that have no annotations yet:

```bash
guardlink unannotated .
```

This shows me where the remaining blind spots are.

### 5. Generate a real threat model report

```bash
guardlink report .
```

Now I have a markdown threat model generated from the annotations already living in the code.

If I want a visual output too:

```bash
guardlink dashboard .
```

That gives me an interactive HTML dashboard over the same structured model.

### 6. Ask for a higher-level analysis

If I want AI-assisted analysis on top of the explicit annotation graph, I run:

```bash
guardlink threat-report stride
```

Or another framework:

```bash
guardlink threat-report dread
guardlink threat-report pasta
guardlink threat-report attacker
```

This is an important distinction: the AI report is **downstream** of the code-grounded threat model. It is not replacing the model.

## A Full Example Session

Here is the workflow as it looks in one terminal session:

```bash
cd /Users/me/dev/my-app

guardlink init

guardlink annotate "annotate auth, API handlers, DB queries, file reads/writes, external API calls, and config parsing" --codex

guardlink validate .

guardlink status .

guardlink scan .

guardlink report .

guardlink dashboard .
```

That is the five-minute bootstrapping flow.

From there, I move into maintenance mode.

## What the Annotation Blocks Look Like

A useful annotation block tells a complete story.

### Example: vulnerable endpoint

```ts
// @exposes App.API to #idor [P1] cwe:CWE-639 -- "[external] User-controlled object ID is fetched without ownership validation"
// @audit App.API -- "Needs authorization review for tenant isolation rules"
// @flows User -> App.API via HTTPS -- "Receipt fetch request"
// @comment -- "Path parameter is used as direct object reference"
app.get('/receipts/:id', getReceipt);
```

### Example: mitigated database query

```ts
// @mitigates App.API against #sqli using #prepared-stmts -- "Parameterized pg query prevents SQL injection"
// @flows App.API -> Database via PostgreSQL -- "Lookup by bound parameter"
// @handles pii on App.API -- "Processes email addresses and account IDs"
const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
```

This is why the output is high-confidence. Each statement is tied to real code behavior.

## Why This Scales Across the Entire Repo

People hear "comments" and assume this will not scale. In practice it scales better than external threat-model documents because it follows normal development ownership.

Each developer updates the security context in the same files they already modify.

That gives me:

- threat model changes in the same commit as code changes
- security context visible in PR review
- machine-readable posture over time
- enforceable CI checks
- AI agent awareness during future edits

The threat model stops being a document and becomes part of the repository itself.

## How I Keep It Current After Day One

The first five minutes are just the start. The real value comes from keeping the model live.

My ongoing loop is:

1. Write or modify security-relevant code.
2. Add or update GuardLink annotations in the same change.
3. Run validation locally.
4. Review posture changes in diff and CI.

Useful commands for that:

```bash
guardlink diff --from HEAD~1
```

```bash
guardlink diff --fail-on-new
```

```bash
guardlink sarif .
```

That means new unmitigated exposures can block a pull request instead of becoming next quarter's surprise.

## Why This Is Faster Than Traditional Threat Modeling

The speed does not come from skipping analysis. It comes from collapsing threat modeling into the development path.

Old model:

- meeting
- whiteboard
- document
- stale artifact
- no enforcement

New model:

- write code
- annotate in place
- validate
- diff
- enforce in CI

That is the real productivity shift.

## Where This Approach Still Has Limits

This is not magic.

There are still real limits:

- unannotated code can still hide risk
- bad annotations can still encode bad assumptions
- governance decisions still need human review
- AI-generated annotations still need verification

So I do not treat GuardLink as an autopilot. I treat it as a structured, reviewable way to keep the threat model attached to the code.

That is a much more defensible system than a stale architecture diagram or a noisy scanner report.

## The Biggest Mindset Shift

The biggest lesson for me was this:

**Threat modeling should behave more like type checking than like a consulting exercise.**

I do not want a quarterly workshop that produces a PDF nobody updates.

I want:

- security context in code
- validation in CI
- posture in diffs
- agent support while coding
- a threat model that evolves with the repo

That is what makes the five-minute workflow possible.

And that is why the "0 false positives" claim is practical: the model is built from explicit security statements tied to real code, not from a tool guessing what might be wrong.

## The Short Version

If I am standing in the root of a repo and I want a live threat model fast, this is what I run:

```bash
guardlink init
guardlink annotate "annotate auth, API handlers, DB queries, file I/O, external API calls, and config parsing" --codex
guardlink validate .
guardlink status .
guardlink report .
```

That gets me from "no threat model" to "living, reviewable, enforceable threat model" in minutes.

And because the findings come from explicit annotations in code, not weak scanner heuristics, I spend my time reviewing real security context instead of dismissing junk.
