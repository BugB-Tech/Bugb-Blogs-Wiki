---
title: "Continuous Threat Modeling as Code: AI Agents, Claude Code, and the CI Fix Loop"
slug: "continuous-threat-modeling-as-code-with-ai-agents"
date: "2026-03-02"
author: "Bugb Security Team"
authorTitle: "Security Researchers"
excerpt: "This is how I run continuous threat modeling as code with GuardLink after the initial bootstrap: AI agents maintain the model in source, Claude Code consumes it to remediate issues, and CI enforces posture over time."
category: "research"
---

# Continuous Threat Modeling as Code: AI Agents, Claude Code, and the CI Fix Loop

## Summary

If the first step is bootstrapping a threat model into the codebase, the next step is keeping it alive.

That is the harder problem, and it is the one most teams never solve.

Most teams still threat model like it is 2015: workshop, diagram, wiki page, and then silence. The code keeps shipping. The threat model rots.

I do the opposite after day one.

I keep the threat model in the repository, directly inside the code, and I let AI agents maintain and consume it continuously. GuardLink is the layer that makes that possible. It turns security annotations in source comments into a structured threat model that can be validated, diffed, queried, exported, and enforced in CI.

With GuardLink, threat modeling becomes a continuous engineering loop:

1. AI agent writes or updates code.
2. AI agent adds or updates GuardLink annotations in the same change.
3. GuardLink parses those annotations into a live threat model.
4. AI agents like Claude Code consume that model through MCP tools and repo instructions.
5. The agent fixes issues, updates annotations, and revalidates the model.
6. CI blocks new unmitigated exposures.

That is the model I want: not a one-time security artifact, but a security feedback loop that stays attached to the repository.

That is what I mean by continuous threat modeling as code.

## Why Continuous Threat Modeling Matters

Threat modeling fails when it is disconnected from engineering.

The usual failure mode looks like this:

- architecture review happens once
- a document gets written
- code changes immediately after
- nobody updates the model
- scanners produce noisy output with weak context
- remediation becomes reactive and expensive

The model is stale because it lives outside the software delivery loop.

Continuous threat modeling fixes that by putting the model where engineering already works:

- in code
- in git
- in pull requests
- in CI
- in the tools developers and AI agents already use

## What GuardLink Changes

[https://guardlink.bugb.io](GuardLink) stores security intent as structured comments next to security-relevant code.

Example:

```ts
// @exposes App.API to #idor [P1] cwe:CWE-639 -- "[external] User-controlled object ID is fetched without ownership validation"
// @audit App.API -- "Needs human review for tenant isolation rules"
// @flows User -> App.API via HTTPS -- "Receipt fetch request"
app.get('/receipts/:id', getReceipt);
```

Or when the code is already defended:

```ts
// @mitigates App.API against #sqli using #prepared-stmts -- "Parameterized query prevents SQL injection"
// @flows App.API -> Database via PostgreSQL -- "Lookup by bound parameter"
// @handles pii on App.API -- "Processes user email and account identifiers"
const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
```

Those annotations become a machine-readable threat model.

Now the repo has a live security graph:

- assets
- threats
- controls
- mitigations
- exposures
- trust boundaries
- data flows
- sensitive data handling
- audits and validation notes

This is the foundation that AI agents can use.

## The Big Shift: AI Does Not Just Write Code, It Maintains the Security Context

This is the part most teams miss.

If you let an AI coding agent write handlers, database queries, auth flows, file operations, and API integrations, but you do not give it a structured way to capture security context, then you are still doing after-the-fact security.

GuardLink changes that.

After `guardlink init`, the repo gets agent instructions and, for supported agents, MCP integration. That means the AI agent is explicitly told:

- when code touches a security boundary, add GuardLink annotations
- reuse existing asset, threat, and control IDs
- write complete annotation blocks, not isolated comments
- validate the model after changes

So the same agent writing the code also updates the threat model.

That is the key to keeping the model continuous instead of stale.

## From Bootstrap to Continuous Operation

The first article in this series is the bootstrap story: get GuardLink into the repo, annotate the codebase, parse the model, validate it, and generate reports.

This article starts after that.

Once the initial model exists, the question changes from:

- how do I create a threat model fast?

to:

- how do I keep it current on every code change?
- how do I let AI agents use it to remediate issues?
- how do I stop threat posture regressions in CI?

That is where continuous threat modeling starts.

## Terminal Walkthrough: Starting in the Repo Root

This is the workflow from a terminal, starting in the root of a repository.

```bash
pwd
```

```bash
/Users/me/dev/my-app
```

### 1. Initialize GuardLink in the repository

```bash
guardlink init
```

What this sets up:

- `.guardlink/` for definitions and config
- `docs/GUARDLINK_REFERENCE.md`
- agent instruction files like `CLAUDE.md` or `AGENTS.md`
- `.mcp.json` for Claude Code MCP integration

Now the repo is ready for the ongoing loop, not just the first annotation pass.

### 2. Start the first annotation pass

I usually kick off an initial pass with a coding agent:

```bash
guardlink annotate "annotate auth, API handlers, DB queries, file I/O, external API calls, process spawning, and config parsing" --claude-code
```

Or:

```bash
guardlink annotate "annotate auth, API handlers, DB queries, file I/O, external API calls, process spawning, and config parsing" --codex
```

This gives the agent a GuardLink-specific prompt with project context, existing IDs, current flows, open exposures, and GAL syntax guidance.

The agent reads the codebase and writes security annotations directly into the source files.

### 3. Parse and validate the model

Once the initial annotation pass is done:

```bash
guardlink parse .
guardlink validate .
```

This gives me a real threat model generated from the code and confirms the annotations are structurally valid.

### 4. Check what is still open

```bash
guardlink status .
```

Then:

```bash
guardlink scan .
guardlink unannotated .
```

Now I know:

- what has been modeled
- what is still unannotated
- what exposures exist
- what lacks mitigation

That output becomes the working set for the next AI remediation pass.

That is where the continuous loop starts to matter.

## How Claude Code Consumes the Threat Model

This is where the workflow stops being "AI writes code" and becomes "AI reasons over a live security model."

Claude Code is not just another editor with autocomplete. With GuardLink, it can consume the threat model as structured security context instead of trying to infer everything from raw code.

GuardLink exposes MCP tools that Claude Code can use, including:

- `guardlink_parse`
- `guardlink_validate`
- `guardlink_status`
- `guardlink_lookup`
- `guardlink_suggest`
- `guardlink_threat_report`
- `guardlink_annotate`
- `guardlink_diff`
- `guardlink_report`
- `guardlink_dashboard`
- `guardlink_sarif`

This means Claude Code can do workflows like:

1. parse the current model
2. inspect unmitigated exposures
3. look up the affected assets and threats
4. open the relevant files
5. implement the remediation
6. update the GuardLink annotations
7. validate the model again
8. diff the posture before and after

That is a very different workflow from asking an agent to "fix security bugs" with no structured context, no threat vocabulary, and no repo-native security graph.

## Example: Prompting Claude Code to Fix Issues From the Threat Model

Once GuardLink is initialized and Claude Code has access to the MCP tools, I can give it tasks like:

```text
Read the current GuardLink threat model, identify all unmitigated exposures related to auth, database access, file I/O, and command execution, remediate what can be fixed in code, update annotations, then run validation again.
```

Or more targeted:

```text
Use the GuardLink model to find all open exposures on App.API. For each one, either implement the mitigation in code and add @mitigates, or add @audit with a clear explanation if it requires human review.
```

That prompt works because Claude Code is not starting blind. It can:

- read the threat model
- understand the existing asset and threat IDs
- see the current exposures
- inspect the code locations behind those exposures
- make changes grounded in the repo's own security vocabulary

## The Continuous Fix Loop

A practical loop with Claude Code looks like this:

### Step 1. Inspect posture

```bash
guardlink status .
```

### Step 2. Ask Claude Code to consume the model and fix issues

Example task:

```text
Use GuardLink MCP tools to review the current threat model. Fix unmitigated exposures where code changes are possible, especially SQL injection, path traversal, command injection, and sensitive data exposure. Update the code annotations in the same change and re-run validation.
```

### Step 3. Claude Code works through the model

Under the hood, the agent can:

- call `guardlink_parse` for the full model
- call `guardlink_lookup` to inspect specific threats and controls
- call `guardlink_validate` to check its edits
- call `guardlink_diff` to verify posture improvement

### Step 4. Re-check the repo from the terminal

```bash
guardlink validate .
guardlink status .
guardlink diff --from HEAD~1
```

Now I can see exactly what changed in the security posture, not just what changed in the code.

That is the loop:

1. detect posture
2. consume the model
3. remediate in code
4. update annotations
5. validate
6. diff the result

## The Important Distinction: AI Is Consuming Security Facts, Not Guessing

This is the reason the workflow works well.

Most AI security usage today looks like this:

- paste a file into an LLM
- ask what is wrong
- get generic advice
- hope it maps to reality

That is weak.

With GuardLink, the agent gets structured, code-local, repo-native security context:

- which component is the asset
- which threat applies
- which control exists
- where the boundary is
- what data is handled
- what is still exposed
- what is already mitigated

That reduces ambiguity and makes remediation much more systematic.

## What Continuous Threat Modeling Looks Like Day to Day

The real value is not the first run. The real value is the loop after that.

Here is the day-to-day pattern:

1. A developer or AI agent writes a new endpoint.
2. The agent adds `@flows`, `@exposes`, `@mitigates`, `@audit`, or `@comment` as needed.
3. GuardLink parses the updated model.
4. Claude Code or another agent consumes the model to review posture changes.
5. If a new exposure appears without mitigation, the issue is fixed before merge or explicitly audited.
6. CI enforces that new unmitigated exposures do not silently enter the codebase.

That means the threat model is updated at the same speed as the code.

That is the real operational difference between "threat modeling exercise" and "threat modeling as code."

## Continuous Threat Modeling in CI

This part matters just as much as the AI integration.

I do not want the model to depend on human discipline alone. I want CI to enforce it.

Useful commands:

```bash
guardlink validate .
```

```bash
guardlink diff --fail-on-new
```

```bash
guardlink sarif .
```

This gives me three layers:

- syntax and reference validation
- drift detection for new exposures
- export into normal security tooling

Now threat modeling becomes part of the delivery pipeline, not a separate activity.

This is the final piece of the loop:

- agents keep the model current
- GuardLink validates and diffs it
- CI enforces that posture does not silently degrade

## A Full Continuous Workflow Example

This is what a real cycle can look like from the repo root:

```bash
cd /Users/me/dev/my-app

guardlink init

guardlink annotate "annotate auth, API handlers, DB queries, file I/O, external API calls, process spawning, and config parsing" --claude-code

guardlink parse .

guardlink validate .

guardlink status .

guardlink scan .

guardlink report .

guardlink diff --from HEAD~1
```

Then I hand the next step to Claude Code:

```text
Consume the GuardLink threat model, identify all open exposures without mitigations, fix what can be remediated safely in code, update the annotations, and validate the model again before stopping.
```

Then I verify the results:

```bash
guardlink validate .
guardlink status .
guardlink diff --from HEAD~1
```

That is continuous threat modeling as code in practice: a live model, AI-assisted remediation, and CI-backed enforcement.

## Can AI Agents Really "Fix All the Issues"?

This needs an honest answer.

AI agents can systematically work through a large class of security issues when the problem is represented as code plus structured context. GuardLink gives them that context.

That means agents are very effective at:

- adding missing validation
- parameterizing queries
- tightening file path handling
- reducing unsafe process spawning patterns
- improving config parsing
- removing dangerous data exposure in logs
- adding missing annotations and audits
- reducing open exposures over repeated passes

But not every issue is purely a code fix.

Some findings still require:

- product decisions
- access control design choices
- architectural tradeoffs
- risk acceptance by humans
- operational mitigations outside the repo

So the right framing is not "AI solves security automatically."

The right framing is:

**AI agents can continuously consume the live threat model, remediate what is fixable in code, and surface the rest in a structured way for human review.**

That is already a huge upgrade over ad hoc security reviews.

## Why This Works Better Than Scanner-Only Security

Scanner-only workflows usually fail in one of two ways:

- too much noise
- too little context

Continuous threat modeling as code fixes both.

The model is explicit.

The code locations are explicit.

The threat vocabulary is explicit.

The data flows are explicit.

And the AI agent is not guessing what matters. It is consuming the same threat model your team sees in the repo.

That is why remediation quality goes up when you pair GuardLink with agents like Claude Code.

## The End State I Want

The end state is simple:

- developers write code
- AI agents add security context as they go
- GuardLink turns that context into a living threat model
- Claude Code consumes that model to fix issues continuously
- CI prevents silent threat posture regressions

At that point, threat modeling is not a one-time deliverable.

It becomes part of software development itself.

## The Short Version

If I want continuous threat modeling as code in a repo, this is the rough sequence I use:

```bash
guardlink init
guardlink annotate "annotate auth, API handlers, DB queries, file I/O, external API calls, process spawning, and config parsing" --claude-code
guardlink parse .
guardlink validate .
guardlink status .
guardlink diff --fail-on-new
```

Then I let Claude Code consume the GuardLink model and work through the open exposures with code changes plus annotation updates.

That is the workflow: threat model in code, AI agents maintaining it, Claude Code consuming it for remediation, and CI enforcing it.
