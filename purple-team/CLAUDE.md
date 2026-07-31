# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Claude Code project (no application code, no build/test tooling) that
orchestrates a purple team exercise loop entirely through Claude Code
customizations: skills (slash commands), an agent, and one MCP server.
There's nothing to build or test — "development" here means editing the
markdown files under `.claude/` that define this behavior.

## Repository structure

- `.claude/commands/*.md` — skill definitions invoked as slash commands.
  Each file is a prompt template with YAML frontmatter (`name`,
  `description`) that Claude follows when the user types the command.
  - `/ingest-ti <url>` (`ingest-ti.md`) — fetch a threat intel report
    (via `defuddle-cli` or web fetch), extract TTPs, map to MITRE ATT&CK
    IDs, and produce a phased simulation plan.
  - `/query <search>` (`query.md`) — translate a request into a SIEM
    query (Splunk SPL by default), run it, map results to ATT&CK, and
    generate an Obsidian-compatible investigation note (uses
    `[[backlink]]` syntax for graph view).
  - `/purple-loop` (`purple-loop.md`) — an 8-step orchestration script
    that chains the above: threat intel → atomic-mapper test planning →
    execution checklist → hayabusa detection analysis → `/query` SIEM
    validation → gap analysis (tested vs. detected) → DOCX/PPTX report →
    Vectr tracking reminder. This is the top-level entry point for a full
    exercise; it calls the other skills/agent rather than duplicating
    their logic.
- `.claude/agents/atomic-mapper.md` — agent that maps a list of ATT&CK
  technique IDs to executable Atomic Red Team tests, filtered for the
  Windows/ConDef lab (minimal prerequisites, clear telemetry, lab-safe),
  and outputs `Invoke-AtomicTest` run + cleanup commands per technique.
- `.claude/settings.json` — sets `enableAllProjectMcpServers: true`, so
  `.mcp.json` servers load automatically without a per-server prompt.
- `.mcp.json` — configures the `hayabusa` MCP server as a local Python
  process (`/Users/milena/mcp-hayabusa/.venv/bin/python server.py`,
  cwd `/Users/milena/mcp-hayabusa`). This is a machine-specific absolute
  path outside this repo — if `hayabusa` tools aren't available, check
  that venv exists first. Used for EVTX analysis and threat hunting
  (exposes `get_hayabusa_rules` and `scan_evtx`).
- `exercises/` and `reports/` — currently empty; output locations for
  exercise runs (see structure below) and generated DOCX/PPTX reports.

## Exercise output structure

`/purple-loop` and the skills it calls expect exercises under
`exercises/YYYY-MM-DD/`:
- `evtx/` — collected event logs exported after Atomic Red Team execution
- `findings.md` — hayabusa/SIEM detection results
- `report.md` — exercise summary

## Lab environment (ConDef)

Atomic tests, expected telemetry, and SIEM queries in these skills all
assume this lab topology:
- **DC** — Domain Controller
- **Win11v** — Workstation with Sysmon installed (primary simulation target)
- **Splunk** — SIEM used for detection validation (`/query` defaults to SPL)

## Editing these skills

When changing a skill's `## Output Format` section, keep it consistent
with what downstream steps in `/purple-loop` expect to consume (e.g.
`/query`'s Obsidian note format feeds Step 5's SIEM validation, and
atomic-mapper's telemetry list feeds Step 4's hayabusa comparison in the
gap analysis at Step 6).
