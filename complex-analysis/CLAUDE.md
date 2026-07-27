# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This subproject is currently pre-implementation — no code, scripts, or
dependency manifests exist yet. This file describes the intended scope so
future work lands in a consistent structure. Update this file as real
content (scripts, workflows, tooling) is added.

## Purpose

Build repeatable workflows for complex, multi-step security analysis tasks
that go beyond single-query lookups — the kind of work an analyst would
otherwise do by hand across several tools and passes.

## Workflows

1. **Threat intel processing** — ingest threat intel reports, extract TTPs
   (tactics, techniques, procedures), and produce simulation plans from
   them.
2. **Multi-source investigation** — correlate endpoint and cloud log
   sources to investigate an incident or hypothesis across systems.

## Log sources

- Windows Security events
- Sysmon events
- Azure AD sign-in logs
- Azure AD audit logs

## Custom commands

- `/ingest-ti <url>` (`.claude/commands/ingest-ti.md`) — implements the
  threat intel processing workflow. Extracts clean article content from a
  report URL via `trafilatura -u "$url" --markdown`, analyzes it for
  campaign/actor context, maps observed behavior to MITRE ATT&CK TTPs,
  extracts IOCs, and proposes an Atomic Red Team simulation plan. Writes
  results to `analysis/ti-[date]-[campaign-name].md`. Requires
  `trafilatura` (`pip3 install trafilatura`) on PATH.

## Relationship to other subprojects

Per the root `/Users/milena/ai-defense-labs/CLAUDE.md`, each top-level
directory is an independent, self-contained subproject with no shared
build system or code. Sysmon parsing logic already exists in
`../sysmon-parser/` (`parser.py`) — reuse or shell out to it for Sysmon
Event ID 1 log handling rather than reimplementing parsing here, unless
this project's needs diverge significantly.
