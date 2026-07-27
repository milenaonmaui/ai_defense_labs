# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository structure

This is not a single application — it's a loose collection of independent
security/defense lab subprojects, each self-contained in its own top-level
directory with its own `CLAUDE.md`. There is no shared build system,
dependency manifest, or code between them. When working inside one of these
directories, read (and keep up to date) its local `CLAUDE.md` rather than
looking for repo-wide tooling.

- **`sysmon-parser/`** — single-file Python 3 stdlib script (`parser.py`) that
  parses Sysmon Event ID 1 (Process Creation) XML logs, with `--image`,
  `--user`, and `--integrity-level` filters and `json`/`jsonl`/`csv` output.
  No external dependencies, no build/test tooling. See
  `sysmon-parser/CLAUDE.md` for field list, usage examples, and the
  streaming-parse architecture (`iter_events()` uses `ET.iterparse()` +
  `element.clear()` to keep memory flat).
- **`siem-queries/`** — intended to hold SIEM detection queries (currently
  just one Splunk SPL query in `queries/`). Has a custom slash command,
  `/query` (`siem-queries/.claude/commands/query.md`), which runs an SPL
  query file against Splunk's REST API (requires `SPLUNK_HOST` and
  `SPLUNK_TOKEN` env vars), analyzes results for suspicious activity, maps
  findings to MITRE ATT&CK techniques, and writes an Obsidian-compatible
  markdown investigation note under `siem-queries/investigations/`.
- **`detection-workflow/`** — a Claude Code `PostToolUse` hook
  (`scripts/validate-rule.sh`) that validates detection rule YAML files
  under `rules/` on write/edit (checks `title`, `description`, and an
  `attack.t*` MITRE tag). See `detection-workflow/CLAUDE.md`.
- **`complex-analysis/`** — pre-implementation; no code yet. Intended for
  repeatable multi-step analysis workflows: threat intel processing
  (ingest reports, extract TTPs, produce simulation plans) and multi-source
  investigation (correlate Windows Security, Sysmon, Azure AD sign-in, and
  Azure AD audit logs). See `complex-analysis/CLAUDE.md`.
- **`hello.txt`** — placeholder file, not part of any project.

## Working across subprojects

- Treat each top-level directory as its own project root. Don't assume
  changes in one affect another.
- If a subproject directory gains real content (e.g. `detection-workflow/`
  or `siem-queries/queries/`) or its structure changes materially, update
  that subdirectory's own `CLAUDE.md` (re-running `/init` there is
  reasonable) rather than this root file.
