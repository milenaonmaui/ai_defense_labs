# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

This repository otherwise has no query content yet. Based on its name, it is intended to hold SIEM queries (e.g., detection rules/searches for a SIEM platform such as Splunk, Elastic, Sentinel, or similar).

No build steps or query architecture exist yet. When query files are added to this repository, re-run `/init` (or ask Claude Code to update this file) so it reflects:
- The SIEM platform(s) targeted and query language(s) used (e.g., SPL, KQL, EQL, Sigma).
- How queries are organized (by data source, MITRE ATT&CK technique, severity, etc.).
- Any validation, linting, or testing tooling for queries.
- Deployment process for pushing queries to the SIEM.

## Custom commands

- **`/query <path-to-query-file> [timerange]`** (`.claude/commands/query.md`) — runs an SPL query (read from a text file) against Splunk's REST API, analyzes the results for suspicious activity, maps findings to MITRE ATT&CK techniques, and writes an Obsidian-compatible markdown note to `investigations/`.
  - `timerange` is the Splunk `earliest_time` for the search (default `-24h`).
  - Requires `SPLUNK_HOST` and `SPLUNK_TOKEN` environment variables (token auth against port 8089).
  - Output notes use frontmatter (`date`, `tags`, `techniques`) and `[[T-code]]` backlinks (e.g. `[[T1003.001]]`) so findings link up in an Obsidian vault.
