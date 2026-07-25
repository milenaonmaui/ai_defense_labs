# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project goal

`parser.py` is a single-file Python tool that parses Sysmon XML logs and
extracts key fields from Event ID 1 (Process Creation) events.

Fields extracted per event:
- EventID
- UtcTime
- Image (process path)
- CommandLine
- User
- IntegrityLevel
- ParentImage
- ParentCommandLine
- Computer
- Hashes

## Usage

```bash
python3 parser.py <path-to-sysmon.xml>
python3 parser.py <path-to-sysmon.xml> --image whoami.exe --user Administrator --integrity-level High
python3 parser.py <path-to-sysmon.xml> --format jsonl
python3 parser.py <path-to-sysmon.xml> --format csv
```

Sample fixtures live in `samples/` (`event1.xml`, `event2.xml`, `event3.xml`
are single-event files; `multi_events.xml` wraps all three in an `<Events>`
root for testing multi-event parsing and filtering together).

## Architecture

- **Parsing**: uses the stdlib `xml.etree.ElementTree`, not a third-party XML
  library — no external dependencies. `iter_events()` streams the file with
  `ET.iterparse()` rather than `ET.parse()`, and calls `element.clear()` on
  each `<Event>` right after reading it, so memory usage stays roughly flat
  regardless of file size instead of loading the whole document into memory
  at once.
- **Output format**: controlled by `--format`, default `json`. `json` prints
  matching events as a JSON array to stdout, always — including an empty
  array `[]` when filters exclude everything (no more collapsing a single
  match down to a bare object). `jsonl` prints one JSON object per line, which
  is friendlier for streaming/piping into tools like `jq` line-by-line. `csv`
  prints a header row followed by one row per event, with columns in the
  fixed order given by `OUTPUT_FIELDS` (matching the field list at the top of
  this file). All three formats iterate over the same filtered list built in
  `main()`.
- **Filtering**: `--image` and `--user` are case-insensitive substring
  matches (so `--user Administrator` matches a field value of
  `CONDEF\Administrator`); `--integrity-level` is an exact match validated
  against the 5 real Sysmon values (`Untrusted`, `Low`, `Medium`, `High`,
  `System`) via `argparse`'s `choices=`, with `type=str.title` so lowercase
  input like `--integrity-level high` still normalizes and validates.
  Multiple filters combine with **AND** — an event must match every filter
  provided. Filtering happens in `event_matches()`, applied in `main()`
  against events as they're yielded from `iter_events()`; `iter_events()`
  itself stays filter-agnostic, purely responsible for streaming XML
  parsing.

This is intentionally a single flat script — no package structure, build
tooling, or test framework. Keep it that way unless the scope changes.
