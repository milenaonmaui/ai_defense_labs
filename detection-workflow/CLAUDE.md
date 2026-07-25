# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Claude Code hook that validates detection rule files as they're written or
edited, so malformed rules get caught immediately instead of at review time.

## Structure

- **`rules/`** — where detection rule YAML files (`*.yaml`/`*.yml`) live.
  Not created yet in this repo — add rule files here as they're authored.
- **`scripts/validate-rule.sh`** — the validation script invoked by the hook.
  Reads a Claude Code hook JSON payload from stdin (`tool_input.file_path`,
  falling back to `.file_path`), and no-ops (exit 0) unless the path is a
  `.yaml`/`.yml` file under `rules/`. For matching files it shells out to
  Python (using PyYAML) to check that `title` and `description` are present
  and non-empty, and that `tags` is a list containing at least one entry
  starting with `attack.t` (a MITRE ATT&CK technique tag). It always exits
  with code **2** and prints its result (success or the list of errors) to
  stderr — exit 2 is what makes Claude Code surface that stderr output back
  to Claude as feedback, on both the success and failure path.
- **`.claude/settings.json`** — registers `scripts/validate-rule.sh` as a
  `PostToolUse` hook on `Write|Edit`, invoked via
  `$CLAUDE_PROJECT_DIR/scripts/validate-rule.sh`. There's also an unrelated
  `Edit|Write` hook here that appends `File modified!` to `hook-test.log`
  (a throwaway test hook from early hook experimentation — harmless, but
  candidate for removal if it's not otherwise useful).

## Dependencies

- `jq` (payload parsing) and `python3` with `PyYAML` installed (rule
  validation). No project-local dependency manifest — these are assumed
  present on the host.

## Testing the hook manually

```bash
echo '{"tool_input":{"file_path":"rules/example.yaml"}}' | ./scripts/validate-rule.sh; echo "exit=$?"
```

Or trigger it for real by having Claude write/edit a file under `rules/`.

## Notes

- `test.txt` and `hook-test.log` in this directory are gitignored scratch
  files used while building out the hook; not part of the design.
