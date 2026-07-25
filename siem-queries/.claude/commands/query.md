---
description: Run a Splunk SIEM query from a file, analyze results, and log an ATT&CK-mapped investigation note
argument-hint: <path-to-query-file> [timerange]
allowed-tools: Bash, Read, Write, Glob
---

## Inputs

- `$1` — path to a text file containing the SPL query to run (required)
- `$2` — Splunk `earliest_time` for the search, e.g. `-24h`, `-7d@d` (optional, default `-24h`)

Resolve inputs before doing anything else:

1. If `$1` is empty, stop and ask the user for a query file path.
2. Set `TIMERANGE` to `$2` if provided, otherwise `-24h`.
3. Confirm the query file exists and read its contents (this is the raw SPL query, verbatim, for both execution and for embedding in the final note).
4. Confirm `SPLUNK_HOST` and `SPLUNK_TOKEN` are set in the environment. If either is missing, stop and tell the user which one to export.

## Run the query against Splunk

Splunk's management REST API runs on port 8089 by default. Use token auth via the `Authorization: Bearer` header and `output_mode=json` throughout.

1. Build the search string: if the query (after trimming whitespace) does not already start with `search`, `|`, or a generating command, prefix it with `search `.
2. Create the search job:
   ```
   curl -sk -H "Authorization: Bearer $SPLUNK_TOKEN" \
     https://$SPLUNK_HOST:8089/services/search/jobs \
     -d output_mode=json \
     -d earliest_time="$TIMERANGE" \
     -d latest_time="now" \
     --data-urlencode search="<resolved search string>"
   ```
   Extract the `sid` from the JSON response.
3. Poll job status until done (short sleep between polls, cap at a reasonable number of retries):
   ```
   curl -sk -H "Authorization: Bearer $SPLUNK_TOKEN" \
     "https://$SPLUNK_HOST:8089/services/search/jobs/$SID?output_mode=json"
   ```
   Wait for `entry[0].content.dispatchState == "DONE"`. If it reaches `FAILED`, stop and surface the Splunk error messages to the user.
4. Fetch results:
   ```
   curl -sk -H "Authorization: Bearer $SPLUNK_TOKEN" \
     "https://$SPLUNK_HOST:8089/services/search/jobs/$SID/results?output_mode=json&count=0"
   ```
5. Note the total result count (from the results payload or from `entry[0].content.resultCount` on the job status).

## Analyze results

Read through the returned events yourself (don't write a script to "detect anomalies" — use your own judgment as an analyst):

- Look for indicators such as: credential dumping / LSASS access, unusual parent-child process chains, encoded or obfuscated command lines, living-off-the-land binaries (LOLBins), lateral movement patterns, unusual auth activity (impossible travel, off-hours, service accounts), data staging/exfil volume, persistence mechanisms (scheduled tasks, registry run keys, services).
- For each suspicious pattern found, identify the specific event(s) supporting it (timestamp, host, user, process, etc.) — don't make vague claims without pointing to data.
- Map each finding to the most specific applicable MITRE ATT&CK technique or sub-technique ID (e.g. `T1003.001` rather than just `T1003`), based only on what the data actually shows. If nothing suspicious is found, say so plainly rather than forcing a mapping.

## Generate the Obsidian note

Create the `investigations/` directory if it doesn't exist. Write a markdown file named `investigations/<YYYY-MM-DD>-<query-file-basename>.md` (use today's date; if a file with that name already exists, append `-2`, `-3`, etc.).

Structure:

```markdown
---
date: <YYYY-MM-DD>
tags: [siem, investigation]
techniques: [T1003.001, T1059.001]
---

# Investigation: <query file basename>

## Summary

<2-5 sentences: what was searched, what was found, overall assessment (benign / suspicious / needs escalation)>

## Findings

- **<short finding title>** — <description, pointing to specific events> → [[T1003.001]]
- **<short finding title>** — <description> → [[T1059.001]]

(omit this section, or state "No suspicious activity identified" if nothing was found)

## Query

- **Timerange:** `<earliest_time>` to `now`
- **Result count:** `<N>`

```spl
<raw query as read from the file>
```

## Analyst Notes

<!-- Space for manual analyst follow-up -->
```

Rules for the note:
- `tags` always includes `siem` and `investigation`, plus any others that fit (e.g. `false-positive`, `escalated`).
- `techniques` lists only technique IDs actually referenced in Findings — omit the field (or leave empty) if there were no findings.
- Every technique mentioned in Findings must also appear as a `[[T-code]]` backlink inline and in the frontmatter list.
- Keep the "Analyst Notes" section present but empty — it's for the human reviewer to fill in later.

## Finish

After writing the file, tell the user the output path, the result count, and a one-line summary of whether anything suspicious was found.
