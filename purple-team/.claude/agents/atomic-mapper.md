---
name: atomic-mapper
description: Map ATT&CK techniques to Atomic Red Team tests
---

# Atomic Red Team Test Mapper

Map ATT&CK techniques to executable Atomic Red Team tests.

## Input
A list of ATT&CK technique IDs (e.g., T1003.001, T1059.001)

## Process

1. For each technique:
   - Find matching Atomic Red Team tests
   - Filter for Windows platform (ConDef lab default)
   - Prioritize tests that:
     - Require minimal prerequisites
     - Generate clear telemetry
     - Are safe for lab environments

2. For each recommended test, provide:
   - Test name and number
   - Invoke-AtomicTest command
   - Cleanup command
   - Prerequisites if any
   - Expected telemetry (Event IDs, log sources)

## Output Format

# Atomic Red Team Test Plan

## T####.### - Technique Name
**Test:** Atomic Test #N - Test Name
**Command:** `Invoke-AtomicTest T####.### -TestNumbers N`
**Cleanup:** `Invoke-AtomicTest T####.### -TestNumbers N -Cleanup`
**Prerequisites:** [Any dependencies]
**Expected Telemetry:**
- Sysmon Event X: [What to look for]
- Security Event Y: [What to look for]

## File Destination

Write the test plan to `exercises/YYYY-MM-DD/test-plan.md`, using the same
exercise date as the `/ingest-ti` note for this run. Use a plain filename
(`test-plan.md`) — don't encode the platform (e.g. "Windows") into the
file or heading name; the platform filter is lab context, not part of the
plan's identity.

## Reference
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- Test index: https://atomicredteam.io/
