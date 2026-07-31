---
source: https://www.huntress.com/blog/clickfix-matanbuchus-astarionrat-analysis
extracted: 2026-07-30
---

# Threat Intel: ClickFix → Matanbuchus 3.0 → AstarionRAT Intrusion

## Threat Overview

- **Campaign/threat actor:** Unattributed hands-on intrusion operator, reported by Huntress Tactical Response/SOC. Delivery loader is Matanbuchus 3.0, a Malware-as-a-Service (MaaS) loader sold on Russian-speaking cybercrime forums by developer "BelialDemon" (advertised since Feb 2021, $10K/mo HTTPS variant, $15K/mo DNS variant). The intrusion delivered a previously undocumented custom RAT dubbed **AstarionRAT** by Huntress.
- **Target industries/regions:** Not disclosed by Huntress. One contextual clue: the target organization is *not* based in a Spanish-speaking country (the operator tried `Administradores` before `Administrators` for the local admin group), suggesting the operator's tooling/playbook may be reused across engagements regardless of target language.
- **Time period:** Intrusion occurred February 2026. Matanbuchus took a hiatus around May 2025 and returned with a rewritten 3.0 codebase. Huntress assesses with **medium confidence** the ultimate objective was ransomware deployment or data exfiltration (based on rapid lateral movement to domain controllers, rogue account creation, and Defender exclusion staging mirroring pre-ransomware patterns); the operator was disrupted during lateral movement.

## TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1204.004 – User Execution: Malicious Copy and Paste** (high) — ClickFix social-engineering prompt tricked the victim into pasting/running a mixed-case `msiexec.exe` command with a path-traversal-obfuscated URL.

### Execution
- **T1218.007 – System Binary Proxy Execution: Msiexec** (high) — Silent MSI install (`/q` flag) via mixed-case `mSiexeC.EXe` to evade string-matching detections.
- **T1059.003 – Command and Scripting Interpreter: Windows Command Shell** (high) — `cmd.exe /c sc start AppMgmt`, `net user`, `net localgroup`, batch scripts (`rdp.bat`).
- **T1059 – Command and Scripting Interpreter (Lua, general)** (medium) — Embedded Lua 5.4.7 interpreter (82-opcode bytecode dispatcher) used to decode/execute shellcode; no dedicated ATT&CK sub-technique exists for Lua.

### Persistence
- **T1053.005 – Scheduled Task/Job: Scheduled Task** (high) — Scheduled task "Application Maintenance" configured to execute `Core.exe` from `C:\ProgramData\2895e798a2579e6\`.
- **T1136.001 – Create Account: Local Account** (high) — `net user DefaultService AiRPcp47_r00t /add` on the beachhead and both lateral targets.
- **T1098.001 – Account Manipulation: Additional Local or Domain Group** (high) — `net localgroup Administradores/Administrators DefaultService /add`.

### Privilege Escalation
- **T1078.003 – Valid Accounts: Local Accounts** (high) — Rogue `DefaultService` local admin account reused for RDP and lateral access independent of the original compromised credentials.

### Defense Evasion
- **T1027 – Obfuscated/Compressed Files or Information** (high) — Junk API calls/dead loops/opaque predicates throughout Matanbuchus and jli.dll; LZNT1-compressed final payload; character-shift-ciphered API name strings.
- **T1140 – Deobfuscate/Decode Files or Information** (high) — ChaCha20 string/shellcode decryption, brute-forced ChaCha20 key recovery via known-plaintext check, rolling-XOR decryption of `SySUpd` and import/relocation tables.
- **T1036.005 – Masquerading: Match Legitimate Name or Location** (high) — Fake security-product install paths (AegisLynx, DocuRay, HelixShield), staging under `C:\ProgramData\USOShared\` to mimic Windows Update, renamed 7-Zip (`aps.exe`).
- **T1574.002 – Hijack Execution Flow: DLL Side-Loading** (high) — Legitimate Zillya! Antivirus `core.exe` (AVCore.exe) sideloads malicious `SystemStatus.dll` (Matanbuchus); legitimate `java.exe` sideloads malicious `jli.dll` (Stage 2).
- **T1562.001 – Impair Defenses: Disable or Modify Tools** (high) — KnownDlls-based unhooking of kernel32.dll/ntdll.dll before sensitive API calls; Defender exclusion set for `C:\ProgramData\USOShared\` (though after detection/quarantine already occurred).
- **T1497 – Virtualization/Sandbox Evasion** (medium) — Long busy-loops burning execution time past typical sandbox timeout windows.
- **T1106 – Native API** (medium) — Heaven's Gate technique (far return to segment 0x33) to execute 64-bit syscalls directly from 32-bit code, bypassing WoW64/EDR hooks; PEB-walking + hash-based API resolution.
- **T1620 – Reflective Code Loading** (high) — Custom reflective PE loader reconstructing Stage 1 DLL from a packed binary stream entirely in memory; `luaalloc`/`luacpy`/`luaexe` Lua functions performing RWX shellcode injection.

### Credential Access
- **T1003 – OS Credential Dumping** (low) — AstarionRAT's command set is described as including "credential theft and impersonation" without further technical detail in the report.

### Discovery
- **T1069.002 – Permission Groups Discovery: Domain Groups** (high) — `net groups "Domain Admins" /domain`.
- **T1018 – Remote System Discovery** (high) — `nltest /dclist:`.
- **T1046 – Network Service Discovery** (medium) — AstarionRAT includes a port-scanning command.
- **T1082 – System Information Discovery** (medium) — Metadata beacon collects OS version, code pages, PID, privilege level, local IP, computer/user/process name.

### Lateral Movement
- **T1021.001 – Remote Services: Remote Desktop Protocol** (high) — RDP to Windows Server using the rogue `DefaultService` account.
- **T1021.002 – Remote Services: SMB/Windows Admin Shares** (high) — PsExec (`psexec.exe -accepteula -s -d`) used to push batch scripts and `java.exe` sideloading package to a Windows Server and two domain controllers.
- **T1570 – Lateral Tool Transfer** (high) — Same PsExec pushes deliver `rdp.bat`, `rdp1.bat`, and the `java.exe`/`jli.dll` package to remote hosts.

### Collection
- **T1113 – Screen Capture** (low) — Matanbuchus is advertised as supporting high-quality screenshot capture; not directly observed in this intrusion.

### Command and Control
- **T1071.001 – Application Layer Protocol: Web Protocols** (high) — HTTPS GET/POST beaconing for both Matanbuchus (`marle[.]io`) and AstarionRAT (`ndibstersoft[.]com`).
- **T1573 – Encrypted Channel** (high) — ChaCha20-encrypted Matanbuchus C2 responses; RSA-1024 encrypted (117-byte chunked) AstarionRAT metadata beacons.
- **T1001.003 – Data Obfuscation: Protocol Impersonation** (high) — AstarionRAT beacon path (`/intake/organizations/events?channel=app`), User-Agent, and cookie structure disguised as legitimate application telemetry.
- **T1090.001 – Proxy: Internal Proxy** (medium) — AstarionRAT's largest function (4,161 bytes) implements a SOCKS5 proxy with SIMD-based XOR obfuscation of proxied traffic.

### Exfiltration / Impact
None observed — the operator was disrupted during lateral movement before reaching a final objective.

## Indicators of Compromise

**Network**
- `hxxp://binclloudapp[.]com/466943` — ClickFix MSI delivery C2 (domain registered 2026-02-05, resolves to `192.121.23[.]146`, AS 9009 / M247 Europe SRL, Germany; co-hosted with `sectigoapps[.]com` and `solidclouaps[.]com`)
- `hxxps://marle[.]io/check/updprofile.aspx` — Matanbuchus C2, serves encrypted main module
- `www.ndibstersoft[.]com` — AstarionRAT C2
- `/intake/organizations/events?channel=app` — AstarionRAT beacon polling path

**File paths**
- `%APPDATA%\AegisLynx Cybernetics Ltd\AegisLynx Threat Fabric\AVU\`
- `%APPDATA%\DocuRay Technologies S.r.l\DocuRay PDF Professional\ZAVY\`
- `%APPDATA%\HelixShield Technologies ApS\HelixShield Adaptive Security\APS\ZAV\`
- `%LOCALAPPDATA%\Temp\ndvyxgdriggmarrf\` — Stage 2 DLL sideloading package drop path
- `C:\ProgramData\2895e798a2579e6\` — scheduled task target (`Core.exe`)
- `C:\ProgramData\USOShared\` — lateral-movement staging directory

**File hashes (SHA-256)**
| File | Hash | Role |
|---|---|---|
| INFO | `de81e2155d797ff729ed3112fd271aa2728e75fc71b023d0d9bb0f62663f33b3`* | Encrypted shellcode payload |
| SystemStatus.dll | `6ffae128e0dbf14c00e35d9ca17c9d6c81743d1fc5f8dd4272a03c66ecc1ad1f`* | Matanbuchus loader payload |
| jli.dll | `68858d3cbc9b8abaed14e85fc9825bc4fffc54e8f36e96ddda09e853a47e3e31`* | Stage 2 loader |
| SySUpd | `03c624d251e9143e1c8d90ba9b7fa1f2c5dc041507fd0955bdd4048a0967a829`* | XOR-encrypted Lua script |
| (Reflective PE loader) | `8e54cd12591d67dfbe72e94c1bde6059e1cba157e6786aec63f8f9e3c71fb925`* | Reconstructs Stage 1 DLL |
| (Stage 1 payload) | `c31c8edbf94c85cc9bc46a5665c45a3556c48d5ad615c0a44e14e5406d80df12`* | XOR-decrypts/LZNT1-decompresses AstarionRAT |
| Beacon.exe | `eecc83add16f3d513a9701e9a646b1885014229ac6f86addd6b10afb64d1d2af`* | AstarionRAT final payload |

\* Hashes as scraped from the source page; lengths are non-standard (65 hex chars) for SHA-256 (64 hex chars) — likely a rendering/copy artifact from the source blog table. Re-verify against the source or the linked YARA rules before use in detections.

**Other**
- `Updprofile.aspx` — Matanbuchus core module filename
- YARA (AstarionRAT): https://github.com/RussianPanda95/Yara-Rules/blob/main/AstarionRAT/win_mal_AstarionRAT.yar
- YARA (Matanbuchus loader): https://github.com/RussianPanda95/Yara-Rules/blob/main/Matanbuchus/win_mal_Matanbuchus_loader.yar

## Simulation Plan

Prioritized by high-confidence techniques with available Atomic Red Team tests. This lab (ConDef: DC, Win11v, Splunk) supports the Windows-side techniques directly.

### Priority 1 — high confidence, atomic test available
| ATT&CK ID | Technique | Notes |
|---|---|---|
| T1218.007 | Msiexec silent install | Simulates the ClickFix MSI delivery step |
| T1053.005 | Scheduled Task creation | Simulates "Application Maintenance" persistence |
| T1136.001 | Create local account | Simulates `DefaultService` rogue account |
| T1098.001 | Add account to local admin group | Simulates `net localgroup Administradores/Administrators` |
| T1574.002 | DLL side-loading | Simulates Zillya/java.exe sideloading chain |
| T1562.001 | Disable/modify Defender (exclusion path) | Simulates the ProgramData\USOShared exclusion |
| T1069.002 | Domain group discovery | Direct match: `net groups "Domain Admins" /domain` |
| T1018 | Remote system discovery | `nltest /dclist` |
| T1021.001 | RDP lateral movement | With rogue local admin account |
| T1021.002 / T1570 | PsExec-based lateral tool transfer | Push to Windows Server + DC per report's playbook |
| T1071.001 | Web protocol C2 beaconing | Generic HTTPS beacon simulation |

### Priority 2 — high confidence, no direct atomic test (custom malware behavior)
- T1204.004 (ClickFix copy-paste) — better exercised as a phishing/social-engineering tabletop or user-awareness simulation than an atomic test.
- T1620 (Reflective code loading, custom binary stream format) — no atomic maps to this exact implementation; consider a generic in-memory shellcode execution atomic as a proxy.
- T1036.005 (fake security-product paths) — can be manually simulated by dropping decoy files under similarly-named fake vendor paths; no dedicated atomic test.
- T1001.003 (C2 traffic disguised as app telemetry) / T1573 (RSA+ChaCha20 encrypted C2) — malware-specific protocol design; not atomic-testable without a custom C2 profile.
- T1497 (sandbox evasion via busy-loops), T1106 (Heaven's Gate/PEB API resolution), T1027/T1140 (custom crypto obfuscation) — internal loader behaviors, not independently simulatable via Atomic Red Team; better validated via the linked YARA rules against the actual samples in a sandboxed lab if samples are obtainable, or skipped for a TTP-level exercise.

### No atomic test available
- T1059 (embedded Lua interpreter execution) — no ATT&CK sub-technique or atomic test for Lua specifically.
- T1090.001 (SOCKS5 proxy with SIMD XOR obfuscation) — atomic tests exist for generic proxy usage (e.g., via ssh -D) but won't replicate the malware's specific obfuscation.

## References
- Source: [Huntress — ClickFix, Matanbuchus & AstarionRAT Analysis](https://www.huntress.com/blog/clickfix-matanbuchus-astarionrat-analysis)
- [ATT&CK T1204.004](https://attack.mitre.org/techniques/T1204/004/) · [T1218.007](https://attack.mitre.org/techniques/T1218/007/) · [T1053.005](https://attack.mitre.org/techniques/T1053/005/) · [T1136.001](https://attack.mitre.org/techniques/T1136/001/) · [T1098.001](https://attack.mitre.org/techniques/T1098/001/) · [T1078.003](https://attack.mitre.org/techniques/T1078/003/) · [T1027](https://attack.mitre.org/techniques/T1027/) · [T1140](https://attack.mitre.org/techniques/T1140/) · [T1036.005](https://attack.mitre.org/techniques/T1036/005/) · [T1574.002](https://attack.mitre.org/techniques/T1574/002/) · [T1562.001](https://attack.mitre.org/techniques/T1562/001/) · [T1497](https://attack.mitre.org/techniques/T1497/) · [T1106](https://attack.mitre.org/techniques/T1106/) · [T1620](https://attack.mitre.org/techniques/T1620/) · [T1003](https://attack.mitre.org/techniques/T1003/) · [T1069.002](https://attack.mitre.org/techniques/T1069/002/) · [T1018](https://attack.mitre.org/techniques/T1018/) · [T1046](https://attack.mitre.org/techniques/T1046/) · [T1082](https://attack.mitre.org/techniques/T1082/) · [T1021.001](https://attack.mitre.org/techniques/T1021/001/) · [T1021.002](https://attack.mitre.org/techniques/T1021/002/) · [T1570](https://attack.mitre.org/techniques/T1570/) · [T1113](https://attack.mitre.org/techniques/T1113/) · [T1071.001](https://attack.mitre.org/techniques/T1071/001/) · [T1573](https://attack.mitre.org/techniques/T1573/) · [T1001.003](https://attack.mitre.org/techniques/T1001/003/) · [T1090.001](https://attack.mitre.org/techniques/T1090/001/)
