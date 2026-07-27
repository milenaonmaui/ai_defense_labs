---
source_url: https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/
extraction_date: 2026-07-26
extraction_tool: trafilatura
report_title: "Apache ActiveMQ Exploit Leads to LockBit Ransomware"
report_publisher: The DFIR Report
intrusion_period: February 2024 (initial access), regained access 18 days later
report_published: 2026-02-23
---

# Threat Intelligence: Apache ActiveMQ Exploit Leads to LockBit Ransomware

## Threat Overview

- **Campaign/actor**: Unattributed independent actor. Ransomware binaries match
  LockBit Black signatures but the ransom note was modified to direct victims
  to the Session private messaging app instead of LockBit's standard Tor/TOX
  infrastructure — assessed as an independent operator using the **leaked
  LockBit Black builder**, not LockBit-the-group itself.
- **Target**: A single organization; internet-facing Windows server running a
  vulnerable Apache ActiveMQ instance. Industry/region not specified in the
  report.
- **Timeline**: Initial exploitation mid-February 2024. Actor was evicted
  ~1 day later, regained access via the same unpatched vulnerability 18 days
  after the first intrusion, then moved to ransomware deployment within hours.
  Time-to-ransomware (TTR) from true initial access: 419 hours (~19 days);
  from the second (final) intrusion: under 90 minutes.

## TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Usage in this campaign | Confidence |
|---|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | RCE via CVE-2023-46604 (Apache ActiveMQ OpenWire/Spring bean XML injection) against an internet-facing server; exploited twice, 18 days apart, via the same unpatched flaw | High |
| Execution | Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Malicious XML config executed shell commands on the ActiveMQ host (Java parent process); `cmd.exe /c echo kesknq > \\.\pipe\kesknq` for getsystem | High |
| Execution | Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Obfuscated PowerShell (string-concatenation + base64 + gzip) used for remote service execution of Metasploit payloads | High |
| Execution | Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | CertUtil used to download the Metasploit stager (`uFSyLszKsuR.exe`) from the C2 server | High |
| Persistence | Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | AnyDesk installed as an autostart service (Event ID 7045) | High |
| Persistence | Remote Access Software | [T1219](https://attack.mitre.org/techniques/T1219/) | AnyDesk used for persistent remote access, installed via a dropped batch file | High |
| Privilege Escalation | Access Token Manipulation: Token Impersonation/Theft | [T1134.001](https://attack.mitre.org/techniques/T1134/001/) | Named-pipe impersonation pattern (`kesknq` service + pipe) consistent with Meterpreter's `getsystem`, escalating to SYSTEM | High |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | System, Application (Event ID 104) and Security (Event ID 1102) logs cleared on the beachhead host | High |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Windows Defender disabled on the Exchange server via the LOLBIN `SystemSettingsAdminFlows.exe` | High |
| Defense Evasion | Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | PowerShell lateral-movement command obfuscated via string concatenation and base64+gzip encoding | High |
| Defense Evasion | Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | Same PowerShell payload required base64-decode + gunzip to recover the shellcode loader | High |
| Defense Evasion | Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | Ransomware/staging files dropped via an injected Winlogon process | Medium (mechanism inferred from process lineage, not fully detailed) |
| Credential Access | OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS memory accessed on multiple hosts in both intrusion rounds (`GrantedAccess 0x1010`, `CallTrace UNKNOWN`) | High |
| Discovery | Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | SMB traffic spike consistent with scanning; later, Advanced IP Scanner (disguised as SoftPerfect Network Scanner) run against the local network | High |
| Discovery | Permission Groups Discovery: Domain Groups | [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | Queried and attempted to modify Domain Admins group membership | High |
| Discovery | System Network Connections Discovery | [T1049](https://attack.mitre.org/techniques/T1049/) | `netstat -t` run (non-standard flag on Windows, syntax errors noted) | Medium |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Domain admin account used to create remote services executing Metasploit payloads across hosts | High |
| Lateral Movement | Remote Services: RDP | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | RDP used to reach backup/file servers and additional hosts to stage and detonate ransomware | High |
| Lateral Movement | Lateral Tool Transfer | [T1570](https://attack.mitre.org/techniques/T1570/) | Ransomware binaries copied to `C:\Intel` and `%USERPROFILE%\Downloads` on target hosts via RDP sessions | High |
| Command and Control | Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Metasploit/Meterpreter C2 over HTTP(S) to the exploit-hosting IP | High |
| Command and Control | Remote Access Software | [T1219](https://attack.mitre.org/techniques/T1219/) | AnyDesk login traced to the same IP as the exploit/C2 server | High |
| Impact | Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | LockBit Black-builder ransomware (`LB3.exe`, `LB3_pass.exe`) deployed and executed interactively via RDP across multiple hosts; one variant used a `-psex` flag suggesting an available (possibly unused) PsExec-style SMB spreader | High |
| Impact | Defacement: Internal Defacement | [T1491.001](https://attack.mitre.org/techniques/T1491/001/) | Desktop wallpaper changed to display the ransom note | High |

## Indicators of Compromise

**Note**: the source report itself contains an inconsistency — the C2 IP is cited as `166.62.100[.]62` in the "Command and Control" narrative but as `166.62.100[.]52` in the "Indicators" and "Execution" sections. Treat both as suspect/blocklist candidates and confirm against raw pcap/logs if available.

### Network
- IP: `166.62.100[.]52` — exploit delivery host, Metasploit C2, AnyDesk login origin (see note above re: `.62` discrepancy)
- AnyDesk Client ID: `1148037084`

### File hashes (SHA-256)
| File | SHA-256 |
|---|---|
| `lb3_pass.exe` (LockBit) | `C8646CFB574FF2C6F183C3C3951BF6B2C6CF16FF8A5E949A118BE27F15962FAE` |
| `lb3.exe` (LockBit) | `8CEEE89550C521BA43F59D24BA53A22A3B69EAD0FCE118508D0A87A383D6A7B6` |
| `netscan.exe` (Advanced IP Scanner, disguised as SoftPerfect) | `87BFB05057F215659CC801750118900145F8A22FA93AC4C6E1BFD81AA98B0A55` |
| `advanced_ip_scanner.exe` | `722FFF8F38197D1449DF500AE31A95BB34A6DDABA56834B13EAAFF2B0F9F1C8B` |
| `rdp.bat` | `D9C888BDE81F19F3DC4F050D184FFA6470F1A93A2B3B10B3CC2D246574F56841` |

### File paths / artifacts
- `%TEMP%\uFSyLszKsuR.exe` — Metasploit stager, delivered via CertUtil
- `rdp.bat` — dropped by an injected Winlogon process, opens RDP through the firewall / sets port 3389, self-deleted ~6 minutes after use
- `C:\Intel\` and `%USERPROFILE%\Downloads\` — ransomware staging locations
- Windows service name `kesknq` — used for the getsystem/named-pipe impersonation privilege escalation

### Vulnerability
- CVE-2023-46604 (Apache ActiveMQ OpenWire RCE)

### Detection content referenced in the report
- Suricata/ET rules: CVE-2023-46604 exploitation (2049009, 2049045, 2049385), Cobalt Strike beacon/stager (2033713, 2851878), CertUtil misuse (2829988), AnyDesk TLS cert (2027761), and others — see full report for the complete rule list.
- Sigma rules (DFIR + community repo): CertUtil download abuse, AnyDesk silent install/service, Windows event log clearing, PowerShell Gzip/Base64 obfuscation, AMSI bypass, named-pipe privilege escalation, domain-group reconnaissance.
- YARA: `Windows_Trojan_Metasploit_7bc0f998`, `Windows_Trojan_Metasploit_91bc5d7d`.

## Simulation Plan

Atomic Red Team coverage below is based on general knowledge of the project's technique catalog — **verify exact test numbers/GUIDs against the current [atomics-red-team](https://github.com/redcanaryco/atomic-red-team) repo before running**, since indices are not guaranteed stable and this was not cross-checked live against the repo for this report.

### High confidence + atomic tests available (prioritize)
- **T1105** Ingress Tool Transfer — atomics exist for CertUtil-based download.
- **T1059.001** PowerShell — atomics exist for encoded/obfuscated command execution.
- **T1003.001** OS Credential Dumping: LSASS Memory — atomics exist (e.g. task manager dump, comsvcs.dll, procdump-style).
- **T1070.001** Indicator Removal: Clear Windows Event Logs — atomics exist (`wevtutil cl`, PowerShell log clearing).
- **T1562.001** Impair Defenses: Disable or Modify Tools — atomics exist for disabling Defender via registry/PowerShell.
- **T1543.003** Create or Modify System Process: Windows Service — atomics exist for service creation/autostart.
- **T1046** Network Service Discovery — atomics exist for network/port scanning.
- **T1069.002** Permission Groups Discovery: Domain Groups — atomics exist (`net group "domain admins" /domain`).
- **T1049** System Network Connections Discovery — atomics exist (`netstat`).
- **T1021.001** Remote Services: RDP — atomics exist for RDP-based lateral movement.
- **T1021.002** Remote Services: SMB/Windows Admin Shares — atomics exist for remote service execution over SMB.
- **T1071.001** Application Layer Protocol: Web Protocols — atomics exist for simple HTTP-based C2 beacon simulation.
- **T1027** Obfuscated Files or Information / **T1140** Deobfuscate/Decode Files — atomics exist for base64/encoded payload tests.
- **T1486** Data Encrypted for Impact — atomics exist that simulate mass file encryption in a contained test directory (use with caution, sandboxed only).

### Techniques without a clean off-the-shelf atomic (gap — needs custom scenario)
- **T1190** Exploit Public-Facing Application — Atomic Red Team does not ship CVE-specific exploit atomics; this specific ActiveMQ RCE would need a dedicated PoC/range exercise (e.g. a disposable ActiveMQ instance patched to the vulnerable version) rather than a generic atomic.
- **T1134.001** Token Impersonation/Theft (named-pipe `getsystem` pattern) — coverage is inconsistent/limited; may need a custom named-pipe impersonation PoC.
- **T1055** Process Injection (Winlogon-specific injection) — generic T1055 atomics exist but won't replicate the exact Winlogon injection vector observed; treat as approximate coverage only.
- **T1219** Remote Access Software (AnyDesk specifically) — no AnyDesk-specific atomic; simulate by scripting a silent AnyDesk install/service-creation sequence and validating against the Sigma rules already cited in the report (`a526e0c3`, `530a6faa`, `114e7f1c`).
- **T1491.001** Internal Defacement (wallpaper change) — no dedicated atomic; trivial to script directly (registry/`SystemParametersInfo` wallpaper change) if needed for detection testing.

### Suggested priority order
1. T1190 (custom range) → T1105 → T1059.001 — reproduce the initial-access-to-execution chain.
2. T1003.001 → T1134.001 (custom) — credential access and privilege escalation.
3. T1070.001 + T1562.001 — defense evasion / log tampering, high detection value.
4. T1046 + T1069.002 + T1049 — discovery.
5. T1021.001 / T1021.002 + T1570 — lateral movement.
6. T1486 (sandboxed only) + T1491.001 — impact, run last and only in an isolated environment.
