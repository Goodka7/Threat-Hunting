# Threat Hunt Report: **Full Threat Hunt**

Analyst: `James Harrington`  
Date Completed: `2025-11-21`  
Environment Investigated: `AZUKI-SL`  
Timeframe: `Nov 19 – 20, 2025`

---

## Scenario

A six-year shipping contract, stable and predictable, was suddenly undercut by a competitor by exactly 3%.  
Not roughly. Not approximately.  
Exactly.

Shortly afterward, Azuki Import/Export’s supplier pricing and contract data appeared on underground forums.

That level of precision was not a market coincidence.  
It was the fingerprint of a deliberate intrusion.

Microsoft Defender for Endpoint telemetry from `AZUKI-SL`, the IT administrator workstation, revealed what happened behind the scenes. An external RDP session from an unfamiliar IP. A compromised internal account. Hidden staging directories created under system paths. Windows Defender exclusions carved out to shelter tools and payloads. Credential theft, archive creation, and data exfiltration over an encrypted channel to a cloud communication platform.

This was not misconfiguration.  
This was espionage.

Your task: rebuild the attacker’s chain of actions, establish how the contract data was stolen, and identify what persistence and residual risk remains.

---

## Executive Summary

Between `November 19–20, 2025`, an external threat actor gained unauthorized access to `AZUKI-SL` via Remote Desktop using the compromised user account `kenji.sato`. The RDP session originated from `88.97.178.12`, an IP outside of Azuki’s normal operating footprint.

Once authenticated, the attacker began with basic discovery, using `arp -a` to enumerate network neighbors and identify potential lateral movement targets. They then created a hidden malware staging directory at `C:\ProgramData\WindowsCache`, a common location abused due to its system context and low user visibility.

Defense evasion followed. The attacker modified Windows Defender settings to exclude three file extensions from scanning and added a Temp directory path (`C:\Users\KENJI~1.SAT\AppData\Local\Temp`) to the Defender exclusions list. This provided a safe zone for downloading and executing tools without triggering standard AV checks.

Leveraging built-in utilities, the attacker abused `certutil.exe` to download files from the internet directly into the staging directory. To ensure long-term access, they created a scheduled task named `Windows Update Check`, configured to execute `C:\ProgramData\WindowsCache\svchost.exe` on a recurring basis, masquerading as routine system maintenance.

From there, the malware established outbound communication with a command-and-control server at `78.141.196.6` over port `443`, blending into normal HTTPS traffic patterns. Credential access was achieved via a short-named binary, `mm.exe`, which was used to dump credentials from LSASS memory using the `sekurlsa::logonpasswords` module, consistent with Mimikatz-style tooling.

Collected data was compressed into `export-data.zip`, staged for exfiltration, and then sent out via Discord as the exfiltration channel. Before closing out, the attacker cleared the Windows `Security` event log to impede forensic reconstruction and created a backdoor local account named `support` to maintain persistent access.

A PowerShell script named `wupdate.ps1` orchestrated portions of the attack chain, and the final phase included attempted lateral movement to `10.1.0.188` using `mstsc.exe`.

Overall, this activity demonstrates a full intrusion lifecycle: initial access via valid credentials, discovery, privilege and credential access, staging, exfiltration, anti-forensics, and groundwork for future operations.

---

## Completed Flags

| Flag # | Objective                                                  | Value                                      |
|--------|------------------------------------------------------------|--------------------------------------------|
| 1      | Source IP of RDP access                                   | `88.97.178.12`                             |
| 2      | Compromised user account                                  | `kenji.sato`                               |
| 3      | Network neighbor discovery command                        | `arp -a`                                   |
| 4      | Malware staging directory                                 | `C:\ProgramData\WindowsCache`             |
| 5      | Number of Defender extension exclusions                   | `3`                                        |
| 6      | Temp folder excluded from Defender                        | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` |
| 7      | Native binary abused to download files                    | `certutil.exe`                             |
| 8      | Scheduled task name                                       | `Windows Update Check`                     |
| 9      | Executable launched by scheduled task                     | `C:\ProgramData\WindowsCache\svchost.exe` |
| 10     | Command-and-control (C2) server IP                        | `78.141.196.6`                             |
| 11     | C2 destination port                                       | `443`                                      |
| 12     | Credential dumping tool filename                          | `mm.exe`                                   |
| 13     | Module used to dump logon passwords                       | `sekurlsa::logonpasswords`                 |
| 14     | Compressed archive used for exfiltration                  | `export-data.zip`                          |
| 15     | Cloud service used for exfiltration                       | `Discord`                                  |
| 16     | First Windows event log cleared                           | `Security`                                 |
| 17     | Backdoor persistence account username                     | `support`                                  |
| 18     | Malicious PowerShell script filename                      | `wupdate.ps1`                              |
| 19     | IP address targeted for lateral movement                  | `10.1.0.188`                               |
| 20     | Remote access tool used for lateral movement              | `mstsc.exe`                                |

---

## Stage 1 - Initial Access

### 🚩 Flag 1: INITIAL ACCESS - Remote Access Source

Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

What to Hunt:  
Query logon events for interactive sessions from external sources during the incident timeframe.

Flag value:  
