# Threat Hunt Report: **Entry-Level Kill Chain**

Analyst: `James Harrington`

Date Completed: `2025-09-21`

Environment Investigated: `slflarewinsysmo`

Timeframe: `Sept 17 – 21, 2025`

##  Scenario

Suspicious activity has been detected on one of our cloud virtual machines. As a Security Analyst, you’ve been assigned to investigate this incident and determine the scope and impact of the breach.

---

## Executive Summary

Between September 17–21, 2025, insider activity was identified on nathan-iel-vm that targeted HR data and audit controls. The actor leveraged PowerShell and native Windows tools to escalate privileges, disable endpoint protections, establish persistence, and exfiltrate sensitive HR configuration files. Tampering with promotion candidate records and repeated access to the personnel file of Carlos Tanaka strongly suggest a fraudulent motive tied to internal promotion processes. Multiple anti-forensic attempts were observed, including event log clearing and AV policy manipulation, indicating deliberate stealth. Data exfiltration occurred through outbound connections to a .net domain (52.54.13.125). The activity represents a successful insider-driven HR data manipulation and exfiltration event with material impact on personnel processes and data integrity.

---

## Completed Flags

| Flag # | Objective | Value |
|--------|-----------|-------|
| **Start** | Identify the first machine | `nathan-iel-vm` |
| **1** | Creation time of the first suspicious process | `2025-07-19T02:07:43.9041721Z` |
| **2** | SHA256 value of this particular instance | `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3` |
| **3** | What is the value of the command | `"powershell.exe" net localgroup Administrators` |
| **4** | Value of the program tied to this activity | `qwinsta.exe` |
| **5** | Value used to execute command | `"powershell.exe" -Command "Set-MpPreference -DisableRealtimeMonitoring $true"` |
| **6** | Provide the name of the registry value | `DisableAntiSpyware`
| **7** | HR related file name associated with this tactic | `HRConfig.json` |
| **8** | Value of the associated command | `"notepad.exe" C:\HRTools\HRConfig.json` |
| **9** | TLD of the unusual outbound connection | `.net` |
| **10** | Ping of the last unusual outbound connection | `52.54.13.125` |
| **11** | File name tied to the registry value | `OnboardTracker.ps1` |
| **12** | Name of the personnel that was repeatedly accessed | `Carlos Tanaka` |
| **13** | SHA1 value of first instance where the file in question is modified | `65a5195e9a36b6ce73fdb40d744e0a97f0aa1d34` |
| **14** | Identify when the first attempt at clearing the trail | `2025-07-19T05:38:55.6800388Z` |
| **15** | Identify when the last associated attempt occurred | `2025-07-19T06:18:38.6841044Z` |

---
## Stage 1 - Initial Access

### 🚩 Flag 1 – Attacker IP Address

**Context:**
Suspicious RDP login activity has been detected on a cloud-hosted Windows server. Multiple failed attempts were followed by a successful login, suggesting brute-force or password spraying behaviour.

**Objective:**
Identify the external IP address that successfully logged in via RDP after a series of failures.

**Guidance:**
Review the authentication telemetry and look for signs of repeated failed logins followed by a successful one. Focus on logins that originated from external IP addresses.

**What is the earliest external IP address successfully logged in via RDP after multiple failed login attempts?**
`159.26.106.84`

**MITRE Technique:**
`🔸T1110.001 – Brute Force: Password Guessing`

### 🚩 Flag 2 – Compromised Account

**Context:**
The attacker gained access to the system using valid credentials through RDP. Identifying which account was accessed is critical to understanding what level of control they have.

**Objective:**
Determine the username that was used during the successful RDP login associated with the attacker’s IP.

**Guidance:**
Pivot from the successful login identified in Flag 1. Analyse the associated account used in that authentication event.

**What user account was successfully used to access the system via RDP?**
`slflare`

**KQL Query:**
```KQL
DeviceLogonEvents
| where DeviceName contains "flare"
```
-Query made based on context clues, found the VM name and IP quickly and it was correct.

Note: Used "Custom time range" for ALL KQL queries: 2025-09-17 to 2025-09-22

<img width="1090" height="594" alt="image" src="https://github.com/user-attachments/assets/32f4d66d-76bd-4e63-a35c-8cd4124002e9" />

**MITRE Technique:**
`🔸T1078 – Valid Accounts`

## Stage 2 - Execution

### 🚩 Flag 3 – Executed Binary Name

**Objective:**
After gaining RDP access, the attacker executed a suspicious binary on the host. Identifying this file is critical to understanding the payload or initial action and objectives of the attacker.

**Objective:**
Identify the name of the binary executed by the attacker.

**Thought:**
Focus your investigation on process execution under the compromised user account from flag 2. Look for binaries launched from unusual paths like Public, Temp, or Downloads folders.

**What binary was executed by the attacker after gaining RDP access?**
`msupdate.exe`

**MITRE Technique(s):**
`🔸 T1059.003 – Command and Scripting Interpreter: Windows Command Shell`
`🔸 T1204.002 – User Execution: Malicious File`

### 🚩 Flag 4 - Command Line Used to Execute the Binary

**Context:**
The attacker used a command line to launch the binary. Understanding how it was executed may reveal intent, obfuscation, or further payloads.

**Objective:**
Provide the full command line used to launch the binary from Flag 3.

**Guidance:**
Review command-line arguments associated with process execution under the compromised account. Pay attention to how the attacker invoked the binary and any parameters used.

**What was the full command line used by the attacker to execute the binary?**
`"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1`

**KQL Query:**
```KQL
DeviceProcessEvents
| where AccountName == "slflare"
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="1110" height="659" alt="image" src="https://github.com/user-attachments/assets/c4d5cfe0-73a1-46c3-858f-c65e50d33cd9" />

**MITRE Technique:**
`🔸 T1059 – Command and Scripting Interpreter`

## Stage 3 - Persistence

### 🚩 Flag 5 – Persistence Mechanism Created

**Context:**
The attacker established persistence on the system to maintain access. In this case, they created a scheduled task to ensure their payload would execute even after reboot or logoff.

**Objective:**
Identify the name of the scheduled task created by the attacker.

**Guidance:**
Investigate task creation activity by examining both process execution events and registry modifications. Look for newly registered scheduled tasks in the Windows TaskCache registry or PowerShell cmdlet execution.

**What is the name of the scheduled task that was created by the attacker?**
`MicrosoftUpdateSync`

**KQL Query:**
```KQL
DeviceRegistryEvents
| where DeviceName contains "flare"
```
-Scanned the logs for unusual task names.

<img width="1140" height="747" alt="image" src="https://github.com/user-attachments/assets/9f0bb93e-5a8e-44dd-9723-e3b76d1bc45b" />

**MITRE Technique:**
`🔸 T1053.005 – Scheduled Task/Job: Scheduled Task`

## Stage 4 - Defense Evasion

### 🚩 Flag 6 – What Defender Setting Was Modified?

**Context:**
After persistence was established, the attacker altered Microsoft Defender's configuration to evade detection. Specifically, they added a folder exclusion in Defender's registry, preventing scans of certain files or directories.

**Objective:**
Identify the folder path that was excluded from Defender scans.

**Guidance:**
Look for registry modification events linked to Defender exclusions. Focus on exclusions that prevent scanning of specific folders.

**What folder path did the attacker add to Microsoft Defender’s exclusions after establishing persistence?**
 `C:\Windows\Temp`

**KQL Query:**
- Same as above query, just looked inside the details.

<img width="1060" height="718" alt="image" src="https://github.com/user-attachments/assets/89d44f8d-65a3-457d-bf81-b8760e76f498" />

**MITRE Technique:**
`🔸 T1562.001 – Impair Defenses: Disable or Modify Windows Defender`

## Stage 5 - Discovery

### 🚩 Flag 7 – What Discovery Command Did the Attacker Run?

**Context:**
After modifying system defences, the attacker began reconnaissance to understand the environment. This included gathering host and/or network configuration details from the compromised system.

**Objective:**
Identify the exact command line the attacker executed to perform system discovery.

**Guidance:**
Review process execution data for evidence of built-in Windows tools used for enumeration. Pay attention to attacker tooling or interactive shells used to issue these commands.

**What is the earliest discovery command that the attacker ran to enumerate the host?**
`"cmd.exe" /c systeminfo`

**KQL Query:**
```KQL
DeviceProcessEvents
| where DeviceName contains "flare"
| where ProcessCommandLine has_any ("systeminfo", "whoami", "ipconfig", "net user", "tasklist")
```

<img width="1078" height="618" alt="image" src="https://github.com/user-attachments/assets/0275dbcd-ec87-4d81-b2dc-8eba0e55e918" />

**MITRE Technique:**
`🔸 T1082 – System Information Discovery`

## Stage 6 - Collection

### 🚩 Flag 8 – Archive File Created by Attacker

**Context:**
After gathering sensitive data, the attacker prepared it for exfiltration by compressing the contents into an archive file on the local system.

**Objective:**
Identify the name of the archive file created by the attacker.

**Guidance:**
Look for file creation or process activity involving archiving tools. Focus on .zip, .rar, or .7z files created in non-standard directories such as Temp, AppData, or ProgramData.

**What archive file did the attacker create to prepare for exfiltration?**
`backup_sync.zip`

KQL Query:

```KQL
DeviceProcessEvents
| where DeviceName contains "flare"
| where ProcessCommandLine contains "zip"
```

<img width="1157" height="798" alt="image" src="https://github.com/user-attachments/assets/4607624f-0797-4971-9218-51111b9b69ae" />

**MITRE Technique:**
`🔸 T1560.001 – Archive Collected Data: Local Archiving`

## Stage 7 - Command and Control (C2)

### 🚩 Flag 9 – C2 Connection Destination

**Context:**
After gaining access, the attacker established contact with an external server to maintain control and retrieve additional tooling.

**Objective:**
Identify the destination the attacker’s beacon connected to or retrieved tooling from.

**Guidance:**
Review outbound network connections tied to suspicious activity. Look for external IPs or domains contacted shortly after initial execution or persistence. Traffic may involve HTTP/S downloads or beacon callbacks.

**What destination did the attacker’s C2 beacon connect to for remote access?**
`185.92.220.87`

**KQL Query:**

-Same query as above flag just a few lines away.

<img width="1133" height="738" alt="image" src="https://github.com/user-attachments/assets/4b2b14fe-5988-474f-aae3-0f321141847f" />

**MITRE Technique:**
`🔸 T1071.001 – Application Layer Protocol: Web Protocols (HTTP/S)
🔸 T1105 – Ingress Tool Transfer`

## Stage 8 - Exfiltration

### 🚩 Flag 10 – Exfiltration Attempt Detected

**Context:**
After staging the archive, the attacker’s session attempted to send data to an external server.

**Objective:**
Identify the external IP address and port used during this data exfiltration attempt.

**Guidance:**
Before exfiltration, there’s always a ping — even if it’s disguised as routine.

**What external IP address and port did the attacker attempt to use when trying to exfiltrate the staged archive file?**
`185.92.220.87:8081`

**KQL Query:**
- Same query and line as above.

**MITRE Technique:**
`🔸 T1048.003 – Exfiltration Over Unencrypted Protocol`

## MITRE ATT&CK Technique Mapping (Evidence-Only)

| Flag | MITRE Technique                               | ID         | Description |
|------|-----------------------------------------------|------------|-------------|
| 1    | PowerShell                                    | T1059.001  | Suspicious PowerShell execution (`whoami` discovery command). |
| 2    | System Owner/User Discovery                   | T1033      | Account/user context enumeration (`whoami` activity). |
| 3    | Permission Groups Discovery: Local Groups     | T1069.001  | Checked elevated accounts with `net localgroup Administrators`. |
| 4    | System Owner/User Discovery                   | T1033      | Session enumeration using `qwinsta.exe` to reveal logged-in users. |
| 5    | Impair Defenses: Disable or Modify Tools      | T1562.001  | Disabled Defender real-time monitoring via PowerShell (`Set-MpPreference`). |
| 6    | Modify Registry                               | T1112      | Registry change (`DisableAntiSpyware`) to weaken endpoint defenses. |
| 7    | Data from Local System                        | T1005      | Accessed HR-related file `HRConfig.json`. |
| 8    | Data from Local System                        | T1005      | Opened `C:\HRTools\HRConfig.json` with `notepad.exe` for inspection. |
| 9    | Application Layer Protocol: Web               | T1071.001  | Outbound connection to unusual `.net` domain. |
| 10   | Registry Run Keys/Startup Folder              | T1547.001  | Persistence via Run key referencing `OnboardTracker.ps1`. |
| 11   | Data from Local System                        | T1005      | Repeated access to personnel file `Carlos Tanaka`. |
| 12   | Data Manipulation: Stored Data                | T1565.001  | Modified `PromotionCandidates.csv` (SHA1 recorded). |
| 13   | Clear Windows Event Logs                      | T1070.001  | Used `wevtutil.exe cl` to clear Windows event logs. |
| 14   | Indicator Removal on Host                     | T1070      | Final cleanup attempt removing artifacts and traces. |

---

# Lessons Learned

- **Native tooling over malware.** The actor relied on built-in utilities for discovery and operational cover: PowerShell (“whoami” discovery) (Flag 1–2), local admin group enumeration via `net localgroup Administrators` (Flag 3), and session enumeration with `qwinsta.exe` (Flag 4).  
- **Deliberate weakening of endpoint defenses.** Defender protections were reduced using `Set-MpPreference -DisableRealtimeMonitoring $true` (Flag 5) and the `DisableAntiSpyware` registry value (Flag 6).  
- **Persistence via Run key.** A PowerShell script (`OnboardTracker.ps1`) was configured for autorun through a Run-key entry (Flag 11).  
- **Targeted HR data access and manipulation.** Sensitive HR artifacts were accessed and inspected (`HRConfig.json`, opened with `notepad.exe`) (Flags 7–8), a specific personnel record was repeatedly accessed (`Carlos Tanaka`) (Flag 12), and promotion data was modified (`PromotionCandidates.csv`, SHA1 captured) (Flag 13).  
- **Anti-forensics to impair investigation.** Event logs were cleared using `wevtutil.exe` (first and last attempts recorded) (Flags 14–15).  
- **External connectivity consistent with staging or testing.** Unusual outbound activity to a `.net` destination and ping to `52.54.13.125` were observed (Flags 9–10). Content transfer is **not** demonstrated by the provided evidence.  
- **Scope (as evidenced).** All documented activity is on `nathan-iel-vm`; no lateral movement is evidenced in the flags provided.

---

## Recommendations for Remediation

- **Containment and scoping**
  - Isolate `nathan-iel-vm`.  
  - Block and monitor the external IP `52.54.13.125` and investigate associated `.net` destinations observed (Flags 9–10).  
- **Eradication**
  - Remove the Run-key persistence referencing `OnboardTracker.ps1`; delete or quarantine the script (Flag 11).  
  - Restore Defender settings, re-enable real-time protection, and verify the `DisableAntiSpyware` value is not set (Flags 5–6).  
- **Recovery and validation**
  - Perform a full AV/EDR scan on `nathan-iel-vm`.  
  - Validate integrity of HR artifacts (`HRConfig.json`, `PromotionCandidates.csv`) and restore from known-good backups if tampering is confirmed (Flags 7–8, 13).  
- **Detection & monitoring (aligned to observed behaviors)**
  - Alert on `Set-MpPreference` calls that disable protections and on changes to Defender-related registry values (Flags 5–6).  
  - Monitor for creation/changes of `HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run*` entries invoking `.ps1` scripts (Flag 11).  
  - Detect `wevtutil.exe cl` (clear log) executions and treat as high-priority review events (Flag 14).  
  - Track access patterns to HR directories/files and alert on unusual modification or repeated access to personnel records (Flags 7–8, 12–13).  
  - Monitor outbound connections to newly observed external domains/TLDs and anomalous ICMP to internet IPs (Flags 9–10).  
- **Hardening**
  - Enforce Defender Tamper Protection and restrict the ability for local users to modify AV settings (Flags 5–6).  
  - Centralize and protect event logs to prevent local clearing from destroying investigative data (Flags 14–15).  
  - Limit administrative group membership and interactive logons on HR-sensitive hosts (Flags 3–4).  
- **Insider-risk and HR follow-up**
  - Review access associated with the repeatedly accessed personnel record (`Carlos Tanaka`) and audit the promotion process for manipulation (Flags 12–13).
