
# Threat Hunt Report: **HR Data Exfil**

Analyst: James Harrington

Date Completed: 2025-08-18

Environment Investigated: nathan-iel-vm

Timeframe: July 17 – 20, 2025

##  Scenario

A sudden, unexplained promotion has triggered whispers across the executive floor. The recipient? A mid-level employee with no standout track record, at least, not one visible anymore.

Internal HR systems show signs of tampering: audit logs wiped, performance reports edited, and sensitive employee reviews quietly exfiltrated. Behind the scenes, someone has buried the real story beneath layers of obfuscation, PowerShell trickery, and stealthy file manipulation.

Your mission: act as a covert threat hunter tasked with dissecting the digital remnants of the breach. Trace the insider’s movements. Expose the fake artifacts. Reconstruct the timeline they tried to erase — and uncover the truth behind the promotion that should never have happened.

Nothing in the system adds up... unless you know where to look.

---

## Executive Summary

Between July 17–20, 2025, insider activity was identified on nathan-iel-vm that targeted HR data and audit controls. The actor leveraged PowerShell and native Windows tools to escalate privileges, disable endpoint protections, establish persistence, and exfiltrate sensitive HR configuration files. Tampering with promotion candidate records and repeated access to the personnel file of Carlos Tanaka strongly suggest a fraudulent motive tied to internal promotion processes. Multiple anti-forensic attempts were observed, including event log clearing and AV policy manipulation, indicating deliberate stealth. Data exfiltration occurred through outbound connections to a .net domain (52.54.13.125). The activity represents a successful insider-driven HR data manipulation and exfiltration event with material impact on personnel processes and data integrity.

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
## Flag by Flag

### Starting Point – Identifying the Initial System

**Objective:**
Before you officially begin the flags, you must first determine where to start hunting. Identify where to start hunting with the following: 

**Intel Given:**
HR related stuffs or tools were recently touched, investigate any dropped scripts or configs over the mid-July weekends

**Identify the first machine to look at:**
nathan-iel-vm

Note: Used "Custom time range for ALL KQL: 2025-07-17 to 2025-07-20"
**KQL Query Used:**
```
DeviceFileEvents
| where FileName contains "HR"
```
-Query made based on context clues, found the VM name quickly and it was correct.

<img width="1090" height="594" alt="image" src="https://github.com/user-attachments/assets/71e813e0-27e8-4737-b31c-ea9b82621b2d" />

### 🚩 Flag 1 – Initial PowerShell Execution

**Objective:**
Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

**What to Hunt:**
Initial signs of PowerShell being used in a way that deviates from baseline usage.

**Thought:**
Understanding where it all began helps chart every move that follows. Look for PowerShell actions that started the chain.

**Hint:**
1. Who?

**Provide the creation time of the first suspicious process that occurred:**
2025-07-19T02:07:43.9041721Z

**KQL Query Used:**
```DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where ProcessCommandLine contains "who"
```
-I used this query because of the hint: Who, it turned out to have all the information I needed.

<img width="1135" height="484" alt="image" src="https://github.com/user-attachments/assets/88008bf4-d60a-48fa-a17c-777bef27f5ab" />
<img width="1046" height="309" alt="image" src="https://github.com/user-attachments/assets/156fd043-f7fb-4544-be8a-64a0f8590350" />

### 🚩 Flag 2 – Local Account Assessment

**Objective:**
Map user accounts available on the system.

**What to Hunt:**
PowerShell queries that enumerates local identities.

**Thought:**
After knowing their own access level, intruders start scanning the local account landscape to plan privilege escalation or impersonation down the line.

**Identify the associated SHA256 value of this particular instance:**
9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3

**KQL Query Used**
```DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where ProcessCommandLine contains "who"
```
-Realted to the query above so didn't need to do anything extra.

### 🚩 Flag 3 - Privileged Group Assessment

**Objective:**
Identify elevated accounts on the target system.

**What to Hunt:**
A method used to check for high-privilege users.

**Thought:**
Knowledge of who has admin rights opens doors for impersonation and deeper lateral movement.

**What is the value of the command?**
"powershell.exe" net localgroup Administrators


**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where ProcessCommandLine contains "powershell"
```
-Query was made so I could observe the baseline powershell commands being ran, after scrolling down for a few seconds I saw the obvious command.

### 🚩 Flag 4 – Active Session Discovery

**Objective:**
Reveal which sessions are currently active for potential masking.

**What to Hunt:**
Might be session-enumeration commands.

**Thought:**
By riding along existing sessions, attackers can blend in and avoid spawning suspicious user contexts.

**Provide the value of the program tied to this activity:**
qwinsta.exe

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where ProcessCommandLine contains "qwinsta"
```
-The previous KQL query showed the next command used was "powershell.exe" qwinsta, out of curiosity I googled qwinsta and found out that it dealt with sessions... so I modified my search to look for the process name.


### 🚩 Flag 5 – Defender Configuration Recon

**Objective:**
Expose tampering or inspection of AV defenses, disguised under HR activity.

**What to Hunt:**
Can be PowerShell related activity.

**Thought:**
Disabling protection under the guise of internal tooling is a hallmark of insider abuse.

**What was the command value used to execute?**
 "powershell.exe" -Command "Set-MpPreference -DisableRealtimeMonitoring $true"

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where ProcessCommandLine contains "powershell"
```
-Third time using this same query, but it has a lot of good info if you just follow the timeline.


### 🚩 Flag 6 – Defender Policy Modification

**Objective:**
Validate if core system protection settings were modified.

**What to Hunt:**
Policy or configuration changes that affect baseline defensive posture.

**Thought:**
Turning down the shield is always a red flag.

**Provide the name of the registry value:**
DisableAntiSpyware

**KQL Query Used:**
```
DeviceRegistryEvents
| where DeviceName == "nathan-iel-vm"
| where RegistryValueName != ""
| order by Timestamp asc
```
-Given the clues, I knew it was related to Registry events, the "thought" was a big clue that it had to do with AntiVirus or Microsoft Defender.

### 🚩 Flag 7 – Access to Credential-Rich Memory Space

**Objective:**
Identify if the attacker dumped memory content from a sensitive process.

**What to Hunt:**
Uncommon use of system utilities interacting with protected memory.

**Thought:**
The path to credentials often runs through memory — if you can reach it, you own it.

**What was the HR related file name associated with this tactic?**
HRConfig.json

KQL Query Used:
```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where FileName in ("procdump.exe", "taskmgr.exe", "rundll32.exe")
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```
-Query was made to look for common filenames that would be included for memory dumps.


### 🚩 Flag 8 – File Inspection of Dumped Artifacts

**Objective:**
Detect whether memory dump contents were reviewed post-collection.

**What to Hunt:**
Signs of local tools accessing sensitive or unusually named files.

**Thought:**
Dumping isn’t the end — verification is essential.

**Hint:**
Utilize previous findings

**Identified Artifact:**
"notepad.exe" C:\HRTools\HRConfig.json

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where ProcessCommandLine contains "HRConfig.json"
```
-Using the hint, was pretty easy to find.

### 🚩 Flag 9 – Outbound Communication Test

**Objective:**
Catch network activity establishing contact outside the environment.

**What to Hunt:**
Lightweight outbound requests to uncommon destinations.

**Thought:**
Before exfiltration, there’s always a ping — even if it’s disguised as routine.

**What was the TLD of the unusual outbound connection?**
.net

**KQL Query Used:**
```
DeviceNetworkEvents
| where DeviceName == "nathan-iel-vm"
| where RemoteIPType == "Public" // external IPs
| where InitiatingProcessFileName in ("powershell.exe", "ping.exe", "curl.exe", "nc.exe", "netcat.exe")
| project Timestamp, RemoteUrl
| order by Timestamp asc
```

### 🚩 Flag 10 – Covert Data Transfer

**Objective:**
Uncover evidence of internal data leaving the environment.

**What to Hunt:**
Activity that hints at transformation or movement of local HR data.

**Thought:**
Staging the data is quiet. Sending it out makes noise — if you know where to listen.

**Identify the ping of the last unusual outbound connection attempt:**
52.54.13.125

**KQL Query Used:**
```
DeviceNetworkEvents
| where DeviceName == "nathan-iel-vm"
| where RemoteIPType == "Public" // external IPs
| where InitiatingProcessFileName in ("powershell.exe", "ping.exe", "curl.exe", "nc.exe", "netcat.exe")
| project Timestamp, RemoteUrl, RemoteIP
| order by Timestamp asc
```
-Added RemoteIP to last query so I could read the IPs assosicated with the suspect .net TLD.

### 🚩 Flag 11 – Persistence via Local Scripting

**Objective:**
Verify if unauthorized persistence was established via legacy tooling.

**What to Hunt:**
Use of startup configurations tied to non-standard executables.

**Thought:**
A quiet script in the right location can make a backdoor look like a business tool.

**Provide the file name tied to the registry value:**
OnboardTracker.ps1

**KQL Query Used:**
```
DeviceRegistryEvents
| where DeviceName == "nathan-iel-vm"
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueData !contains "Microsoft"  // filters out normal system entries
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc
```

### 🚩 Flag 12 – Targeted File Reuse / Access

**Objective:**
Surface the document that stood out in the attack sequence.

**What to Hunt:**
Repeated or anomalous access to personnel files.

**Thought:**
The file that draws the most interest often holds the motive.

**Format:**
Abcd Efgh

**What is the name of the personnel file that was repeatedly accessed?**
Carlos Tanaka

**KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "nathan-iel-vm"
| summarize AccessCount = count() by FileName, FolderPath
| order by AccessCount desc
```
-To be honest this one was kind of out there, I had seen a file before when I was running queries that had someone's name attached, so I just scrolled down and saw a name (format was the hint) and it happened to be correct.

### 🚩 Flag 13 – Candidate List Manipulation

**Objective:**
Trace tampering with promotion-related data.

**What to Hunt:**
Unexpected modifications to structured HR records.

**Thought:**
Whether tampering or staging — file changes precede extraction.

**Identify the first instance where the file in question is modified and drop the corresponding SHA1 value of it:**
65a5195e9a36b6ce73fdb40d744e0a97f0aa1d34

**KQL Queries Used:**
```
DeviceFileEvents
| where DeviceName == "nathan-iel-vm"
| where ActionType in ("FileModified", "FileCreated", "FileDeleted")

DeviceFileEvents
| where DeviceName == "nathan-iel-vm"
| where ActionType in ("FileModified", "FileCreated", "FileDeleted")
| where FileName contains "PromotionCandidates.csv"
| project SHA1
```
-Added to the query once I saw the appropriate file name, then projected SHA values so I could get the correct one.

### 🚩 Flag 14 – Audit Trail Disruption

**Objective:**
Detect attempts to impair system forensics.

**What to Hunt:**
Operations aimed at removing historical system activity.

**Thought:**
The first thing to go when a crime’s committed? The cameras.

**Hint:**
"ab"

**Identify when the first attempt at clearing the trail was done:**
2025-07-19T05:38:55.6800388Z

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "nathan-iel-vm"
| where ProcessCommandLine contains "wevtutil.exe"
| sort by Timestamp desc
| project Timestamp, InitiatingProcessFileName, ProcessCommandLine
```
- wevtutil.exe is regularly leveraged to delete logs, so all I had to do was look for the first "wevtutil.exe" cl (log).

### 🚩Flag 15 – Final Cleanup and Exit Prep

**Objective:**
Capture the combination of anti-forensics actions signaling attacker exit.

**What to Hunt:**
Artifact deletions, security tool misconfigurations, and trace removals.

**Thought:**
Every digital intruder knows — clean up before you leave or you’re already caugh


**Identify when the last associated attempt occurred:**
2025-07-19T06:18:38.6841044Z

**KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "nathan-iel-vm"
| where InitiatingProcessAccountName == "nathan13l_vm"
| order by Timestamp desc
```
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
