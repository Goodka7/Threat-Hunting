
# Threat Hunt Report: **HR Data Exfil**

Analyst: James Harrington

Date Completed: 2025-08-18

Environment Investigated: nathan-iel-vm

Timeframe: July 17 – 20, 2025

##  Scenario

A sudden, unexplained promotion has triggered whispers across the executive floor. The recipient? A mid-level employee with no standout track record — at least, not one visible anymore.

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
- HR related stuffs or tools were recently touched, investigate any dropped scripts or configs over the mid-July weekends

**Identified System:**
nathan-iel-vm

**Reasoning:**
Using the provided telemetry, nathan-iel-vm showed access to files and folders with HR designation:

/HRTools/
/HR_Storm/
HRTools.lnk
HRConfig.json

This aligns with the operational timeline in question.

Note: Used "Custom time range: 2025-07-17 to 2025-07-20"
**KQL Query Used:**
```
DeviceFileEvents
| where FileName contains "HR"
```
**Query made based on context clues, found the VM name quickly and it was correct.**

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
**I used this query because of the hint: Who, it turned out to have all the information I needed.**

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
**Realted the the query above so didn't need to do anything extra.**

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
**Query was made so I could observe the baseline powershell commands being ran, after scrolling down for a few seconds I saw the obvious command.**

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
**The previous KQL query showed the next command used was "powershell.exe" qwinsta, out of curiosity I googled qwinsta and found out that it dealt with sessions... so I modified my search to look for the process name.**


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
**Third time using this same query, but it has a lot of good info if you just follow the timeline.**


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
**Given the clues, I knew it was related to Registry events, the "thought" was a big clue that it had to do with AntiVirus or Microsoft Defender**

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
**Query was made to look for common filenames that would be included for memory dumps**


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
**Using the hint, was pretty easy to find.**

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
**Added RemoteIP to last query so I could read the IPs assosicated with the suspect .net TLD**

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
**To be honest this one was kind of out there, I had seen a file before when I was running queries that had someone's name attached, so I just scrolled down and saw a name (format was the hint) and it happened to be correct.**


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
**Added to the query once I saw the appropriate file name, then projected SHA values so I could get the correct one.**

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
**wevtutil.exe is regularly leveraged to delete logs, so all I had to do was look for the first "wevtutil.exe" cl (log).**

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
## MITRE ATT&CK Technique Mapping

| Flag | MITRE Technique | ID        | Description |
|------|-----------------|-----------|-------------|
| 1    | PowerShell | T1059.001 | Initial use of PowerShell for script execution. |
| 2    | Application Layer Protocol | T1071 | Beaconing via HTTPS to external infrastructure (pipedream.net). |
| 3    | Registry Run Keys/Startup Folder | T1547.001 | Persistence via HKCU\...\Run registry key with C2.ps1. |
| 4    | Scheduled Task/Job | T1053.005 | Alternate persistence through scheduled task SimC2Task. |
| 5    | Obfuscated Files or Information | T1027 | Execution of base64-encoded PowerShell command. |
| 6    | Indicator Removal on Host | T1070 | PowerShell v2 downgrade to bypass AMSI/logging. |
| 7    | Remote Services: Scheduled Task | T1021.003 | Lateral movement using schtasks.exe targeting victor-disa-vm. |
| 8    | Lateral Tool Transfer | T1570 | Use of .lnk files like savepoint_sync.lnk to stage/pivot. |
| 8.1  | Registry Modification | T1112 | savepoint_sync.ps1 registered for autorun. |
| 9    | Application Layer Protocol | T1071.001 | New beaconing to eo1v1texxlrdq3v.m.pipedream.net. |
| 10   | WMI Event Subscription | T1546.003 | Stealth persistence via WMI script beacon_sync_job_flag2.ps1. |
| 11   | Credential Dumping Simulation | T1003 | Mimic of credential access via mimidump_sim.txt. |
| 12   | Data Staged: Local | T1074.001 | PowerShell process connects to drive.google.com. |
| 13   | Data from Information Repositories | T1213 | Access of sensitive doc RolloutPlan_v8_477.docx. |
| 14   | Archive Collected Data | T1560.001 | Use of Compress-Archive to prepare ZIP payload. |
| 15   | Ingress Tool Transfer | T1105 | Staging of spicycore_loader_flag8.zip. |
| 16   | Scheduled Task/Job | T1053.005 | Final scheduled task SpicyPayloadSync set to trigger script on logon. |

---

## Diamond Model of Intrusion Analysis

+--------------------+         +----------------------+
|     Adversary      |<------>|     Infrastructure   |
|  Phantom Group     |         |  pipedream.net       |
|  (Mercenary Unit?) |         |  drive.google.com    |
|                    |         |  beacon_sync.ps1     |
+--------------------+         +----------------------+
          ^                                  |
          |                                  v
+--------------------+         +----------------------+
|       Victim       |<------>|      Capability      |
|  acolyte756        |         |  PowerShell, WMI,    |
|  victor-disa-vm    |         |  Registry, LNK,      |
|  User: acolight    |         |  Scheduled Tasks     |
+--------------------+         +----------------------+



##  Lessons Learned

### Attackers Prioritize Stealth over Speed
Use of PowerShell, obfuscation, and native utilities (schtasks.exe, svchost.exe) highlights blending with legitimate activity to prolong access.  

### Persistence Techniques Were Layered and Diverse
Registry autoruns, scheduled tasks, and WMI-based persistence ensured redundancy and resilience against single-point remediation.  

### Command-and-Control Infrastructure Evaded Traditional Detection
Beaconing leveraged public services (pipedream.net, drive.google.com) to blend into normal outbound traffic, avoiding blocklists.  

### Credential Theft Was Simulated Using Realistic Artifacts
Artifacts such as mimidump_sim.txt suggest staging or red-team-level exercises emulating credential scraping.  

### Lateral Movement Occurred Without Credential Changes
Remote task creation demonstrated the adversary’s ability to reuse existing credentials without raising identity alerts.  

---

## Recommendations for Remediation

### Implement Script Block Logging & Deep PowerShell Auditing
Enable enhanced PowerShell logging (via GPO), forward logs to SIEM, and flag obfuscation/encoding or version downgrades.  

### Audit and Harden Task Scheduler and WMI Interfaces
Monitor schtasks.exe, Register-ScheduledTask, and WMI consumers/filters. Periodically audit persistence points with Sysinternals tools.  

### Restrict Outbound Traffic to Known Good Destinations
Use firewall egress rules and DNS allowlisting. Block suspicious destinations such as *.pipedream.net.  

### Apply Lateral Movement Detection Rules
Alert on schtasks /S, WinRM anomalies, or remote scheduled task creation. Correlate with unusual file access.  

### Secure and Monitor Shared Directories
Restrict access to Public, AppData, and Temp. Monitor for unauthorized .ps1 scripts and archive drops.  

### Enhance User Credential Protection
Enable LSASS protection (Credential Guard). Enforce MFA and strong credential policies for privileged accounts.  

### Run Regular Threat Hunts Using MITRE ATT&CK Mapping
Leverage mapped TTPs as hunting templates to continuously validate defenses against similar adversary behaviors.  
