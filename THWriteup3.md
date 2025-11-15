# Threat Hunt Report: **Entry-Level Kill Chain**

Analyst: `James Harrington`

Date Completed: `2025-09-21`

Environment Investigated: `slflarewinsysmo`

Timeframe: `Sept 17 – 21, 2025`

##  Scenario

## Scenario

A routine support request should have been a harmless session: quick reset, reassurance, and closure.  
Instead, what unfolded resembled a covert assessment — a sequence of actions that probed, cataloged, and quietly documented the environment under the guise of “help.”

Across multiple machines, processes originating from Downloads hinted at a common vector. Naming patterns like *desk, help, support, tool* began to stand out. Intern-operated hosts in particular showed the earliest anomalies, and one stood out above the rest.

This wasn’t troubleshooting.  
It was reconnaissance disguised as assistance.

Your task: reconstruct the timeline, correlate artifacts, and determine what was legitimate and what was staged.

---

## Executive Summary

Between **October 5–10, 2025**, a pattern of suspicious activity emerged across several machines in the department. Multiple endpoints were observed spawning executables from Downloads directories, sharing similar naming conventions. Analysis quickly identified **gab-intern-vm** as the earliest and most suspicious host, matching all observed indicators.

The actor initiated activity by executing a script using PowerShell with `-ExecutionPolicy` bypass, then placed a staged Defender-related shortcut (`DefenderTamperArtifact.lnk`) to simulate security tampering without performing any real configuration changes. Immediately afterward, the operator performed quick probes such as clipboard scraping, followed by a chain of host and identity reconnaissance.

Host context enumeration, storage mapping, network resolution checks, session enumeration, process inventory, and privilege checks all occurred in rapid sequence — consistent with structured reconnaissance methodology rather than legitimate remote support.

Outbound connectivity was validated using **www.msftconnecttest.com**, and artifacts were consolidated into **C:\Users\Public\ReconArtifacts.zip** for staging. A simulated exfiltration test followed, communicating with **100.29.147.161**.

Persistence was then established via a scheduled task (`SupportToolUpdater`) and reinforced with a fallback autorun entry (`RemoteAssistUpdater`). Finally, a narrative-shaping shortcut (`SupportChat_log.lnk`) was placed — likely intended to justify previous activity.

No lateral movement was observed, but the coherence and sequencing strongly indicate intentional recon rather than accidental or benign support actions.

---

## Completed Flags

| Flag # | Objective | Value |
|--------|-----------|-------|
| **Start** | Identify the environment investigated | `gab-intern-vm` |
| **1** | First CLI parameter used during suspicious execution | `-ExecutionPolicy` |
| **2** | Name of staged tamper artifact | `DefenderTamperArtifact.lnk` |
| **3** | Clipboard probe command | `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"` |
| **4** | Timestamp of last host recon | `2025-10-09T12:51:44.3425653Z` |
| **5** | Second storage enumeration command | `"cmd.exe" /c wmic logicaldisk get name,freespace,size"` |
| **6** | File name of parent process for network check | `RuntimeBroker.exe` |
| **7** | Unique ID of initiating process | `2533274790397065` |
| **8** | Process that shows runtime application inventory | `tasklist.exe` |
| **9** | Timestamp of first privilege query | `2025-10-09T12:52:14.3135459Z` |
| **10** | First outbound destination contacted | `www.msftconnecttest.com` |
| **11** | Full path where staging archive was dropped | `C:\Users\Public\ReconArtifacts.zip` |
| **12** | Last unusual outbound IP contacted | `100.29.147.161` |
| **13** | Scheduled task name created for persistence | `SupportToolUpdater` |
| **14** | Name of autorun registry value created | `RemoteAssistUpdater` |
| **15** | Planted narrative artifact filename | `SupportChat_log.lnk` |

---

## Stage 1 - Initial Access

### 🚩 Flag 1 – Initial Execution Detection

**Objective:**  
Detect the earliest anomalous execution that could represent an entry point.

**What to Hunt:**  
Look for early script execution in Downloads, especially involving PowerShell or unfamiliar support tools.

**Thought:**  
The first deviation from normal user behavior often sets the timeline anchor.

**Hint:**  
1. Downloads  
2. Two  

**What was the first CLI parameter used?**  
`-ExecutionPolicy`

**MITRE Technique:**  
`🔸 T1059.001 – Command and Scripting Interpreter: PowerShell`

---

# Stage 2 - Defense Evasion

### 🚩 Flag 2 – Defense Disabling (Staged)

**Objective:**  
Identify artifacts suggesting attempted or simulated security tampering.

**Thought:**  
A planted tamper indicator isn’t proof of tampering — it signals *intent*.

**Hint:**  
1. File was manually accessed

**What was the name of the file?**  
`DefenderTamperArtifact.lnk`

**MITRE Technique:**  
`🔸 T1562.001 – Impair Defenses (Simulated)`

---

# Stage 3 - Collection (Ephemeral)

### 🚩 Flag 3 – Quick Data Probe

**Objective:**  
Detect brief checks for easily accessible sensitive data.

**Hint:**  
1. Clip  
Side Note: 1/2 — has query code

**Command value:**  
`"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`

**MITRE Technique:**  
`🔸 T1115 – Clipboard Data`

---

# Stage 4 - Discovery

### 🚩 Flag 4 – Host Context Recon

**Objective:**  
Identify when the actor gathered host/environment details.

**Hint:**  
1. qwi  

**Last recon timestamp:**  
`2025-10-09T12:51:44.3425653Z`

**MITRE Technique:**  
`🔸 T1082 – System Information Discovery`

---

# Stage 5 - Storage Surface Mapping

### 🚩 Flag 5 – Storage Assessment

**Objective:**  
Detect enumeration of drives or storage resources.

**Hint:**  
1. Storage assessment  

**Second command:**  
`"cmd.exe" /c wmic logicaldisk get name,freespace,size"`

**MITRE Technique:**  
`🔸 T1083 – File and Directory Discovery`

---

# Stage 6 - Connectivity & Name Resolution

### 🚩 Flag 6 – Network Capability Check

**Objective:**  
Detect outbound connectivity or DNS probes.

**Side Note:**  
1. session  

**Parent process filename:**  
`RuntimeBroker.exe`

**MITRE Technique:**  
`🔸 T1016 – System Network Configuration Discovery`

---

# Stage 7 - Interactive Session Discovery

### 🚩 Flag 7 – Session Enumeration

**Objective:**  
Reveal attempts to identify active sessions.

**Unique Process ID:**  
`2533274790397065`

**MITRE Technique:**  
`🔸 T1033 – System Owner/User Discovery`

---

# Stage 8 - Runtime Application Inventory

### 🚩 Flag 8 – Process Enumeration

**Hint:**  
1. Task  
2. List  
3. Last  

**Representative file:**  
`tasklist.exe`

**MITRE Technique:**  
`🔸 T1057 – Process Discovery`

---

# Stage 9 - Privilege Surface Check

### 🚩 Flag 9 – Privilege Enumeration

**Hint:**  
1. Who  

**Timestamp of first attempt:**  
`2025-10-09T12:52:14.3135459Z`

**MITRE Technique:**  
`🔸 T1069 – Permission Group Discovery`

---

# Stage 10 - Proof-of-Access & Egress Validation

### 🚩 Flag 10 – Outbound Capability Check

**Side Note:**  
1. support  

**First outbound destination contacted:**  
`www.msftconnecttest.com`

**MITRE Technique:**  
`🔸 T1041 – Exfiltration Over C2 Channel`

---

# Stage 11 - Bundling / Staging Artifacts

### 🚩 Flag 11 – Artifact Consolidation

**Hint:**  
1. Include the file value  

**Full folder path:**  
`C:\Users\Public\ReconArtifacts.zip`

**MITRE Technique:**  
`🔸 T1074.001 – Local Data Staging`

---

# Stage 12 - Outbound Transfer Attempt (Simulated)

### 🚩 Flag 12 – Unusual Outbound Traffic

**Side Note:**  
1. chat  

**IP of last unusual outbound connection:**  
`100.29.147.161`

**MITRE Technique:**  
`🔸 T1048 – Exfiltration Over Unencrypted Channel`

---

# Stage 13 - Scheduled Re-Execution Persistence

### 🚩 Flag 13 – Scheduled Task

**Task Name:**  
`SupportToolUpdater`

**MITRE Technique:**  
`🔸 T1053.005 – Scheduled Task`

---

# Stage 14 - Autorun Fallback Persistence

### 🚩 Flag 14 – Registry Run Key

**Name of the registry value:**  
`RemoteAssistUpdater`

**MITRE Technique:**  
`🔸 T1547.001 – Registry Run Keys / Startup Folder`

---

# Stage 15 - Planted Narrative / Cover Artifact

### 🚩 Flag 15 – Cover Story

**Hint:**  
1. The actor opened it for some reason  

**Artifact name:**  
`SupportChat_log.lnk`

**MITRE Technique:**  
`🔸 T1036 – Masquerading (Narrative / Cover Artifact)`

---

# Lessons Learned

- **Suspicious “support tooling” mirrored adversarial behavior.**
- **Clipboard, host, session, privilege, and storage recon happened sequentially.**
- **Persistence was layered**, suggesting preparation for future sessions.
- **Outbound capability was validated before staging**, aligning with structured recon workflows.
- **A narrative artifact was planted**, indicating deliberate misdirection.

---

# Recommendations for Remediation

### Containment
- Immediately isolate **gab-intern-vm**.
- Block outbound traffic to **100.29.147.161**.
- Hunt for the same artifacts on similarly affected hosts.

### Eradication
- Remove persistence mechanisms:  
  - Scheduled Task: `SupportToolUpdater`  
  - Run Key: `RemoteAssistUpdater`
- Delete staging artifacts:  
  - `ReconArtifacts.zip`  
  - `DefenderTamperArtifact.lnk`  
  - `SupportChat_log.lnk`

### Recovery
- Perform full endpoint scans.
- Validate no additional persistence exists.
- Rebuild the machine if scope cannot be confirmed.

### Detection & Monitoring
- Alert on PowerShell execution with **ExecutionPolicy bypass**.
- Detect creation of `.lnk` artifacts in suspicious locations.
- Monitor for **tasklist, whoami, wmic**, and other recon commands in unusual contexts.

### Hardening
- Restrict execution from Downloads.
- Enforce stricter logging and centralization.
- Apply least-privilege principles to intern machines.

