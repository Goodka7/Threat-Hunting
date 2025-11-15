# Threat Hunt Report: **Full Threat Hunt**

Analyst: `James Harrington`

Date Completed: `2025-11-08`

Environment Investigated: `gab-intern-vm`

Timeframe: `Nov 08 – 15, 2025`

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
| **3** | Clipboard probe command |` "powershell.exe" -NoProfile -Sta -Command try { Get-Clipboard Out-Null} catch{}" ` |
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
Look for atypical script or interactive command activity that deviates from normal user behavior or baseline patterns.

**Thought:**  
Pinpointing the first unusual execution helps you anchor the timeline and follow the actor’s parent/child process chain.

**What was the first CLI parameter name used during the execution of the suspicious program?**  
`-ExecutionPolicy`

**MITRE Technique:**  
`🔸 T1059.001 – Command and Scripting Interpreter: PowerShell`

---

# Stage 2 - Defense Evasion

### 🚩 Flag 2 – Defense Disabling

**Objective:**  
Identify indicators that suggest attempts to imply or simulate changing security posture.

**What to Hunt:**  
Search for artifact creation or short-lived process activity that contains tamper-related content or hints, without assuming an actual configuration change occurred.

**Thought:**  
A planted or staged tamper indicator is a signal of intent — treat it as intent, not proof of actual mitigation changes.

**What was the name of the file related to this exploit?**  
`DefenderTamperArtifact.lnk`

**MITRE Technique:**  
`🔸 T1562.001 – Impair Defenses`

---

# Stage 3 - Collection (Ephemeral)

### 🚩 Flag 3 – Quick Data Probe

**Objective:**  
Spot brief, opportunistic checks for readily available sensitive content.

**What to Hunt:**  
Find short-lived actions that attempt to read transient data sources common on endpoints.

**Thought:** 
Attackers look for low-effort wins first; these quick probes often precede broader reconnaissance.

**Provide the command value tied to this particular exploit:**  
`"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`

**MITRE Technique:**  
`🔸 T1115 – Clipboard Data`

---

# Stage 4 - Discovery

### 🚩 Flag 4 – Host Context Recon

**Objective:**  
Find activity that gathers basic host and user context to inform follow-up actions.

**What to Hunt:**
Telemetry that shows the actor collecting environment or account details without modifying them.

**Thought::**
Context-gathering shapes attacker decisions — who, what, and where to target next.

**Point out when the last recon attempt was:**  
`2025-10-09T12:51:44.3425653Z`

**MITRE Technique:**  
`🔸 T1082 – System Information Discovery`

---

# Stage 5 - Storage Assessment

### 🚩 Flag 5 – Storage Surface Mapping

**Objective:**  
Detect discovery of local or network storage locations that might hold interesting data.

**What to Hunt:**
Look for enumeration of filesystem or share surfaces and lightweight checks of available storage.

**Thought:**
Mapping where data lives is a preparatory step for collection and staging.

**Provide the 2nd command tied to this activity:**  
`"cmd.exe" /c wmic logicaldisk get name,freespace,size"`

**MITRE Technique:**  
`🔸 T1083 – File and Directory Discovery`

---

# Stage 6 - Network Capability Check

### 🚩 Flag 6 – Connectivity & Name Resolution Check

**Objective:**  
Detect outbound connectivity or DNS probes.

**What to Hunt:**
Network or process events indicating DNS or interface queries and simple outward connectivity probes.

**Thought:**
Confirming egress is a necessary precondition before any attempt to move data off-host.

**Provide the File Name of the initiating parent process:**  
`RuntimeBroker.exe`

**MITRE Technique:**  
`🔸 T1016 – System Network Configuration Discovery`

---

# Stage 7 - Session Enumeration

### 🚩 Flag 7 – Interactive Session Discovery

**Objective:**  
Reveal attempts to detect interactive or active user sessions on the host.

**What to Hunt:**
Signals that enumerate current session state or logged-in sessions without initiating a takeover.

**Thought:**
Knowing which sessions are active helps an actor decide whether to act immediately or wait.

**What is the unique ID of the initiating process:**  
`2533274790397065`

**MITRE Technique:**  
`🔸 T1033 – System Owner/User Discovery`

---

# Stage 8 - Process Enumeration

### 🚩 Flag 8 – Runtime Application Inventory

**Objective:**  
Detect enumeration of running applications and services to inform risk and opportunity.

**What to Hunt:**
Events that capture broad process/process-list snapshots or queries of running services.

**Thought:**
A process inventory shows what’s present and what to avoid or target for collection.

**Provide the file name of the process that best demonstrates a runtime process enumeration event on the target host:**  
`tasklist.exe`

**MITRE Technique:**  
`🔸 T1057 – Process Discovery`

---

# Stage 9 - Privilege Enumeration

### 🚩 Flag 9 – Privilege Surface Check

**Objective:**  
Detect attempts to understand privileges available to the current actor.

**What to Hunt:**
Telemetry that reflects queries of group membership, token properties, or privilege listings.

**Thought:**
Privilege mapping informs whether the actor proceeds as a user or seeks elevation.

**Identify the timestamp of the very first attempt:**  
`2025-10-09T12:52:14.3135459Z`

**MITRE Technique:**  
`🔸 T1069 – Permission Group Discovery`

---

# Stage 10 - Outbound Capability Check

### 🚩 Flag 10 – Proof-of-Access & Egress Validation

**Objective:**  
Find actions that both validate outbound reachability and attempt to capture host state for exfiltration value.

**What to Hunt:**
Look for combined evidence of outbound network checks and artifacts created as proof the actor can view or collect host data.

**Thought:**
This step demonstrates both access and the potential to move meaningful data off the host.

**Which outbound destination was contacted first?**  
`www.msftconnecttest.com`

**MITRE Technique:**  
`🔸 T1041 – Exfiltration Over C2 Channel`

---

# Stage 11 - Artifact Consolidation

### 🚩 Flag 11 – Bundling / Staging Artifacts

**Objective:**  
Detect consolidation of artifacts into a single location or package for transfer.

**What to Hunt:**
File system events or operations that show grouping, consolidation, or packaging of gathered items.

**Thought:**
Staging is the practical step that simplifies exfiltration and should be correlated back to prior recon.

**Full folder path:**  
`C:\Users\Public\ReconArtifacts.zip`

**MITRE Technique:**  
`🔸 T1074.001 – Local Data Staging`

---

# Stage 12 - Unusual Outbound Traffic

### 🚩 Flag 12 – Outbound Transfer Attempt (Simulated)

**Objective:**  
Identify attempts to move data off-host or test upload capability.

**What to Hunt:**
Network events or process activity indicating outbound transfers or upload attempts, even if they fail.

**Thought:**
Succeeded or not, attempt is still proof of intent — and it reveals egress paths or block points.

**Provide the IP of the last unusual outbound connection:**  
`100.29.147.161`

**MITRE Technique:**  
`🔸 T1048 – Exfiltration Over Unencrypted Channel`

---

# Stage 13 - Persistence via Scheduled Tasks

### 🚩 Flag 13 – Scheduled Re-Execution Persistence

**Objective:**  
Detect creation of mechanisms that ensure the actor’s tooling runs again on reuse or sign-in.

**What to Hunt:**
Process or scheduler-related events that create recurring or logon-triggered executions tied to the same actor pattern.

**Thought:**
Re-execution mechanisms are the actor’s way of surviving beyond a single session — interrupting them reduces risk.

**Provide the value of the task name down below:**  
`SupportToolUpdater`

**MITRE Technique:**  
`🔸 T1053.005 – Scheduled Task`

---

# Stage 14 - Registry Key Autorun

### 🚩 Flag 14 – Autorun Fallback Persistence

**Objective:**  
Spot lightweight autorun entries placed as backup persistence in user scope.

**What to Hunt:**
Registry or startup-area modifications that reference familiar execution patterns or repeat previously observed commands.

**Thought:**
Redundant persistence increases resilience; find the fallback to prevent easy re-entry.

**⚠️ If table returned nothing: RemoteAssistUpdater**

**What was the name of the registry value:**  
`RemoteAssistUpdater`

**MITRE Technique:**  
`🔸 T1547.001 – Registry Run Keys / Startup Folder`

---

# Stage 15 - Cover Story

### 🚩 Flag 15 – Planted Narrative / Cover Artifact

**Objective:**  
Identify a narrative or explanatory artifact intended to justify the activity.

**What to Hunt:**
Creation of explanatory files or user-facing artifacts near the time of suspicious operations; focus on timing and correlation rather than contents.

**Thought:**
A planted explanation is a classic misdirection. The sequence and context reveal deception more than the text itself.

**Artifact name:**  
`SupportChat_log.lnk`

**MITRE Technique:**  
`🔸 T1036 – Masquerading (Narrative / Cover Artifact)`

---

# Lessons Learned

**Initial execution was disguised as routine support activity.**  
The earliest suspicious action — PowerShell execution using `-ExecutionPolicy` bypass demonstrates how easily malicious or dual-use tooling can be slipped into a support narrative. This highlights the need for stricter monitoring of script execution originating from user-facing directories like Downloads, especially when tied to unusual parameters or remote-assistance contexts.

**Staged security tamper artifacts indicate narrative shaping, not actual defense evasion.**  
The presence of `DefenderTamperArtifact.lnk` shows that the operator attempted to *suggest* Defender manipulation without modifying any real configuration. This sort of planted evidence is an advanced misdirection technique and underscores the importance of verifying telemetry rather than relying on surface-level artifacts.

**Early reconnaissance focused on quick-win data sources.**  
Clipboard probing reveals opportunistic attempts to capture sensitive information with minimal effort. These checks often precede deeper recon and demonstrate why endpoint auditing of ephemeral data access must be taken seriously.

**Host and environment discovery was systematic and sequential.**  
The timestamped recon commands (`2025-10-09T12:51:44.3425653Z`) illustrate a structured approach to understanding the system’s operating context. Gathering user, system, and environment details enables adversaries — or malicious “support” operators — to plan subsequent actions with precision.

**The actor performed detailed storage mapping to identify data-rich locations.**  
Commands such as `wmic logicaldisk get` show that the operator enumerated storage surfaces to determine where valuable data might reside. This stage mirrors the preparation phase seen in targeted intrusions prior to staging or exfiltration.

**Connectivity and DNS checks confirmed outbound egress capability.**  
Outbound validation through system processes like `RuntimeBroker.exe` and test destinations such as `www.msftconnecttest.com` indicates deliberate verification of network reachability. This behavior typically signals preparation for data movement or C2 communication.

**Session and privilege discovery informed the attacker’s operational posture.**  
Identifying active sessions `2533274790397065` and enumerating privileges `2025-10-09T12:52:14.3135459Z` reflect an assessment of whether the current user context was safe for continued activity. Recon of this kind helps adversaries decide if escalation is needed or if they must wait for low-visibility windows.

**Runtime process inventory enabled the actor to understand active defenses and workloads.**  
Execution of tools like `tasklist.exe` shows that the operator sought insight into running applications and potential interference points. This step corresponds to the situational awareness phase in many intrusion playbooks.

**Artifacts were consolidated for potential exfiltration.**  
The creation of `ReconArtifacts.zip` indicates deliberate staging of collected data into a centralized, easy-to-transfer package. Even if no full exfiltration succeeded, this behavior demonstrates clear intent and preparation.

**Outbound attempts to unusual external IPs were made, even if only simulated.**  
Connections to hosts such as `100.29.147.161` show tests of external accessibility and mock upload paths. Whether real or simulated, these attempts provide visibility into the operator’s intent to validate external communication routes.

**Persistence mechanisms were intentionally layered.**  
The scheduled task `SupportToolUpdater` combined with the registry autorun value `RemoteAssistUpdater` demonstrates redundant persistence. This mirrors attacker tradecraft meant to ensure re-entry even if one mechanism is discovered and removed.

**A narrative artifact was deliberately planted to justify suspicious actions.**  
The creation of `SupportChat_log.lnk` highlights active misdirection. By providing a faux support log, the operator attempted to manufacture legitimacy for their activity, a behavior aligned with threat actors who anticipate post-incident review.

**No lateral movement was observed.**  
All activity remained localized to a single endpoint — **gab-intern-vm** — suggesting either a controlled assessment or an early-stage intrusion. This containment, whether by design or by limitation, reinforces the importance of early detection and segmentation to prevent broader compromise.


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
