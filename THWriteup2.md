# Threat Hunt Report: **Entry-Level Kill Chain**

Analyst: `James Harrington`

Date Completed: `2025-09-21`

Environment Investigated: `slflarewinsysmo`

Timeframe: `Sept 17 – 21, 2025`

##  Scenario

Suspicious activity has been detected on one of our cloud virtual machines. As a Security Analyst, you’ve been assigned to investigate this incident and determine the scope and impact of the breach.

---

## Executive Summary

Between September 17–21, 2025, an attacker compromised the Windows VM within the slflarewinsysmo environment by brute-forcing RDP access from external IP 159.26.106.84 and successfully logging in with the slflare account. Once inside, the adversary executed a malicious binary (msupdate.exe) via PowerShell with execution bypass, and established persistence by creating a scheduled task (MicrosoftUpdateSync). To evade detection, Microsoft Defender settings were modified to exclude C:\Windows\Temp from scanning.

Following persistence, the attacker conducted system discovery using built-in commands (systeminfo), collected local data, and staged it for exfiltration in an archive file (backup_sync.zip). Outbound communications were established with external infrastructure at 185.92.220.87, with attempts to exfiltrate the staged archive over HTTP to port 8081. Multiple anti-forensic behaviors, including event log clearing, were also observed.

The intrusion demonstrates a complete intrusion kill chain on a single host, from brute-force initial access through execution, persistence, defense evasion, discovery, collection, C2 communication, and exfiltration attempts. No evidence of lateral movement was observed.

---

## Completed Flags

| Flag # | Objective | Value |
|--------|-----------|-------|
| **Start** | Identify the environment investigated | `slflarewinsysmo` |
| **1** | Earliest external IP successfully logged in via RDP | `159.26.106.84` |
| **2** | Compromised account used for login | `slflare` |
| **3** | Name of the executed binary | `msupdate.exe` |
| **4** | Full command line used to execute the binary | `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1"` |
| **5** | Name of persistence mechanism created | `MicrosoftUpdateSync` |
| **6** | Defender setting/folder path modified | `C:\Windows\Temp` |
| **7** | Earliest discovery command executed | `"cmd.exe" /c systeminfo"` |
| **8** | Archive file created by attacker | `backup_sync.zip` |
| **9** | C2 connection destination | `185.92.220.87` |
| **10** | IP and port used in exfiltration attempt | `185.92.220.87:8081` |

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
| 1    | Brute Force: Password Guessing                | T1110.001  | Multiple failed RDP attempts followed by a successful login from external IP `159.26.106.84`. |
| 2    | Valid Accounts                                | T1078      | Attacker used compromised account `slflare` to log in via RDP. |
| 3    | User Execution: Malicious File                | T1204.002  | Executed malicious binary `msupdate.exe` on the host. |
| 4    | Command and Scripting Interpreter: PowerShell | T1059.001  | Launched binary with PowerShell execution bypass (`update_check.ps1`). |
| 5    | Scheduled Task/Job: Scheduled Task            | T1053.005  | Created scheduled task `MicrosoftUpdateSync` for persistence. |
| 6    | Impair Defenses: Disable or Modify Defender   | T1562.001  | Added folder exclusion `C:\Windows\Temp` to bypass Microsoft Defender scans. |
| 7    | System Information Discovery                  | T1082      | Ran `systeminfo` to gather host environment details. |
| 8    | Archive Collected Data: Local Archiving       | T1560.001  | Created archive file `backup_sync.zip` to stage data for exfiltration. |
| 9    | Application Layer Protocol: Web Protocols     | T1071.001  | Established C2 connection with external host `185.92.220.87`. |
| 10   | Exfiltration Over Unencrypted Protocol        | T1048.003  | Attempted to exfiltrate archive file to `185.92.220.87:8081` over HTTP. |

---

# Lessons Learned


- **Initial Access through brute force is still effective.**  
  The attacker gained entry by brute-forcing RDP (Flag 1), then leveraging a valid account (`slflare`) to establish remote access (Flag 2). This highlights the importance of enforcing account lockouts, MFA, and monitoring RDP activity.

- **Malicious binaries combined with PowerShell abuse.**  
  The attacker executed `msupdate.exe` (Flag 3) with an execution bypass PowerShell command (Flag 4). This shows how adversaries blend native interpreters with simple droppers to avoid detection.

- **Persistence established with scheduled tasks.**  
  The scheduled task `MicrosoftUpdateSync` (Flag 5) ensured recurring access, demonstrating how adversaries use Windows Task Scheduler for stealthy persistence.

- **Defender protections were weakened.**  
  By excluding `C:\Windows\Temp` from scanning (Flag 6), the attacker created a safe zone for malicious tools. This reflects a common defense evasion tactic that bypasses endpoint controls without disabling them entirely.

- **Discovery with native tools.**  
  Running `systeminfo` (Flag 7) shows the attacker used living-off-the-land commands to enumerate host details before taking further action.

- **Data staging before exfiltration.**  
  Creation of `backup_sync.zip` (Flag 8) indicates a deliberate step to consolidate files, consistent with preparing sensitive data for transfer.

- **Active command-and-control communications.**  
  Outbound traffic to `185.92.220.87` (Flag 9) demonstrates beaconing and C2 control, further reinforced by the exfiltration attempt (Flag 10).

- **Exfiltration via unencrypted protocol.**  
  Attempting to send data over HTTP to `185.92.220.87:8081` (Flag 10) shows adversaries may not always use encryption, and network-level monitoring can detect such activity.

- **No lateral movement observed.**  
  All malicious activity was contained to a single VM, reducing scope but reinforcing the importance of segmentation and early detection.
  
---

## Recommendations for Remediation

### Containment and Scoping
- Immediately isolate the compromised VM (`slflarewinsysmo`) from the network.  
- Block and monitor traffic to external IP `185.92.220.87` and port `8081`.  
- Review other hosts in the environment for similar brute-force login attempts or scheduled task creation.

### Eradication
- Remove the malicious binary (`msupdate.exe`) and associated script (`update_check.ps1`).  
- Delete the scheduled task `MicrosoftUpdateSync` (Flag 5).  
- Remove the Defender exclusion on `C:\Windows\Temp` and restore default AV policies (Flag 6).  

### Recovery and Validation
- Run a full endpoint scan across the environment to ensure no secondary persistence mechanisms exist.  
- Validate whether any sensitive data was successfully exfiltrated by reviewing network logs around the time of the attempted transfer (Flags 8–10).  
- Rebuild the affected VM from a clean image if compromise scope cannot be fully verified.  

### Detection and Monitoring
- Implement alerting for repeated failed RDP logins followed by success from external IPs (Flags 1–2).  
- Detect execution of PowerShell with `-ExecutionPolicy Bypass` and suspicious script file paths (Flag 4).  
- Monitor creation of scheduled tasks, especially those mimicking system updates (Flag 5).  
- Alert on Defender configuration changes such as folder exclusions (Flag 6).  
- Track native discovery commands (`systeminfo`, `whoami`, `ipconfig`) executed in unusual contexts (Flag 7).  
- Watch for creation of archive files in Temp, Public, or unusual directories (Flag 8).  
- Flag outbound HTTP/S traffic to unknown IPs and high-risk ports like `8081` (Flags 9–10).

### Hardening
- Enforce MFA on all RDP logins and restrict access to trusted IP ranges.  
- Apply account lockout policies to prevent brute-force attacks.  
- Enable Defender Tamper Protection to prevent unauthorized policy changes.  
- Centralize logging (e.g., via SIEM) to prevent local log tampering from impeding investigations.  
- Apply least privilege and limit administrative access on cloud VMs.

### Strategic Improvements
- Conduct user awareness training on credential hygiene to reduce password spraying/brute force success.  
- Regularly review and audit remote access requirements, removing unused accounts.  
- Incorporate simulated brute-force/red-team scenarios into detection engineering to validate readiness.
