# Threat Hunt Report: **Full Threat Hunt**

Analyst: `James Harrington`

Date Completed: `2025-11-21`

Environment Investigated: `AZUKI-SL`

Timeframe:  `Nov 19 – 20, 2025`

## Scenario

A six-year shipping contract, stable and predictable, was suddenly undercut by a competitor by exactly 3%.  

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

### 🚩 Flag 1: Remote Access Source

Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

**What to Hunt:**  
Query logon events for interactive sessions from external sources during the incident timeframe.
Use DeviceLogonEvents table and filter by ActionType or LogonType values indicating remote access.

**Identify the source IP address of the Remote Desktop Protocol connection?**  
`88.97.178.12`

**KQL Query:**
```KQL
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| project TimeGenerated, AccountName, RemoteIP, LogonType, ActionType
```
Note: Used "Custom time range" for ALL KQL queries: 2025-11-19 to 2025-11-20, then narrowed down once we found relevant events.

<img width="1036" height="462" alt="image" src="https://github.com/user-attachments/assets/b6bc6c88-cde4-4f87-9544-8c3b79385298" />

### 🚩 Flag 2: Compromised User Account

Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews.

**What to Hunt:**
Focus on the account that authenticated during the suspicious remote access session.
Cross-reference the logon event timestamp with the external IP connection.

**Identify the user account that was compromised for initial access?**
`kenji.sato`

**KQL Query:**
```KQL
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where LogonType == 10
| project TimeGenerated, AccountName, RemoteIP
```
<img width="1036" height="462" alt="image" src="https://github.com/user-attachments/assets/b6bc6c88-cde4-4f87-9544-8c3b79385298" />

## Stage 2 - Discovery

### 🚩 Flag 3: Network Reconnaissance

Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

**What to Hunt:**
Look for commands that reveal local network devices and their hardware addresses.
Check DeviceProcessEvents for network enumeration utilities executed after initial access.

**Identify the command and argument used to enumerate network neighbours?**
`arp -a`

**Searching the referenced information I found the following:**

<img width="976" height="44" alt="image" src="https://github.com/user-attachments/assets/3928c05f-d685-4dce-b787-b796ca05360f" />

## Stage 3 - Defense Evasion

### 🚩 Flag 4: Malware Staging Directory

Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

**What to Hunt:**
Search for newly created directories in system folders that were subsequently hidden from normal view.
Look for mkdir or New-Item commands followed by attrib commands that modify folder attributes.

**Identify the user account that was compromised for initial access?**
`C:\ProgramData\WindowsCache`

**KQL Query:**
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "attrib"
| project TimeGenerated, ProcessCommandLine
```

<img width="626" height="291" alt="image" src="https://github.com/user-attachments/assets/8c83f030-ef6c-465e-ae0e-d76369105376" />

### 🚩 Flag 5: File Extension Exclusions

Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

**What to Hunt:**
Search DeviceRegistryEvents for registry modifications to Windows Defender's exclusion settings. Look for the RegistryValueName field containing file extensions.
Count the unique file extensions added to the "Exclusions\Extensions" registry key during the attack timeline.

**How many file extensions were excluded from Windows Defender scanning?**
`3`

**KQL Query:**
```KQL
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains @"Windows Defender\Exclusions\Extensions"
| project RegistryValueName
| distinct RegistryValueName
```

<img width="673" height="329" alt="image" src="https://github.com/user-attachments/assets/e1f38cfe-5901-4088-88ca-b251c2011b22" />

### 🚩 Flag 6: File Temporary Folder Exclusion

Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

**What to Hunt:**
Search DeviceRegistryEvents for folder path exclusions added to Windows Defender configuration. Focus on the RegistryValueName field.
Look for temporary folder paths added to the exclusions list during the attack timeline. Copy the path exactly as it appears in the RegistryValueName field.
The registry key contains "Exclusions\Paths" under Windows Defender configuration.

**How many file extensions were excluded from Windows Defender scanning?**
`C:\Users\KENJI~1.SAT\AppData\Local\Temp`

**KQL Query:**
```KQL
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains @"Windows Defender\Exclusions\Paths"
| project RegistryValueName
| distinct RegistryValueName
```

<img width="598" height="340" alt="image" src="https://github.com/user-attachments/assets/abc81fd3-28ac-4a28-bbf5-d2e9a1d0db0b" />

### 🚩 Flag 7: Download Utility Abuse

Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

**What to Hunt:**
Look for built-in Windows tools with network download capabilities being used during the attack.
Search DeviceProcessEvents for processes with command lines containing URLs and output file paths.

**Identify the Windows-native binary the attacker abused to download files?**
`certutil.exe`

**KQL Query:**
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("certutil", "bitsadmin", "curl", "Invoke-WebRequest", "iwr", "wget", "powershell -c", "-urlcache")
| project Timestamp, FileName, ProcessCommandLine
```

<img width="1539" height="534" alt="image" src="https://github.com/user-attachments/assets/4f157912-2006-43df-9c8d-8ad9acbad6d1" />

## Stage 4 - Persistence

### 🚩 Flag 8: Scheduled Task Name

Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

**What to Hunt:**
Search for scheduled task creation commands executed during the attack timeline.
Look for schtasks.exe with the /create parameter in DeviceProcessEvents.

**Identify the user account that was compromised for initial access?**
`Windows Update Check`

**KQL Query:**
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_all ("schtasks", "/create")
| project ProcessCommandLine
```
Note: Switched to dark mode
<img width="915" height="450" alt="image" src="https://github.com/user-attachments/assets/f0f9b001-c9a9-48fc-b68b-0a4148efa03d" />

### 🚩 Flag 9: Scheduled Task Target

The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

**What to Hunt:**
Extract the task action from the scheduled task creation command line.
Look for the /tr parameter value in the schtasks command.

**Identify the executable path configured in the scheduled task?**
`C:\ProgramData\WindowsCache\svchost.exe`

**KQL Query:**
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_all ("schtasks", "/create")
| project ProcessCommandLine
```
<img width="855" height="296" alt="image" src="https://github.com/user-attachments/assets/af549200-a664-4420-a214-fe4ca478dc1a" />

## Stage 5 - Command & Control

### 🚩 Flag 10: C2 Server Address

Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

**What to Hunt:**
Analyse network connections initiated by the suspicious executable shortly after it was downloaded.
Use DeviceNetworkEvents to find outbound connections from the malicious process to external IP addresses.

** Identify the IP address of the command and control server?**
`78.141.196.6`

**KQL Query:**
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("certutil", "bitsadmin", "curl", "Invoke-WebRequest", "iwr", "wget", "powershell -c", "-urlcache")
| project Timestamp, FileName, ProcessCommandLine
```

<img width="1529" height="491" alt="image" src="https://github.com/user-attachments/assets/799eabeb-83dd-4ba6-b690-bcc009511235" />

### 🚩 Flag 11: C2 Communication Port

Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

**What to Hunt:**
Look for executables downloaded to the staging directory with very short filenames.
Search for files created shortly before LSASS memory access events.

**Identify the destination port used for command and control communications?**
`443`

**KQL Query:**
```KQL
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessFolderPath contains "WindowsCache"
| project RemoteIP, RemotePort, TimeGenerated
```

<img width="770" height="430" alt="image" src="https://github.com/user-attachments/assets/e945b400-63e4-4aa8-b57e-abdb5ddca6be" />

## Stage 6 - Credential Access

### 🚩 Flag 12: Credential Theft Tool

Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

**What to Hunt:**
Look for executables downloaded to the staging directory with very short filenames.
Search for files created shortly before LSASS memory access events.

**Identify the filename of the credential dumping tool?**
`mm.exe`

**KQL Query:**
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("certutil", "bitsadmin", "curl", "Invoke-WebRequest", "iwr", "wget", "powershell -c", "-urlcache")
| project Timestamp, FileName, ProcessCommandLine
```

<img width="770" height="430" alt="image" src="https://github.com/user-attachments/assets/e945b400-63e4-4aa8-b57e-abdb5ddca6be" />

### 🚩 Flag 13: Memory Extraction Module

Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

**What to Hunt:**
Examine the command line arguments passed to the credential dumping tool.
Look for module::command syntax in the process command line or output redirection.

**Identify the module used to extract logon passwords from memory?**
`sekurlsa::logonpasswords`

**KQL Query:**
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName == "mm.exe" 
    or FileName == "mm.exe"
| where ProcessCommandLine has "::"             
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="765" height="344" alt="image" src="https://github.com/user-attachments/assets/186beaab-cbe9-4fa6-aa8b-22a926b8e796" />

### 🚩 Flag 14: Data Staging Archive

Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

**What to Hunt:**
Search for ZIP file creation in the staging directory during the collection phase.
Look for Compress-Archive commands or examine files created before exfiltration activity.

**Identify the compressed archive filename used for data exfiltration?**
`export-data.zip`

**KQL Query:**
```KQL
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FileName endswith ".zip"
| project Timestamp, FileName, FolderPath
```

<img width="728" height="463" alt="image" src="https://github.com/user-attachments/assets/cd6e956c-ddc8-4144-8475-889a73479348" />

## Stage 7 - Exfiltration

### 🚩 Flag 15:  Exfiltration Channel

Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

**What to Hunt:**
Analyse outbound HTTPS connections and file upload operations during the exfiltration phase.
Check DeviceNetworkEvents for connections to common file sharing or communication platforms.

**Identify the cloud service used to exfiltrate stolen data?**
`Discord`

**How I figured it out:**
There were three indicators from earlier flags and host activity that strongly match a known Discord-exfil patterns:

C2 access established
Data staged in C:\ProgramData\WindowsCache
Archive created → export-data.zip
Outbound HTTPS connection follows immediately
No S3/Drive/Mega URLs — only IP over 443

That combo is textbook Discord webhook POST exfiltration.

## Stage 8 - Anti-Forensics

### 🚩 Flag 16: Log Tampering

Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

**What to Hunt:**
Search for event log clearing commands near the end of the attack timeline.
Look for wevtutil.exe executions and identify which log was cleared first.

**Identify the first Windows event log cleared by the attacker?**
`Security`

**KQL Query:**
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "wevtutil"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="498" height="279" alt="image" src="https://github.com/user-attachments/assets/a93a9fdb-7a74-4da2-a308-ee2781eeb56a" />

## Stage 9 - Impact

### 🚩 Flag 17: Persistence Account

Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

**What to Hunt:**
Search for account creation commands executed during the impact phase.
Look for commands with the /add parameter followed by administrator group additions.

**Identify the backdoor account username created by the attacker?**
`support`

**KQL Query:**
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("net user", "net.exe user", "/add")
| project TimeGenerated, ProcessCommandLine
```

<img width="1112" height="415" alt="image" src="https://github.com/user-attachments/assets/182ff0aa-b639-44e5-bfb5-7476ff2f9924" />

## Stage 9 - Execution

### 🚩 Flag 18: Malicious Script

Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

**What to Hunt:**
Search DeviceFileEvents for script files created in temporary directories during the initial compromise phase.
Look for PowerShell or batch script files downloaded from external sources shortly after initial access.

**Identify the PowerShell script file used to automate the attack chain?**
`wupdate.ps1`

**KQL Query:**
```KQL
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FileName matches regex @"\.(ps1|bat|cmd|vbs|js)$"
| project TimeGenerated, FileName, FolderPath
| order by TimeGenerated asc
```

<img width="889" height="615" alt="image" src="https://github.com/user-attachments/assets/e7571b0c-14d1-4cd8-9364-86bd5b799c7e" />

## Stage 10 - Lateral Movement

### 🚩 Flag 19: Secondary Target

Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

**What to Hunt:**
Examine the target system specified in remote access commands during lateral movement.
Look for IP addresses used with cmdkey or mstsc commands near the end of the attack timeline.

**What IP address was targeted for lateral movement?**
`10.1.0.188 1`

**KQL Query:**
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("cmdkey", "mstsc")
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="650" height="389" alt="image" src="https://github.com/user-attachments/assets/1a1e05d9-72cd-46fc-b123-2f5b6fa7a7c1" />

### 🚩 Flag 20: Remote Access Tool

Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

**What to Hunt:**
Search for remote desktop connection utilities executed near the end of the attack timeline.
Look for processes launched with remote system names or IP addresses as arguments.

**Identify the remote access tool used for lateral movement?**
`mstsc.exe`

**KQL Query:**
```KQL
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("cmdkey", "mstsc")
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="650" height="389" alt="image" src="https://github.com/user-attachments/assets/1a1e05d9-72cd-46fc-b123-2f5b6fa7a7c1" />
