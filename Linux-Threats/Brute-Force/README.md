<img width="400" src="https://github.com/user-attachments/assets/495a74f2-9b7d-4f44-9017-015d6449675f"/>

# Threat Hunt Report: Brute Force
- [Scenario Creation](https://github.com/Goodka7/Threat-Hunting/blob/main/Linux-Threats/Brute-Force/Threat-Hunt-Event(Brute%20Force).md)
  
## Platforms and Languages Leveraged
- Linux (Ubuntu 22.04) Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- hydra
- Bash

## Scenario

Management suspects that an attacker is attempting to gain unauthorized access to a system by brute-forcing SSH credentials, they are concerned that the attacker may have compromised a machine on the network. Additionally, they are concerned that the attacker may have access to sensetive and confidential company information. The goal is to detect any attempts to access a computer on the network as well as to check and see if any files have been manipulated.

## High-Level IoC Discovery Plan

- **Check `DeviceLogonEvents`** for login events that could indicate Brute-Force attempts.
- **Check `DeviceFilesEvents`** for events that indicate file manipulation.
- **Check `DeviceProcessEvents`** for suspicious processes that might indicate persistence.
- **Check `DeviceNetworkEvents`** for suspicious network activity for connections or potential data exfiltration.
---

## Steps Taken

### 1. Searched the `DeviceLogonEvents` Table

Searched for login events on the network to see if there were any machines receiving multiple login attempts and faailures. Though many machines had questionable traffic, it was seen that another user **"backdoor"** was created on the same machine that had been logged in by the user **"baddog"**.

At Feb 8, 2025 1:05:00 PM, the user **"baddog"** had 18 `LogonFailed` events on `DeviceName` **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**.

At Feb 8, 2025 1:10:00 PM, the user **"backdoor"** had 6 `LogonFailed` events on `DeviceName` **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" or ActionType == "LogonSuccess"
| summarize FailedAttempts = count() by AccountName, DeviceName, bin(Timestamp, 5m)
| where FailedAttempts > 5
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/1f45fbd9-f1cc-4e8f-9f75-5c550dd63aeb">

### 2. Searched the `DeviceFileEvents` Table

Searched for file events on the machine to check for any unusual activity related to file creation or modification, which could indicate backdoor creation or persistence mechanisms. Several suspicious files were identified, particularly those related to the **"backdoor"** user and the creation of a system backdoor.

At **Feb 8, 2025 1:13:08 PM**, a file named `backdoor.sh` was created on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**, located at `/home/backdoor/backdoor.sh`. This file is indicative of an attempt to establish a reverse shell or another form of backdoor.

At **Feb 8, 2025 1:13:38 PM**, a file named `.backdoor.service.swp` was created on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**, located at `/etc/systemd/system/.backdoor.service.swp`. This file is a temporary file, likely related to the creation of a malicious systemd service designed to ensure persistence.

At **Feb 8, 2025 1:11:54 PM**, a file named `authorized_keys` was created on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**, located at `/home/backdoor/.ssh/authorized_keys`. This file indicates that the attacker has set up SSH key-based access for the **"backdoor"** account, allowing future, password-less logins.

These file events point to suspicious activity that suggests the attacker is trying to secure ongoing access to the machine and potentially maintain control after the initial login.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "thlinux"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessId
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/d90281cf-81cc-40ee-8c8e-582ef3adc93a">

### 3. Searched the `DeviceProcessEvents` Table

Searched for suspicious processes executed by the **"baddog"** and **"backdoor"** accounts on the device. The following processes were found to be potentially related to backdoor creation and persistence:

At **Feb 8, 2025 1:11:06 PM**, the **"baddog"** account executed the process `-bash` on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**. This could indicate an attempt to gain interactive shell access.

At **Feb 8, 2025 1:11:32 PM**, the **"backdoor"** account executed `/bin/bash /home/backdoor/backdoor.sh` on the same device. This script is likely related to the backdoor setup, allowing the attacker to maintain persistent access.

At **Feb 8, 2025 1:11:32 PM** and onwards, the **"backdoor"** account repeatedly executed `/bin/bash /home/backdoor/backdoor.sh`, further solidifying that the attacker is attempting to maintain and potentially escalate access through a malicious script.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where AccountName in ("baddog", "backdoor")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/4b989818-b55e-4645-82dc-6c2bf8a80f29">

### 4. Searched the `DeviceNetworkEvents` Table

Searched for network activity to detect any suspicious connections or potential data exfiltration attempts by the **"baddog"** and **"backdoor"** accounts. Several key connections were observed:

At **Feb 8, 2025 1:07:18 PM**, the **"baddog"** account established a connection to `10.0.0.36` on `port 22 (SSH)`, using the `TCP` protocol. This connection could indicate an attempt to access the system remotely or communicate with another system.

This connection is consistent with the attacker's use of SSH for remote control and potentially for data exfiltration or further manipulation of the system.

```kql
DeviceNetworkEvents
| where DeviceName == "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where ActionType == "ConnectionSuccess"
| where RemoteIP != "Internal"  // Assuming internal traffic should be from known IP ranges
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol, InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/f01822dd-8b3b-4851-b92a-8a4c88543690">

---

## **Chronological Event Timeline**

### 1. **Suspicious Login Attempts - Brute Force (Logon Table)**
- **Time:** `Feb 8, 2025 1:05:00 PM`
- **Event:** The **"baddog"** account experienced 18 failed login attempts on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**.
- **Action:** Brute force login attempts detected.
- **Account Name:** `baddog`
- **Device Name:** `thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

### 2. **Suspicious Login Attempts - Brute Force (Logon Table)**
- **Time:** `Feb 8, 2025 1:10:00 PM`
- **Event:** The **"backdoor"** account had 6 failed login attempts on the same device, suggesting that the attacker attempted to access the system using the backdoor account.
- **Action:** Brute force login attempts detected.
- **Account Name:** `backdoor`
- **Device Name:** `thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

### 3. **Suspicious Network Connection - Outbound to Internal IP (Network Table)**
- **Time:** `Feb 8, 2025 1:07:18 PM`
- **Event:** The **"baddog"** account initiated an outbound SSH connection to `10.0.0.36` on port `22`, which could indicate an attempt to access an internal system or transfer data.
- **Action:** Network connection detected.
- **Remote IP:** `10.0.0.36`
- **Remote Port:** `22`
- **Protocol:** `TCP`
- **Initiating Account:** `baddog`

### 4. **Suspicious Process Execution - Backdoor Script (Process Table)**
- **Time:** `Feb 8, 2025 1:11:32 PM`
- **Event:** The **"backdoor"** account executed `/bin/bash /home/backdoor/backdoor.sh`, which is likely part of the backdoor setup for maintaining persistent access.
- **Action:** Process execution detected.
- **Command:** `/bin/bash /home/backdoor/backdoor.sh`
- **File Path:** `/home/backdoor/backdoor.sh`

### 5. **File Creation - Backdoor SSH Access (File Table)**
- **Time:** `Feb 8, 2025 1:11:54 PM`
- **Event:** The **"backdoor"** account created the `authorized_keys` file in the `/home/backdoor/.ssh/` directory, allowing SSH key-based access for future logins without a password.
- **Action:** File creation detected.
- **File Path:** `/home/backdoor/.ssh/authorized_keys`
- **File Name:** `authorized_keys`

### 6. **Suspicious File Creation - Backdoor Script (File Table)**
- **Time:** `Feb 8, 2025 1:13:08 PM`
- **Event:** The **"backdoor"** account created the `backdoor.sh` file in the `/home/backdoor/` directory, which is likely used to maintain persistent access to the system.
- **Action:** File creation detected.
- **File Path:** `/home/backdoor/backdoor.sh`
- **File Name:** `backdoor.sh`

### 7. **Suspicious File Creation - Backdoor Service (File Table)**
- **Time:** `Feb 8, 2025 1:13:38 PM`
- **Event:** The **"backdoor"** account created a temporary file `.backdoor.service.swp` in the `/etc/systemd/system/` directory, which could indicate an attempt to create a malicious systemd service for persistence.
- **Action:** File creation detected.
- **File Path:** `/etc/systemd/system/.backdoor.service.swp`
- **File Name:** `.backdoor.service.swp`

---

## **Summary**

The user **"baddog"** on the device **"thlinux"** engaged in a series of suspicious actions, suggesting potential unauthorized activities. First, **"baddog"** attempted multiple login attempts, with 18 failed attempts followed by 6 failed login attempts from the **"backdoor"** account, raising concerns about brute-force login activity. After successfully gaining access, the user executed a series of commands, including running a backdoor script (`/home/backdoor/backdoor.sh`) and setting up SSH key-based access by creating the `authorized_keys` file in the `/home/backdoor/.ssh/` directory, which allowed for password-less logins in the future.

Additionally, the user created files related to maintaining persistence, such as `backdoor.sh` and a temporary file `.backdoor.service.swp` in the `/etc/systemd/system/` directory, which could indicate an attempt to set up a malicious systemd service. The network logs also showed that **"baddog"** successfully initiated an SSH connection to an internal device `10.0.0.36`, suggesting possible lateral movement or communication between compromised systems.

These actions indicate that **"baddog"** and **"backdoor"** were involved in setting up a backdoor for persistent access, executing a reverse shell, and potentially exfiltrating data or further compromising the system.

---

## **Response Taken**

The suspicious file manipulation and encryption activities performed by the employee **"baddog"** on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"** were confirmed. The device was immediately isolated to prevent any further risks.

I suggest the encrypted files (`fake_cards.enc`, `fake_user.enc`) be reviewed to ensure no sensitive data was exfiltrated.

Further monitoring is being conducted to ensure no unauthorized access or data exfiltration occurred during the period of exposure.

---
