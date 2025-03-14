<img width="400" src="https://github.com/user-attachments/assets/c878e233-d060-4f34-96e9-deb4bcc32fe8"/>

# Threat Hunt Report: Impossible Travel
- [Scenario Creation](https://github.com/Goodka7/Threat-Hunting-Impossible-Travel-/blob/main/resources/Threat-Hunt-Event(Impossible%20Travel).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell

## Scenario

Management is concerned about potential unauthorized access attempts from geographically distant locations, which may indicate compromised credentials or unauthorized user activity. Recent security logs have revealed irregular login attempts from multiple locations within a short time frame, suggesting the possibility of impossible travel. The goal is to detect suspicious login activity, such as logins from distant IPs that occur simultaneously or within an unrealistic timeframe, and analyze any related security incidents. If such activity is identified, notify management for further investigation.

### High-Level PowerShell Discovery Plan

- **Check `DeviceLogonEvents`** for suspicious logon activities, such as multiple logins from distant IP addresses in a short time frame.  
- **Check `DeviceNetworkEvents`** to identify unusual network activity, including logins from unexpected or foreign IP addresses and VPN-related connections.  
- **Check `DeviceProcessEvents`** for evidence of tools or scripts used to simulate logins or tamper with authentication mechanisms (e.g., `powershell.exe`, `cmd.exe`).  

---

## Steps Taken

### 1. Searched the `DeviceLogonEvents' Table

Searched for any suspicious logon activities, such as multiple logins from distant IP addresses in a short time.

The dataset included login events across multiple devices and user accounts, with notable activity for the account `labuser`. Logins were recorded for various devices, but the focus has been placed on the machine `windows-target-1`, which exhibited activity indicative of potential compromise. Many entries lacked `RemoteIP` details, reducing their relevance to identifying geographic or source anomalies.

**Query used to locate events:**

```kql
DeviceLogonEvents
| project Timestamp, AccountName, DeviceName, RemoteIP
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/6e3da45a-4ab1-4d06-8ad3-fad9a877ae70">

---

### 2. Searched the `DeviceLogonEvents` Table again

Searched for login events on the device `windows-target-1` associated with the account `labuser`.

The scope was been refined to prioritize:
- Login events originating from `windows-target-1` to identify patterns of unauthorized access.
- Activity associated with the account `labuser` to trace potential misuse of credentials.
- Available `RemoteIP` data to detect geographic variations and potential indicators of lateral movement or external compromise.

The dataset reveals multiple login events for the user `labuser` on the device `windows-target-1`, originating from two distinct IP addresses. On **Jan 27, 2025, at 11:14:46 AM**, login activity was recorded from the IP `89.117.41.164`. Earlier, at **11:12:31 AM**, a login was recorded from the IP `135.237.186.85`. These logins occurred within a short timeframe, indicating geographically disparate access points.

This activity indicates Impossible Travel, where a single account is used to log in from different locations in rapid succession. The presence of these distinct IPs suggests potential credential compromise or the use of obfuscation techniques, such as a VPN, to simulate external access. Further analysis of network and process events may provide additional context to validate this behavior.

**Query used to locate event:**

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1" and AccountName == "labuser"
| project Timestamp, AccountName, DeviceName, RemoteIP
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/45288972-df92-47bb-9acc-45959bc34f3d">

---

### 3. Searched the `DeviceNetworksEvents` Table

Searched for network activity on the device `windows-target-1` within the specified time range, filtering for actions initiated by the account `labuser`.

The dataset reveals multiple successful network connections initiated by processes tied to the account `labuser`. On **Jan 27, 2025, at 11:12:49 AM**, a connection was established to the external IP `4.153.57.10` via `smartscreen.exe`, a process associated with Windows SmartScreen. Additional connections were made shortly thereafter using `SearchApp.exe` at **11:12:48 AM** and **11:12:47 AM**, reaching IPs such as `13.107.246.41` and `150.171.84.254`. These processes indicate legitimate post-login activity from the user, reinforcing evidence of interaction on the system.

While the observed network activity does not directly correspond to the `RemoteIP` addresses from the login events, it supports the timeline of events surrounding the logins. This validates that the account `labuser` was actively performing actions during the specified timeframe, lending credibility to the login events as part of a larger behavioral pattern. Additional investigation of the `RemoteIP` addresses may provide further clarity, particularly regarding their geographic origins or connections to known infrastructure.

This information strengthens the case for Impossible Travel by confirming active use of the account during and immediately after the login events, supporting the broader context of the investigation.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "windows-target-1" and InitiatingProcessAccountName == "labuser"
| where Timestamp >= datetime(2025-01-27T02:36:26.576202Z) and Timestamp <= datetime(2025-01-27T03:15:06.3246301Z)
| project Timestamp, DeviceName, RemoteIP, LocalIP, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/92db7d4a-d5c2-4695-bb18-45d5de33944e">

---

### 4. Searched the `DeviceProcessEvents` Table

### Analysis of `DeviceProcessEvents`

Searched for evidence of tools or scripts used to simulate logins or tamper with authentication mechanisms on the device `windows-target-1`.

The dataset reveals multiple instances of `cmd.exe` executed by the account `labuser` on `windows-target-1`. On **Jan 27, 2025, at 11:15:06 AM**, `cmd.exe` was executed, followed by another execution at **11:12:48 AM**. An earlier execution of `cmd.exe` was recorded at **10:36:26 AM**. No other tools, such as `powershell.exe`, were identified in this dataset.

The use of `cmd.exe` indicates interactive activity on the system and corresponds with observed login events. Commands such as `ipconfig` may have been executed to validate network configurations or system information during user activity. While these actions may align with legitimate use, further investigation is required to determine whether they represent authorized actions or potential misuse.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "windows-target-1" and AccountName == "labuser"
| where FileName in ("powershell.exe", "cmd.exe")
| project Timestamp, AccountName, DeviceName, FileName, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/aed5e71a-8641-4b5b-bf64-119cc0f9a010">

---

## Chronological Event Timeline

### 1. Login Event and Command Execution
- **Time:** `11:12:31 AM, January 27, 2025`
- **Event:** A login was recorded for the account `labuser` from the IP address `135.237.186.85` on the device `windows-target-1`.
- **Action:** Shortly after, a process initiated by `cmd.exe` executed the command `ipconfig` to retrieve network configuration details.
- **Initiating Process:** `cmd.exe`

### 2. Second Login Event from a Different Location
- **Time:** `11:14:46 AM, January 27, 2025`
- **Event:** Another login was recorded for the same account `labuser` from the IP address `89.117.41.164` on the same device.
- **Action:** Following this login, another instance of `cmd.exe` was executed to run the `ipconfig` command.
- **Initiating Process:** `cmd.exe`

---

## Summary

The user "labuser" on the device "windows-target-1" performed a series of actions that align with suspicious behavior. Key findings include geographically disparate logins originating from two different IP addresses within a short time frame, suggesting potential credential compromise or the use of obfuscation techniques such as a VPN. Following these logins, `cmd.exe` was executed twice to run the `ipconfig` command, which may indicate an attempt to validate network configurations after login. These actions, while not conclusively malicious, warrant further investigation to determine whether they represent unauthorized activity or legitimate user behavior.

---

## Response Taken

Suspicious activity was confirmed on the endpoint `windows-target-1` by the user `labuser`. Anomalous login behavior, combined with subsequent command execution, suggests the possibility of credential misuse. The device has been flagged for monitoring, and a recommendation has been made to isolate it if further suspicious behavior is observed. A detailed report has been provided to the manager to determine next steps, which may include credential resets for the affected account, a deeper investigation into the identified IPs, and reviewing access policies to prevent recurrence.

---
