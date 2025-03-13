# Threat Event (Data Theft)

## Steps the "Bad Actor" took to Create Logs and IoCs:

1. Create a folder and a few files housing "sensetive corparate" information.
2. Create a folder for the bad actor to transfer the files to.
3. Move the files into the bad actors folder.
4. Encrypt the files using OpenSSL.
5. Make another folder that mimics an External Drive.
6. Move the files to said folder.


## Tables Used to Detect IoCs:

| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceProcessEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose** | Used to detect the copying, moving and/or encryption of confidential company data. |

---

## Related Queries:

```kql
// Detect the copying, moving and/or encryption of confidential company data.
DeviceProcessEvents
| project AccountName, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
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
