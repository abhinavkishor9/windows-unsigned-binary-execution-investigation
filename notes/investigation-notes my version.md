# Investigation Notes

## Lab Summary

This lab examined an unsigned Windows executable from an endpoint-investigation perspective. The analysis combined file-level characteristics with execution telemetry to understand the binary's identity, trust status, and activity on the system.

The investigation also demonstrated how local Windows evidence can be strengthened by correlating it with Sysmon, Windows Security logging, and Wazuh telemetry.

---

## Analyst Methodology

- Establish the suspicious executable and its location.
- Examine its filesystem characteristics and timestamps.
- Inspect embedded application and publisher metadata.
- Validate the executable's digital-signature state.
- Generate a cryptographic fingerprint for the file.
- Compare the filename with the binary's embedded identity.
- Monitor the endpoint for execution activity.
- Examine process-creation evidence from Windows and Sysmon.
- Correlate the activity with Wazuh telemetry.
- Compare findings across evidence sources.
- Assess the overall execution context.
- Record the investigation findings and forensic timeline.

---

## Investigation Scenario

A Windows 11 endpoint is found executing an unsigned executable from the user's Downloads directory. The SOC analyst investigates the file to determine whether it is legitimate or suspicious.

The investigation focuses on:

- Digital Signature – Determine whether the executable is signed.
- File Hash – Calculate the SHA-256 hash for identification and correlation.
- File Metadata – Examine publisher, product name, version, and original filename.
- File Timestamps – Review creation, modification, and access times.
- Execution Evidence – Confirm whether the executable was actually executed.
- Windows Security Logs – Analyze Event ID 4688 for process creation.
- Sysmon Telemetry – Analyze Event ID 1 for additional process details.
- Wazuh Correlation – Determine whether the execution activity was collected by the SIEM.
- DFIR Assessment – Correlate the evidence to determine whether the unsigned binary requires further investigation.

---

## Evidence Collected

### Evidence 1 

`C:\UnsignedBinaryLab`

Finding:

A dedicated investigation workspace was created to isolate the lab artifact from the original Downloads directory.

---

### Evidence 2 



`C:\Users\Dell\Downloads\7z2602-x64.exe`

Finding:

The executable was identified in the user's Downloads directory and selected as the controlled sample for the investigation.

---

### Evidence 3 –

Command Used:

`Get-Item "C:\Users\Dell\Downloads\7z2602-x64.exe" | Select-Object FullName, Length, CreationTime, LastWriteTime, LastAccessTime`

Collected:

- Full path
- File size
- Creation time
- Last write time
- Last access time

Finding:

Filesystem metadata established the basic timeline and location of the executable.

---

### Evidence 4 

Command Used:

`(Get-Item "C:\Users\Dell\Downloads\7z2602-x64.exe").VersionInfo | Select-Object FileName, FileVersion, ProductName, CompanyName, OriginalFilename`

Observed:

- FileVersion: `26.02`
- ProductName: `7-Zip`
- CompanyName: `Igor Pavlov`
- OriginalFilename: `7zipInstall.exe`

Finding:

The embedded metadata identified the executable as a 7-Zip installer despite its current filename.

---

### Evidence 5 

Command Used:

`Get-AuthenticodeSignature "C:\Users\Dell\Downloads\7z2602-x64.exe"`

Result:

`Status: NotSigned`

Finding:

The executable did not contain a valid Authenticode signature.

This indicates that Windows could not establish publisher trust through Authenticode for this file.

---

### Evidence 6

Command Used:

`Get-FileHash "C:\Users\Dell\Downloads\7z2602-x64.exe" -Algorithm SHA256`

Observed SHA256:

`6745FA76DC2EA031596D8678F6F6B99C3C1B435B4164A63485ADBBC7B8D82EF0`

Finding:

The hash provides a unique identifier for the investigated binary.

---

### Evidence 7 

Command Used:

`Get-ChildItem "$env:USERPROFILE" -Filter *.exe -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $sig = Get-AuthenticodeSignature $_.FullName; if ($sig.Status -eq "NotSigned") { $_.FullName } }`

Observed:

`C:\Users\Dell\Downloads\7z2602-x64.exe`

Finding:

The original executable was identified as an unsigned executable during the endpoint search.

---

### Evidence 8 

Collected:

`C:\UnsignedBinaryLab\DemoApp.exe`

Finding:

The original 7-Zip executable was copied into the investigation workspace and renamed to `DemoApp.exe`.

---

### Evidence 9 

Command Used:

`Get-AuthenticodeSignature "C:\UnsignedBinaryLab\DemoApp.exe"`

Result:

`Status: NotSigned`

Finding:

Renaming the executable did not change its signature status.

---

### Evidence 10 

Command Used:

`C:\UnsignedBinaryLab\DemoApp.exe`

Finding:

The executable was launched from the investigation workspace.

This generated process creation activity for subsequent analysis.

---

### Evidence 11 

Source:

`Windows Security Log`

Event ID:

`4688`

---

### Evidence 12 

Source:

`Microsoft-Windows-Sysmon/Operational`

Event ID:

`1`

Finding:

Sysmon provided detailed process creation telemetry including fields such as:

- Image
- Process ID
- Process GUID
- User
- Command line
- Parent image
- Parent process ID
- Hashes

This provides stronger execution context than a basic process creation event alone.

---

### Evidence 13 

Endpoint:

`DESKTOP-9MMM37V`

Agent ID:

`001`

Finding:

Wazuh successfully reported endpoint telemetry and exposed Windows process-related fields through Wazuh Discover.

Relevant fields included:

- `agent.name`
- `agent.id`
- `data.win.eventdata.image`
- `data.win.eventdata.commandLine`
- `data.win.eventdata.parentImage`
- `data.win.eventdata.hashes`
- `data.win.eventdata.originalFileName`
- `data.win.eventdata.company`
- `data.win.eventdata.fileVersion`

---

## Evidence Correlation

| Evidence | Source | Finding |
| -------- | ------ | ------- |
| Original file | Windows filesystem | `7z2602-x64.exe` |
| Product identity | VersionInfo | 7-Zip |
| Company | VersionInfo | Igor Pavlov |
| Original filename | VersionInfo | `7zipInstall.exe` |
| Signature | PowerShell | NotSigned |
| SHA256 | PowerShell | `6745FA76DC2EA031596D8678F6F6B99C3C1B435B4164A63485ADBBC7B8D82EF0` |
| Renamed file | Windows filesystem | `DemoApp.exe` |
| Process creation | Security Log | Event ID 4688 |
| Process creation | Sysmon | Event ID 1 |
| Endpoint visibility | Wazuh | Telemetry available |

---


## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Relevance |
| ------ | --------- | -- | --------- |
| Execution | User Execution | T1204 | Relevant to executable execution investigations |
| Execution | Command and Scripting Interpreter | T1059 | PowerShell used for investigation and execution workflow |
| Defense Evasion | Masquerading | T1036 | Binary renamed from its original application name |
| Defense Evasion | Indicator Removal | T1070 | Relevant to broader investigation context |

---

