# Investigation Notes

## Lab Summary

This investigation focused on analyzing the execution of an unsigned Windows executable using native PowerShell tools, Windows Event Viewer, Sysmon, and Wazuh.

The investigation began with an executable located in the user's Downloads directory. The file was identified as a 7-Zip executable through its embedded version information. Its Authenticode signature status was checked and returned `NotSigned`.

The executable was then copied into a dedicated investigation directory and renamed to `DemoApp.exe`. The renamed executable was executed to generate process creation telemetry for forensic correlation.

---

## Analyst Methodology

1. Create investigation workspace.
2. Identify the original executable.
3. Collect file metadata.
4. Collect embedded version information.
5. Calculate SHA256 hash.
6. Verify Authenticode signature.
7. Search for unsigned executables.
8. Copy the executable into the investigation workspace.
9. Rename the executable.
10. Verify the renamed executable.
11. Execute the binary.
12. Review Windows Security Event ID 4688.
13. Review Sysmon Event ID 1.
14. Review Wazuh endpoint telemetry.
15. Correlate forensic evidence.
16. Document findings.

---

## Investigation Scenario

Suppose a SOC analyst receives an alert indicating that an unusual executable was executed on a Windows endpoint.

The executable is located in a user-controlled directory and does not have a valid digital signature.

The analyst needs to determine:

- What is the executable?
- Who appears to have produced it?
- Is the binary digitally signed?
- What is its SHA256 hash?
- Has the filename been changed?
- Was the executable actually executed?
- What process-creation evidence exists?
- Can the activity be correlated in Wazuh?

The investigation uses native Windows evidence and centralized endpoint telemetry to answer these questions.

---

## Evidence Collected

### Evidence 1 – Investigation Workspace

Collected:

`C:\UnsignedBinaryLab`

Finding:

A dedicated investigation workspace was created to isolate the lab artifact from the original Downloads directory.

---

### Evidence 2 – Original Executable

Collected:

`C:\Users\Dell\Downloads\7z2602-x64.exe`

Finding:

The executable was identified in the user's Downloads directory and selected as the controlled sample for the investigation.

---

### Evidence 3 – File Metadata

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

### Evidence 4 – Embedded Version Information

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

### Evidence 5 – Authenticode Signature

Command Used:

`Get-AuthenticodeSignature "C:\Users\Dell\Downloads\7z2602-x64.exe"`

Result:

`Status: NotSigned`

Finding:

The executable did not contain a valid Authenticode signature.

This indicates that Windows could not establish publisher trust through Authenticode for this file.

---

### Evidence 6 – SHA256 Hash

Command Used:

`Get-FileHash "C:\Users\Dell\Downloads\7z2602-x64.exe" -Algorithm SHA256`

Observed SHA256:

`6745FA76DC2EA031596D8678F6F6B99C3C1B435B4164A63485ADBBC7B8D82EF0`

Finding:

The hash provides a unique identifier for the investigated binary.

---

### Evidence 7 – Unsigned Executable Discovery

Command Used:

`Get-ChildItem "$env:USERPROFILE" -Filter *.exe -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $sig = Get-AuthenticodeSignature $_.FullName; if ($sig.Status -eq "NotSigned") { $_.FullName } }`

Observed:

`C:\Users\Dell\Downloads\7z2602-x64.exe`

Finding:

The original executable was identified as an unsigned executable during the endpoint search.

---

### Evidence 8 – Renamed Executable

Collected:

`C:\UnsignedBinaryLab\DemoApp.exe`

Finding:

The original 7-Zip executable was copied into the investigation workspace and renamed to `DemoApp.exe`.

This demonstrates why filename-based identification alone can be misleading during DFIR investigations.

---

### Evidence 9 – Renamed Binary Signature Validation

Command Used:

`Get-AuthenticodeSignature "C:\UnsignedBinaryLab\DemoApp.exe"`

Result:

`Status: NotSigned`

Finding:

Renaming the executable did not change its signature status.

---

### Evidence 10 – Process Execution

Command Used:

`C:\UnsignedBinaryLab\DemoApp.exe`

Finding:

The executable was launched from the investigation workspace.

This generated process creation activity for subsequent analysis.

---

### Evidence 11 – Windows Security Event ID 4688

Source:

`Windows Security Log`

Event ID:

`4688`

Finding:

Windows Security auditing contained process creation events for the endpoint.

Event ID 4688 provides host-level evidence that a new process was created.

---

### Evidence 12 – Sysmon Event ID 1

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

### Evidence 13 – Wazuh Endpoint Telemetry

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

## DFIR Analysis

The investigation demonstrates that executable identity should be established through multiple artifacts rather than the filename alone.

The executable was originally named `7z2602-x64.exe`, but its embedded metadata identified it as a 7-Zip executable with an original filename of `7zipInstall.exe`.

The binary returned `NotSigned` through Authenticode validation. This is an important triage observation but does not independently establish maliciousness.

The SHA256 hash provides a strong artifact identifier that can be used for future correlation.

After the file was renamed to `DemoApp.exe` and executed, process creation telemetry could be examined through Windows Security Event ID 4688, Sysmon Event ID 1, and Wazuh.

The combination of file metadata, signature information, hashing, process creation logs, and SIEM telemetry provides significantly stronger evidence than any individual artifact.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Relevance |
| ------ | --------- | -- | --------- |
| Execution | User Execution | T1204 | Relevant to executable execution investigations |
| Execution | Command and Scripting Interpreter | T1059 | PowerShell used for investigation and execution workflow |
| Defense Evasion | Masquerading | T1036 | Binary renamed from its original application name |
| Defense Evasion | Indicator Removal | T1070 | Relevant to broader investigation context |

---

## Analyst Observations

- Digital signature status should always be validated directly.
- `NotSigned` does not automatically mean malware.
- Embedded metadata can reveal the identity of renamed executables.
- Filenames should not be treated as authoritative evidence of software identity.
- SHA256 provides a useful artifact identifier.
- Event ID 4688 provides process creation evidence.
- Sysmon Event ID 1 provides richer execution context.
- Wazuh provides centralized visibility into Windows endpoint activity.
- Multiple evidence sources should be correlated before assigning maliciousness.
- A renamed executable should be investigated using hashes and embedded metadata rather than filename alone.

---

## Investigation Conclusion

The investigation successfully demonstrated a structured DFIR workflow for an unsigned executable.

The binary was identified as a 7-Zip executable, its embedded metadata was collected, its Authenticode status was confirmed as `NotSigned`, and its SHA256 hash was recorded.

The binary was then renamed to `DemoApp.exe`, executed in the controlled lab environment, and correlated with Windows process creation telemetry and Wazuh endpoint data.

The investigation demonstrates how Windows-native tools and SIEM telemetry can be combined to validate executable identity, execution activity, and endpoint context.
