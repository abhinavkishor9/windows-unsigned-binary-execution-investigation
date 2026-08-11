# Windows Unsigned Binary Execution Investigation (DFIR Lab)

## Overview

Unsigned executables can represent a significant endpoint security concern because Windows cannot use a valid Authenticode publisher signature to establish the file's software identity and publisher trust.

From a DFIR perspective, an unsigned executable should not automatically be considered malicious. However, when an unsigned binary is found in a user-controlled location, renamed to an unexpected filename, and executed, investigators should preserve its metadata, calculate its cryptographic hash, verify its signature status, and correlate the execution with endpoint telemetry.

In this lab, an unsigned 7-Zip executable was copied from the user's Downloads directory into a dedicated investigation workspace and renamed to `DemoApp.exe`. The file was then analyzed using PowerShell and executed to generate process-creation telemetry.

The execution was correlated with Windows Security Event ID 4688, Sysmon Event ID 1, and Wazuh endpoint telemetry.

---

# Lab Objectives

- Understand unsigned binary execution from a DFIR perspective
- Verify the digital signature of an executable
- Calculate a SHA256 file hash
- Collect executable metadata
- Identify file origin and naming changes
- Execute an unsigned binary in a controlled lab environment
- Analyze Windows Event ID 4688
- Analyze Sysmon Event ID 1
- Correlate endpoint telemetry using Wazuh Discover
- Document forensic observations

---

# Lab Environment

| Component          | Value                                      |
| ------------------ | ------------------------------------------ |
| Host OS            | Windows 11 Pro                              |
| SIEM               | Wazuh 4.12                                  |
| Endpoint Agent     | Wazuh Agent                                 |
| Endpoint Name      | DESKTOP-9MMM37V                             |
| Investigation Type | Unsigned Binary Execution Investigation     |
| Investigation Host | Windows Endpoint                            |
| Tools Used         | PowerShell, Event Viewer, Sysmon, Wazuh     |

---

# Tools Used

- Windows PowerShell
- Get-AuthenticodeSignature
- Get-FileHash
- Get-Item
- VersionInfo
- Windows Event Viewer
- Windows Security Event ID 4688
- Sysmon Event ID 1
- Wazuh Discover
- Wazuh Agent

---

# Investigation Scenario

An analyst discovers an executable in a user's Downloads directory.

The file has several characteristics that require investigation:

- It is located in a user-controlled Downloads directory.
- The executable is not digitally signed.
- The file is renamed before execution.
- The original filename identifies the file as a 7-Zip installer.
- The renamed executable is executed from an investigation directory.
- Process creation telemetry is available through Windows and Wazuh.

The investigation must determine:

- Is the executable digitally signed?
- Who is the apparent publisher?
- What is the SHA256 hash?
- What was the original filename?
- Was the executable executed?
- Can process creation telemetry confirm execution?
- Can Wazuh provide additional endpoint context?

---

# Investigation Steps

### Step 1 – Create Investigation Workspace

Create a dedicated workspace:

`C:\UnsignedBinaryLab`

This separates the investigation artifact from the original Downloads location.

---

### Step 2 – Identify the Original Executable

The original executable was located at:

`C:\Users\Dell\Downloads\7z2602-x64.exe`

The file was selected as the controlled unsigned-binary sample for this lab.

---

### Step 3 – Collect File Metadata

Command Used:

`Get-Item "C:\Users\Dell\Downloads\7z2602-x64.exe" | Select-Object FullName, Length, CreationTime, LastWriteTime, LastAccessTime`

Collected metadata included:

- Full file path
- File size
- Creation time
- Last write time
- Last access time

---

### Step 4 – Collect Version Information

Command Used:

`(Get-Item "C:\Users\Dell\Downloads\7z2602-x64.exe").VersionInfo | Select-Object FileName, FileVersion, ProductName, CompanyName, OriginalFilename`

Observed metadata:

| Field            | Value            |
| ---------------- | ---------------- |
| FileVersion      | 26.02            |
| ProductName      | 7-Zip             |
| CompanyName      | Igor Pavlov       |
| OriginalFilename | 7zipInstall.exe  |

This is important because the file was later renamed to `DemoApp.exe`.

---

### Step 5 – Calculate SHA256 Hash

Command Used:

`Get-FileHash "C:\Users\Dell\Downloads\7z2602-x64.exe" -Algorithm SHA256`

Observed SHA256:

`6745FA76DC2EA031596D8678F6F6B99C3C1B435B4164A63485ADBBC7B8D82EF0`

The hash provides a stable identifier for the analyzed file.

---

### Step 6 – Verify Authenticode Signature

Command Used:

`Get-AuthenticodeSignature "C:\Users\Dell\Downloads\7z2602-x64.exe"`

Result:

`Status: NotSigned`

This established that Windows did not identify a valid Authenticode signature for the executable.

---

### Step 7 – Search for Unsigned Executables

Command Used:

`Get-ChildItem "$env:USERPROFILE" -Filter *.exe -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $sig = Get-AuthenticodeSignature $_.FullName; if ($sig.Status -eq "NotSigned") { $_.FullName } }`

The investigation identified:

`C:\Users\Dell\Downloads\7z2602-x64.exe`

as an unsigned executable.

---

### Step 8 – Copy and Rename the Binary

The executable was copied into the investigation workspace and renamed:

`C:\UnsignedBinaryLab\DemoApp.exe`

Command Used:

`Copy-Item "C:\Users\Dell\Downloads\7z2602-x64.exe" "C:\UnsignedBinaryLab\DemoApp.exe"`

This simulated a suspicious scenario in which an executable is given a misleading or generic filename.

---

### Step 9 – Verify the Renamed Binary

Command Used:

`Get-AuthenticodeSignature "C:\UnsignedBinaryLab\DemoApp.exe"`

Result:

`Status: NotSigned`

The renamed file remained unsigned.

The original file metadata also remained associated with the binary, allowing investigators to identify it as a 7-Zip executable despite the filename change.

---

### Step 10 – Execute the Binary

Command Used:

`C:\UnsignedBinaryLab\DemoApp.exe`

The executable was launched from the investigation workspace to generate process creation telemetry.

---

### Step 11 – Review Windows Security Event ID 4688

Windows Security Event ID 4688 records process creation when appropriate auditing is enabled.

Event Viewer was filtered for:

`Event ID: 4688`

The lab environment contained process creation events associated with the endpoint.

This provides host-level evidence that processes were created during the investigation period.

---

### Step 12 – Review Sysmon Event ID 1

Sysmon Event ID 1 records process creation activity and can provide richer execution context.

The investigation reviewed:

`Microsoft-Windows-Sysmon/Operational`

with:

`Event ID: 1`

The event data includes fields such as:

- Process GUID
- Process ID
- Image
- User
- Command line
- Parent process
- Parent process ID
- Hashes

These fields can be used to correlate an executable with its execution context.

---

### Step 13 – Review Wazuh Discover

Wazuh Discover was used to review endpoint telemetry from:

`DESKTOP-9MMM37V`

Relevant fields include:

- `agent.name`
- `agent.id`
- `agent.ip`
- `data.win.eventdata.image`
- `data.win.eventdata.commandLine`
- `data.win.eventdata.parentImage`
- `data.win.eventdata.parentCommandLine`
- `data.win.eventdata.hashes`
- `data.win.eventdata.originalFileName`
- `data.win.eventdata.company`
- `data.win.eventdata.fileVersion`

This demonstrates how local Windows evidence can be correlated with centralized SIEM telemetry.

---

# Key Findings

- The original executable was located in the user's Downloads directory.
- The executable identified itself through version metadata as 7-Zip.
- Company metadata identified `Igor Pavlov`.
- The original filename was `7zipInstall.exe`.
- The executable was renamed to `DemoApp.exe`.
- The executable returned `NotSigned` through `Get-AuthenticodeSignature`.
- The SHA256 hash was `6745FA76DC2EA031596D8678F6F6B99C3C1B435B4164A63485ADBBC7B8D82EF0`.
- The renamed executable was successfully executed.
- Windows Security Event ID 4688 provided process-creation telemetry.
- Sysmon Event ID 1 provided detailed process-creation telemetry.
- Wazuh provided centralized endpoint visibility.

---

# Evidence Correlation

| Evidence | Source | Observation |
| -------- | ------ | ----------- |
| Original executable | Windows filesystem | `7z2602-x64.exe` found in Downloads |
| File metadata | PowerShell | Creation, modification, access and size information collected |
| Version metadata | PowerShell VersionInfo | 7-Zip / Igor Pavlov metadata identified |
| Original filename | VersionInfo | `7zipInstall.exe` |
| Digital signature | Get-AuthenticodeSignature | `NotSigned` |
| SHA256 | Get-FileHash | `6745FA76DC2EA031596D8678F6F6B99C3C1B435B4164A63485ADBBC7B8D82EF0` |
| Renamed binary | Windows filesystem | `C:\UnsignedBinaryLab\DemoApp.exe` |
| Process execution | Windows Security | Event ID 4688 available |
| Process execution | Sysmon | Event ID 1 available |
| Endpoint telemetry | Wazuh Discover | Endpoint telemetry available |
| Execution metadata | Wazuh | Image, command line, parent process and hash fields available |

---

# DFIR Analysis

The important forensic finding was not simply that the executable was unsigned.

The investigation demonstrated a chain of evidence:

`User Downloads → Unsigned Executable → Metadata Collection → Filename Change → Execution → Process Creation Telemetry → Wazuh Correlation`

The filename `DemoApp.exe` did not represent the executable's original identity. Version metadata identified the file as a 7-Zip installer, demonstrating why investigators should not rely only on filenames when analyzing suspicious executables.

The Authenticode result of `NotSigned` means the file lacked a valid Authenticode signature that Windows could use to establish publisher trust. This alone does not prove maliciousness, but it increases the need for additional validation.

The SHA256 hash provides an artifact identifier that can be used for future correlation with malware repositories, threat intelligence, endpoint telemetry, and other forensic evidence.

---

# MITRE ATT&CK Context

This lab primarily focuses on forensic investigation of execution rather than demonstrating an attack technique.

Relevant ATT&CK context includes:

- T1204 – User Execution
- T1059 – Command and Scripting Interpreter
- T1036 – Masquerading
- T1070 – Indicator Removal on Host

`T1036 – Masquerading` is particularly relevant to the filename change from a 7-Zip executable to `DemoApp.exe`.

---

# Analyst Observations

- File signatures should be verified rather than inferred from filenames.
- An unsigned executable is not automatically malicious.
- File metadata can reveal an executable's original identity.
- Renaming a binary does not necessarily remove embedded version information.
- SHA256 provides a reliable artifact identifier.
- Event ID 4688 can confirm process creation when auditing is enabled.
- Sysmon Event ID 1 provides richer process execution context.
- Wazuh can centralize Windows endpoint telemetry.
- Multiple independent artifacts provide stronger forensic confidence than a single indicator.

---

# Skills Practiced

- Windows DFIR
- Unsigned Binary Analysis
- Authenticode Verification
- File Metadata Analysis
- SHA256 Hashing
- Process Execution Analysis
- Windows Event ID 4688
- Sysmon Event ID 1
- Wazuh Discover
- Evidence Correlation
- Endpoint Investigation
- DFIR Documentation

---

# Outcome

Successfully investigated an unsigned Windows executable by collecting file metadata, verifying its Authenticode signature, calculating its SHA256 hash, identifying its original application metadata, executing it in a controlled environment, and correlating process-creation evidence with Windows Security logs, Sysmon, and Wazuh endpoint telemetry.
