# windows-unsigned-binary-execution-investigation
## Overview

Windows executable files can be digitally signed by their publisher.

A digital signature helps an investigator determine:

Who claims to have published the file
Whether Windows trusts the publisher
Whether the file has been modified after signing
Whether the binary has a valid Authenticode signature

For example:

Executable
    ↓
Digital Signature
    ↓
Publisher
    ↓
Signature Status

Why unsigned binaries matter in DFIR

Suppose Wazuh detects:

C:\Users\Public\Downloads\update.exe

The analyst discovers:

Signature: Not Signed
Publisher: Unknown

That alone isn't enough.

But then we discover:

update.exe
    ↓
executed by user
    ↓
launched PowerShell
    ↓
created another executable
    ↓
made outbound connection

Now the unsigned binary becomes a high-value investigative lead.

The investigation is therefore about execution context and behavior, not simply signature status.

In this lab, an unsigned 7-Zip executable was copied from the user's Downloads directory into a dedicated investigation workspace and renamed to `DemoApp.exe`. The file was then analyzed using PowerShell and executed to generate process-creation telemetry.

The execution was correlated with Windows Security Event ID 4688, Sysmon Event ID 1, and Wazuh endpoint telemetry.

---

# Lab Objectives

- Determine whether an executable has a trusted publisher identity.
- Establish the file's unique identity using cryptographic evidence.
- Identify discrepancies between the executable's filename and embedded metadata.
- Reconstruct when the file was introduced, modified, and accessed.
- Establish whether the binary transitioned from file presence to actual execution.
- Trace the process back to its parent process and execution context.
- Validate the same activity across multiple independent telemetry sources.
- Assess whether the available evidence is sufficient to classify the activity as suspicious or requires further investigation.

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

# Investigation Steps

### Step 1 

Create a dedicated workspace:

`C:\UnsignedBinaryLab`


---

### Step 2 – Identify the Original Executable

Located at:

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




# MITRE ATT&CK Context

This lab primarily focuses on forensic investigation of execution rather than demonstrating an attack technique.

Relevant ATT&CK context includes:

- T1204 – User Execution
- T1059 – Command and Scripting Interpreter
- T1036 – Masquerading
- T1070 – Indicator Removal on Host

`T1036 – Masquerading` is particularly relevant to the filename change from a 7-Zip executable to `DemoApp.exe`.

---

