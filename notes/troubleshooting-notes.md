# Troubleshooting Notes

## Lab: Windows Unsigned Binary Execution Investigation

---

## Issue 1 – Add-Type Compilation Failed

### Problem

The original lab approach attempted to compile a custom executable using PowerShell `Add-Type`.

The command returned an error indicating:

`Both the assembly types 'ConsoleApplication' and 'WindowsApplication' are not currently supported.`

### Cause

The available PowerShell/.NET environment did not support the requested executable assembly output through the attempted `Add-Type` configuration.

### Resolution

The compilation-based portion of the lab was removed.

Instead of creating a custom executable, an existing executable was used as the controlled investigation sample.

This produced a more reliable DFIR workflow because the primary objective of the lab was unsigned-binary analysis and execution telemetry rather than software development.

---

## Issue 2 – csc.exe Was Not Used

### Problem

The initial approach considered compiling the sample using `csc.exe`.

### Resolution

The lab was modified so that no C# compilation was required.

An existing executable was copied into the investigation directory and analyzed using native Windows tools.

This simplified the lab and reduced unnecessary dependency on a compiler.

---

## Issue 3 – Existing Unsigned Binary Required

### Problem

A controlled unsigned executable was required to generate realistic investigation evidence.

### Resolution

The executable:

`C:\Users\Dell\Downloads\7z2602-x64.exe`

was selected after verifying its Authenticode status.

Command Used:

`Get-AuthenticodeSignature "C:\Users\Dell\Downloads\7z2602-x64.exe"`

Result:

`NotSigned`

This made the file suitable for the lab.

---

## Issue 4 – Filename Did Not Represent the Embedded Application Identity

### Observation

The executable was copied and renamed to:

`C:\UnsignedBinaryLab\DemoApp.exe`

However, embedded version information continued to identify it as 7-Zip.

### Verification

Command Used:

`(Get-Item "C:\UnsignedBinaryLab\DemoApp.exe").VersionInfo | Select-Object FileName, FileVersion, ProductName, CompanyName, OriginalFilename`

Observed metadata included:

- ProductName: `7-Zip`
- CompanyName: `Igor Pavlov`
- OriginalFilename: `7zipInstall.exe`

### Resolution

The filename was treated only as one evidence source.

Embedded metadata and cryptographic hash were used to establish the executable's identity.

---

## Issue 5 – Signature Status Remained NotSigned After Rename

### Observation

After renaming the executable, signature verification continued to return:

`NotSigned`

### Explanation

Renaming a file does not create a digital signature.

The Authenticode signature state is associated with the executable's signed content and certificate information rather than the filename itself.

### Verification

`Get-AuthenticodeSignature "C:\UnsignedBinaryLab\DemoApp.exe"`

Result:

`NotSigned`

---

## Issue 6 – File Hash Required for Correlation

### Problem

Filename-based correlation is unreliable because executables can be renamed.

### Resolution

The SHA256 hash was collected.

Command Used:

`Get-FileHash "C:\UnsignedBinaryLab\DemoApp.exe" -Algorithm SHA256`

Observed SHA256:

`6745FA76DC2EA031596D8678F6F6B99C3C1B435B4164A63485ADBBC7B8D82EF0`

The hash provides a stable identifier for the binary.

---

## Issue 7 – Windows Event ID 4688 Contains Many Process Creation Events

### Observation

The Security log contained a large number of Event ID 4688 records.

### Resolution

The investigation focused on:

- Event timestamp
- New process information
- Process image
- Creator process
- Account information
- Command line where available

Event ID 4688 should be correlated with other telemetry rather than treated as standalone evidence.

---

## Issue 8 – Sysmon Event ID 1 Contains Large Amounts of Data

### Observation

Sysmon Event ID 1 generates detailed process creation telemetry.

The event can contain:

- Process GUID
- Process ID
- Image
- Command line
- Parent process
- Parent command line
- User
- Hashes
- File metadata

### Resolution

The investigation focused on the fields most useful for executable correlation:

`Image`

`CommandLine`

`ParentImage`

`Hashes`

`OriginalFileName`

`Company`

`FileVersion`

These fields provide stronger evidence when correlated with the analyzed executable.

---

## Issue 9 – Wazuh Discover Contains Numerous Endpoint Events

### Observation

Wazuh Discover contained many Windows process-related events.

### Resolution

The endpoint was narrowed using:

`agent.name: DESKTOP-9MMM37V`

Relevant process fields were then reviewed.

This reduced unrelated endpoint telemetry and made process execution analysis easier.

---

## Issue 10 – Do Not Automatically Treat an Unsigned File as Malware

### Observation

The executable returned:

`Status: NotSigned`

### Interpretation

An unsigned executable is not automatically malicious.

Legitimate software can be unsigned.

The correct DFIR approach is to combine:

- Signature status
- File location
- File metadata
- Original filename
- SHA256 hash
- Process execution
- Parent process
- Command line
- User context
- SIEM telemetry
- Threat intelligence when available

### Resolution

The lab documented the binary as an unsigned executable rather than automatically labeling it as malware.

---

## Lessons Learned

- A lab should prioritize the investigation objective rather than unnecessary technical complexity.
- Native Windows tools are sufficient for many executable triage tasks.
- File signatures should be checked directly.
- File hashes are more reliable for correlation than filenames.
- Embedded version metadata can reveal renamed executables.
- Windows Event ID 4688 provides useful process creation evidence.
- Sysmon Event ID 1 provides richer process execution context.
- Wazuh can centralize endpoint evidence.
- An unsigned binary requires investigation, not automatic classification as malicious.
