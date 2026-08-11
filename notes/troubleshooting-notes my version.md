# Troubleshooting Notes

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

