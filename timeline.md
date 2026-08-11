# Investigation Timeline

## Lab: Windows Unsigned Binary Execution Investigation

| Time | Event | Evidence Source | Investigation Significance |
| ---- | ----- | --------------- | -------------------------- |
| 05-08-2026 07:02:58 | Original executable creation time recorded | Windows filesystem metadata | Establishes original file creation timestamp |
| 05-08-2026 07:02:59 | Original executable last-write time recorded | Windows filesystem metadata | Establishes file modification timestamp |
| 11-08-2026 10:23 | Investigation workspace created | PowerShell | Created `C:\UnsignedBinaryLab` |
| 11-08-2026 10:26:33 | Original executable accessed | Windows filesystem metadata | Shows recent access to the original binary |
| 11-08-2026 10:xx | File metadata collected | PowerShell | Collected path, size and filesystem timestamps |
| 11-08-2026 10:xx | Version information collected | PowerShell | Identified 7-Zip metadata and original filename |
| 11-08-2026 10:xx | Authenticode signature checked | PowerShell | Binary returned `NotSigned` |
| 11-08-2026 10:xx | SHA256 calculated | PowerShell | Hash recorded as `6745FA76DC2EA031596D8678F6F6B99C3C1B435B4164A63485ADBBC7B8D82EF0` |
| 11-08-2026 10:xx | Unsigned executable identified | PowerShell | `7z2602-x64.exe` identified as unsigned |
| 11-08-2026 10:xx | Binary copied to investigation workspace | PowerShell | Created `C:\UnsignedBinaryLab\DemoApp.exe` |
| 11-08-2026 10:xx | Renamed binary signature checked | PowerShell | Renamed binary remained `NotSigned` |
| 11-08-2026 10:xx | `DemoApp.exe` executed | PowerShell | Generated process execution activity |
| 11-08-2026 10:34:xx | Process creation telemetry observed | Sysmon | Sysmon Event ID 1 available for endpoint process activity |
| 11-08-2026 09:37:23–09:37:24 | Windows process creation events observed | Security Log | Event ID 4688 records present on endpoint |
| 11-08-2026 10:34:31 | Sysmon process creation event observed | Sysmon Event ID 1 | Process creation telemetry captured |
| 11-08-2026 10:xx | Endpoint telemetry reviewed | Wazuh Discover | Windows execution-related fields available |
| 11-08-2026 10:xx | Evidence correlation completed | DFIR analysis | File, signature, hash and execution evidence correlated |
| 11-08-2026 10:xx | Investigation documented | Investigation notes | Findings and observations recorded |

---

## Key Timeline Events

### 1. Original File Creation

The original executable was created on:

`05-08-2026 07:02:58`

Source:

Windows filesystem metadata.

---

### 2. Original File Modification

The recorded last-write timestamp was:

`05-08-2026 07:02:59`

Source:

Windows filesystem metadata.

---

### 3. Investigation Workspace Creation

At approximately:

`11-08-2026 10:23`

the investigation directory was created:

`C:\UnsignedBinaryLab`

---

### 4. File Access

The original executable showed a last-access timestamp of:

`11-08-2026 10:26:33`

This establishes that the file was accessed on the investigation date.

---

### 5. Binary Identification

The executable metadata identified:

- Product: `7-Zip`
- Company: `Igor Pavlov`
- Version: `26.02`
- Original filename: `7zipInstall.exe`

This demonstrated that the file's embedded identity differed from the investigation filename used later.

---

### 6. Signature Verification

The executable returned:

`NotSigned`

This established the absence of a valid Authenticode signature.

---

### 7. Hash Collection

SHA256:

`6745FA76DC2EA031596D8678F6F6B99C3C1B435B4164A63485ADBBC7B8D82EF0`

The hash became the primary artifact identifier for correlation.

---

### 8. Filename Change

The executable was copied to:

`C:\UnsignedBinaryLab\DemoApp.exe`

This introduced a filename different from the embedded original filename.

---

### 9. Execution

The renamed executable was launched:

`C:\UnsignedBinaryLab\DemoApp.exe`

This generated process execution activity.

---

### 10. Windows Process Creation Telemetry

Windows Security Event ID 4688 was reviewed to identify process creation activity.

The endpoint contained multiple Event ID 4688 records.

---

### 11. Sysmon Process Creation Telemetry

Sysmon Event ID 1 was reviewed for detailed process creation information.

Relevant fields included:

- Image
- Process ID
- Process GUID
- Command line
- Parent image
- Parent process ID
- Hashes
- User

---

### 12. Wazuh Correlation

Wazuh Discover was reviewed for:

`agent.name: DESKTOP-9MMM37V`

Relevant Windows process fields were examined to correlate endpoint execution activity.

---

## Timeline Assessment

The timeline demonstrates the progression:

`Original File → Metadata Collection → Signature Verification → Hash Collection → Filename Change → Execution → Windows Telemetry → Sysmon Telemetry → Wazuh Correlation`

The timeline also demonstrates why filesystem metadata, executable metadata, cryptographic hashes, process creation logs, and centralized SIEM telemetry should be analyzed together during Windows DFIR investigations.

---

## Final Timeline Conclusion

The investigation successfully reconstructed the major stages of the unsigned binary investigation.

The executable originated from the user's Downloads directory, contained 7-Zip metadata, was unsigned, was assigned a SHA256 identifier, was copied and renamed to `DemoApp.exe`, and was executed in the controlled investigation environment.

Windows Security, Sysmon, and Wazuh provided complementary telemetry for validating endpoint process activity.
