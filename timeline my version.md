# Investigation Timeline

|Step | Event | Evidence Source | Investigation Significance |
| ---- | ----- | --------------- | -------------------------- |
| 1 | Original executable creation time recorded | Windows filesystem metadata | Establishes original file creation timestamp |
| 2 | Original executable last-write time recorded | Windows filesystem metadata | Establishes file modification timestamp |
| 3 | Investigation workspace created | PowerShell | Created `C:\UnsignedBinaryLab` |
| 4 | Original executable accessed | Windows filesystem metadata | Shows recent access to the original binary |
| 5 | File metadata collected | PowerShell | Collected path, size and filesystem timestamps |
| 6 | Version information collected | PowerShell | Identified 7-Zip metadata and original filename |
| 7 | Authenticode signature checked | PowerShell | Binary returned `NotSigned` |
| 8 | SHA256 calculated | PowerShell | Hash recorded as `6745FA76DC2EA031596D8678F6F6B99C3C1B435B4164A63485ADBBC7B8D82EF0` |
| 9 | Unsigned executable identified | PowerShell | `7z2602-x64.exe` identified as unsigned |
| 10 | Binary copied to investigation workspace | PowerShell | Created `C:\UnsignedBinaryLab\DemoApp.exe` |
| 11| Renamed binary signature checked | PowerShell | Renamed binary remained `NotSigned` |
| 12 | `DemoApp.exe` executed | PowerShell | Generated process execution activity |
| 13 | Process creation telemetry observed | Sysmon | Sysmon Event ID 1 available for endpoint process activity |
| 14 | Windows process creation events observed | Security Log | Event ID 4688 records present on endpoint |
| 15 | Sysmon process creation event observed | Sysmon Event ID 1 | Process creation telemetry captured |
| 16 | Endpoint telemetry reviewed | Wazuh Discover | Windows execution-related fields available |

---
