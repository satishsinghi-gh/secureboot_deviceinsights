# Device Insights — Secure Boot Readiness & Device Posture Collector

PowerShell telemetry collector for Windows Secure Boot certificate readiness — gathers firmware, device health, patching, and identity signals via Intune-deployed scheduled task, with Azure Log Analytics ingestion for Power BI dashboards.

## Why This Exists

Microsoft's Secure Boot certificates (originally provisioned in 2011) expire in **June 2026**. Every enterprise Windows device needs updated certificates before then. This script collects the telemetry you need to assess readiness, identify blockers, and track deployment progress across your entire fleet.

## How It Works

```
Intune Platform Script (wrapper)
  └─► Creates local folder on device
  └─► Writes embedded Audit Script to .ps1
  └─► Executes once on deployment
  └─► Registers Scheduled Task (daily, SYSTEM, highest privileges)
        └─► Audit Script runs daily
              ├─► Collects 45+ data points from device
              ├─► Writes local log file
              ├─► (Optional) Exports CSV
              └─► Ingests to Azure Log Analytics (HTTP Data Collector API)
                    └─► Power BI dashboards via MQuery
```

## What It Collects

### Secure Boot Insights
| Field | Source | Purpose |
|-------|--------|---------|
| `SecureBoot_Status` | Confirm-SecureBootUEFI / Registry | Is Secure Boot enabled? |
| `SecureBoot_Servicing_CertUpdate_Compatibility` | WindowsUEFICA2023Capable registry | Compatibility level (0/1/2) |
| `SecureBoot_Servicing_CertStatus` | UEFICA2023Status registry | NotStarted / InProgress / Updated |
| `SecureBoot_Servicing_ConfidenceLevel` | Registry + Event 1801 | Microsoft's confidence assessment |
| `SecureBoot_Cert_Legacy` | Get-UEFICertificate -Type KEK | Legacy 2011 KEK certificate in firmware |
| `SecureBoot_Cert_Current` | Get-UEFICertificate -Type KEK | New 2023 KEK certificate in firmware |
| `SecureBoot_Servicing_UEFICA2023Error` | Registry | Error code if update failed |
| `SecureBoot_Servicing_UEFICA2023ErrorEvent` | Registry | Associated error event |
| `Events_1801` / `Events_1808` | System Event Log | Certificate update lifecycle events |

### Hardware & Firmware
| Field | Source |
|-------|--------|
| `HW_OEM` | SecureBoot\Servicing\DeviceAttributes |
| `HW_Model` / `HW_Model_Family` / `HW_SKU` | SecureBoot\Servicing\DeviceAttributes |
| `HW_FirmwareVersion` / `HW_FirmwareReleaseDate` | SecureBoot\Servicing\DeviceAttributes |

### Device & Identity
| Field | Source |
|-------|--------|
| `DeviceName` | $env:COMPUTERNAME |
| `Device_Type` | Configurable naming convention rules (Initials/Suffix) |
| `Entra_DeviceID` | dsregcmd /status |
| `Device_Identity_JoinType` | dsregcmd /status (Entra Joined / Hybrid / Domain / Workgroup) |
| `LastLoggedOnUser_UPN` | LogonUI + IdentityStore + Security 4624 fallback |
| `LastLoggedOnUser_NTID` | SID resolution via SecurityIdentifier.Translate() |
| `Device_AutopilotProfile` | Autopilot registry |

### OS, Patching & Reboot
| Field | Source |
|-------|--------|
| `OS_Edition` / `OS_DisplayVersion` / `OS_BuildFull` | Win32_OperatingSystem + CurrentVersion registry |
| `LastBootDate` / `Device_UpTime` | Win32_OperatingSystem.LastBootUpTime |
| `LastPatch_InstallDate` | CBS RollupFix (authoritative) |
| `LastPatch_KB` / `LastPatch_Caption` | WUA history enrichment (filters out Defender/SSU/.NET) |
| `LastPatch_BuildRevision` | CurrentBuildNumber.UBR from registry |

### Overall Status
Computed automatically based on configurable desired-state criteria:
```powershell
$Config.Desired = [ordered]@{
    SecureBoot_Status                             = $true
    SecureBoot_Servicing_CertStatus               = "Updated"
    SecureBoot_Servicing_CertUpdate_Compatibility = "2"
    SecureBoot_Cert_Current                       = "CN=Microsoft Corporation KEK 2K CA 2023, O=Microsoft Corporation, C=US"
}
```
Result is either **"All checks passed"** or **"Need Attention (failing_field_1, failing_field_2)"**.

## Configuration

All settings are defined in the `$Config` hashtable at the top of the audit script. Key knobs:

```powershell
$Config = [ordered]@{
    # Log Analytics
    WorkspaceId              = "your-workspace-id"
    SharedKey                = "your-shared-key"
    LogType                  = "YourTableName"    # Results in: YourTableName_CL

    # Execution mode
    LocalMode                = $false             # $true = CSV only, skip Log Analytics
    LocalModeSendToLA        = $false             # $true = CSV + Log Analytics

    # CSV output
    CsvPath                  = "C:\YourFolder"
    CsvFileName              = "output.csv"

    # Identity fallback (for VDI/AVD environments)
    PreferRdpIdentityForLastLoggedOnUser = $true
    RdpIdentityMaxEventsToScan           = 8000

    # Device type classification rules
    DeviceTypeRules = @(
        @{ Initials = "ABC"; Suffix = "-L"; DeviceType = "Laptop" },
        @{ Initials = "DEF"; Suffix = "-V"; DeviceType = "AVD" }
    )
}
```

The wrapper script configuration is separate and controls deployment behavior:

```powershell
$TaskName                = "Device Insights"
$TaskPath                = "\YourTaskSchedulerFolder\"
$DestinationFolder       = "C:\YourAuditScriptFolder"
$DailyRunTime            = "08:00"
$RunSecondaryOnceNow     = $true
```

## Deployment

### Prerequisites
- Windows 10/11 devices managed by Microsoft Intune
- Azure Log Analytics workspace (if using cloud ingestion)
- Devices must run the script as **SYSTEM** (elevated context)

### Steps

1. **Configure** — Edit the `$Config` values in the audit script and the wrapper script parameters
2. **Test locally** — Run with `LocalMode = $true` to generate CSV output; validate rows, columns, and values
3. **Smoke test Log Analytics** — Switch to `LocalMode = $false` and run on a single device; verify data appears in your custom table
4. **Deploy via Intune** — Upload the wrapper script as an Intune Platform Script:
   - Run this script using the logged on credentials: **No**
   - Run script in 64-bit PowerShell: **Yes**
   - Enforce script signature check: **No** (unless you sign it)
5. **Build dashboards** — Import Log Analytics data into Power BI using MQuery

## Identity Resolution

The script uses a multi-layered approach for last-logged-on user identification, which is critical for VDI, shared devices, and kiosk scenarios where Intune's primary user isn't always reliable:

1. **Primary** — LogonUI registry + IdentityStore UPN enrichment
2. **Fallback** — Security 4624 LogonType 10 (RDP/AVD) when primary returns "Not Found"
3. **NTID** — Always resolved from SID via `SecurityIdentifier.Translate()` (never guessed from UPN)

## Patch Detection

Patch information uses a dual-source strategy to avoid false positives from Defender intelligence updates:

- **CBS RollupFix** — Authoritative install timestamp of the latest cumulative update
- **WUA History** — Used only to enrich KB number and title, with explicit filters excluding Defender (KB2267602), .NET, SSU, MSRT, Preview, and OOB updates
- **Build Revision** — Taken from the running OS build (`CurrentBuildNumber.UBR`), not from patch metadata

## Certificate Update Deployment

Once your data confirms readiness, the actual certificate update is a single registry value:

```powershell
$RegPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$ValueName = "AvailableUpdates"
$HexValue  = 0x5944

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

New-ItemProperty -Path $RegPath -Name $ValueName `
    -PropertyType DWord -Value $HexValue -Force | Out-Null
```

Two natural reboots are required to complete the process — no forced restart.

## Acknowledgments

- **Richard Hicks** — [Get-UEFICertificate](https://directaccess.richardhicks.com/category/secure-boot/) script for reading KEK certificates from firmware, embedded within this audit script

## References

- [Act now: Secure Boot certificates expire in June 2026](https://techcommunity.microsoft.com/blog/windows-itpro-blog/act-now-secure-boot-certificates-expire-in-june-2026/4385728)
- [Secure Boot Certificate updates: Guidance for IT professionals](https://support.microsoft.com/en-us/topic/secure-boot-certificate-updates-guidance-for-it-professionals-and-organizations-fe498568-dc39-4575-8c1d-4e5e01f2af06)
- [Secure Boot DB and DBX variable update events](https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf7-4ff0-4ef1-8540-65a30f95e445)
- [Registry key updates for Secure Boot: IT-managed updates](https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-12cbcf12-f649-4396-85d4-7fce9a001814)
- [OEM pages for Secure Boot](https://support.microsoft.com/en-us/topic/original-equipment-manufacturer-oem-pages-for-secure-boot-40e2498c-caac-480c-baf1-d40b8c37b267)

## License

MIT
