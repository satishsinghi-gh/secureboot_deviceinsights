<#
.SYNOPSIS
  Intune PowerShell Script (single payload) that:
   1) Creates a persistent local folder
   2) Writes your Secondary script content to a local .ps1 (you will paste content)
   3) Executes the local Secondary script once (silent)
   4) Creates/updates a Scheduled Task to run daily at 08:00 as SYSTEM (highest),
      whether or not a user is logged on, and if missed runs ASAP when available.

.INSTRUCTIONS
  1) Upload THIS script to Intune as a PowerShell script and assign to devices.
  2) Recommended Intune settings:
      - Run this script using the logged on credentials: NO
      - Run script in 64-bit PowerShell: YES
      - Enforce script signature check: NO (unless you sign it)
#>

# =========================
# Configuration (edit here)
# =========================
$TaskName                = "Device Insights"
$TaskPath                = "\YourTaskSchedulerFolder\"              # MUST start and end with "\"
$DestinationFolder        = "YourAuditScriptFolder"
$SecondaryScriptFileName  = "YourAuditScriptName"
$DailyRunTime             = "DailyRunTime"                        # "HH:mm" 24-hour format
$RunSecondaryOnceNow      = $true                          # run once during deployment

# PowerShell execution parameters for BOTH one-time run and scheduled task
$PowerShellExe            = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$ExecutionPolicy          = "Bypass"
$UseNoProfile             = $true
$HiddenWindow             = $true

# Scheduled task behavior
$AllowOnBatteries         = $true
$DontStopOnBatteries      = $true

# Logging
$EnableLog                = $true
$LogPath                  = "LogPath (Device Insights one-time setup)"

# What to treat as "success"
$FailInstallIfSecondaryFails = $false   # set $true if you want Intune install to fail when secondary returns non-zero

# =========================
# Audit Script (Configure as needed)
# =========================
$SecondaryScriptContent = @'
<#
.SYNOPSIS
    Secure Boot certificate readiness and device posture collector (Intune-friendly).

.DESCRIPTION
    Collects the key signals needed to assess readiness for the Secure Boot certificate transition:
      - Secure Boot enabled state
      - Secure Boot servicing registry values (split into individual columns)
      - OEM / firmware attributes from Secure Boot servicing registry
      - KEK certificates (legacy 2011 vs current 2023) via Get-UEFICertificate
      - Secure Boot CA update events:
          * 1801: full message retained + parsed confidence + timestamp
          * 1808: short one-liner status + timestamp
      - Identity context (NTID + UPN + SID) and last interactive logon time
          * Primary: LogonUI + IdentityStore
          * Fallback (optional): Security 4624 LogonType 10 (RDP/AVD) when primary is Not Found
          * NTID is resolved from SID (no UPN-left guessing)
      - Entra Device ID from dsregcmd /status
      - OS edition + display version + build/buildfull
      - Last boot date/time + calculated uptime (hours)
      - Autopilot DeploymentProfileName
      - Device type classification from naming rules (most-specific rules win)
      - Last patch installed (offline):
          * CBS RollupFix gives authoritative install time
          * WUA history used only to enrich KB/title, with filters to avoid Defender KB2267602
          * Patch build revision taken from the running OS build (CurrentBuildNumber.UBR)

    Output:
      - Local log file per run
      - Optional CSV export (LocalMode)
      - Optional Log Analytics ingestion (HTTP Data Collector API)

.NOTES
    - Missing data is always recorded as "Not Found" (no blanks).
    - Numeric registry values are captured in decimal format.
    - Designed to run under SYSTEM (Intune) or elevated/admin context.
#>

#region ============================ CONFIGURATION ============================

# Keep all knobs here so you can test locally and deploy via Intune without edits elsewhere.
$Config = [ordered]@{
    # Log Analytics (HTTP Data Collector API)
    WorkspaceId              = "LogAnalytics WorkspaceID"
    SharedKey                = "LogAnalytics SharedKey"
    LogType                  = "Custom Table Name"   # Results in: TableName_CL

    # Local logging
    LocalLogRoot             = "AuditScriptLogFolder"
    LocalLogFilePrefix       = "AuditScriptName-Prefix"
    CreateTranscript         = $false

    # Execution mode
    LocalMode                = $false                   # If $true: write CSV and skip LA unless LocalModeSendToLA = $true
    LocalModeSendToLA        = $false

    # CSV output
    # - If CsvPath ends with .csv => treated as full file path; CsvFileName ignored
    # - If CsvPath is a folder path => output = Join-Path CsvPath CsvFileName
    CsvPath                  = "YourCSVFolder"
    CsvFileName              = "YourCSVFileName"

    # Get-UEFICertificate helper script
    EnsureGetUEFICertificate = $false
    PSGalleryRepository      = "PSGallery"
    InstallScope             = "AllUsers"              # Preferred for Intune/SYSTEM

    # Event logs (Secure Boot updates)
    EventLogName             = "System"
    MaxEventsToScan          = 200

    # Security log scan (last interactive logon)
    SecurityLogMaxEventsToScan = 2000
    InteractiveLogonTypes      = @(2, 7, 10, 11)       # 2=Interactive, 7=Unlock, 10=RemoteInteractive, 11=CachedInteractive

    # AVD/RDP identity fallback
    # Primary method is always attempted first (LogonUI + IdentityStore).
    # This flag enables a fallback to Security 4624 LogonType 10 only when primary identity is Not Found.
    PreferRdpIdentityForLastLoggedOnUser = $true
    RdpIdentityMaxEventsToScan           = 8000

    # Field length guardrails
    MaxFieldLengthChars      = 6000

    # WUA history read guardrails (used only for KB/title enrichment)
    WuaHistoryMaxItems       = 2000
    WuaHistoryTimeoutSec     = 20                      # Hard timeout to avoid hangs on some devices
    WuaNearestWindowDays     = 7

    # Device type classification based on naming convention
    # Rules are evaluated top-to-bottom within specificity tiers; most-specific tiers win:
    #   1) Initials + Suffix
    #   2) Initials only
    #   3) Suffix only
    #
    # Initials = prefix match (start of name)
    # Suffix   = suffix match (end of name)
    # Either can be blank; blank criteria is ignored
    # Use below mapping if your use cases can be identified based on Device Name (Initials & Suffix) OR set the below values to blank if not relevant. Add more in the array if needed
    DeviceTypeRules = @(
        @{ Initials = "ABC"; Suffix = "-P"; DeviceType = "HR" },# both must match
    @{ Initials = "ABC"; Suffix = "-A"; DeviceType = "UseCase" },# both must match
    @{ Initials = "ABC"; Suffix = "-B"; DeviceType = "UseCase" },
    @{ Initials = "ABC"; Suffix = "-C"; DeviceType = "UseCase" },
    @{ Initials = "ABC"; Suffix = "-D"; DeviceType = "UseCase" },
    @{ Initials = "ABC"; Suffix = "-F"; DeviceType = "UseCase" },
    @{ Initials = "ABC"; Suffix = "-G"; DeviceType = "UseCase" },
    @{ Initials = "ABC"; Suffix = "-H"; DeviceType = "UseCase" },
    @{ Initials = "DEF"; Suffix = "-I"; DeviceType = "UseCase" },
    @{ Initials = "DEF"; Suffix = "-J"; DeviceType = "UseCase" },
    @{ Initials = "DEF"; Suffix = "-K"; DeviceType = "UseCase" },
    @{ Initials = "DEF"; Suffix = "-L"; DeviceType = "UseCase" },
    @{ Initials = "DEF"; Suffix = "-M"; DeviceType = "UseCase" },
    @{ Initials = "DEF"; Suffix = "-N"; DeviceType = "UseCase" }
)

    DeviceTypeDefault = "Not Found"

    # OverallStatus criteria (explicit)
    Desired                  = [ordered]@{
        SecureBoot_Status                               = $true
        SecureBoot_Servicing_CertStatus                 = "Updated"
        SecureBoot_Servicing_CertUpdate_Compatibility   = "2"
        SecureBoot_Cert_Current                         = "CN=Microsoft Corporation KEK 2K CA 2023, O=Microsoft Corporation, C=US"
    }
}

#endregion ============================ CONFIGURATION ============================

#region ============================ UTILITIES ============================

function Get-UEFICertificate {
    <#
      Embedded replacement for the PSGallery Get-UEFICertificate script.
      Supports -Type KEK (enough for your readiness checks).

      Output objects expose:
        Subject, Description, Expires
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("KEK","PK","db","dbx")]
        [string]$Type
    )

    # EFI_CERT_X509_GUID (UEFI SignatureType for DER-encoded X.509 certs)
    $GuidX509 = [Guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072"  # EFI_CERT_X509_GUID :contentReference[oaicite:1]{index=1}

    # Read the UEFI variable bytes using the built-in SecureBoot cmdlets
    try {
        $var = Get-SecureBootUEFI -Name $Type -ErrorAction Stop
        $bytes = $var.Bytes
        if (-not $bytes -or $bytes.Length -lt 28) { return @() }
    }
    catch {
        # Not supported, Secure Boot off, permissions, etc.
        return @()
    }

    $ms = New-Object System.IO.MemoryStream(,$bytes)
    $br = New-Object System.IO.BinaryReader($ms)

    $results = New-Object System.Collections.Generic.List[object]

    function Read-GuidFromReader {
        param([System.IO.BinaryReader]$Reader)
        $gbytes = $Reader.ReadBytes(16)
        if ($gbytes.Length -ne 16) { throw "Unexpected EOF while reading GUID" }
        return [Guid]::new($gbytes)
    }

    try {
        while ($ms.Position -lt $ms.Length) {
            # EFI_SIGNATURE_LIST
            $sigType = Read-GuidFromReader -Reader $br
            if (($ms.Length - $ms.Position) -lt 12) { break }

            $sigListSize    = $br.ReadUInt32()
            $sigHeaderSize  = $br.ReadUInt32()
            $sigSize        = $br.ReadUInt32()

            if ($sigListSize -lt 28) { break }            # minimum size sanity
            if ($sigSize -lt 16) { break }                # must fit SignatureOwner GUID
            if (($ms.Position + $sigHeaderSize) -gt $ms.Length) { break }

            # Skip SignatureHeader
            if ($sigHeaderSize -gt 0) { [void]$br.ReadBytes([int]$sigHeaderSize) }

            # Calculate remaining bytes in this signature list
            $bytesConsumed = 16 + 12 + $sigHeaderSize
            $remainingInList = [int]$sigListSize - [int]$bytesConsumed
            if ($remainingInList -lt 0) { break }

            # How many EFI_SIGNATURE_DATA entries?
            if ($sigSize -eq 0) {
                # Avoid divide by zero / malformed list
                $ms.Position = [Math]::Min($ms.Position + $remainingInList, $ms.Length)
                continue
            }

            $entryCount = [Math]::Floor($remainingInList / $sigSize)

            for ($i=0; $i -lt $entryCount; $i++) {
                # EFI_SIGNATURE_DATA: SignatureOwner GUID + SignatureData
                $owner = Read-GuidFromReader -Reader $br
                $dataLen = [int]$sigSize - 16
                if ($dataLen -le 0) { continue }

                $sigData = $br.ReadBytes($dataLen)
                if ($sigData.Length -ne $dataLen) { break }

                # We only care about X.509 certs for KEK readiness
                if ($sigType -ne $GuidX509) { continue }

                # DER X.509 cert
                try {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$sigData)
                    $results.Add([pscustomobject]@{
                        Subject     = [string]$cert.Subject
                        Description = [string]$cert.Issuer
                        Expires     = $cert.NotAfter
                    })
                }
                catch {
                    # Ignore malformed cert entries
                    continue
                }
            }

            # Jump to the end of this signature list if we didn't land exactly
            $listEnd = ($ms.Position - ($entryCount * $sigSize)) + $remainingInList
            if ($listEnd -gt $ms.Position -and $listEnd -le $ms.Length) {
                $ms.Position = $listEnd
            }
        }
    }
    catch {
        # If parsing fails, return what we collected so far
    }
    finally {
        $br.Close()
        $ms.Close()
    }

    return $results
}


function New-DirectoryIfMissing {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Limit-String {
    param(
        [AllowNull()][string]$Value,
        [int]$MaxChars = 6000
    )
    if ($null -eq $Value) { return $null }
    if ($Value.Length -le $MaxChars) { return $Value }
    return ($Value.Substring(0, $MaxChars) + " [TRUNCATED]")
}

# Local log writer. Empty strings are allowed so we can keep spacing readable.
function Write-LocalLogLine {
    param(
        [Parameter(Mandatory=$true)][string]$LogFile,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    Add-Content -LiteralPath $LogFile -Value "$timestamp`t$Message" -Encoding UTF8
}

# Safe registry read:
# - Missing keys/values => "Not Found"
# - Numeric values => returned as decimal strings
function Get-RegistryValueSafe {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name
    )
    try {
        if ($Name -eq "(Default)") { return $null }

        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        if (-not ($item.PSObject.Properties.Name -contains $Name)) { return "Not Found" }

        $raw = $item.$Name
        if ($null -eq $raw) { return "Not Found" }

        if ($raw -is [int] -or $raw -is [long] -or $raw -is [uint32] -or $raw -is [uint64]) {
            return ([string]([int64]$raw))
        }

        return ([string]$raw)
    }
    catch {
        return "Not Found"
    }
}

# dsregcmd is the most reliable local source for the Entra (Azure AD) DeviceId on the machine.
function Get-EntraDeviceId {
    try {
        $output = dsregcmd /status 2>$null
        if (-not $output) { return "Not Found" }

        foreach ($line in $output) {
            if ($line -match '^\s*DeviceId\s*:\s*(.+)$') {
                $id = $matches[1].Trim()
                if ($id) { return $id }
            }
        }
    }
    catch { }
    return "Not Found"
}

function Get-DeviceJoinType {
    try {
        $lines = dsregcmd /status 2>$null
        if (-not $lines) { return "Not Found" }

        $aadJoined    = $null
        $domainJoined = $null

        foreach ($line in $lines) {
            if ($line -match '^\s*AzureAdJoined\s*:\s*(YES|NO)\s*$') {
                $aadJoined = $matches[1]
                continue
            }
            if ($line -match '^\s*DomainJoined\s*:\s*(YES|NO)\s*$') {
                $domainJoined = $matches[1]
                continue
            }
        }

        if (-not $aadJoined -and -not $domainJoined) { return "Not Found" }

        if ($aadJoined -eq "YES" -and $domainJoined -eq "YES") { return "Hybrid Joined" }
        if ($aadJoined -eq "YES" -and $domainJoined -eq "NO")  { return "Entra Joined" }
        if ($aadJoined -eq "NO"  -and $domainJoined -eq "YES") { return "Domain Joined" }
        if ($aadJoined -eq "NO"  -and $domainJoined -eq "NO")  { return "Workgroup" }

        return "Not Found"
    }
    catch {
        return "Not Found"
    }
}

function Get-AutopilotDeploymentProfileName {
    $path = "HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot"
    $val  = Get-RegistryValueSafe -Path $path -Name "DeploymentProfileName"
    if ([string]::IsNullOrWhiteSpace($val)) { return "Not Found" }
    return $val
}

function Get-DeviceUptimeHours {
    param([Parameter(Mandatory=$true)][datetime]$LastBoot)
    try {
        $uptime = (Get-Date) - $LastBoot
        return ([math]::Round($uptime.TotalHours, 2)).ToString()
    }
    catch {
        return "Not Found"
    }
}

# Device type from name + rules (most-specific rules win; preserves original order within tier)
function Get-DeviceTypeFromName {
    param(
        [Parameter(Mandatory=$true)][string]$DeviceName,
        [Parameter(Mandatory=$true)][object[]]$Rules,
        [Parameter(Mandatory=$true)][string]$DefaultType
    )

    if ([string]::IsNullOrWhiteSpace($DeviceName)) { return $DefaultType }
    if (-not $Rules -or $Rules.Count -eq 0) { return $DefaultType }

    $name = $DeviceName.Trim()

    $normalized = @()
    for ($i = 0; $i -lt $Rules.Count; $i++) {
        $r = $Rules[$i]

        $ini = ""
        $suf = ""
        $typ = ""

        try {
            $ini = [string]$r.Initials
            $suf = [string]$r.Suffix
            $typ = [string]$r.DeviceType
        } catch {
            continue
        }

        $ini = if ($ini) { $ini.Trim() } else { "" }
        $suf = if ($suf) { $suf.Trim() } else { "" }
        $typ = if ($typ) { $typ.Trim() } else { "" }

        if ([string]::IsNullOrWhiteSpace($typ)) { continue }
        if ([string]::IsNullOrWhiteSpace($ini) -and [string]::IsNullOrWhiteSpace($suf)) { continue }

        $rank =
            if (-not [string]::IsNullOrWhiteSpace($ini) -and -not [string]::IsNullOrWhiteSpace($suf)) { 1 }
            elseif (-not [string]::IsNullOrWhiteSpace($ini) -and  [string]::IsNullOrWhiteSpace($suf)) { 2 }
            else { 3 }

        $normalized += [pscustomobject]@{
            Index      = $i
            Rank       = $rank
            Initials   = $ini
            Suffix     = $suf
            DeviceType = $typ
        }
    }

    foreach ($rule in ($normalized | Sort-Object Rank, Index)) {
        $matchIni = $true
        $matchSuf = $true

        if (-not [string]::IsNullOrWhiteSpace($rule.Initials)) {
            $matchIni = $name.StartsWith($rule.Initials, [System.StringComparison]::OrdinalIgnoreCase)
        }
        if (-not [string]::IsNullOrWhiteSpace($rule.Suffix)) {
            $matchSuf = $name.EndsWith($rule.Suffix, [System.StringComparison]::OrdinalIgnoreCase)
        }

        if ($matchIni -and $matchSuf) {
            return $rule.DeviceType
        }
    }

    return $DefaultType
}

#endregion ============================ UTILITIES ============================

#region ============================ OS INFO ============================

# OS Edition comes from Win32_OperatingSystem.Caption.
# DisplayVersion/build come from CurrentVersion registry so we get the real running build.
function Get-OsReleaseInfo {
    $out = [ordered]@{
        OS_Edition        = "Not Found"  # e.g. Windows 10 Enterprise LTSC 2021
        OS_DisplayVersion = "Not Found"  # e.g. 25H2 / 24H2 / 23H2
        OS_Build          = "Not Found"  # e.g. 26200
        OS_BuildFull      = "Not Found"  # e.g. 26200.7628
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os.Caption) { $out.OS_Edition = [string]$os.Caption }
    } catch { }

    try {
        $cv = Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop

        if ($cv.PSObject.Properties.Name -contains "DisplayVersion" -and $cv.DisplayVersion) {
            $out.OS_DisplayVersion = [string]$cv.DisplayVersion
        }

        $build = $null
        $ubr   = $null

        if ($cv.PSObject.Properties.Name -contains "CurrentBuildNumber" -and $cv.CurrentBuildNumber) {
            $build = [string]$cv.CurrentBuildNumber
            $out.OS_Build = $build
        }

        if ($cv.PSObject.Properties.Name -contains "UBR" -and $cv.UBR -ne $null) {
            $ubr = [string]([int64]$cv.UBR)
        }

        if ($build -and $ubr) {
            $out.OS_BuildFull = "$build.$ubr"
        }
    } catch { }

    [pscustomobject]$out
}

#endregion ============================ OS INFO ============================

#region ============================ BOOT INFO ============================

function Get-LastBootInfo {
    try {
        $boot = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
        return [pscustomobject]@{
            LastBootDate     = $boot.ToString("yyyy-MM-dd")
            LastBootTime     = $boot.ToString("HH:mm:ss")
            LastBootDateTime = $boot
        }
    }
    catch {
        return [pscustomobject]@{
            LastBootDate     = "Not Found"
            LastBootTime     = "Not Found"
            LastBootDateTime = $null
        }
    }
}

#endregion ============================ BOOT INFO ============================

#region ============================ LAST PATCH (OFFLINE) ============================

# Returns a WUA history list via a bounded job so we can hard-stop if it hangs.
function Get-WuaHistorySafe {
    param(
        [int]$MaxItems = 2000,
        [int]$TimeoutSec = 20
    )

    $job = $null
    try {
        $job = Start-Job -ScriptBlock {
            param($MaxItemsInner)

            $session  = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()

            $take = [int]$MaxItemsInner
            if ($take -le 0) { $take = 2000 }

            $history = $searcher.QueryHistory(0, $take)
            return $history
        } -ArgumentList $MaxItems

        $finished = Wait-Job -Job $job -Timeout $TimeoutSec
        if (-not $finished) {
            Stop-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
            return $null
        }

        $data = Receive-Job -Job $job -ErrorAction SilentlyContinue
        return $data
    }
    catch {
        return $null
    }
    finally {
        if ($job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null }
    }
}

# Patch info strategy:
# - CBS RollupFix gives us the correct install time (what actually got applied)
# - WUA history is used only to enrich KB/title near the install time, avoiding Defender intelligence updates
# - BuildRevision is reported from the running OS build (so 25H2 shows 26200.x, not 26100.x)
function Get-LastPatchInfo {
    param([Parameter(Mandatory=$true)][hashtable]$Cfg)

    $result = [ordered]@{
        LastPatch_InstallDate    = "Not Found"   # DD-MM-YYYY
        LastPatch_ReleaseInfo    = "Not Found"   # YYYY-MM
        LastPatch_KB             = "Not Found"   # KB#######
        LastPatch_BuildRevision  = "Not Found"   # Running OS build+UBR (e.g. 26200.7628)
        LastPatch_Caption        = "Not Found"   # WUA title near the install time
    }

    # Running OS build is the most reliable "what is this device on right now".
    try {
        $cv = Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
        if ($cv.CurrentBuildNumber -and $cv.UBR -ne $null) {
            $result.LastPatch_BuildRevision = ("{0}.{1}" -f [string]$cv.CurrentBuildNumber, [string]([int64]$cv.UBR))
        }
    } catch { }

    # CBS: authoritative install time of the latest cumulative rollup package.
    $installTime = $null
    try {
        $cbs = Get-WindowsPackage -Online -ErrorAction Stop |
            Where-Object {
                $_.PackageState -eq 'Installed' -and
                $_.PackageName -like 'Package_for_RollupFix*' -and
                $_.InstallTime
            } |
            Sort-Object InstallTime -Descending |
            Select-Object -First 1

        if ($cbs -and $cbs.InstallTime) {
            $installTime = [datetime]$cbs.InstallTime
            $result.LastPatch_InstallDate = $installTime.ToString("dd-MM-yyyy")
            $result.LastPatch_ReleaseInfo = $installTime.ToString("yyyy-MM")
        }
    } catch { }

    if (-not $installTime) {
        return [pscustomobject]$result
    }

    # WUA: best-effort enrichment for KB + title (caption)
    try {
        $history = Get-WuaHistorySafe -MaxItems $Cfg.WuaHistoryMaxItems -TimeoutSec $Cfg.WuaHistoryTimeoutSec
        if ($history) {
            $windowDays = [int]$Cfg.WuaNearestWindowDays
            if ($windowDays -le 0) { $windowDays = 7 }

            $windowed = @($history) |
                Where-Object {
                    $_.ResultCode -eq 2 -and $_.Title -and
                    ([math]::Abs(($_.Date - $installTime).TotalDays) -le $windowDays)
                } |
                Select-Object Date, Title

            # Preferred: match the exact format you want:
            # "YYYY-MM Update (KB#######) (build.revision)"
            $preferred = $windowed |
                Where-Object {
                    $_.Title -match '^\d{4}-\d{2}\s+Update\s+\(KB\d{7}\)\s+\(\d+\.\d+\)' -and
                    $_.Title -notmatch '(Defender|Security Intelligence|Antivirus|KB2267602|\.NET|Malicious Software Removal Tool|Servicing Stack|Dynamic Update|Preview|Out-of-band|\bOOB\b)'
                } |
                Sort-Object { [math]::Abs(($_.Date - $installTime).TotalSeconds) } |
                Select-Object -First 1

            # Fallback: still exclude Defender/etc, but accept any KB-bearing update title
            $fallback = $null
            if (-not $preferred) {
                $fallback = $windowed |
                    Where-Object {
                        $_.Title -match '\(KB\d{7}\)' -and
                        $_.Title -notmatch '(Defender|Security Intelligence|Antivirus|KB2267602|\.NET|Malicious Software Removal Tool|Servicing Stack|Dynamic Update|Preview|Out-of-band|\bOOB\b)'
                    } |
                    Sort-Object { [math]::Abs(($_.Date - $installTime).TotalSeconds) } |
                    Select-Object -First 1
            }

            $chosen = if ($preferred) { $preferred } else { $fallback }

            if ($chosen -and $chosen.Title) {
                $title = [string]$chosen.Title
                $result.LastPatch_Caption = $title
                if ($title -match '(KB\d{7})') {
                    $result.LastPatch_KB = $matches[1]
                }
            }
        }
    } catch { }

    [pscustomobject]$result
}

#endregion ============================ LAST PATCH (OFFLINE) ============================

#region ============================ IDENTITY / LAST LOGON ============================

function Get-UPNFromIdentityStore {
    param([Parameter(Mandatory=$true)][string]$Sid)

    $base = "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$Sid\IdentityCache"
    if (-not (Test-Path -LiteralPath $base)) { return $null }

    try {
        $subkeys = Get-ChildItem -LiteralPath $base -ErrorAction Stop |
                   Sort-Object -Property LastWriteTime -Descending

        foreach ($k in $subkeys) {
            try {
                $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop
                foreach ($name in @("UserName","UPN","AccountName","Name")) {
                    if ($p.PSObject.Properties.Name -contains $name) {
                        $v = [string]$p.$name
                        if ($v -and $v.Contains("@")) { return $v }
                    }
                }
            } catch { }
        }
    } catch { }

    return $null
}

# Resolve NTID (DOMAIN\sAMAccountName) from SID translation.
# This is the only safe way to get NTID without guessing from UPN.
function Resolve-NTIDFromSid {
    param([Parameter(Mandatory=$true)][string]$Sid)

    try {
        return (
            New-Object System.Security.Principal.SecurityIdentifier($Sid)
        ).Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        return "Not Found"
    }
}

# Primary last-identity: LogonUI registry + IdentityStore UPN enrichment
function Get-LastLoggedOnIdentity {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
    $lastUser = Get-RegistryValueSafe -Path $regPath -Name "LastLoggedOnUser"
    $lastSam  = Get-RegistryValueSafe -Path $regPath -Name "LastLoggedOnSAMUser"
    $sid      = Get-RegistryValueSafe -Path $regPath -Name "LastLoggedOnUserSID"

    $ntid = $null
    if ($lastSam -and $lastSam -ne "Not Found") {
        $ntid = $lastSam
    } elseif ($lastUser -and $lastUser -ne "Not Found") {
        $ntid = $lastUser
    } else {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $ntid = $cs.UserName
        if (-not $ntid) { $ntid = "Not Found" }
    }

    # Try to surface UPN if present in any common identity strings
    $upn = $null
    foreach ($candidate in @($lastUser, $lastSam, $ntid)) {
        if (-not $candidate -or $candidate -eq "Not Found") { continue }
        if ($candidate -match '^(AzureAD\\)(.+@.+)$') { $upn = $matches[2]; break }
        if ($candidate -match '.+@.+') { $upn = $candidate; break }
    }

    # If we still don’t have a UPN, IdentityStore cache is usually best on Entra-joined devices
    if (-not $upn -and $sid -and $sid -ne "Not Found") {
        $u = Get-UPNFromIdentityStore -Sid $sid
        if ($u) { $upn = $u }
    }

    if (-not $upn) { $upn = "Not Found" }
    if (-not $sid) { $sid = "Not Found" }

    [pscustomobject]@{ User = $ntid; Upn = $upn; Sid = $sid }
}

# Fallback identity for AVD/RDP: latest 4624 LogonType 10, extracts UPN+SID, and resolves NTID from SID.
function Get-LastRdpLogonIdentityFromSecurity4624 {
    param(
        [int]$MaxEvents = 8000,
        [int[]]$LogonTypes = @(10) # 10 = RemoteInteractive (RDP/AVD)
    )

    $result = [ordered]@{
        User = "Not Found"  # DOMAIN\NTID (resolved), otherwise best-effort
        Upn  = "Not Found"  # user@domain
        Sid  = "Not Found"  # S-1-5-...
    }

    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4624 } -MaxEvents $MaxEvents -ErrorAction Stop |
                  Sort-Object TimeCreated -Descending

        foreach ($ev in $events) {
            try {
                $xml = [xml]$ev.ToXml()
                $data = @{}
                foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = [string]$d.'#text' }

                if (-not $data.ContainsKey("LogonType")) { continue }
                if ($LogonTypes -notcontains [int]$data["LogonType"]) { continue }

                if ($data.ContainsKey("TargetUserName") -and $data["TargetUserName"] -match '\$$') { continue }

                $targetDomain = if ($data.ContainsKey("TargetDomainName")) { [string]$data["TargetDomainName"] } else { "" }
                $targetUser   = if ($data.ContainsKey("TargetUserName"))   { [string]$data["TargetUserName"] }   else { "" }
                $sid          = if ($data.ContainsKey("TargetUserSid"))    { [string]$data["TargetUserSid"] }    else { "" }

                if ([string]::IsNullOrWhiteSpace($sid)) { continue }
                if ([string]::IsNullOrWhiteSpace($targetUser)) { continue }

                $combined = ("{0}\{1}" -f $targetDomain, $targetUser).Trim('\')
                $result.Sid = $sid

                # UPN extraction: AVD often puts UPN directly in TargetUserName
                if ($targetUser.Contains("@")) {
                    $result.Upn = $targetUser.Trim()
                } else {
                    $candidate = ($combined -split '\\')[-1].Trim()
                    if ($candidate.Contains("@")) { $result.Upn = $candidate }
                }

                # Resolve NTID from SID (authoritative). If it fails, keep combined as a fallback display value.
                $ntid = Resolve-NTIDFromSid -Sid $sid
                if ($ntid -ne "Not Found") {
                    $result.User = $ntid
                } else {
                    $result.User = if ($combined) { $combined } else { "Not Found" }
                }

                # If still no UPN, try IdentityStore
                if ($result.Upn -eq "Not Found") {
                    $u = Get-UPNFromIdentityStore -Sid $sid
                    if ($u) { $result.Upn = $u }
                }

                return [pscustomobject]$result
            }
            catch { continue }
        }
    }
    catch { }

    return [pscustomobject]$result
}

# Security 4624 is best “last interactive logon” source when available and accessible.
function Get-LastLogonFromSecurity4624 {
    param(
        [Parameter(Mandatory=$true)][string]$Sid,
        [int]$MaxEvents = 2000,
        [int[]]$LogonTypes = @(2,7,10,11)
    )

    $result = [ordered]@{
        LastLogonDate      = "Not Found"
        LastLogonTimestamp = "Not Found"
        LastLogonSource    = "Security4624"
    }

    if ([string]::IsNullOrWhiteSpace($Sid) -or $Sid -eq "Not Found") {
        $result.LastLogonSource = "Security4624 (SID missing)"
        return [pscustomobject]$result
    }

    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4624 } -MaxEvents $MaxEvents -ErrorAction Stop |
                  Sort-Object TimeCreated -Descending

        foreach ($ev in $events) {
            try {
                $xml = [xml]$ev.ToXml()
                $data = @{}
                foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = [string]$d.'#text' }

                if (-not $data.ContainsKey("TargetUserSid")) { continue }
                if ($data["TargetUserSid"] -ne $Sid) { continue }

                $logonType = $null
                if ($data.ContainsKey("LogonType")) { [void][int]::TryParse($data["LogonType"], [ref]$logonType) }
                if ($null -eq $logonType -or ($LogonTypes -notcontains $logonType)) { continue }

                if ($data.ContainsKey("TargetUserName")) {
                    $tu = $data["TargetUserName"]
                    if ($tu -match '\$$') { continue }
                }

                $dt = $ev.TimeCreated
                if ($dt) {
                    $result.LastLogonDate      = $dt.ToString("yyyy-MM-dd")
                    $result.LastLogonTimestamp = $dt.ToString("yyyy-MM-dd HH:mm:ss")
                    return [pscustomobject]$result
                }
            } catch { continue }
        }
    }
    catch {
        $result.LastLogonSource = "Security4624 (error: $($_.Exception.Message))"
    }

    return [pscustomobject]$result
}

function Get-LastLogonTimestamps {
    param(
        [AllowNull()][string]$Sid,
        [hashtable]$Cfg
    )

    if ($Sid -and $Sid -ne "Not Found") {
        $sec = Get-LastLogonFromSecurity4624 -Sid $Sid -MaxEvents ($Cfg.SecurityLogMaxEventsToScan) -LogonTypes ($Cfg.InteractiveLogonTypes)
        if ($sec.LastLogonTimestamp -ne "Not Found") { return $sec }
    }

    $result = [ordered]@{
        LastLogonDate      = "Not Found"
        LastLogonTimestamp = "Not Found"
        LastLogonSource    = "WMI"
    }

    # Best-effort fallbacks when Security logs are unavailable.
    try {
        $nlp = Get-CimInstance -ClassName Win32_NetworkLoginProfile -ErrorAction SilentlyContinue |
               Where-Object { $_.LastLogon -ne $null } |
               Sort-Object -Property LastLogon -Descending |
               Select-Object -First 1

        if ($nlp -and $nlp.LastLogon) {
            $dt = [Management.ManagementDateTimeConverter]::ToDateTime($nlp.LastLogon)
            $result.LastLogonDate      = $dt.ToString("yyyy-MM-dd")
            $result.LastLogonTimestamp = $dt.ToString("yyyy-MM-dd HH:mm:ss")
            $result.LastLogonSource    = "Win32_NetworkLoginProfile"
            return [pscustomobject]$result
        }
    } catch { }

    try {
        $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastUseTime -ne $null } |
                    Sort-Object -Property LastUseTime -Descending

        $p = $profiles | Select-Object -First 1
        if ($p -and $p.LastUseTime) {
            $dt = [Management.ManagementDateTimeConverter]::ToDateTime($p.LastUseTime)
            $result.LastLogonDate      = $dt.ToString("yyyy-MM-dd")
            $result.LastLogonTimestamp = $dt.ToString("yyyy-MM-dd HH:mm:ss")
            $result.LastLogonSource    = "Win32_UserProfile"
        }
    } catch { }

    [pscustomobject]$result
}

#endregion ============================ IDENTITY / LAST LOGON ============================

#region ============================ SECURE BOOT / CERTIFICATES ============================

function Ensure-GetUEFICertificate {
    param(
        [Parameter(Mandatory=$true)][hashtable]$Cfg,
        [Parameter(Mandatory=$true)][string]$LogFile
    )

    if (-not $Cfg.EnsureGetUEFICertificate) { return $true }

    if (Get-Command -Name "Get-UEFICertificate" -ErrorAction SilentlyContinue) {
        Write-LocalLogLine -LogFile $LogFile -Message "Get-UEFICertificate already available."
        return $true
    }

    Write-LocalLogLine -LogFile $LogFile -Message "Get-UEFICertificate not found. Attempting Install-Script (Repo: $($Cfg.PSGalleryRepository), Scope: $($Cfg.InstallScope))..."

    try {
        $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
        try { Set-PSRepository -Name $Cfg.PSGalleryRepository -InstallationPolicy Trusted -ErrorAction SilentlyContinue } catch { }

        Install-Script -Name Get-UEFICertificate -Scope $Cfg.InstallScope -Force -ErrorAction Stop | Out-Null

        if (Get-Command -Name "Get-UEFICertificate" -ErrorAction SilentlyContinue) {
            Write-LocalLogLine -LogFile $LogFile -Message "Install-Script succeeded; Get-UEFICertificate is now available."
            return $true
        }

        Write-LocalLogLine -LogFile $LogFile -Message "Install-Script completed but Get-UEFICertificate still not found."
        return $false
    }
    catch {
        Write-LocalLogLine -LogFile $LogFile -Message ("Install-Script failed: " + $_.Exception.Message)
        return $false
    }
}

function Get-SecureBootEnabled {
    try { Confirm-SecureBootUEFI -ErrorAction Stop }
    catch { "Not supported or error: $($_.Exception.Message)" }
}

function Get-SecureBootCertsKEK {
    param([Parameter(Mandatory=$true)][hashtable]$Cfg)

    $out = [ordered]@{
        SecureBoot_Cert_Legacy          = "Not Found"
        SecureBoot_Cert_Desc_Legacy     = "Not Found"
        SecureBoot_Cert_Expiry_Legacy   = "Not Found"
        SecureBoot_Cert_Current         = "Not Found"
        SecureBoot_Cert_Desc_Current    = "Not Found"
        SecureBoot_Cert_Expiry_Current  = "Not Found"
    }

    if (-not (Get-Command -Name "Get-UEFICertificate" -ErrorAction SilentlyContinue)) {
        return [pscustomobject]$out
    }

    try {
        $certs = @(Get-UEFICertificate -Type KEK -ErrorAction Stop)

        foreach ($c in $certs) {
            $subject = [string]$c.Subject
            $desc    = [string]$c.Description
            $expires = $c.Expires

            if ($subject -match "KEK CA 2011") {
                $out.SecureBoot_Cert_Legacy        = $subject
                $out.SecureBoot_Cert_Desc_Legacy   = $desc
                $out.SecureBoot_Cert_Expiry_Legacy = if ($expires) { (Get-Date $expires).ToString("yyyy-MM-dd") } else { "Not Found" }
            }

            if ($subject -match "KEK 2K CA 2023") {
                $out.SecureBoot_Cert_Current        = $subject
                $out.SecureBoot_Cert_Desc_Current   = $desc
                $out.SecureBoot_Cert_Expiry_Current = if ($expires) { (Get-Date $expires).ToString("yyyy-MM-dd") } else { "Not Found" }
            }
        }
    } catch { }

    [pscustomobject]$out
}

function Get-SecureBootUpdateEventsSplit {
    param([Parameter(Mandatory=$true)][hashtable]$Cfg)

    $out = [ordered]@{
        SecureBoot_CertUpdate_Events_1801               = "Not Found"
        SecureBoot_CertUpdate_Events_1801_TimeStamp     = "Not Found"
        SecureBoot_CertUpdate_Events_1801_Confidence    = "Not Found"
        SecureBoot_CertUpdate_Events_1808               = "Not Found"
        SecureBoot_CertUpdate_Events_1808_TimeStamp     = "Not Found"
    }

    $events = @(
        Get-WinEvent -FilterHashtable @{ LogName = $Cfg.EventLogName; Id = @(1801, 1808) } `
            -MaxEvents $Cfg.MaxEventsToScan -ErrorAction SilentlyContinue
    )

    $latest1801 = $events | Where-Object { $_.Id -eq 1801 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $latest1808 = $events | Where-Object { $_.Id -eq 1808 } | Sort-Object TimeCreated -Descending | Select-Object -First 1

    # 1801: keep the full message (this is where you’ll see blockers and the extra diagnostics)
    if ($latest1801) {
        $msg1801 = [string]$latest1801.Message

        if ([string]::IsNullOrWhiteSpace($msg1801)) {
            $out.SecureBoot_CertUpdate_Events_1801 = "Event 1801 found (message empty)"
            $out.SecureBoot_CertUpdate_Events_1801_Confidence = "Not Found"
        } else {
            $out.SecureBoot_CertUpdate_Events_1801 = $msg1801.Trim()

            # Confidence token sometimes appears as plain text (per Microsoft sample).
            if ($msg1801 -match '(High Confidence|Needs More Data|Unknown|Paused)') {
                $out.SecureBoot_CertUpdate_Events_1801_Confidence = $matches[1]
            }
            # If the event includes BucketConfidenceLevel but it's blank, call it out explicitly.
            elseif ($msg1801 -match 'BucketConfidenceLevel:\s*(\S.*)?$') {
                $val = $matches[1]
                if ([string]::IsNullOrWhiteSpace($val)) {
                    $out.SecureBoot_CertUpdate_Events_1801_Confidence = "Blank"
                } else {
                    $out.SecureBoot_CertUpdate_Events_1801_Confidence = $val.Trim()
                }
            }
            else {
                $out.SecureBoot_CertUpdate_Events_1801_Confidence = "Not Found"
            }
        }

        $out.SecureBoot_CertUpdate_Events_1801_TimeStamp = $latest1801.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
    } else {
        $out.SecureBoot_CertUpdate_Events_1801 = "No 1801 event found"
        $out.SecureBoot_CertUpdate_Events_1801_TimeStamp = "Not Found"
        $out.SecureBoot_CertUpdate_Events_1801_Confidence = "Not Found"
    }

    # 1808: keep it short; we only need a clean “updated/not updated” signal at scale
    if ($latest1808) {
        $out.SecureBoot_CertUpdate_Events_1808 = "Secure Boot CA certificates have been updated"
        $out.SecureBoot_CertUpdate_Events_1808_TimeStamp = $latest1808.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
    } else {
        $out.SecureBoot_CertUpdate_Events_1808 = "Secure Boot CA certificates have not been updated yet"
        $out.SecureBoot_CertUpdate_Events_1808_TimeStamp = "Not Found"
    }

    foreach ($k in @($out.Keys)) {
        $out[$k] = Limit-String -Value ([string]$out[$k]) -MaxChars $Cfg.MaxFieldLengthChars
        if ([string]::IsNullOrWhiteSpace($out[$k])) { $out[$k] = "Not Found" }
    }

    [pscustomobject]$out
}

#endregion ============================ SECURE BOOT / CERTIFICATES ============================

#region ============================ LOG ANALYTICS ============================

function New-LogAnalyticsSignature {
    param(
        [Parameter(Mandatory=$true)][string]$WorkspaceId,
        [Parameter(Mandatory=$true)][string]$SharedKey,
        [Parameter(Mandatory=$true)][string]$DateRfc1123,
        [Parameter(Mandatory=$true)][int]$ContentLength,
        [Parameter(Mandatory=$true)][string]$Method,
        [Parameter(Mandatory=$true)][string]$ContentType,
        [Parameter(Mandatory=$true)][string]$Resource
    )

    $xHeaders = "x-ms-date:$DateRfc1123"
    $stringToHash = "$Method`n$ContentLength`n$ContentType`n$xHeaders`n$Resource"
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($SharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)

    return ("SharedKey {0}:{1}" -f $WorkspaceId, $encodedHash)
}

function Send-LogAnalyticsData {
    param(
        [Parameter(Mandatory=$true)][hashtable]$Cfg,
        [Parameter(Mandatory=$true)][pscustomobject]$BodyObject,
        [Parameter(Mandatory=$true)][string]$LogFile
    )

    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123Date = [DateTime]::UtcNow.ToString("r")

    $json = $BodyObject | ConvertTo-Json -Depth 12
    $json = Limit-String -Value $json -MaxChars 290000
    $contentLength = ([Text.Encoding]::UTF8.GetBytes($json)).Length

    $signature = New-LogAnalyticsSignature -WorkspaceId $Cfg.WorkspaceId -SharedKey $Cfg.SharedKey `
        -DateRfc1123 $rfc1123Date -ContentLength $contentLength -Method $method -ContentType $contentType -Resource $resource

    # IMPORTANT: include the '?' before api-version
    $uri = "https://{0}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" -f $Cfg.WorkspaceId

    $headers = @{
        "Authorization"        = $signature
        "Log-Type"             = $Cfg.LogType
        "x-ms-date"            = $rfc1123Date
        "time-generated-field" = "TimeGeneratedUtc"
    }

    try {
        Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -ContentType $contentType -Body $json -ErrorAction Stop | Out-Null
        Write-LocalLogLine -LogFile $LogFile -Message "Log Analytics ingestion succeeded (LogType: $($Cfg.LogType))."
        return $true
    }
    catch {
        Write-LocalLogLine -LogFile $LogFile -Message ("Log Analytics ingestion failed: " + $_.Exception.Message)
        return $false
    }
}

#endregion ============================ LOG ANALYTICS ============================

#region ============================ CSV PATH ============================

function Resolve-CsvFilePath {
    param([Parameter(Mandatory=$true)][hashtable]$Cfg)

    if (-not $Cfg.ContainsKey("CsvPath") -or [string]::IsNullOrWhiteSpace($Cfg.CsvPath)) {
        throw "CsvPath must be defined in configuration when LocalMode is enabled."
    }
    if (-not $Cfg.ContainsKey("CsvFileName") -or [string]::IsNullOrWhiteSpace($Cfg.CsvFileName)) {
        throw "CsvFileName must be defined in configuration when LocalMode is enabled."
    }

    $csvPath = [string]$Cfg.CsvPath
    $ext = [IO.Path]::GetExtension($csvPath)

    if ($ext -ieq ".csv") { return $csvPath }
    return (Join-Path -Path $csvPath -ChildPath $Cfg.CsvFileName)
}

#endregion ============================ CSV PATH ============================

#region ============================ MAIN ============================

New-DirectoryIfMissing -Path $Config.LocalLogRoot

$runStamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$logFile = Join-Path $Config.LocalLogRoot ("{0}_{1}.log" -f $Config.LocalLogFilePrefix, $runStamp)

Write-LocalLogLine -LogFile $logFile -Message "=== Secure Boot Readiness Script Start ==="
Write-LocalLogLine -LogFile $logFile -Message ("RunningAs: " + [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
Write-LocalLogLine -LogFile $logFile -Message ("LocalMode: " + $Config.LocalMode + " | LocalModeSendToLA: " + $Config.LocalModeSendToLA)
Write-LocalLogLine -LogFile $logFile -Message ("LocalLogRoot: " + $Config.LocalLogRoot)

if ($Config.CreateTranscript) {
    try {
        Start-Transcript -Path (Join-Path $Config.LocalLogRoot ("{0}_{1}.transcript.txt" -f $Config.LocalLogFilePrefix, $runStamp)) -Force | Out-Null
    } catch { }
}

function Log-CheckOutcome {
    param(
        [Parameter(Mandatory=$true)][string]$CheckName,
        [Parameter(Mandatory=$true)][object]$Output,
        [Parameter(Mandatory=$true)][string]$StatusText
    )
    Write-LocalLogLine -LogFile $logFile -Message "CHECK: $CheckName"
    Write-LocalLogLine -LogFile $logFile -Message ("OUTPUT: " + (Limit-String -Value ([string]$Output) -MaxChars $Config.MaxFieldLengthChars))
    Write-LocalLogLine -LogFile $logFile -Message ("RESULT: " + $StatusText)
    Write-LocalLogLine -LogFile $logFile -Message ""
}

$deviceName = $env:COMPUTERNAME
$execLocal  = Get-Date
$execUtc    = [DateTime]::UtcNow

$osInfo        = Get-OsReleaseInfo
$entraDeviceId = Get-EntraDeviceId
$deviceJoinType = Get-DeviceJoinType
$bootInfo      = Get-LastBootInfo
$patchInfo     = Get-LastPatchInfo -Cfg $Config

$deviceUptimeHours = "Not Found"
if ($bootInfo.LastBootDateTime) {
    $deviceUptimeHours = Get-DeviceUptimeHours -LastBoot $bootInfo.LastBootDateTime
}

$autopilotProfile = Get-AutopilotDeploymentProfileName
$deviceType       = Get-DeviceTypeFromName -DeviceName $deviceName -Rules $Config.DeviceTypeRules -DefaultType $Config.DeviceTypeDefault

# --- Identity: primary first, fallback only if primary not found (and config allows it) ---
$identity = Get-LastLoggedOnIdentity

if ($Config.PreferRdpIdentityForLastLoggedOnUser -and (
        $identity.User -eq "Not Found" -or
        $identity.Sid  -eq "Not Found" -or
        $identity.Upn  -eq "Not Found"
    )) {

    $rdpId = Get-LastRdpLogonIdentityFromSecurity4624 -MaxEvents $Config.RdpIdentityMaxEventsToScan -LogonTypes @(10)

    # Only override if we got a real SID and a real NTID (or at least a user string)
    if ($rdpId.Sid -and $rdpId.Sid -ne "Not Found" -and $rdpId.User -and $rdpId.User -ne "Not Found") {
        $identity = [pscustomobject]@{
            User = $rdpId.User
            Upn  = $rdpId.Upn
            Sid  = $rdpId.Sid
        }
    }
}

$logonTimes = Get-LastLogonTimestamps -Sid $identity.Sid -Cfg $Config

# Build the row once; this is the single source of truth for both CSV and Log Analytics.
$row = [ordered]@{
    DeviceName                 = $deviceName
    DateOfExecution            = $execLocal.ToString("yyyy-MM-dd")
    ClientLocalTime            = $execLocal.ToString("yyyy-MM-dd HH:mm:ss")
    TimeGeneratedUtc           = $execUtc.ToString("o")

    Entra_DeviceID             = $entraDeviceId

    OS_Edition                 = $osInfo.OS_Edition
    OS_DisplayVersion          = $osInfo.OS_DisplayVersion
    OS_Build                   = $osInfo.OS_Build
    OS_BuildFull               = $osInfo.OS_BuildFull

    Device_AutopilotProfile    = $autopilotProfile
    Device_Type                = $deviceType
    Device_UpTime              = $deviceUptimeHours

    Device_Identity_JoinType    = $deviceJoinType

    LastLoggedOnUser           = $identity.User
    LastLoggedOnUser_UPN       = $identity.Upn
    LastLoggedOnUserSid        = $identity.Sid

    LastLogonDate              = $logonTimes.LastLogonDate
    LastLogonTimestamp         = $logonTimes.LastLogonTimestamp
    LastLogonSource            = $logonTimes.LastLogonSource

    LastBootDate               = $bootInfo.LastBootDate
    LastBootTime               = $bootInfo.LastBootTime

    LastPatch_InstallDate      = $patchInfo.LastPatch_InstallDate
    LastPatch_ReleaseInfo      = $patchInfo.LastPatch_ReleaseInfo
    LastPatch_KB               = $patchInfo.LastPatch_KB
    LastPatch_BuildRevision    = $patchInfo.LastPatch_BuildRevision
    LastPatch_Caption          = $patchInfo.LastPatch_Caption

    SecureBoot_Status                               = "Not Found"
    SecureBoot_AvailableUpdates                     = "Not Found"

    SecureBoot_Servicing_ConfidenceLevel            = "Not Found"
    SecureBoot_Servicing_CertStatus                 = "Not Found"
    SecureBoot_Servicing_CertUpdate_Compatibility   = "Not Found"
    SecureBoot_Servicing_UEFICA2023Error      	    = "Not Found"
    SecureBoot_Servicing_UEFICA2023ErrorEvent       = "Not Found"


    HW_OEM                          = "Not Found"
    HW_Model_Family                 = "Not Found"
    HW_Model                        = "Not Found"
    HW_SKU                          = "Not Found"
    HW_FirmwareReleaseDate          = "Not Found"
    HW_FirmwareVersion              = "Not Found"

    SecureBoot_Cert_Legacy          = "Not Found"
    SecureBoot_Cert_Desc_Legacy     = "Not Found"
    SecureBoot_Cert_Expiry_Legacy   = "Not Found"
    SecureBoot_Cert_Current         = "Not Found"
    SecureBoot_Cert_Desc_Current    = "Not Found"
    SecureBoot_Cert_Expiry_Current  = "Not Found"

    SecureBoot_CertUpdate_Events_1801             = "Not Found"
    SecureBoot_CertUpdate_Events_1801_TimeStamp   = "Not Found"
    SecureBoot_CertUpdate_Events_1801_Confidence  = "Not Found"
    SecureBoot_CertUpdate_Events_1808             = "Not Found"
    SecureBoot_CertUpdate_Events_1808_TimeStamp   = "Not Found"

    OverallStatus                   = "Not Found"
}

# Log basics for troubleshooting
Log-CheckOutcome -CheckName "OS Release Info" -Output (
    "Edition={0}; DisplayVersion={1}; Build={2}; BuildFull={3}" -f `
    $row.OS_Edition, $row.OS_DisplayVersion, $row.OS_Build, $row.OS_BuildFull
) -StatusText "Recorded"

Log-CheckOutcome -CheckName "Entra Device ID" -Output $row.Entra_DeviceID -StatusText "Recorded"
Log-CheckOutcome -CheckName "Autopilot Profile" -Output $row.Device_AutopilotProfile -StatusText "Recorded"
Log-CheckOutcome -CheckName "Device Type" -Output $row.Device_Type -StatusText "Recorded"
Log-CheckOutcome -CheckName "Last Boot" -Output ("Date={0}; Time={1}" -f $row.LastBootDate, $row.LastBootTime) -StatusText "Recorded"
Log-CheckOutcome -CheckName "Device Uptime (hrs)" -Output $row.Device_UpTime -StatusText "Recorded"
Log-CheckOutcome -CheckName "Last Patch" -Output (
    "InstallDate={0}; ReleaseInfo={1}; KB={2}; BuildRevision={3}; Caption={4}" -f `
    $row.LastPatch_InstallDate, $row.LastPatch_ReleaseInfo, $row.LastPatch_KB, $row.LastPatch_BuildRevision, $row.LastPatch_Caption
) -StatusText "Recorded"

Log-CheckOutcome -CheckName "Last Logged On User (NTID)" -Output $row.LastLoggedOnUser -StatusText "Recorded"
Log-CheckOutcome -CheckName "Last Logged On User (UPN)" -Output $row.LastLoggedOnUser_UPN -StatusText "Recorded"
Log-CheckOutcome -CheckName "Last Logged On User (SID)" -Output $row.LastLoggedOnUserSid -StatusText "Recorded"
Log-CheckOutcome -CheckName "Last Logon (Date/Time/Source)" -Output (
    "Date={0}; Time={1}; Source={2}" -f $row.LastLogonDate, $row.LastLogonTimestamp, $row.LastLogonSource
) -StatusText "Recorded"

# --- Secure Boot status ---
$sb = Get-SecureBootEnabled
$row.SecureBoot_Status = $sb
Log-CheckOutcome -CheckName "Secure Boot Enabled (Confirm-SecureBootUEFI)" -Output $sb -StatusText "Recorded"

# --- Secure Boot registry root ---
# AvailableUpdates is sometimes spelled with or without a space depending on build.
$rootPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$au = Get-RegistryValueSafe -Path $rootPath -Name "AvailableUpdates"
if ($au -eq "Not Found") { $au = Get-RegistryValueSafe -Path $rootPath -Name "Available Updates" }
$row.SecureBoot_AvailableUpdates = $au
Log-CheckOutcome -CheckName "SecureBoot Registry Root: AvailableUpdates" -Output $row.SecureBoot_AvailableUpdates -StatusText "Recorded"

# --- Secure Boot servicing registry (split) ---
$svcPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
$row.SecureBoot_Servicing_ConfidenceLevel          = Get-RegistryValueSafe -Path $svcPath -Name "ConfidenceLevel"
$row.SecureBoot_Servicing_CertStatus               = Get-RegistryValueSafe -Path $svcPath -Name "UEFICA2023Status"
$row.SecureBoot_Servicing_CertUpdate_Compatibility = Get-RegistryValueSafe -Path $svcPath -Name "WindowsUEFICA2023Capable"
$row.SecureBoot_Servicing_UEFICA2023Error      = Get-RegistryValueSafe -Path $svcPath -Name "UEFICA2023Error"
$row.SecureBoot_Servicing_UEFICA2023ErrorEvent = Get-RegistryValueSafe -Path $svcPath -Name "UEFICA2023ErrorEvent"

Log-CheckOutcome -CheckName "SecureBoot Servicing: ConfidenceLevel" -Output $row.SecureBoot_Servicing_ConfidenceLevel -StatusText "Recorded"
Log-CheckOutcome -CheckName "SecureBoot Servicing: CertStatus (UEFICA2023Status)" -Output $row.SecureBoot_Servicing_CertStatus -StatusText "Recorded"
Log-CheckOutcome -CheckName "SecureBoot Servicing: CertUpdate Compatibility (WindowsUEFICA2023Capable)" -Output $row.SecureBoot_Servicing_CertUpdate_Compatibility -StatusText "Recorded"
Log-CheckOutcome -CheckName "SecureBoot Servicing: UEFICA2023Error" -Output $row.SecureBoot_Servicing_UEFICA2023Error -StatusText "Recorded"
Log-CheckOutcome -CheckName "SecureBoot Servicing: UEFICA2023ErrorEvent" -Output $row.SecureBoot_Servicing_UEFICA2023ErrorEvent -StatusText "Recorded"

# --- Hardware attributes from Secure Boot servicing registry ---
$attrPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes"
$row.HW_OEM                 = Get-RegistryValueSafe -Path $attrPath -Name "OEMManufacturerName"
$row.HW_Model_Family        = Get-RegistryValueSafe -Path $attrPath -Name "OEMModelSystemFamily"
$row.HW_Model               = Get-RegistryValueSafe -Path $attrPath -Name "OEMModelNumber"
$row.HW_SKU                 = Get-RegistryValueSafe -Path $attrPath -Name "OEMModelSKU"
$row.HW_FirmwareReleaseDate = Get-RegistryValueSafe -Path $attrPath -Name "FirmwareReleaseDate"
$row.HW_FirmwareVersion     = Get-RegistryValueSafe -Path $attrPath -Name "FirmwareVersion"

Log-CheckOutcome -CheckName "Hardware OEM / Firmware Attributes" -Output (
    "OEM=$($row.HW_OEM); Family=$($row.HW_Model_Family); Model=$($row.HW_Model); SKU=$($row.HW_SKU); FirmwareReleaseDate=$($row.HW_FirmwareReleaseDate); FirmwareVersion=$($row.HW_FirmwareVersion)"
) -StatusText "Recorded"

# --- KEK certificates (requires Get-UEFICertificate) ---
$certToolReady = Ensure-GetUEFICertificate -Cfg $Config -LogFile $logFile
if ($certToolReady) {
    $certs = Get-SecureBootCertsKEK -Cfg $Config

    $row.SecureBoot_Cert_Legacy        = Limit-String -Value $certs.SecureBoot_Cert_Legacy       -MaxChars $Config.MaxFieldLengthChars
    $row.SecureBoot_Cert_Desc_Legacy   = Limit-String -Value $certs.SecureBoot_Cert_Desc_Legacy  -MaxChars $Config.MaxFieldLengthChars
    $row.SecureBoot_Cert_Expiry_Legacy = $certs.SecureBoot_Cert_Expiry_Legacy

    $row.SecureBoot_Cert_Current        = Limit-String -Value $certs.SecureBoot_Cert_Current      -MaxChars $Config.MaxFieldLengthChars
    $row.SecureBoot_Cert_Desc_Current   = Limit-String -Value $certs.SecureBoot_Cert_Desc_Current  -MaxChars $Config.MaxFieldLengthChars
    $row.SecureBoot_Cert_Expiry_Current = $certs.SecureBoot_Cert_Expiry_Current

    Log-CheckOutcome -CheckName "KEK Certificates (Get-UEFICertificate -Type KEK)" -Output (
        "LegacySubject=$($row.SecureBoot_Cert_Legacy); LegacyExpires=$($row.SecureBoot_Cert_Expiry_Legacy); CurrentSubject=$($row.SecureBoot_Cert_Current); CurrentExpires=$($row.SecureBoot_Cert_Expiry_Current)"
    ) -StatusText "Recorded"
} else {
    Log-CheckOutcome -CheckName "KEK Certificates (Get-UEFICertificate -Type KEK)" -Output "Get-UEFICertificate not available" -StatusText "Need Attention (Certificate tool missing)"
}

# --- Secure Boot certificate update events (1801/1808) ---
$evt = Get-SecureBootUpdateEventsSplit -Cfg $Config

$row.SecureBoot_CertUpdate_Events_1801            = $evt.SecureBoot_CertUpdate_Events_1801
$row.SecureBoot_CertUpdate_Events_1801_TimeStamp  = $evt.SecureBoot_CertUpdate_Events_1801_TimeStamp
$row.SecureBoot_CertUpdate_Events_1801_Confidence = $evt.SecureBoot_CertUpdate_Events_1801_Confidence
$row.SecureBoot_CertUpdate_Events_1808            = $evt.SecureBoot_CertUpdate_Events_1808
$row.SecureBoot_CertUpdate_Events_1808_TimeStamp  = $evt.SecureBoot_CertUpdate_Events_1808_TimeStamp

Log-CheckOutcome -CheckName "Secure Boot CA Update Event 1801" `
    -Output ("Time={0}; Confidence={1}`r`n{2}" -f `
        $row.SecureBoot_CertUpdate_Events_1801_TimeStamp,
        $row.SecureBoot_CertUpdate_Events_1801_Confidence,
        $row.SecureBoot_CertUpdate_Events_1801) `
    -StatusText "Recorded"

Log-CheckOutcome -CheckName "Secure Boot CA Update Event 1808" `
    -Output ("Time={0}; {1}" -f $row.SecureBoot_CertUpdate_Events_1808_TimeStamp, $row.SecureBoot_CertUpdate_Events_1808) `
    -StatusText "Recorded"

Log-CheckOutcome -CheckName "Device Join Type (dsregcmd)" -Output $row.Device_Identity_JoinType -StatusText "Recorded"

# --- OverallStatus (explicit criteria only) ---
$failedColumns = @()
foreach ($k in $Config.Desired.Keys) {
    $desired = $Config.Desired[$k]
    $actual  = $row[$k]

    $ok = $false
    if ($desired -is [bool]) {
        $ok = ($actual -is [bool] -and $actual -eq $desired)
    } else {
        $ok = ([string]$actual -eq [string]$desired)
    }

    if (-not $ok) { $failedColumns += $k }
}

if ($failedColumns.Count -eq 0) {
    $row.OverallStatus = "All checks passed"
} else {
    $row.OverallStatus = "Need Attention (" + ($failedColumns -join ", ") + ")"
}

Log-CheckOutcome -CheckName "Overall Status" -Output $row.OverallStatus -StatusText $row.OverallStatus

# Final normalization: avoid blanks in output. Keep booleans as booleans where applicable.
foreach ($key in @($row.Keys)) {
    $val = $row[$key]
    if ($val -eq $null) {
        $row[$key] = "Not Found"
        continue
    }
    if ($val -is [string] -and [string]::IsNullOrWhiteSpace($val)) {
        $row[$key] = "Not Found"
        continue
    }
    if ($val -is [string]) {
        $row[$key] = Limit-String -Value $val -MaxChars $Config.MaxFieldLengthChars
    }
}

# --- LocalMode CSV export ---
if ($Config.LocalMode) {
    try {
        $csvPathFinal = Resolve-CsvFilePath -Cfg $Config
        $csvDir = Split-Path -Path $csvPathFinal -Parent
        New-DirectoryIfMissing -Path $csvDir

        Write-LocalLogLine -LogFile $logFile -Message ("Resolved CSV output file: " + $csvPathFinal)

        $rowObj = [pscustomobject]$row
        if (-not (Test-Path -LiteralPath $csvPathFinal)) {
            $rowObj | Export-Csv -LiteralPath $csvPathFinal -NoTypeInformation -Encoding UTF8
        } else {
            $rowObj | Export-Csv -LiteralPath $csvPathFinal -NoTypeInformation -Encoding UTF8 -Append
        }

        Write-LocalLogLine -LogFile $logFile -Message ("LocalMode CSV export succeeded: " + $csvPathFinal)
    }
    catch {
        Write-LocalLogLine -LogFile $logFile -Message ("LocalMode CSV export failed: " + $_.Exception.Message)
    }
}

# --- Log Analytics send (skipped in LocalMode unless explicitly enabled) ---
$shouldSend = (-not $Config.LocalMode) -or ($Config.LocalMode -and $Config.LocalModeSendToLA)
if ($shouldSend) {
    $sent = Send-LogAnalyticsData -Cfg $Config -BodyObject ([pscustomobject]$row) -LogFile $logFile
    if ($sent) {
        Write-LocalLogLine -LogFile $logFile -Message "Row sent to Log Analytics table: $($Config.LogType)_CL"
    } else {
        Write-LocalLogLine -LogFile $logFile -Message "Row NOT sent to Log Analytics (send failed)."
    }
} else {
    Write-LocalLogLine -LogFile $logFile -Message "LocalMode enabled and LocalModeSendToLA is false: skipping Log Analytics send."
}

Write-LocalLogLine -LogFile $logFile -Message "=== Secure Boot Readiness Script End ==="

if ($Config.CreateTranscript) {
    try { Stop-Transcript | Out-Null } catch { }
}

#endregion ============================ MAIN ============================
'@

# =========================
# Helpers
# =========================
function Write-Log {
    param([string]$Message)
    $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line  = "$stamp | $Message"
    if ($EnableLog) {
        try {
            New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
            Add-Content -Path $LogPath -Value $line
        } catch {
            # swallow logging errors
        }
    }
}

function Fail {
    param([string]$Message, [int]$Code = 1)
    Write-Log "ERROR: $Message"
    exit $Code
}

function Get-PSArgs {
    param([string]$FilePath)

    $parts = @()
    if ($UseNoProfile) { $parts += "-NoProfile" }
    $parts += "-ExecutionPolicy $ExecutionPolicy"
    $parts += "-File `"$FilePath`""
    return ($parts -join " ")
}

# =========================
# Start
# =========================
Write-Log "Starting Intune deployment. TaskName=$TaskName TaskPath=$TaskPath Dest=$DestinationFolder"

# Validate TaskPath format
if ($TaskPath -notmatch '^\\.*\\$') {
    Fail "TaskPath must start and end with '\'. Provided: $TaskPath"
}

# Ensure destination folder exists
try {
    New-Item -ItemType Directory -Path $DestinationFolder -Force | Out-Null
    Write-Log "Ensured destination folder exists: $DestinationFolder"
} catch {
    Fail "Failed to create destination folder: $DestinationFolder. $($_.Exception.Message)"
}

# Write Secondary script to local path
$SecondaryLocalPath = Join-Path $DestinationFolder $SecondaryScriptFileName
try {
    if ([string]::IsNullOrWhiteSpace($SecondaryScriptContent) -or $SecondaryScriptContent -match 'PASTE YOUR Secondary\.ps1 CONTENT') {
        Write-Log "WARNING: Secondary script content looks like placeholder text. Ensure you've pasted your Secondary script."
        # Don't hard-fail here—some people intentionally stage later. Uncomment to enforce:
        # Fail "Secondary script content is not set. Paste your Secondary.ps1 content into `$SecondaryScriptContent."
    }

    Set-Content -Path $SecondaryLocalPath -Value $SecondaryScriptContent -Encoding UTF8 -Force
    Write-Log "Wrote Secondary script to: $SecondaryLocalPath"
} catch {
    Fail "Failed to write Secondary script to: $SecondaryLocalPath. $($_.Exception.Message)"
}

# One-time execution during deployment (silent)
if ($RunSecondaryOnceNow) {
    try {
        $args = Get-PSArgs -FilePath $SecondaryLocalPath
        Write-Log "Running Secondary script once now: $PowerShellExe $args"

        $sp = @{
            FilePath     = $PowerShellExe
            ArgumentList = $args
            Wait         = $true
            PassThru     = $true
        }
        if ($HiddenWindow) { $sp["WindowStyle"] = "Hidden" }

        $p = Start-Process @sp
        Write-Log "Secondary one-time run complete. ExitCode=$($p.ExitCode)"

        if ($FailInstallIfSecondaryFails -and $p.ExitCode -ne 0) {
            Fail "Secondary one-time execution failed with ExitCode=$($p.ExitCode)"
        }
    } catch {
        Fail "Failed to execute Secondary script one-time. $($_.Exception.Message)"
    }
}

# Build scheduled task action
try {
    $taskArgs = Get-PSArgs -FilePath $SecondaryLocalPath
    $Action   = New-ScheduledTaskAction -Execute $PowerShellExe -Argument $taskArgs
    Write-Log "Created scheduled task action: $PowerShellExe $taskArgs"
} catch {
    Fail "Failed to create ScheduledTaskAction. $($_.Exception.Message)"
}

# Trigger: daily at configured time
# Trigger: daily at configured time (expects DateTime)
try {
    $Trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::ParseExact($DailyRunTime, "HH:mm", [System.Globalization.CultureInfo]::InvariantCulture))
    Write-Log "Created daily trigger at: $DailyRunTime"
} catch {
    Fail "Failed to parse DailyRunTime=$DailyRunTime. Use HH:mm (24h). $($_.Exception.Message)"
}

# Settings: StartWhenAvailable == "Run task as soon as possible after a scheduled start is missed"
try {
    $settingsParams = @{ StartWhenAvailable = $true }
    if ($AllowOnBatteries)   { $settingsParams["AllowStartIfOnBatteries"]      = $true }
    if ($DontStopOnBatteries){ $settingsParams["DontStopIfGoingOnBatteries"]   = $true }

    $Settings = New-ScheduledTaskSettingsSet @settingsParams
    Write-Log "Created task settings. StartWhenAvailable=True AllowOnBatteries=$AllowOnBatteries DontStopOnBatteries=$DontStopOnBatteries"
} catch {
    Fail "Failed to create ScheduledTaskSettingsSet. $($_.Exception.Message)"
}

# Principal: SYSTEM + Highest
try {
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Write-Log "Created task principal: SYSTEM / Highest"
} catch {
    Fail "Failed to create ScheduledTaskPrincipal. $($_.Exception.Message)"
}

# Create/Update scheduled task (idempotent)
try {
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Force | Out-Null
    Write-Log "Registered/updated scheduled task: $TaskPath$TaskName"
} catch {
    Fail "Failed to register scheduled task. $($_.Exception.Message)"
}

# Post-check (optional but good)
try {
    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
    if (-not $task.Settings.StartWhenAvailable) {
        Fail "Post-check failed: StartWhenAvailable is not enabled on the task."
    }
    Write-Log "Post-check OK: Task exists and StartWhenAvailable=True"
} catch {
    Fail "Post-check failed: Could not read scheduled task. $($_.Exception.Message)"
}

# --- Cleanup: remove old SecureBoot audit script (legacy version) ---
$oldScriptPath = "C:\Program Files\BP\Device Insights\SecureBoot_Audit_V1.8.ps1"

try {
    if (Test-Path -LiteralPath $oldScriptPath) {
        Remove-Item -LiteralPath $oldScriptPath -Force -ErrorAction Stop
        Write-LocalLogLine -LogFile $logFile -Message "Removed legacy script: $oldScriptPath"
    } else {
        Write-LocalLogLine -LogFile $logFile -Message "Legacy script not found (no cleanup needed): $oldScriptPath"
    }
}
catch {
    Write-LocalLogLine -LogFile $logFile -Message ("Failed to remove legacy script '$oldScriptPath': " + $_.Exception.Message)
}


Write-Log "Deployment completed successfully."
exit 0
