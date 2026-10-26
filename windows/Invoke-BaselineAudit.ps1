#Requires -Version 5.1
<#
.SYNOPSIS
  Report the Windows rows this register tracks. Application is limited to SMBv1.

.DESCRIPTION
  With no switches, this only reports. It never writes a password policy.

  -Apply saves the current FS-SMB1 install state to
  $env:ProgramData\FindingsRegister\FS-SMB1-before.xml, then uninstalls the feature.
  It does not reboot unless -Reboot is also set.

  -Revert reads that file and reinstalls FS-SMB1 only when the saved state says it
  was installed. It does not reboot unless -Reboot is also set.

  -Apply and -Revert together are refused.

  -Snapshot <path> writes a windows-posture JSON file for the findings register
  and changes nothing: host, observed_at, domain controller role, w32tm time
  source and type, SMBv1 state, password policy source, pending reboot, and the
  WSUS target group and server. A probe that cannot run records null for its
  field and a line in probe_errors. -Snapshot with -Apply or -Revert is refused.

.PARAMETER Apply
  Uninstall FS-SMB1 after saving the current state. Ignored for every other control.

.PARAMETER Revert
  Put FS-SMB1 back when the saved state says it was installed.

.PARAMETER Reboot
  Allow the SMBv1 change to restart the computer.

.PARAMETER Snapshot
  Write a read-only posture snapshot to this path and exit. Nothing is changed.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Revert,
    [switch]$Reboot,
    [string]$Gate = "",
    [string]$Snapshot = ""
)

$ErrorActionPreference = "Stop"

if ($Apply -and $Revert) {
    throw "Use -Apply or -Revert, not both."
}

if ($Snapshot -and ($Apply -or $Revert)) {
    throw "-Snapshot only reads. Run it without -Apply or -Revert."
}

function Get-PostureSnapshot {
    $probeErrors = New-Object System.Collections.Generic.List[string]
    $data = [ordered]@{
        kind                   = "windows-posture"
        host                   = $null
        observed_at            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        is_domain_controller   = $null
        time_source            = $null
        time_type              = $null
        smb1_installed         = $null
        smb1_state             = $null
        password_policy_source = $null
        pending_reboot         = $null
        pending_reboot_reasons = @()
        wsus_target_group      = $null
        wsus_server            = $null
        probe_errors           = @()
    }

    try {
        $data.host = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
    } catch {
        $probeErrors.Add("host: $($_.Exception.Message.Trim())")
        $data.host = $env:COMPUTERNAME
    }

    $partOfDomain = $null
    try {
        $system = Get-CimInstance -ClassName Win32_ComputerSystem
        $partOfDomain = [bool]$system.PartOfDomain
        # DomainRole 4 is a backup domain controller, 5 the primary.
        $data.is_domain_controller = ([int]$system.DomainRole -ge 4)
    } catch {
        $probeErrors.Add("is_domain_controller: $($_.Exception.Message.Trim())")
    }

    try {
        $output = & w32tm.exe /query /source 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "w32tm /query /source exited $LASTEXITCODE. $($output.Trim())" }
        $data.time_source = $output.Trim()
    } catch {
        $probeErrors.Add("time_source: $($_.Exception.Message.Trim())")
    }

    try {
        $output = & w32tm.exe /query /configuration 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "w32tm /query /configuration exited $LASTEXITCODE. $($output.Trim())" }
        if ($output -match "(?m)^\s*Type:\s*(.+?)\s*$") {
            $data.time_type = $Matches[1]
        }
    } catch {
        $probeErrors.Add("time_type: $($_.Exception.Message.Trim())")
    }

    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $state = [string](Get-WindowsFeature -Name FS-SMB1).InstallState
        } elseif (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
            $state = [string](Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
        } else {
            throw "Neither Get-WindowsFeature nor Get-WindowsOptionalFeature is available."
        }
        $data.smb1_state = $state
        if ($state -in @("Installed", "InstallPending", "Enabled", "EnablePending")) {
            $data.smb1_installed = $true
        } elseif ($state -in @("Available", "Removed", "UninstallPending", "Disabled", "DisablePending", "DisabledWithPayloadRemoved")) {
            $data.smb1_installed = $false
        } else {
            throw "FS-SMB1 state '$state' was not recognized."
        }
    } catch {
        $probeErrors.Add("smb1_installed: $($_.Exception.Message.Trim())")
    }

    try {
        if ($partOfDomain -eq $false) {
            # A workgroup host has no domain GPO to apply.
            $data.password_policy_source = "local"
        } else {
            $output = & gpresult.exe /r /scope computer 2>&1
            if ($LASTEXITCODE -ne 0) { throw "gpresult /r /scope computer exited $LASTEXITCODE. $(($output | Out-String).Trim())" }
            $applied = @()
            $inList = $false
            foreach ($line in $output) {
                $text = [string]$line
                if ($text -match "^\s*Applied Group Policy Objects\s*$") { $inList = $true; continue }
                if (-not $inList) { continue }
                if ($text -match "^\s*-+\s*$") { continue }
                if (-not $text.Trim()) {
                    if ($applied.Count -gt 0) { break }
                    continue
                }
                $applied += $text.Trim()
            }
            $domainGpos = @($applied | Where-Object { $_ -ne "Local Group Policy" })
            if ($domainGpos -contains "Default Domain Policy") {
                $data.password_policy_source = "Default Domain Policy"
            } elseif ($domainGpos.Count -gt 0) {
                $data.password_policy_source = $domainGpos[0]
            } else {
                $data.password_policy_source = "local"
            }
        }
    } catch {
        $probeErrors.Add("password_policy_source: $($_.Exception.Message.Trim())")
    }

    try {
        $reasons = @()
        if (Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $reasons += "Component Based Servicing RebootPending"
        }
        if (Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $reasons += "Windows Update RebootRequired"
        }
        $session = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        if ($session.PendingFileRenameOperations) {
            $reasons += "PendingFileRenameOperations"
        }
        $data.pending_reboot = ($reasons.Count -gt 0)
        $data.pending_reboot_reasons = $reasons
    } catch {
        $probeErrors.Add("pending_reboot: $($_.Exception.Message.Trim())")
    }

    try {
        $policyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (Test-Path -LiteralPath $policyKey) {
            $policy = Get-ItemProperty -LiteralPath $policyKey
            if ($null -ne $policy.TargetGroup) { $data.wsus_target_group = [string]$policy.TargetGroup }
            if ($null -ne $policy.WUServer) { $data.wsus_server = [string]$policy.WUServer }
        }
    } catch {
        $probeErrors.Add("wsus: $($_.Exception.Message.Trim())")
    }

    $data.probe_errors = @($probeErrors)
    [pscustomobject]$data
}

if ($Snapshot) {
    $target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Snapshot)
    $parent = Split-Path -Parent $target
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        throw "Snapshot folder $parent does not exist. Nothing was written."
    }
    $posture = Get-PostureSnapshot
    $json = $posture | ConvertTo-Json -Depth 4
    # UTF-8 without a byte order mark, so any JSON reader takes it as written.
    [System.IO.File]::WriteAllText($target, $json, (New-Object System.Text.UTF8Encoding $false))
    Write-Output "Wrote $target. Nothing on this host was changed."
    foreach ($problem in $posture.probe_errors) { Write-Warning $problem }
    exit 0
}

function Assert-ApplyAllowed {
    param([string]$Control, [string]$GatePath)
    if (-not $Apply) { return }
    $path = $GatePath
    if (-not $path) {
        $path = Join-Path (Split-Path $PSScriptRoot -Parent) "ansible/generated/apply-gate.json"
    }
    if (-not (Test-Path -LiteralPath $path)) {
        throw "No apply gate at $path. Refusing to change the host."
    }
    $gate = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $name = $env:COMPUTERNAME
    $hit = @($gate.decisions) | Where-Object {
        $_.control -eq $Control -and ($_.host_short -eq $name -or $_.host -like "$name.*")
    } | Select-Object -First 1
    if ($hit -and $hit.action -in @("refuse", "hollow", "probe", "bundle", "window")) {
        throw "$($hit.control): $($hit.reason)"
    }
}

$stateDir = Join-Path $env:ProgramData "FindingsRegister"
$stateFile = Join-Path $stateDir "FS-SMB1-before.xml"

$partOfDomain = $false
try {
    $partOfDomain = [bool](Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain
} catch {
    Write-Warning "Could not tell if this host is domain-joined. Password policy will stay report-only."
    $partOfDomain = $true
}

function Write-Row {
    param([string]$Control, [string]$State, [string]$Detail)
    [pscustomobject]@{ Control = $Control; State = $State; Detail = $Detail }
}

function Save-Smb1State {
    param($Feature)
    New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
    [pscustomobject]@{
        Feature      = "FS-SMB1"
        InstallState = [string]$Feature.InstallState
        SavedAt      = (Get-Date).ToUniversalTime().ToString("o")
    } | Export-Clixml -LiteralPath $stateFile
}

$results = @()

if (-not (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
    if ($Apply -or $Revert) {
        throw "Get-WindowsFeature is not available on this SKU. Nothing was changed."
    }
    $results += Write-Row "WN22-00-000380" "unknown" "Get-WindowsFeature is not available on this SKU."
} elseif ($Revert) {
    if (-not (Test-Path -LiteralPath $stateFile)) {
        throw "No saved FS-SMB1 state at $stateFile. -Revert only puts back a feature this script removed."
    }
    $saved = Import-Clixml -LiteralPath $stateFile
    if ($saved.InstallState -eq "Installed") {
        if ($Reboot) {
            Install-WindowsFeature -Name FS-SMB1 -Restart | Out-Null
        } else {
            Install-WindowsFeature -Name FS-SMB1 | Out-Null
            Write-Warning "FS-SMB1 was reinstalled. Reboot before you treat the change as finished."
        }
        $results += Write-Row "WN22-00-000380" "changed" "FS-SMB1 was reinstalled from the saved state ($($saved.SavedAt))."
    } else {
        $results += Write-Row "WN22-00-000380" "unchanged" "Saved state was $($saved.InstallState). The feature was not reinstalled."
    }
} else {
    $smb1 = Get-WindowsFeature -Name FS-SMB1
    if ($smb1.InstallState -eq "Installed") {
        if ($Apply) {
            Assert-ApplyAllowed -Control "WN22-00-000380" -GatePath $Gate
            Save-Smb1State -Feature $smb1
            if ($Reboot) {
                Uninstall-WindowsFeature -Name FS-SMB1 -Restart | Out-Null
            } else {
                Uninstall-WindowsFeature -Name FS-SMB1 | Out-Null
                Write-Warning "FS-SMB1 was removed. Reboot before you call the finding closed. -Revert reads $stateFile."
            }
            $results += Write-Row "WN22-00-000380" "changed" "Uninstall requested. Prior state saved to $stateFile."
        } else {
            $results += Write-Row "WN22-00-000380" "open" "FS-SMB1 is installed. Re-run with -Apply when the change window allows a reboot."
        }
    } elseif ($Apply) {
        Save-Smb1State -Feature $smb1
        $results += Write-Row "WN22-00-000380" "closed" "FS-SMB1 is $($smb1.InstallState). State saved. Nothing was removed."
    } else {
        $results += Write-Row "WN22-00-000380" "closed" "FS-SMB1 is $($smb1.InstallState)."
    }
}

$netAccounts = net accounts | Out-String
$length = "unknown"
if ($netAccounts -match "Minimum password length:\s+(\d+)") {
    $length = $Matches[1]
}
if ($partOfDomain) {
    $results += Write-Row "WN22-AC-000070" "report" "Minimum password length reads $length. This host is domain-joined. Fix the GPO link. This script will not write local policy."
} else {
    $results += Write-Row "WN22-AC-000070" "report" "Minimum password length reads $length. This is a standalone host; confirm before any local change."
}

if (($Apply -or $Revert) -and $partOfDomain) {
    Write-Warning "No password setting was written. -Apply and -Revert only touch FS-SMB1."
}

$results | Format-Table -AutoSize
