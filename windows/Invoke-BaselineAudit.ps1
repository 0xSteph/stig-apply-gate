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

.PARAMETER Apply
  Uninstall FS-SMB1 after saving the current state. Ignored for every other control.

.PARAMETER Revert
  Put FS-SMB1 back when the saved state says it was installed.

.PARAMETER Reboot
  Allow the SMBv1 change to restart the computer.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Revert,
    [switch]$Reboot,
    [string]$Gate = ""
)

$ErrorActionPreference = "Stop"

if ($Apply -and $Revert) {
    throw "Use -Apply or -Revert, not both."
}

function Assert-ApplyAllowed {
    param([string]$Control)
    if (-not $Apply) { return }
    $path = $Gate
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
            Assert-ApplyAllowed -Control "WN22-00-000380"
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
