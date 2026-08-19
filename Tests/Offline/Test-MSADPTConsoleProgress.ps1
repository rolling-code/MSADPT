<#
.SYNOPSIS
Runs offline tests for MSADPT.Console.psm1.
.NOTES
Version: 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ModulePath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ModulePath -PathType Leaf)) { throw "Module not found: $ModulePath" }

$Tokens = $null
$Errors = $null
$Ast = [System.Management.Automation.Language.Parser]::ParseFile($ModulePath,[ref]$Tokens,[ref]$Errors)
if ($Errors.Count -gt 0) { throw "Parse failed: $($Errors.Message -join '; ')" }

Import-Module $ModulePath -Force
$Start = @(Start-MSADPTProgress -Activity 'Offline progress test' -Total 2 -Quiet -NoColor)
$First = @(Update-MSADPTProgress -Action 'Checking patch state' -Target 'server01.example.test' -Data @{CVE='CVE-2026-25177'})
$Second = @(Update-MSADPTProgress -Action 'Checking identity attribute' -Target 'user01' -Data @{Attribute='userPrincipalName'})
$End = @(Complete-MSADPTProgress -Message 'Offline test completed.' -Outcome Success)

$Checks = [ordered]@{
    ModuleParsed = ($Errors.Count -eq 0)
    StartEventCreated = (@($Start | Where-Object Code -eq 'ProgressStarted').Count -eq 1)
    FirstActionCreated = (@($First | Where-Object { $_.Code -eq 'ProgressAction' -and $_.Target -eq 'server01.example.test' }).Count -eq 1)
    CveMetadataPreserved = (@($First | Where-Object { $_.Data.CVE -eq 'CVE-2026-25177' }).Count -eq 1)
    SecondActionCreated = (@($Second | Where-Object { $_.Data.Attribute -eq 'userPrincipalName' }).Count -eq 1)
    CompletionCreated = (@($End | Where-Object Code -eq 'ProgressCompleted').Count -eq 1)
    AutomationSafeObjects = (@($Start + $First + $Second + $End | Where-Object { $_ -is [psobject] }).Count -ge 4)
}

$Results = foreach ($Check in $Checks.GetEnumerator()) {
    [pscustomobject]@{ Test=$Check.Key; Passed=[bool]$Check.Value }
}
$Results | Format-Table -AutoSize
$Failed = @($Results | Where-Object { -not $_.Passed })
if ($Failed.Count -gt 0) { throw "$($Failed.Count) console progress test(s) failed." }
[pscustomobject]@{ Status='Passed'; TestCount=$Results.Count; ModuleVersion='0.1.0'; TestVersion='1.0.0'; ModulePath=$ModulePath }
