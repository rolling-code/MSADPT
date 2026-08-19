<# .SYNOPSIS Tests MSADPT LAN session launcher without network activity. .NOTES Version: 1.0.1 #>
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$LauncherPath,[Parameter(Mandatory=$true)][string]$OutputRoot)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$Tok=$null;$Err=$null;$null=[Management.Automation.Language.Parser]::ParseFile($LauncherPath,[ref]$Tok,[ref]$Err);if($Err.Count -gt 0){throw($Err.Message -join '; ')}
if(Test-Path $OutputRoot){Remove-Item $OutputRoot -Recurse -Force};$Root=Join-Path $OutputRoot 'MSADPT';$Session=Join-Path $OutputRoot 'Session';New-Item -ItemType Directory -Path (Join-Path $Root 'Analysis'),(Join-Path $Root 'Tests') -Force|Out-Null
'param()'|Set-Content (Join-Path $Root 'Analysis\Good.ps1')
$CollectorPath=Join-Path $Root 'Collector.ps1'
@'
[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$Target='synthetic')
if($PSCmdlet.ShouldProcess($Target,'Synthetic collector action')){[pscustomobject]@{Status='Executed';Target=$Target}}
'@|Set-Content -LiteralPath $CollectorPath -Encoding UTF8;'param('|Set-Content (Join-Path $Root 'Tests\Bad.ps1')
$Blocked=$false
try {
    & $LauncherPath -MSADPTRoot $Root -SessionRoot $Session -PreflightOnly -Quiet | Out-Null
}
catch {
    $Blocked=$true
}
Remove-Item (Join-Path $Root 'Tests\Bad.ps1') -Force
$Out=@(& $LauncherPath -MSADPTRoot $Root -SessionRoot $Session -PreflightOnly -Quiet)
$Terminal=@($Out|Where-Object{$null -ne $_ -and $null -ne $_.PSObject.Properties['LauncherVersion'] -and [string]$_.Status -eq 'Passed'})|Select-Object -Last 1
$DryRunOut=@(& $LauncherPath -MSADPTRoot $Root -SessionRoot $Session -RunCollectorDryRun -CollectorScriptPath $CollectorPath -CollectorParameters @{Target='synthetic'} -Resume -Quiet)
$DryRunTerminal=@($DryRunOut|Where-Object{$null -ne $_ -and $null -ne $_.PSObject.Properties['LauncherVersion'] -and [string]$_.ParameterSet -eq 'DryRun'})|Select-Object -Last 1
$Checks=@(
    [pscustomobject]@{Test='ParseFailureBlocks';Passed=$Blocked}
    [pscustomobject]@{Test='PreflightPasses';Passed=$null -ne $Terminal}
    [pscustomobject]@{Test='DriveRootHandlingPassed';Passed=($null -ne $Terminal.Result -and [string]$Terminal.Result.status -eq 'Passed')}
    [pscustomobject]@{Test='StateCreated';Passed=Test-Path $Terminal.StatePath}
    [pscustomobject]@{Test='EventsCreated';Passed=Test-Path $Terminal.EventPath}
    [pscustomobject]@{Test='OfflineStageRecorded';Passed='OfflinePreflight' -in @($Terminal.CompletedStages)}
    [pscustomobject]@{Test='DryRunPassed';Passed=$null -ne $DryRunTerminal}
    [pscustomobject]@{Test='DryRunCheckpointRecorded';Passed='CollectorDryRun' -in @($DryRunTerminal.CompletedStages)}
    [pscustomobject]@{Test='DryRunDidNotExecute';Passed=@($DryRunTerminal.Result.output|Where-Object{$null -ne $_ -and $null -ne $_.PSObject.Properties['Status'] -and [string]$_.Status -eq 'Executed'}).Count -eq 0}
    [pscustomobject]@{Test='LockRemoved';Passed=-not(Test-Path (Join-Path $Session '.session.lock'))}
)
$Failed=@($Checks|Where-Object{-not $_.Passed});if($Failed.Count -gt 0){$Failed|Format-List;throw"$($Failed.Count) launcher tests failed"};[pscustomobject]@{Status='Passed';TestCount=$Checks.Count;LauncherVersion='0.1.1';TestVersion='1.0.1'}
