[CmdletBinding()]
param([string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$OrchestratorPath = Join-Path $RepositoryRoot 'Invoke-MSADPT.ps1'
$Source = Get-Content -LiteralPath $OrchestratorPath -Raw
$RequiredTokens = @(
    '# DIRECTORY-CONTROL-STAGE-BEGIN',
    "if (`$IncludeDirectoryControl)",
    "`$Mode -in @('Audit','Resume')",
    'Invoke-MSADPTDirectoryControlAssessment-v1.0.0.ps1',
    'DirectoryControlTerminalResultMissing',
    'DirectoryControlManifestValidationFailed',
    "`$DirectoryControlExecuted = `$true",
    "`$LiveModulesExecuted++",
    "ModuleId = 'Invoke-MSADPTDirectoryControlAssessment'",
    'Invoke-MSADPTDirectoryControlCandidateReduction-v1.0.4.ps1',
    'DirectoryControlReductionManifestValidationFailed',
    '$DirectoryControlReductionExecuted = $true',
    '# DIRECTORY-CONTROL-STAGE-END'
)
foreach ($Token in $RequiredTokens) {
    if (-not $Source.Contains($Token)) { throw "DirectoryControlDispatchContractMissing: $Token" }
}
$DispatchIndex = $Source.IndexOf('# DIRECTORY-CONTROL-STAGE-BEGIN')
$PatchIndex = $Source.IndexOf('# PATCH-STAGE-BEGIN')
$LedgerIndex = $Source.IndexOf('$Ledger = [pscustomobject][ordered]@{')
if ($DispatchIndex -lt 0 -or $PatchIndex -lt 0 -or $LedgerIndex -lt 0) { throw 'DispatchOrderingMarkerMissing' }
if ($DispatchIndex -gt $PatchIndex -or $DispatchIndex -gt $LedgerIndex) { throw 'DirectoryControlDispatchOccursTooLate' }
$Tokens = $null; $ParseErrors = $null
[void][Management.Automation.Language.Parser]::ParseFile($OrchestratorPath,[ref]$Tokens,[ref]$ParseErrors)
if (@($ParseErrors).Count -gt 0) { throw "OrchestratorParserFailure: $(@($ParseErrors | ForEach-Object {$_.Message}) -join '; ')" }
[pscustomobject][ordered]@{Status='Passed';TestVersion='1.0.0';DispatchBlockPresent=$true;DispatchBeforePatchAndLedger=$true;ParserErrors=0;NetworkActivity='None';RemoteChanges='None'}
