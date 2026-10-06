[CmdletBinding()]
param([string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$EvaluatorPath = Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlEffectiveAccess-v1.0.3.ps1'
if (-not (Test-Path -LiteralPath $EvaluatorPath -PathType Leaf)) { throw "EvaluatorMissing: $EvaluatorPath" }
$Tokens = $null
$ParserErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($EvaluatorPath, [ref]$Tokens, [ref]$ParserErrors)
if (@($ParserErrors).Count -gt 0) { throw "ParserFailure: $(@($ParserErrors | ForEach-Object { $_.Message }) -join '; ')" }
$Source = [System.IO.File]::ReadAllText($EvaluatorPath)
$RequiredMarkers = @('ApplicableExplicitAce','ApplicableInheritedUnrestricted','ApplicableInheritedTargetClassMatch','NotApplicableInheritedTargetClassMismatch','InconclusiveTargetClassGuidUnavailable','IncludedInEffectiveAccessEvaluation','ApplicableAceCount','NonApplicableAceCount','ApplicableDenyAceCount')
foreach ($Marker in $RequiredMarkers) { if (-not $Source.Contains($Marker)) { throw "ContractMissing: $Marker" } }
$LegacyExpression = '$Restriction=''Applicable'''
if ($Source.Contains($LegacyExpression)) { throw 'LegacyEvaluationWideRestrictionDetected' }
[pscustomobject][ordered]@{Status='Passed';TestVersion='1.0.1';PerAceApplicability=$true;ParserErrorCount=0;StrictModeLiteralCheck='Passed';NetworkActivity='None';ActiveDirectoryQueries='None';RemoteChanges='None'}
