<#
.SYNOPSIS
Runs deterministic offline tests for Convert-MSADPTADCSCARuntimeEvidence.ps1.
.NOTES
Version: 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ParserPath,
    [Parameter(Mandatory=$true)][string]$FixtureGeneratorPath,
    [Parameter(Mandatory=$true)][string]$OutputRoot
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
foreach($Path in @($ParserPath,$FixtureGeneratorPath)){if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "Required script not found: $Path"}}
if(Test-Path -LiteralPath $OutputRoot){Remove-Item -LiteralPath $OutputRoot -Recurse -Force}
$FixtureRoot=Join-Path $OutputRoot 'Fixtures'
$Generated=& $FixtureGeneratorPath -OutputDirectory $FixtureRoot
$Index=@(Get-Content -LiteralPath $Generated.IndexPath -Raw|ConvertFrom-Json)
$Expected=@{
    HexKnownFlag=@{Disposition='Observed';ParseStatus='NumericValueParsed';ParsedValue=262144;Flag='EDITF_ATTRIBUTESUBJECTALTNAME2'}
    DecimalValue=@{Disposition='Observed';ParseStatus='NumericValueParsed';ParsedValue=512;Flag='IF_ENFORCEENCRYPTICERTREQUEST'}
    FrenchNumeric=@{Disposition='Observed';ParseStatus='NumericValueParsed';ParsedValue=262144;Flag='EDITF_ATTRIBUTESUBJECTALTNAME2'}
    AccessDenied=@{Disposition='Query failed';ParseStatus='AccessDenied'}
    FrenchAccessDenied=@{Disposition='Query failed';ParseStatus='AccessDenied'}
    ValueNotFound=@{Disposition='Not observed';ParseStatus='ValueNotFound'}
    FrenchValueNotFound=@{Disposition='Not observed';ParseStatus='ValueNotFound'}
    RpcUnavailable=@{Disposition='Query failed';ParseStatus='RpcUnavailable'}
    Timeout=@{Disposition='Query failed';ParseStatus='TimedOut'}
    EmptyOutput=@{Disposition='Inconclusive';ParseStatus='EmptyOutput'}
    UnknownText=@{Disposition='Unsupported format';ParseStatus='NumericValueNotFound'}
    NonZeroPartial=@{Disposition='Query failed';ParseStatus='NonZeroExitCode'}
}
$Results=foreach($Case in $Index){
    $CaseOutput=Join-Path $OutputRoot ('Parsed\'+$Case.Case)
    $ParserOutput=@(& $ParserPath -EvidencePath $Case.EvidencePath -OutputDirectory $CaseOutput)
    $Terminal=$ParserOutput|Where-Object{$null-ne$_.PSObject.Properties['parserVersion']}|Select-Object -Last 1
    $Observation=@(Get-Content -LiteralPath (Join-Path $CaseOutput 'ca-runtime-observations.json') -Raw|ConvertFrom-Json)[0]
    $Expectation=$Expected[[string]$Case.Case]
    $Passed=([string]$Observation.Disposition -eq [string]$Expectation.Disposition -and [string]$Observation.ParseStatus -eq [string]$Expectation.ParseStatus)
    if($Expectation.ContainsKey('ParsedValue')){$Passed=$Passed -and ([uint64]$Observation.ParsedValue -eq [uint64]$Expectation.ParsedValue)}
    if($Expectation.ContainsKey('Flag')){$Passed=$Passed -and (@($Observation.EnabledKnownFlags)-contains [string]$Expectation.Flag)}
    [pscustomobject]@{Case=$Case.Case;Disposition=$Observation.Disposition;ParseStatus=$Observation.ParseStatus;Passed=$Passed}
}
$Results|Format-Table -AutoSize
$Failed=@($Results|Where-Object{-not $_.Passed})
if($Failed.Count -gt 0){throw "$($Failed.Count) CA-runtime parser test(s) failed."}
[pscustomobject]@{Status='Passed';TestCount=$Results.Count;ParserVersion='0.1.0';OutputRoot=$OutputRoot}
