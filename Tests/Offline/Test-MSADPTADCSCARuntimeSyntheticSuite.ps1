<#
.SYNOPSIS
Creates and validates all synthetic ADCS CA-runtime scenarios offline.
.NOTES
Version: 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$FixtureGeneratorPath,
    [Parameter(Mandatory=$true)][string]$EvidenceValidatorPath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
foreach($Path in @($FixtureGeneratorPath,$EvidenceValidatorPath)){if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "Required script not found: $Path"}}
if(Test-Path -LiteralPath $OutputDirectory){Remove-Item -LiteralPath $OutputDirectory -Recurse -Force}
$GenerationResult=& $FixtureGeneratorPath -OutputDirectory $OutputDirectory
$Index=@(Get-Content -LiteralPath $GenerationResult.IndexPath -Raw|ConvertFrom-Json)
$Results=foreach($Scenario in $Index){
    try{
        $Validation=& $EvidenceValidatorPath -EvidencePath $Scenario.EvidencePath -SummaryCsvPath $Scenario.SummaryPath -ServiceConnectionPointPath $Scenario.ServiceConnectionPointPath
        [pscustomobject]@{Scenario=$Scenario.Scenario;Passed=($Validation.Status -eq 'Passed');CaCount=$Validation.CaCount;Error=$null}
    }
    catch{[pscustomobject]@{Scenario=$Scenario.Scenario;Passed=$false;CaCount=$null;Error=$_.Exception.Message}}
}
$Results|Format-Table -AutoSize
$Failed=@($Results|Where-Object{-not $_.Passed})
if($Failed.Count -gt 0){throw "$($Failed.Count) synthetic CA-runtime scenario(s) failed."}
[pscustomobject]@{Status='Passed';ScenarioCount=$Results.Count;OutputDirectory=$OutputDirectory}
