<#
.SYNOPSIS
Tests six-technique ADCS unified inventory expansion.
.NOTES
Version: 1.0.0
#>
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$ExpanderPath,[Parameter(Mandatory=$true)][string]$OutputRoot)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Tokens=$null;$ParseErrors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($ExpanderPath,[ref]$Tokens,[ref]$ParseErrors)
if($ParseErrors.Count -gt 0){throw "Expander parse failed: $($ParseErrors.Message -join '; ')"}
if(Test-Path -LiteralPath $OutputRoot){Remove-Item -LiteralPath $OutputRoot -Recurse -Force}
New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null
function New-Fact([string]$Id,[string]$State){[pscustomobject]@{id=$Id;state=$State;rationale='synthetic'}}
function New-Candidate([string]$Technique){[pscustomobject]@{candidateId="$Technique|CA|T|P";technique=$Technique;certificationAuthority='CA';template='T';principal='P';identityCategory='SecurityGroup';disposition='Incomplete evidence';requiredCount=1;satisfiedRequiredCount=0;facts=@((New-Fact 'x' 'Inconclusive'));safeFollowUp='synthetic'}}
$Existing=@((New-Candidate 'ESC1'),(New-Candidate 'ESC2'),(New-Candidate 'ESC4'),(New-Candidate 'ESC15'))
$New=@((New-Candidate 'ESC3'),(New-Candidate 'ESC13'))
$ExistingPath=Join-Path $OutputRoot 'existing.json';$NewPath=Join-Path $OutputRoot 'new.json';$AnalysisRoot=Join-Path $OutputRoot 'analysis'
$Existing|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $ExistingPath -Encoding UTF8
$New|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $NewPath -Encoding UTF8
$Output=@(& $ExpanderPath -ExistingUnifiedInventoryPath $ExistingPath -Esc3Esc13CandidatePath $NewPath -OutputDirectory $AnalysisRoot -ExpectedRoutesPerTechnique 1 -Quiet)
$Terminal = @(
    $Output | Where-Object {
        $null -ne $_ -and
        $null -ne $_.PSObject.Properties['expanderVersion'] -and
        $null -ne $_.PSObject.Properties['status'] -and
        [string]$_.status -eq 'Completed'
    }
) | Select-Object -Last 1
if($null -eq $Terminal){throw 'Expander terminal result missing.'}
$Rows=@(Get-Content -LiteralPath $Terminal.outputPath -Raw|ConvertFrom-Json)
$Checks=@(
    [pscustomobject]@{Test='SixRoutes';Passed=($Rows.Count -eq 6)}
    [pscustomobject]@{Test='SixTechniques';Passed=(@($Rows.technique|Sort-Object -Unique).Count -eq 6)}
    [pscustomobject]@{Test='UniqueIds';Passed=(@($Rows|Group-Object candidateId|Where-Object{$_.Count -gt 1}).Count -eq 0)}
    [pscustomobject]@{Test='MissingFactsDerived';Passed=(@($Rows|Where-Object{@($_.missingOrInconclusive).Count -eq 1}).Count -eq 6)}
    [pscustomobject]@{Test='SourceInventoriesPreserved';Passed=(@($Rows.sourceInventory|Sort-Object -Unique).Count -eq 2)}
    [pscustomobject]@{Test='SummaryWritten';Passed=(Test-Path -LiteralPath (Join-Path $AnalysisRoot 'adcs-unified-candidate-inventory-v020-summary.json') -PathType Leaf)}
)
$Checks|Format-Table -AutoSize
$Failed=@($Checks|Where-Object{-not $_.Passed})
if($Failed.Count -gt 0){$Failed|Format-List Test,Passed;throw "$($Failed.Count) expansion test(s) failed."}
[pscustomobject]@{Status='Passed';TestCount=$Checks.Count;ExpanderVersion='0.2.0';TestVersion='1.0.0'}
