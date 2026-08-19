<#
.SYNOPSIS
Tests unified ADCS candidate inventory merging.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$MergerPath,
    [Parameter(Mandatory=$true)][string]$OutputRoot
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Tokens=$null;$ParseErrors=$null
$null=[Management.Automation.Language.Parser]::ParseFile($MergerPath,[ref]$Tokens,[ref]$ParseErrors)
if($ParseErrors.Count -gt 0){throw "Merger parse failed: $($ParseErrors.Message -join '; ')"}
if(Test-Path -LiteralPath $OutputRoot){Remove-Item -LiteralPath $OutputRoot -Recurse -Force}
New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null
function New-Fact([string]$Id,[string]$State){[pscustomobject]@{id=$Id;state=$State;rationale='synthetic'}}
$First=@(
    [pscustomobject]@{candidateId='ESC1|CA|T|P';technique='ESC1';certificationAuthority='CA';template='T';principal='P';accessRowCount=2;disposition='Incomplete evidence';requiredCount=2;satisfiedRequiredCount=1;facts=@((New-Fact 'a' 'Confirmed'),(New-Fact 'b' 'Inconclusive'));safeFollowUp='x'}
    [pscustomobject]@{candidateId='ESC4|CA|T|P';technique='ESC4';certificationAuthority='CA';template='T';principal='P';accessRowCount=2;disposition='Blocked';requiredCount=1;satisfiedRequiredCount=0;facts=@((New-Fact 'c' 'Not observed'));safeFollowUp='x'}
)
$Second=@(
    [pscustomobject]@{candidateId='ESC2|CA|T|P';technique='ESC2';certificationAuthority='CA';template='T';principal='P';identityCategory='SecurityGroup';disposition='Incomplete evidence';requiredCount=2;satisfiedRequiredCount=1;facts=@((New-Fact 'a' 'Confirmed'),(New-Fact 'd' 'Inconclusive'));safeFollowUp='x'}
    [pscustomobject]@{candidateId='ESC15|CA|T|P';technique='ESC15';certificationAuthority='CA';template='T';principal='P';identityCategory='SecurityGroup';disposition='Incomplete evidence';requiredCount=2;satisfiedRequiredCount=1;facts=@((New-Fact 'a' 'Confirmed'),(New-Fact 'e' 'Inconclusive'));safeFollowUp='x'}
)
$FirstPath=Join-Path $OutputRoot 'first.json';$SecondPath=Join-Path $OutputRoot 'second.json';$AnalysisRoot=Join-Path $OutputRoot 'analysis'
$First|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $FirstPath -Encoding UTF8
$Second|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $SecondPath -Encoding UTF8
$Output=@(& $MergerPath -Esc1Esc4CandidatePath $FirstPath -Esc2Esc15CandidatePath $SecondPath -OutputDirectory $AnalysisRoot -Quiet)
$Terminal=@($Output|Where-Object{$null -ne $_ -and $null -ne $_.PSObject.Properties['mergerVersion'] -and $null -ne $_.PSObject.Properties['status'] -and [string]$_.status -eq 'Completed'})|Select-Object -Last 1
if($null -eq $Terminal){throw 'Merger terminal result missing.'}
$Rows=@(Get-Content -LiteralPath $Terminal.outputPath -Raw|ConvertFrom-Json)
$Esc2=@($Rows|Where-Object{[string]$_.technique -eq 'ESC2'})[0]
$Esc4=@($Rows|Where-Object{[string]$_.technique -eq 'ESC4'})[0]
$Checks=@(
    [pscustomobject]@{Test='FourRoutes';Passed=($Rows.Count -eq 4)}
    [pscustomobject]@{Test='TechniqueCounts';Passed=([int]$Terminal.esc1Count -eq 1 -and [int]$Terminal.esc2Count -eq 1 -and [int]$Terminal.esc4Count -eq 1 -and [int]$Terminal.esc15Count -eq 1)}
    [pscustomobject]@{Test='MissingDerived';Passed=(@($Esc2.missingOrInconclusive).Count -eq 1)}
    [pscustomobject]@{Test='NotObservedDerived';Passed=(@($Esc4.notObserved).Count -eq 1)}
    [pscustomobject]@{Test='UniqueIds';Passed=(@($Rows|Group-Object candidateId|Where-Object{$_.Count -gt 1}).Count -eq 0)}
)
$Checks|Format-Table -AutoSize
$Failed=@($Checks|Where-Object{-not $_.Passed})
if($Failed.Count -gt 0){throw "$($Failed.Count) merge test(s) failed."}
[pscustomobject]@{Status='Passed';TestCount=$Checks.Count;MergerVersion='0.1.0';TestVersion='1.0.1'}
