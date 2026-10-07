<#
.SYNOPSIS
Validates completeness and integrity of an MSADPT AD Health v1.3.0 collection.
.NOTES
Version: 1.4.0. Offline only.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$CollectionRoot)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$CollectionRoot=(Resolve-Path -LiteralPath $CollectionRoot).Path
function Add-Check { param([string]$Name,[bool]$Passed,[string]$Detail); [pscustomobject]@{Check=$Name;Passed=$Passed;Detail=$Detail} }
$checks=New-Object 'System.Collections.Generic.List[object]'
$summaryPath=Join-Path $CollectionRoot 'ADHealth-Collection-Summary.json'
$manifestPath=Join-Path $CollectionRoot 'ADHealth-Collection-Manifest.json'
$targetsPath=Join-Path $CollectionRoot 'ExpectedTargets.csv'
$raw=Join-Path $CollectionRoot 'Raw'
$checks.Add((Add-Check 'CollectionSummaryPresent' (Test-Path -LiteralPath $summaryPath -PathType Leaf) $summaryPath))
$checks.Add((Add-Check 'CollectionManifestPresent' (Test-Path -LiteralPath $manifestPath -PathType Leaf) $manifestPath))
$checks.Add((Add-Check 'ExpectedTargetsPresent' (Test-Path -LiteralPath $targetsPath -PathType Leaf) $targetsPath))
$checks.Add((Add-Check 'RawEvidenceRootPresent' (Test-Path -LiteralPath $raw -PathType Container) $raw))
if (@($checks|Where-Object{-not$_.Passed}).Count) { $checks|Format-Table -AutoSize|Out-Host; throw 'Required collection control files are missing.' }
$summary=Get-Content -LiteralPath $summaryPath -Raw|ConvertFrom-Json
$manifest=@(Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json)
$targets=@(Import-Csv -LiteralPath $targetsPath|ForEach-Object{$_.Target}|Where-Object{$_}|Sort-Object -Unique)
$checks.Add((Add-Check 'ExpectedTargetsNonEmpty' ($targets.Count-gt0) "Targets=$($targets.Count)"))
$checks.Add((Add-Check 'ManifestNonEmpty' ($manifest.Count-gt0) "Records=$($manifest.Count)"))
foreach($target in $targets){
    $safe=$target-replace'[^A-Za-z0-9._-]','_'
    foreach($name in @("DCDiag-$safe.txt","Repadmin-ShowRepl-$safe.txt","Repadmin-Queue-$safe.txt","Nltest-Query-$safe.txt","Nltest-DSGetSite-$safe.txt","W32tm-Status-$safe.txt")){
        $path=Join-Path $raw $name
        $exists=Test-Path -LiteralPath $path -PathType Leaf
        $length=if($exists){(Get-Item -LiteralPath $path).Length}else{0}
        $checks.Add((Add-Check "Evidence:${target}:${name}" ($exists-and$length-gt0) "Exists=$exists; Bytes=$length"))
    }
}
$repl=Join-Path $raw 'Repadmin-ReplSummary.txt';$replExists=Test-Path -LiteralPath $repl -PathType Leaf;$replLength=if($replExists){(Get-Item $repl).Length}else{0};$checks.Add((Add-Check 'DomainReplicationSummary' ($replExists-and$replLength-gt0) "Exists=$replExists; Bytes=$replLength"))
foreach($record in $manifest){
    if($record.OutputPath-and(Test-Path -LiteralPath $record.OutputPath -PathType Leaf)){
        $actual=(Get-FileHash -LiteralPath $record.OutputPath -Algorithm SHA256).Hash
        $checks.Add((Add-Check "Hash:$($record.Target):$($record.Utility)" ($actual-eq$record.SHA256) "Recorded=$($record.SHA256); Actual=$actual"))
    } else {$checks.Add((Add-Check "ManifestOutput:$($record.Target):$($record.Utility)" $false "Missing=$($record.OutputPath)"))}
}
$html=Join-Path $CollectionRoot 'OfflineAssessment\Assessment\MSADPT-AD-Health.html'
if(-not(Test-Path -LiteralPath $html -PathType Leaf)){$html=Join-Path $CollectionRoot 'OfflineAssessment\MSADPT-AD-Health.html'}
$checks.Add((Add-Check 'OfflineAssessmentHtmlPresent' (Test-Path -LiteralPath $html -PathType Leaf) $html))
$failed=@($checks|Where-Object{-not$_.Passed})
$report=[pscustomobject]@{Status=if($failed.Count){'Failed'}else{'Passed'};GateVersion='1.4.0';CollectionRoot=$CollectionRoot;TargetCount=$targets.Count;ManifestRecordCount=$manifest.Count;CheckCount=$checks.Count;FailedCheckCount=$failed.Count;CollectionStatus=$summary.Status;Checks=@($checks.ToArray());ValidatedUtc=(Get-Date).ToUniversalTime().ToString('o');NetworkActivity='None';ActiveDirectoryQueries='None';RemoteChanges='None'}
$out=Join-Path $CollectionRoot 'ADHealth-Collection-Validation.json';$report|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $out -Encoding UTF8
$checks|Format-Table Check,Passed,Detail -Wrap|Out-Host
if($failed.Count){throw "AD Health collection validation failed with $($failed.Count) failed check(s). Evidence: $out"}
$report
