<#
.SYNOPSIS
Stages a saved AD diagnostic collection into the MSADPT AD Health filename contract and optionally runs the offline assessment pipeline.
.DESCRIPTION
Preserves source evidence, copies only recognized files, records SHA-256 hashes, leaves ambiguous files unmapped, derives expected targets from explicit input or confidently mapped per-DC evidence, and invokes the offline pipeline by default.
.NOTES
Version: 1.2.0
Safety: Local filesystem only. No network, Active Directory, remote, or Git operations.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceEvidenceRoot,
    [Parameter(Mandatory)][string]$OutputRoot,
    [string[]]$ExpectedTarget = @(),
    [string]$ExpectedTargetPath,
    [switch]$SkipAssessment
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$started=(Get-Date).ToUniversalTime()
$SourceEvidenceRoot=(Resolve-Path -LiteralPath $SourceEvidenceRoot).Path
$OutputRoot=[IO.Path]::GetFullPath($OutputRoot)
$staging=Join-Path $OutputRoot 'StagedEvidence'
$assessmentRoot=Join-Path $OutputRoot 'Assessment'
New-Item -ItemType Directory -Path $staging -Force|Out-Null

function Get-ExpectedTargetList {
    $list=New-Object 'System.Collections.Generic.List[string]'
    foreach($t in @($ExpectedTarget)){if(-not[string]::IsNullOrWhiteSpace($t)){$list.Add($t.Trim())}}
    if($ExpectedTargetPath){
        if(-not(Test-Path -LiteralPath $ExpectedTargetPath -PathType Leaf)){throw "ExpectedTargetPathMissing: $ExpectedTargetPath"}
        if([IO.Path]::GetExtension($ExpectedTargetPath)-ieq'.csv'){
            foreach($row in @(Import-Csv -LiteralPath $ExpectedTargetPath)){
                $v=if($row.PSObject.Properties['Target']){$row.Target}elseif($row.PSObject.Properties['Name']){$row.Name}elseif($row.PSObject.Properties['HostName']){$row.HostName}else{$null}
                if($v){$list.Add(([string]$v).Trim())}
            }
        }else{foreach($line in @(Get-Content -LiteralPath $ExpectedTargetPath)){if(-not[string]::IsNullOrWhiteSpace($line)){$list.Add($line.Trim())}}}
    }
    @($list.ToArray()|Sort-Object -Unique)
}
function Get-SafeTarget([string]$Value){($Value.Trim()-replace'[^A-Za-z0-9._-]','_')}
function Resolve-Mapping {
    param([IO.FileInfo]$File)
    $name=$File.BaseName;$lower=$name.ToLowerInvariant();$dest=$null;$tool=$null;$target=$null;$subtype=$null;$confidence='None';$reason='No deterministic filename mapping matched.'
    switch -Regex ($name){
        '^DCDiag[-_. ](?<target>[^.]+)$'{$tool='DCDiag';$target=$Matches.target;$subtype='DCDiag';$dest="DCDiag-$(Get-SafeTarget $target).txt";$confidence='High';$reason='Explicit DCDiag target filename.';break}
        '^(?<target>[^.]+)[-_. ]DCDiag$'{$tool='DCDiag';$target=$Matches.target;$subtype='DCDiag';$dest="DCDiag-$(Get-SafeTarget $target).txt";$confidence='High';$reason='Explicit target plus DCDiag filename.';break}
        '^Repadmin[-_. ](?<type>ReplSummary|Bridgeheads)$'{$tool='Repadmin';$target='Domain';$subtype=$Matches.type;$dest="Repadmin-$subtype.txt";$confidence='High';$reason='Explicit domain-wide Repadmin filename.';break}
        '^Repadmin[-_. ](?<type>ShowRepl|Queue)[-_. ](?<target>.+)$'{$tool='Repadmin';$target=$Matches.target;$subtype=$Matches.type;$dest="Repadmin-$subtype-$(Get-SafeTarget $target).txt";$confidence='High';$reason='Explicit Repadmin subtype and target filename.';break}
        '^(?<target>.+)[-_. ]Repadmin[-_. ](?<type>ShowRepl|Queue)$'{$tool='Repadmin';$target=$Matches.target;$subtype=$Matches.type;$dest="Repadmin-$subtype-$(Get-SafeTarget $target).txt";$confidence='High';$reason='Explicit target, Repadmin, and subtype filename.';break}
        '^Nltest[-_. ](?<type>Query|DSGetSite)[-_. ](?<target>.+)$'{$tool='Nltest';$target=$Matches.target;$subtype=$Matches.type;$dest="Nltest-$subtype-$(Get-SafeTarget $target).txt";$confidence='High';$reason='Explicit Nltest subtype and target filename.';break}
        '^Nltest[-_. ]DSGetDC[-_. ](?<target>.+)$'{$tool='Nltest';$target=$Matches.target;$subtype='DSGetDC';$dest="Nltest-DSGetDC-$(Get-SafeTarget $target).txt";$confidence='High';$reason='Explicit Nltest DSGetDC filename.';break}
        '^W32tm[-_. ](?<type>Status|Config|Monitor)[-_. ](?<target>.+)$'{$tool='W32tm';$target=$Matches.target;$subtype=$Matches.type;$dest="W32tm-$subtype-$(Get-SafeTarget $target).txt";$confidence='High';$reason='Explicit W32tm subtype and target filename.';break}
        '^EventLog[-_. ](?<type>[^-_. ]+)[-_. ](?<target>.+)$'{$tool='EventLog';$target=$Matches.target;$subtype=$Matches.type;$dest="EventLog-$subtype-$(Get-SafeTarget $target).json";$confidence='High';$reason='Explicit event-log channel and target filename.';break}
        default{
            if($lower-match'dcdiag'){$tool='DCDiag';$reason='DCDiag keyword found, but target attribution was ambiguous.'}
            elseif($lower-match'repadmin|replsummary|showrepl'){$tool='Repadmin';$reason='Repadmin keyword found, but subtype or target attribution was ambiguous.'}
            elseif($lower-match'nltest'){$tool='Nltest';$reason='Nltest keyword found, but subtype or target attribution was ambiguous.'}
            elseif($lower-match'w32tm'){$tool='W32tm';$reason='W32tm keyword found, but subtype or target attribution was ambiguous.'}
            elseif($lower-match'event|directory.?service'){$tool='EventLog';$reason='Event-log keyword found, but channel or target attribution was ambiguous.'}
        }
    }
    [pscustomobject][ordered]@{SourcePath=$File.FullName;SourceRelativePath=$File.FullName.Substring($SourceEvidenceRoot.Length).TrimStart('\','/');SourceFileName=$File.Name;SourceLength=[int64]$File.Length;SourceSHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash;Tool=$tool;Subtype=$subtype;Target=$target;MappingConfidence=$confidence;MappingReason=$reason;Mapped=[bool]$dest;StagedFileName=$dest;StagedPath=$null;StagedSHA256=$null;HashVerified=$false;Collision=$false}
}

$mappings=New-Object 'System.Collections.Generic.List[object]';$targets=New-Object 'System.Collections.Generic.List[string]'
foreach($file in @(Get-ChildItem -LiteralPath $SourceEvidenceRoot -File -Recurse|Sort-Object FullName)){
    $m=Resolve-Mapping -File $file
    if($m.Mapped){
        $dest=Join-Path $staging $m.StagedFileName
        if(Test-Path -LiteralPath $dest){$m.Collision=$true;$m.Mapped=$false;$m.MappingConfidence='None';$m.MappingReason="Destination collision: $($m.StagedFileName). Evidence left unmapped."}
        else{Copy-Item -LiteralPath $file.FullName -Destination $dest;$m.StagedPath=$dest;$m.StagedSHA256=(Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash;$m.HashVerified=($m.SourceSHA256-eq$m.StagedSHA256);if(-not$m.HashVerified){throw "HashVerificationFailed: $($file.FullName)"};if($m.Target-and$m.Target-ne'Domain'){$targets.Add($m.Target)}}
    }
    $mappings.Add($m)
}
$explicit=@(Get-ExpectedTargetList);$expected=if($explicit.Count){$explicit}else{@($targets.ToArray()|Sort-Object -Unique)}
$expectedSource=if($ExpectedTargetPath){[IO.Path]::GetFullPath($ExpectedTargetPath)}elseif($explicit.Count){'Parameter'}elseif($expected.Count){'DerivedFromHighConfidenceMappings'}else{'None'}
$expectedCsv=Join-Path $OutputRoot 'ExpectedTargets.csv';@($expected|ForEach-Object{[pscustomobject]@{Target=$_}})|Export-Csv -LiteralPath $expectedCsv -NoTypeInformation -Encoding UTF8
$mappingCsv=Join-Path $OutputRoot 'ADHealth-Staging-Mappings.csv';@($mappings.ToArray())|Export-Csv -LiteralPath $mappingCsv -NoTypeInformation -Encoding UTF8
$mappingJson=Join-Path $OutputRoot 'ADHealth-Staging-Mappings.json';@($mappings.ToArray())|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $mappingJson -Encoding UTF8
$assessment=$null
if(-not$SkipAssessment){
    $pipeline=Join-Path $PSScriptRoot 'Invoke-MSADPTADHealthOfflineAssessment-v1.1.0.ps1'
    if(-not(Test-Path -LiteralPath $pipeline -PathType Leaf)){throw "OfflinePipelineMissing: $pipeline"}
    $args=@{EvidenceRoot=$staging;OutputRoot=$assessmentRoot};if($expected.Count){$args.ExpectedTargetPath=$expectedCsv};$assessment=& $pipeline @args
}
$finished=(Get-Date).ToUniversalTime();$summary=[pscustomobject][ordered]@{SchemaVersion='1.2';PreparationVersion='1.2.0';Status='Succeeded';SourceEvidenceRoot=$SourceEvidenceRoot;OutputRoot=$OutputRoot;StagingRoot=$staging;AssessmentRoot=if($SkipAssessment){$null}else{$assessmentRoot};SourceFileCount=$mappings.Count;MappedFileCount=@($mappings|Where-Object Mapped).Count;UnmappedFileCount=@($mappings|Where-Object{-not$_.Mapped}).Count;CollisionCount=@($mappings|Where-Object Collision).Count;HashVerifiedCount=@($mappings|Where-Object HashVerified).Count;ExpectedTargetCount=@($expected).Count;ExpectedTargetSource=$expectedSource;ExpectedTargets=@($expected);AssessmentStatus=if($SkipAssessment){'Skipped'}else{$assessment.Status};AssessmentDisposition=if($SkipAssessment){$null}else{$assessment.Disposition};StartedUtc=$started.ToString('o');CompletedUtc=$finished.ToString('o');DurationMilliseconds=[math]::Round(($finished-$started).TotalMilliseconds);NetworkActivity='None';ActiveDirectoryQueries='None';RemoteChanges='None';GitChanges='None';Outputs=[pscustomobject]@{MappingCsv=$mappingCsv;MappingJson=$mappingJson;ExpectedTargets=$expectedCsv;StagingRoot=$staging;AssessmentRoot=if($SkipAssessment){$null}else{$assessmentRoot}}}
$summaryPath=Join-Path $OutputRoot 'ADHealth-Preparation-Summary.json';$summary|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $summaryPath -Encoding UTF8;$summary
