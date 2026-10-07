<#
.SYNOPSIS
Creates a reviewable, sanitized AD Health real-output fixture candidate from a completed collection.
.DESCRIPTION
Copies only declared AD Health outputs, replaces supplied environment identifiers with stable neutral tokens,
records source and fixture hashes, and fails closed when supplied sensitive identifiers remain.
No parser-format assumptions are introduced.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][string]$CollectionRoot,
 [Parameter(Mandatory)][string]$FixtureName,
 [Parameter(Mandatory)][string]$OutputRoot,
 [hashtable]$ReplacementMap,
 [string[]]$ForbiddenPatterns=@(),
 [switch]$IncludeEventLogs
)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$CollectionRoot=(Resolve-Path -LiteralPath $CollectionRoot).Path
if($FixtureName-notmatch'^[A-Za-z0-9._-]+$'){throw 'FixtureName may contain only letters, numbers, dot, underscore, and hyphen.'}
$manifestPath=Join-Path $CollectionRoot 'ADHealth-Collection-Manifest.json'
$targetsPath=Join-Path $CollectionRoot 'ExpectedTargets.csv'
$summaryPath=Join-Path $CollectionRoot 'ADHealth-Collection-Summary.json'
foreach($p in @($manifestPath,$targetsPath,$summaryPath)){if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw "Required collection file missing: $p"}}
$destination=Join-Path $OutputRoot $FixtureName
if(Test-Path -LiteralPath $destination){throw "Fixture destination already exists: $destination"}
New-Item -ItemType Directory -Path $destination -Force|Out-Null
$rawDest=Join-Path $destination 'Raw';New-Item -ItemType Directory -Path $rawDest -Force|Out-Null
$map=[ordered]@{}
if($ReplacementMap){foreach($k in $ReplacementMap.Keys){if([string]::IsNullOrWhiteSpace([string]$k)){throw 'ReplacementMap contains an empty source token.'};$map[[string]$k]=[string]$ReplacementMap[$k]}}
$targets=@(Import-Csv -LiteralPath $targetsPath)
$targetIndex=0
foreach($row in $targets){if($row.PSObject.Properties['Target']-and$row.Target){$targetIndex++;$name=[string]$row.Target;if(-not$map.Contains($name)){$map[$name]="DC$('{0:d2}'-f$targetIndex).example.test"};$short=($name-split'\.')[0];if ($short -and -not $map.Contains($short)){$map[$short]="DC$('{0:d2}'-f$targetIndex)"}}}
function Protect-Text{param([string]$Text);$result=$Text;foreach($key in @($map.Keys|Sort-Object Length -Descending)){$result=$result-replace[regex]::Escape($key),[System.Text.RegularExpressions.MatchEvaluator]{param($m)$map[$key]}};$result}
$allowed=@('DCDiag-*.txt','Repadmin-ShowRepl-*.txt','Repadmin-Queue-*.txt','Repadmin-ReplSummary.txt','Nltest-Query-*.txt','Nltest-DSGetSite-*.txt','W32tm-Status-*.txt')
if($IncludeEventLogs){$allowed+=@('EventLog-*.json')}
$sourceFiles = @(foreach ($pattern in $allowed) {
    Get-ChildItem -LiteralPath (Join-Path $CollectionRoot 'Raw') -File -Filter $pattern -ErrorAction SilentlyContinue
}) | Sort-Object FullName -Unique
if(@($sourceFiles).Count-eq0){throw 'No declared AD Health raw output files were found.'}
$records=New-Object 'System.Collections.Generic.List[object]'
foreach($file in $sourceFiles){
 $safeName=Protect-Text $file.Name;$dest=Join-Path $rawDest $safeName
 $content=Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
 $protected=Protect-Text $content
 Set-Content -LiteralPath $dest -Value $protected -Encoding UTF8
 $records.Add([pscustomobject]@{SourceName=$file.Name;FixtureName=$safeName;SourceSHA256=(Get-FileHash $file.FullName -Algorithm SHA256).Hash;FixtureSHA256=(Get-FileHash $dest -Algorithm SHA256).Hash;SourceBytes=$file.Length;FixtureBytes=(Get-Item $dest).Length})
}
$sanitizedTargets=foreach($row in $targets){$o=[ordered]@{};foreach($p in $row.PSObject.Properties){$o[$p.Name]=Protect-Text([string]$p.Value)};[pscustomobject]$o}
$sanitizedTargets|Export-Csv -LiteralPath (Join-Path $destination 'ExpectedTargets.csv')-NoTypeInformation -Encoding UTF8
$summary=Protect-Text(Get-Content $summaryPath -Raw);Set-Content -LiteralPath (Join-Path $destination 'ADHealth-Collection-Summary.json')-Value $summary -Encoding UTF8
$scanPatterns=@($ForbiddenPatterns)+@($map.Keys)
$leaks=New-Object 'System.Collections.Generic.List[object]'
foreach($pattern in @($scanPatterns|Where-Object{$_}|Sort-Object -Unique)){
 Get-ChildItem -LiteralPath $destination -File -Recurse|Select-String -SimpleMatch -Pattern $pattern -ErrorAction SilentlyContinue|ForEach-Object{$leaks.Add([pscustomobject]@{Pattern=$pattern;Path=$_.Path;LineNumber=$_.LineNumber})}
}
$records|Export-Csv -LiteralPath (Join-Path $destination 'Fixture-File-Manifest.csv')-NoTypeInformation -Encoding UTF8
$map.GetEnumerator()|ForEach-Object{[pscustomobject]@{SourceToken=$_.Key;ReplacementToken=$_.Value}}|Export-Csv -LiteralPath (Join-Path $destination 'Fixture-Replacement-Map-REVIEW-AND-REMOVE.csv')-NoTypeInformation -Encoding UTF8
$metadata=[pscustomobject]@{SchemaVersion='1.0';FixtureVersion='1.6.1';FixtureName=$FixtureName;SourceCollection=$CollectionRoot;FileCount=$records.Count;SanitizationStatus=if($leaks.Count){'Blocked'}else{'ReviewRequired'};LeakCount=$leaks.Count;RealNativeEvidence=$true;ApprovedForRegression=$false;CreatedUtc=(Get-Date).ToUniversalTime().ToString('o');InterpretationBoundary='Sanitization and structural preservation do not validate parser accuracy.'}
$metadata|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $destination 'Fixture-Metadata.json')-Encoding UTF8
if($leaks.Count){$leaks|Export-Csv -LiteralPath (Join-Path $destination 'Fixture-Leak-Report.csv')-NoTypeInformation -Encoding UTF8;throw "Fixture blocked: $($leaks.Count) supplied sensitive token occurrence(s) remain. Review $destination"}
[pscustomobject]@{Status='ReviewRequired';FixtureRoot=$destination;FileCount=$records.Count;LeakCount=0;ReplacementMapReviewPath=(Join-Path $destination 'Fixture-Replacement-Map-REVIEW-AND-REMOVE.csv');NetworkActivity='None';ActiveDirectoryQueries='None';RemoteChanges='None'}
