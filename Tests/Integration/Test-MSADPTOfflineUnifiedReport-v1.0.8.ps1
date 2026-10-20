<#
.SYNOPSIS
Discovers existing MSADPT evidence and performs an offline unified-report test.
.NOTES
Version: 1.0.8
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = 'C:\Users\ExampleUser\Downloads\MSADPT',
    [string]$SearchRoot = 'C:\Users\ExampleUser\Downloads',
    [string]$EngagementDirectory,
    [switch]$OpenReport,
    [switch]$NoColor
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
function Write-Step { param([string]$State,[string]$Message,[ConsoleColor]$Color='Gray'); if($NoColor){Write-Host "[$State] $Message"}else{Write-Host "[$State] $Message" -ForegroundColor $Color} }
function Full { param([string]$Path); [IO.Path]::GetFullPath($Path) }
function Get-CommonParent { param([string[]]$Path)
    $parts=@($Path|ForEach-Object{,@((Full $_).TrimEnd('\').Split('\'))});$limit=($parts|ForEach-Object{[int]$_.Count}|Measure-Object -Minimum).Minimum;$common=[Collections.Generic.List[string]]::new()
    for($i=0;$i-lt$limit;$i++){if(@($parts|ForEach-Object{$_[$i].ToLowerInvariant()}|Select-Object -Unique).Count-ne1){break};$common.Add($parts[0][$i])}
    if($common.Count-lt2){throw 'Unable to calculate a safe common engagement root.'};$value=$common -join '\';if($value -match '^[A-Za-z]:$'){$value+='\'};return $value
}
$RepositoryRoot=Full $RepositoryRoot;$SearchRoot=Full $SearchRoot
$payloadBuilder=Join-Path $PSScriptRoot 'Build-MSADPTUnifiedReport-v1.0.9.ps1'
$builder=Join-Path $RepositoryRoot 'Tools\Build-MSADPTUnifiedReport-v1.0.9.ps1'
if(-not(Test-Path -LiteralPath $payloadBuilder -PathType Leaf)){throw "Required builder payload not found beside validator: $payloadBuilder"}
if(Test-Path -LiteralPath $builder){Copy-Item -LiteralPath $builder -Destination ($builder+'.pre-offline-test.bak') -Force}
Copy-Item -LiteralPath $payloadBuilder -Destination $builder -Force
Write-Step INSTALL "Installed corrected builder: $builder" Green
$payloadAdapter=Join-Path $PSScriptRoot 'New-MSADPTManagedSecretsAndGmsaReportSection-v1.0.9.ps1'
$adapter=Join-Path $RepositoryRoot 'Modules\ObjectControl\New-MSADPTManagedSecretsAndGmsaReportSection-v1.0.9.ps1'
if(-not(Test-Path -LiteralPath $payloadAdapter -PathType Leaf)){throw "Required adapter payload not found beside validator: $payloadAdapter"}
if(Test-Path -LiteralPath $adapter){Copy-Item -LiteralPath $adapter -Destination ($adapter+'.pre-offline-test.bak') -Force}
Copy-Item -LiteralPath $payloadAdapter -Destination $adapter -Force
Write-Step INSTALL "Installed corrected adapter: $adapter" Green
$payloadAssembler=Join-Path $PSScriptRoot 'New-MSADPTUnifiedReport-v1.0.3.ps1'
$assembler=Join-Path $RepositoryRoot 'Tools\New-MSADPTUnifiedReport-v1.0.3.ps1'
if(-not(Test-Path -LiteralPath $payloadAssembler -PathType Leaf)){throw "Required assembler payload not found: $payloadAssembler"}
Copy-Item -LiteralPath $payloadAssembler -Destination $assembler -Force
Write-Step INSTALL "Installed corrected assembler: $assembler" Green
foreach($required in @($RepositoryRoot,$SearchRoot,$payloadBuilder)){if(-not(Test-Path -LiteralPath $required)){throw "Required path not found: $required"}}
Write-Step INFO "Repository: $RepositoryRoot" Cyan
Write-Step INFO "Search root: $SearchRoot" Cyan
Write-Step INFO 'Network activity: None; Active Directory queries: None; directory changes: None.' Green
if([string]::IsNullOrWhiteSpace($EngagementDirectory)){
    Write-Step DISCOVER 'Locating existing managed-secrets and gMSA evidence.' Cyan
    $managed=@(Get-ChildItem -LiteralPath $SearchRoot -Directory -Filter 'ManagedSecretsExposure-*' -Recurse -ErrorAction SilentlyContinue|Where-Object{Test-Path (Join-Path $_.FullName 'evidence-manifest.json')}|Sort-Object LastWriteTimeUtc -Descending)
    $gmsa=@(Get-ChildItem -LiteralPath $SearchRoot -Directory -Filter 'GmsaRetrievalPrincipals-*' -Recurse -ErrorAction SilentlyContinue|Where-Object{Test-Path (Join-Path $_.FullName 'evidence-manifest.json')}|Sort-Object LastWriteTimeUtc -Descending)
    if($managed.Count-eq0){throw "No ManagedSecretsExposure-* evidence directory with evidence-manifest.json was found under $SearchRoot"}
    if($gmsa.Count-eq0){throw "No GmsaRetrievalPrincipals-* evidence directory with evidence-manifest.json was found under $SearchRoot"}
    $managedPath=$managed[0].FullName;$gmsaPath=$gmsa[0].FullName
    $collectionRoot=Get-CommonParent @($managedPath,$gmsaPath)
    $EngagementDirectory=Split-Path -Path $collectionRoot -Parent
    Write-Step FOUND "Managed secrets: $managedPath" Green
    Write-Step FOUND "gMSA retrieval: $gmsaPath" Green
}else{$EngagementDirectory=Full $EngagementDirectory}
if(-not(Test-Path -LiteralPath $EngagementDirectory -PathType Container)){throw "Engagement directory not found: $EngagementDirectory"}
$output=Join-Path $EngagementDirectory 'reports\offline-unified-test'
$name='MSADPT-Offline-Unified-Test-'+(Get-Date -Format 'yyyyMMdd-HHmmss')
Write-Step PLAN "Engagement root: $EngagementDirectory" Cyan
Write-Step PLAN "Output directory: $output" Cyan
Write-Step RUN 'Rebuilding normalized sections from existing evidence and assembling one HTML report.' Yellow
$allOutput=& $builder -EngagementDirectory $EngagementDirectory -RepositoryRoot $RepositoryRoot -OutputDirectory $output -ReportName $name -DuplicateModulePolicy Newest -ForceRebuildSections -OpenReport:$OpenReport -NoColor:$NoColor
$result=@($allOutput|Where-Object{$_-is[psobject]-and$null-ne$_.PSObject.Properties['HtmlReportPath']}|Select-Object -Last 1)
if($result.Count-ne1){throw 'Unified-report builder did not return one result object.'}
foreach($path in @($result[0].HtmlReportPath,$result[0].JsonIndexPath,$result[0].ValidationPath,$result[0].BuildManifestPath)){if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Expected report artifact was not created: $path"}}
$manifest=Get-Content -LiteralPath $result[0].BuildManifestPath -Raw|ConvertFrom-Json
$managedSection=@($manifest.selectedSectionPaths|Where-Object{$_ -match 'managed-secrets-gmsa-report-section\.json$'})
if($managedSection.Count-ne1){throw "Managed-secrets/gMSA section validation failed; selected count: $($managedSection.Count)"}
$validation=Get-Content -LiteralPath $result[0].ValidationPath -Raw|ConvertFrom-Json
Write-Step PASS "Unified report generated with $($result[0].SectionCount) sections and $($result[0].FindingCount) findings." Green
Write-Step PASS "Managed-secrets/gMSA section selected: $($managedSection[0])" Green
Write-Step REPORT $result[0].HtmlReportPath Cyan
[pscustomobject][ordered]@{Status='Passed';EngagementDirectory=$EngagementDirectory;SectionCount=$result[0].SectionCount;FindingCount=$result[0].FindingCount;HtmlReportPath=$result[0].HtmlReportPath;JsonIndexPath=$result[0].JsonIndexPath;ValidationPath=$result[0].ValidationPath;BuildManifestPath=$result[0].BuildManifestPath;ManagedSecretsGmsaSection=$managedSection[0];NetworkActivity='None';DirectoryChanges='None'}
