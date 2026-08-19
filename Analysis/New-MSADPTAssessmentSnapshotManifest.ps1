<#
.SYNOPSIS
Creates a deterministic MSADPT assessment snapshot manifest.
.DESCRIPTION
Builds a reusable, environment-agnostic manifest from explicitly selected files and directories.
Records normalized relative paths, sizes, SHA-256 hashes, timestamps, file types, and JSON record
counts where applicable. It performs no network, directory-service, collector, Ollama, or ledger action.
.NOTES
Version: 0.1.1
Execution class: offline_snapshot
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string[]]$InputPath,
    [Parameter(Mandatory=$true)][string]$SnapshotRoot,
    [Parameter(Mandatory=$true)][string]$OutputManifestPath,
    [string]$SnapshotLabel='MSADPT Assessment Snapshot',
    [string]$SourceScope='preserved_evidence',
    [switch]$IncludeBackupFiles,
    [switch]$FailOnJsonParseError,
    [switch]$Quiet
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$BuilderVersion='0.1.1'
function Write-Step([string]$Status,[string]$Message,[ConsoleColor]$Color){if(-not $Quiet){Write-Host ('[{0,-5}] {1}' -f $Status,$Message) -ForegroundColor $Color}}
function Get-NormalizedRelativePath([string]$FullPath,[string]$RootPath){
    $Root=[IO.Path]::GetFullPath($RootPath).TrimEnd([char[]]@([char]92,[char]47))
    $Full=[IO.Path]::GetFullPath($FullPath)
    if($Full.StartsWith($Root,[StringComparison]::OrdinalIgnoreCase)){
        return $Full.Substring($Root.Length).TrimStart([char[]]@([char]92,[char]47)).Replace([char]92,[char]47)
    }
    return [IO.Path]::GetFileName($Full)
}
function Get-JsonRecordInfo([string]$Path){
    $Result=[ordered]@{parseStatus='NotApplicable';recordCount=$null;topLevelType=$null;error=$null}
    if([IO.Path]::GetExtension($Path) -ne '.json'){return [pscustomobject]$Result}
    try{
        $Value=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop
        $Result.parseStatus='Passed'
        if($Value -is [array]){$Result.topLevelType='Array';$Result.recordCount=@($Value).Count}
        else{$Result.topLevelType='Object';$Result.recordCount=1}
    }catch{$Result.parseStatus='Failed';$Result.error=$_.Exception.Message}
    return [pscustomobject]$Result
}
Write-Step 'START' 'Creating deterministic MSADPT snapshot manifest.' Cyan
if(-not(Test-Path -LiteralPath $SnapshotRoot -PathType Container)){throw "SnapshotRootMissing: $SnapshotRoot"}
$DiscoveredFiles = New-Object 'Collections.Generic.List[IO.FileInfo]'
foreach($Path in $InputPath){
    if(Test-Path -LiteralPath $Path -PathType Leaf){
        $Item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if($Item -isnot [IO.FileInfo]){throw "InputPathIsNotFile: $Path"}
        $DiscoveredFiles.Add([IO.FileInfo]$Item)
    }
    elseif(Test-Path -LiteralPath $Path -PathType Container){
        foreach($Item in @(Get-ChildItem -LiteralPath $Path -File -Recurse -ErrorAction Stop)){
            if($Item -is [IO.FileInfo]){$DiscoveredFiles.Add([IO.FileInfo]$Item)}
        }
    }
    else{throw "InputPathMissing: $Path"}
}
$Files = @(
    $DiscoveredFiles |
        Where-Object { $IncludeBackupFiles -or $_.Name -notmatch '\.backup-' } |
        Sort-Object FullName -Unique |
        ForEach-Object { [IO.FileInfo]$_ }
)
if($Files.Count -eq 0){throw 'SnapshotFileSetEmpty'}
$Rows=@();$JsonFailures=@();$Index=0
foreach($FileEntry in $Files){
    $Index++
    $File = [IO.FileInfo]$FileEntry
    $Json=Get-JsonRecordInfo $File.FullName
    if($Json.parseStatus -eq 'Failed'){$JsonFailures+=,$File.FullName}
    $Rows+=,[pscustomobject][ordered]@{
        relativePath=Get-NormalizedRelativePath $File.FullName $SnapshotRoot
        sourcePath=$File.FullName
        size=[int64]$File.Length
        sha256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        extension=$File.Extension.ToLowerInvariant()
        lastWriteTimeUtc=([DateTime]$File.LastWriteTimeUtc).ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)
        jsonParseStatus=$Json.parseStatus
        jsonRecordCount=$Json.recordCount
        jsonTopLevelType=$Json.topLevelType
        jsonParseError=$Json.error
    }
    if(-not $Quiet -and ($Index%50 -eq 0 -or $Index -eq $Files.Count)){Write-Step 'STEP' "Hashed $Index of $($Files.Count) files." Yellow}
}
if($FailOnJsonParseError -and $JsonFailures.Count -gt 0){throw "JsonParseFailures: $($JsonFailures -join '; ')"}
$Manifest=[pscustomobject][ordered]@{
    schemaVersion='1.0'
    builder='MSADPTAssessmentSnapshotManifest'
    builderVersion=$BuilderVersion
    status=if($JsonFailures.Count -eq 0){'Completed'}else{'CompletedWithWarnings'}
    snapshotLabel=$SnapshotLabel
    sourceScope=$SourceScope
    generatedUtc=([DateTime](Get-Date)).ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)
    snapshotRoot=[IO.Path]::GetFullPath($SnapshotRoot)
    fileCount=$Rows.Count
    totalBytes=[int64](($Rows|Measure-Object size -Sum).Sum)
    jsonFileCount=@($Rows|Where-Object{$_.extension -eq '.json'}).Count
    jsonParseFailureCount=$JsonFailures.Count
    files=@($Rows|ForEach-Object{$_})
}
$Parent=Split-Path $OutputManifestPath -Parent
if(-not[string]::IsNullOrWhiteSpace($Parent)){New-Item -ItemType Directory -Path $Parent -Force|Out-Null}
$Manifest|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $OutputManifestPath -Encoding UTF8
$RoundTrip=Get-Content -LiteralPath $OutputManifestPath -Raw|ConvertFrom-Json -ErrorAction Stop
if(@($RoundTrip.files).Count -ne $Rows.Count){throw "ManifestRoundTripCountMismatch: expected $($Rows.Count), found $(@($RoundTrip.files).Count)"}
$ManifestHash=(Get-FileHash -LiteralPath $OutputManifestPath -Algorithm SHA256).Hash.ToUpperInvariant()
Write-Step 'DONE' "Snapshot manifest created: files=$($Rows.Count), JSON failures=$($JsonFailures.Count)." Green
[pscustomobject][ordered]@{Status=$Manifest.status;BuilderVersion=$BuilderVersion;FileCount=$Rows.Count;TotalBytes=$Manifest.totalBytes;JsonFileCount=$Manifest.jsonFileCount;JsonParseFailureCount=$JsonFailures.Count;ManifestPath=$OutputManifestPath;ManifestSha256=$ManifestHash;NetworkActivity='None';CollectorActivity='None';LedgerChanges='None'}
