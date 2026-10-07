<#
.SYNOPSIS
Discovers and classifies saved AD Health evidence without contacting Active Directory.
.NOTES
Version: 1.1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [string[]]$ExpectedTarget = @(),
    [string]$ExpectedTargetPath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$EvidenceRoot = (Resolve-Path -LiteralPath $EvidenceRoot).Path

function Get-ExpectedTargets {
    $targets = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @($ExpectedTarget)) { if (-not [string]::IsNullOrWhiteSpace($item)) { $targets.Add($item.Trim()) } }
    if ($ExpectedTargetPath) {
        if (-not (Test-Path -LiteralPath $ExpectedTargetPath -PathType Leaf)) { throw "ExpectedTargetPathMissing: $ExpectedTargetPath" }
        if ([IO.Path]::GetExtension($ExpectedTargetPath) -ieq '.csv') {
            $csv = @(Import-Csv -LiteralPath $ExpectedTargetPath)
            foreach ($row in $csv) {
                $value = if ($row.PSObject.Properties['Target']) { $row.Target } elseif ($row.PSObject.Properties['Name']) { $row.Name } elseif ($row.PSObject.Properties['HostName']) { $row.HostName } else { $null }
                if ($value) { $targets.Add(([string]$value).Trim()) }
            }
        } else {
            foreach ($line in @(Get-Content -LiteralPath $ExpectedTargetPath)) { if (-not [string]::IsNullOrWhiteSpace($line)) { $targets.Add($line.Trim()) } }
        }
    }
    @($targets.ToArray() | Sort-Object -Unique)
}

function Resolve-EvidenceIdentity {
    param([IO.FileInfo]$File)
    $name = $File.BaseName
    $tool = $null; $target = 'Unknown'; $subtype = 'Unknown'; $supported = $true; $reason = ''
    switch -Regex ($name) {
        '^DCDiag-(?<target>.+)$' { $tool='DCDiag';$target=$Matches.target;$subtype='DCDiag';break }
        '^Repadmin-(?<type>ReplSummary|Bridgeheads)$' { $tool='Repadmin';$target='Domain';$subtype=$Matches.type;break }
        '^Repadmin-(?<type>ShowRepl|Queue)-(?<target>.+)$' { $tool='Repadmin';$target=$Matches.target;$subtype=$Matches.type;break }
        '^Nltest-(?<type>Query|DSGetSite)-(?<target>.+)$' { $tool='Nltest';$target=$Matches.target;$subtype=$Matches.type;break }
        '^Nltest-DSGetDC-(?<target>.+)$' { $tool='Nltest';$target=$Matches.target;$subtype='DSGetDC';break }
        '^W32tm-(?<type>Status|Config|Monitor)-(?<target>.+)$' { $tool='W32tm';$target=$Matches.target;$subtype=$Matches.type;break }
        '^EventLog-(?<type>[^-]+)-(?<target>.+)$' { $tool='EventLog';$target=$Matches.target;$subtype=$Matches.type;break }
        default { $supported=$false;$reason='Filename did not match an explicit supported AD Health evidence pattern.' }
    }
    [pscustomobject][ordered]@{ Path=$File.FullName; RelativePath=$File.FullName.Substring($EvidenceRoot.Length).TrimStart('\','/'); FileName=$File.Name; Tool=$tool; Subtype=$subtype; Target=$target; Supported=$supported; Reason=$reason; Length=[int64]$File.Length; SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash }
}

$allowed = @('.txt','.log','.out','.json','.csv')
$items = New-Object 'System.Collections.Generic.List[object]'
foreach ($file in @(Get-ChildItem -LiteralPath $EvidenceRoot -File -Recurse | Sort-Object FullName)) {
    if ($file.Extension.ToLowerInvariant() -notin $allowed) {
        $items.Add([pscustomobject][ordered]@{Path=$file.FullName;RelativePath=$file.FullName.Substring($EvidenceRoot.Length).TrimStart('\','/');FileName=$file.Name;Tool=$null;Subtype='UnsupportedExtension';Target='Unknown';Supported=$false;Reason="Unsupported extension: $($file.Extension)";Length=[int64]$file.Length;SHA256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash})
    } else { $items.Add((Resolve-EvidenceIdentity -File $file)) }
}
$expected = @(Get-ExpectedTargets)
[pscustomobject][ordered]@{SchemaVersion='1.1';ImporterVersion='1.1.0';EvidenceRoot=$EvidenceRoot;ExpectedTargets=$expected;ExpectedTargetSource=if($ExpectedTargetPath){[IO.Path]::GetFullPath($ExpectedTargetPath)}elseif($expected.Count){'Parameter'}else{'None'};CompletenessClaimsAllowed=[bool]($expected.Count -gt 0);DiscoveredFileCount=$items.Count;SupportedFileCount=@($items|Where-Object Supported).Count;UnsupportedFileCount=@($items|Where-Object{-not $_.Supported}).Count;Items=@($items.ToArray());NetworkActivity='None';ActiveDirectoryQueries='None';RemoteChanges='None'}
