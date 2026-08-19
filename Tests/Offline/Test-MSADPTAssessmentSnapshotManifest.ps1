<#
.SYNOPSIS
Tests the generic MSADPT snapshot manifest builder.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$BuilderPath,[Parameter(Mandatory=$true)][string]$OutputRoot)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Tokens=$null;$Errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($BuilderPath,[ref]$Tokens,[ref]$Errors)
if($Errors.Count -gt 0){throw "Builder parse failed: $($Errors.Message -join '; ')"}
if(Test-Path -LiteralPath $OutputRoot){Remove-Item -LiteralPath $OutputRoot -Recurse -Force}
$DataRoot=Join-Path $OutputRoot 'data';New-Item -ItemType Directory -Path (Join-Path $DataRoot 'nested') -Force|Out-Null
@([pscustomobject]@{id=1},[pscustomobject]@{id=2})|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $DataRoot 'records.json') -Encoding UTF8
[pscustomobject]@{name='single'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $DataRoot 'nested\object.json') -Encoding UTF8
'text'|Set-Content -LiteralPath (Join-Path $DataRoot 'notes.txt') -Encoding UTF8
'ignored'|Set-Content -LiteralPath (Join-Path $DataRoot 'notes.txt.backup-20260101') -Encoding UTF8
$ManifestPath=Join-Path $OutputRoot 'manifest.json'
$Output=@(& $BuilderPath -InputPath $DataRoot -SnapshotRoot $DataRoot -OutputManifestPath $ManifestPath -SnapshotLabel 'Synthetic' -Quiet)
$Terminal=@($Output|Where-Object{$null -ne $_ -and $null -ne $_.PSObject.Properties['BuilderVersion']})|Select-Object -Last 1
if($null -eq $Terminal){throw 'Builder terminal result missing.'}
$Manifest=Get-Content -LiteralPath $ManifestPath -Raw|ConvertFrom-Json
$ArrayRow=@($Manifest.files|Where-Object{$_.relativePath -eq 'records.json'})[0]
$Checks=@(
    [pscustomobject]@{Test='ThreeFiles';Passed=([int]$Terminal.FileCount -eq 3)}
    [pscustomobject]@{Test='BackupExcluded';Passed=(@($Manifest.files|Where-Object{$_.relativePath -like '*.backup-*'}).Count -eq 0)}
    [pscustomobject]@{Test='RelativePathsNormalized';Passed=(@($Manifest.files|Where-Object{$_.relativePath -match '\\'}).Count -eq 0)}
    [pscustomobject]@{Test='JsonArrayCount';Passed=([int]$ArrayRow.jsonRecordCount -eq 2)}
    [pscustomobject]@{Test='JsonFilesParsed';Passed=([int]$Terminal.JsonParseFailureCount -eq 0)}
    [pscustomobject]@{Test='TimestampFormatting';Passed=(@($Manifest.files | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.lastWriteTimeUtc) }).Count -eq 0)}
    [pscustomobject]@{Test='TimestampRoundTrip';Passed=(@($Manifest.files | Where-Object { $null -eq ([DateTime]::Parse([string]$_.lastWriteTimeUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)) }).Count -eq 0)}
    [pscustomobject]@{Test='ManifestHashPresent';Passed=(-not[string]::IsNullOrWhiteSpace([string]$Terminal.ManifestSha256))}
    [pscustomobject]@{Test='RoundTripFiles';Passed=(@($Manifest.files).Count -eq 3)}
)
$Checks|Format-Table -AutoSize
$Failed=@($Checks|Where-Object{-not $_.Passed})
if($Failed.Count -gt 0){$Failed|Format-List Test,Passed;throw "$($Failed.Count) snapshot builder test(s) failed."}
[pscustomobject][ordered]@{Status='Passed';TestCount=$Checks.Count;BuilderVersion='0.1.1';TestVersion='1.0.1'}
