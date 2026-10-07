<# .SYNOPSIS Approves a reviewed sanitized fixture by removing the sensitive replacement map and recording reviewer attestation. #>
[CmdletBinding(SupportsShouldProcess)]param([Parameter(Mandatory)][string]$FixtureRoot,[Parameter(Mandatory)][string]$ReviewedBy,[Parameter(Mandatory)][string]$ReviewStatement)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$FixtureRoot=(Resolve-Path -LiteralPath $FixtureRoot).Path
$metadataPath=Join-Path $FixtureRoot 'Fixture-Metadata.json';$mapPath=Join-Path $FixtureRoot 'Fixture-Replacement-Map-REVIEW-AND-REMOVE.csv'
if(-not(Test-Path $metadataPath)){throw 'Fixture-Metadata.json is missing.'};$m=Get-Content $metadataPath -Raw|ConvertFrom-Json
if($m.SanitizationStatus-ne'ReviewRequired'){throw "Fixture is not ready for approval. Status=$($m.SanitizationStatus)"}
if(Test-Path $mapPath){Remove-Item -LiteralPath $mapPath -Force}
$m.SanitizationStatus='Approved';$m.ApprovedForRegression=$true;$m.ReviewedBy=$ReviewedBy;$m.ReviewStatement=$ReviewStatement;$m.ApprovedUtc=(Get-Date).ToUniversalTime().ToString('o')
$m|ConvertTo-Json -Depth 10|Set-Content $metadataPath -Encoding UTF8
[pscustomobject]@{Status='Approved';FixtureRoot=$FixtureRoot;ReviewedBy=$ReviewedBy;SensitiveMapRemoved=(-not(Test-Path $mapPath))}
