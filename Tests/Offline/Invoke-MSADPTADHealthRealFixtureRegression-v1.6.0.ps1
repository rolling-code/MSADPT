<# .SYNOPSIS Runs AD Health parser regression only against an explicitly approved real-output fixture. #>
[CmdletBinding()]param([Parameter(Mandatory)][string]$FixtureRoot,[string]$OutputRoot)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$FixtureRoot=(Resolve-Path -LiteralPath $FixtureRoot).Path
$repo=Split-Path -Parent (Split-Path -Parent $PSScriptRoot);$metaPath=Join-Path $FixtureRoot 'Fixture-Metadata.json';if(-not(Test-Path $metaPath)){throw 'Fixture metadata is missing.'}
$m=Get-Content $metaPath -Raw|ConvertFrom-Json;if (-not $m.ApprovedForRegression -or $m.SanitizationStatus -ne 'Approved'){throw 'Fixture is not approved for regression.'}
if(-not$OutputRoot){$OutputRoot=Join-Path ([IO.Path]::GetTempPath())('MSADPT-ADHealth-RealFixture-'+[guid]::NewGuid().ToString('N'))}
New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null
$invoke=Join-Path $repo 'Modules\ADHealth\Invoke-MSADPTADHealthOfflineAssessment-v1.1.0.ps1';if(-not(Test-Path $invoke)){throw "Offline assessment entry point missing: $invoke"}
$params=@{EvidenceRoot=$FixtureRoot;OutputRoot=$OutputRoot}
$result=& $invoke @params
$files=@(Get-ChildItem -LiteralPath $OutputRoot -File -Recurse -ErrorAction SilentlyContinue)
$report=[pscustomobject]@{Status='Completed';FixtureName=$m.FixtureName;FixtureVersion=$m.FixtureVersion;OutputRoot=$OutputRoot;OutputFileCount=$files.Count;AssessmentResult=$result;ExecutedUtc=(Get-Date).ToUniversalTime().ToString('o');InterpretationBoundary='A completed regression proves deterministic processing of this approved fixture, not universal native-output coverage.'}
$report|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $OutputRoot 'Real-Fixture-Regression.json')-Encoding UTF8;$report
