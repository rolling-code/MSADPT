<# .SYNOPSIS Tests the offline Unicode identity analyzer. .NOTES Version: 1.0.0 #>
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$AnalyzerPath,[Parameter(Mandatory=$true)][string]$FixtureGeneratorPath,[Parameter(Mandatory=$true)][string]$OutputRoot)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
foreach($Path in @($AnalyzerPath,$FixtureGeneratorPath)){if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "Required file not found: $Path"}}
if(Test-Path -LiteralPath $OutputRoot){Remove-Item -LiteralPath $OutputRoot -Recurse -Force};New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null
$FixturePath=Join-Path $OutputRoot 'unicode-identities.json';$null=& $FixtureGeneratorPath -OutputPath $FixturePath
$AnalysisOutput=Join-Path $OutputRoot 'Analysis';$Terminal=@(& $AnalyzerPath -InputPath $FixturePath -OutputDirectory $AnalysisOutput)|Where-Object{$null-ne$_.PSObject.Properties['analyzerVersion']}|Select-Object -Last 1
$Findings=@(Get-Content -LiteralPath (Join-Path $AnalysisOutput 'unicode-identity-findings.json') -Raw|ConvertFrom-Json)
$Checks=@(
[pscustomobject]@{Test='SuspiciousCodePointDetected';Passed=(@($Findings|Where-Object FindingType -eq 'SuspiciousUnicodeCodePoint').Count -ge 1)},
[pscustomobject]@{Test='SpnCollisionDetected';Passed=(@($Findings|Where-Object FindingType -eq 'NormalizedSpnCollision').Count -eq 1)},
[pscustomobject]@{Test='IdentityCollisionDetected';Passed=(@($Findings|Where-Object FindingType -eq 'NormalizedIdentityCollision').Count -ge 1)},
[pscustomobject]@{Test='CompatibilityNormalizationDetected';Passed=(@($Findings|Where-Object FindingType -eq 'CompatibilityNormalizationChange').Count -ge 1)},
[pscustomobject]@{Test='FourObjectsProcessed';Passed=([int]$Terminal.objectCount -eq 4)}
)
$Checks|Format-Table -AutoSize;$Failed=@($Checks|Where-Object{-not $_.Passed});if($Failed.Count -gt 0){throw "$($Failed.Count) Unicode identity analyzer test(s) failed."};[pscustomobject]@{Status='Passed';TestCount=$Checks.Count;AnalyzerVersion='0.1.0';ObjectCount=$Terminal.objectCount;FindingCount=$Terminal.findingCount;OutputRoot=$OutputRoot}
