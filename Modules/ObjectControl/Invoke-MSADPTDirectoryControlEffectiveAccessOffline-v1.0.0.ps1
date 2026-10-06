<# .SYNOPSIS Reprocesses saved MSADPT effective-access evidence offline. .NOTES Version: 1.0.0 #>
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$EngagementDirectory,[string]$OutputDirectory,[switch]$NoColor)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$Root=(Resolve-Path(Join-Path $PSScriptRoot '..\..')).Path
if([string]::IsNullOrWhiteSpace($OutputDirectory)){$OutputDirectory=Join-Path $EngagementDirectory 'analysis\DirectoryControlEffectiveAccess-v1.0.3'}
$Evaluator=Join-Path $Root 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlEffectiveAccess-v1.0.3.ps1'
$Evidence=Join-Path $EngagementDirectory 'evidence\DirectoryControl';$Reduction=Join-Path $EngagementDirectory 'analysis\DirectoryControlReduction'
$Token=Join-Path $EngagementDirectory 'evidence\DirectoryControlToken\directory-control-token-evidence.csv'
$Schema=Join-Path $EngagementDirectory 'evidence\DirectoryControlSchema\directory-control-schema-class-map.csv'
Write-Host '[SAFETY      ] Offline CSV/JSON processing only. Network=None; AD queries=None; remote changes=None.' -ForegroundColor Yellow
& $Evaluator -DirectoryControlEvidenceDirectory $Evidence -CandidateReductionDirectory $Reduction -OutputDirectory $OutputDirectory -TokenEvidencePath $Token -SchemaClassMapPath $Schema -NoColor:$NoColor
