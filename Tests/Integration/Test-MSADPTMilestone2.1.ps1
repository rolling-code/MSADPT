[CmdletBinding()]param([string]$MSADPTRoot=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';Import-Module (Join-Path $MSADPTRoot 'Controller\MSADPT.Reasoning.psm1') -Force
$r=@(Get-MSADPTModuleRegistry $MSADPTRoot);if($r.Count-lt2){throw "Registry count invalid: $($r.Count)"}
$e=Get-ChildItem -LiteralPath (Join-Path $MSADPTRoot 'Engagements') -Directory|Sort-Object LastWriteTime -Descending|Select-Object -First 1
$l=@(Initialize-MSADPTLedger -EngagementPath $e.FullName -Registry $r);$dc=@($l|Where-Object{[string]$_.module-eq'DomainControllerEnumeration'-and[string]$_.status-eq'Completed'})
if($dc.Count-eq0){throw 'Completed DomainControllerEnumeration was not migrated into the ledger.'}
$recursive=@(Get-MSADPTEvidenceIndex $e.FullName|Where-Object path -like 'evidence/DomainControllerEnumeration/*')
if($recursive.Count-eq0){throw 'Recursive module evidence was not indexed.'}
Write-Host "Ledger entries: $($l.Count)" -ForegroundColor Cyan;Write-Host "Recursive DC evidence files: $($recursive.Count)" -ForegroundColor Cyan;Write-Host '[SUCCESS] MSADPT Milestone 2.1 smoke test passed.' -ForegroundColor Green
