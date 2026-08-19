<# .SYNOPSIS Tests version-aware module refresh without AD access. .VERSION 1.0.0 #>
[CmdletBinding()]param([string]$MSADPTRoot=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';Import-Module (Join-Path $MSADPTRoot 'Controller\MSADPT.Reasoning.psm1') -Force
$cap=@('enterpriseCAObjectPresence')
function New-Reg([string]$Version){[pscustomobject]@{Definition=[pscustomobject]@{name='ADCSConfigurationCollection';moduleVersion=$Version;requires=@('enterpriseCAObjectPresence')}}}
$old=[pscustomobject]@{module='ADCSConfigurationCollection';moduleVersion='0.1.0';status='Completed';superseded=$false}
$other=[pscustomobject]@{module='DomainControllerEnumeration';moduleVersion='0.1.0';status='Completed';superseded=$false}
$tests=@(
 @{Name='Upgrade becomes eligible';Registry=@(New-Reg '0.2.0');Ledger=@($old,$other);Expected=1},
 @{Name='Same version stays closed';Registry=@(New-Reg '0.1.0');Ledger=@($old,$other);Expected=0},
 @{Name='Downgrade stays closed';Registry=@(New-Reg '0.0.9');Ledger=@($old,$other);Expected=0},
 @{Name='Unrelated completed module does not block';Registry=@(New-Reg '0.2.0');Ledger=@($other);Expected=1}
)
foreach($x in $tests){$actual=@(Get-MSADPTEligibleRegistry -Registry $x.Registry -Capabilities $cap -Ledger $x.Ledger).Count;if($actual-ne$x.Expected){throw "$($x.Name): expected $($x.Expected), got $actual"};Write-Host "[PASS] $($x.Name)" -ForegroundColor Green}
Write-Host '[PASS] Version-aware refresh tests completed without AD access.' -ForegroundColor Green
