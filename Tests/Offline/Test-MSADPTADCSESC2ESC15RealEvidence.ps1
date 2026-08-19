<#
.SYNOPSIS
Tests the real-evidence ESC2 and ESC15 runner in a fully synthetic MSADPT tree.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RunnerPath,
    [Parameter(Mandatory=$true)][string]$BuilderSourcePath,
    [Parameter(Mandatory=$true)][string]$OutputRoot
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Tokens=$null;$Errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($RunnerPath,[ref]$Tokens,[ref]$Errors)
if($Errors.Count){throw "Runner parse failed: $($Errors.Message -join '; ')"}
if(Test-Path $OutputRoot){Remove-Item $OutputRoot -Recurse -Force}
$Root=Join-Path $OutputRoot 'MSADPT';$Analysis=Join-Path $Root 'Analysis\ADCS';$Common=Join-Path $Root 'Common';$Generated=Join-Path $Root 'Tests\Offline\Generated'
New-Item -ItemType Directory -Path $Analysis,$Common,(Join-Path $Generated 'ADCSCandidateSpecificFacts'),(Join-Path $Generated 'ADIdentityContext'),(Join-Path $Root 'Engagements\E1\evidence\ADCSConfigurationCollection') -Force|Out-Null
Copy-Item $BuilderSourcePath (Join-Path $Analysis 'Convert-MSADPTADCSEvidenceToESC2ESC15CandidateFacts.ps1')
@'
function Write-MSADPTConsoleEvent { param($Kind,$Message,$Target,$Code) [pscustomobject]@{Kind=$Kind;Message=$Message;Target=$Target;Code=$Code} }
'@|Set-Content (Join-Path $Common 'MSADPT.Console.psm1')
function F($id,$state){[pscustomobject]@{id=$id;state=$state;rationale='s';sourceEvidence=@('s');limitations=@()}}
$Facts=@((F 'enterpriseCaPresent' 'Confirmed'),(F 'templatePublished' 'Confirmed'),(F 'effectiveLowPrivilegeEnrollment' 'Confirmed'),(F 'managerApprovalDisabled' 'Confirmed'),(F 'authorizedSignaturesNotRequired' 'Confirmed'),(F 'principalResolved' 'Confirmed'))
@([pscustomobject]@{candidateId='ESC1|CA|V1|EXAMPLE\Users';technique='ESC1';certificationAuthority='CA';template='V1';principal='EXAMPLE\Users';facts=$Facts})|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Generated 'ADCSCandidateSpecificFacts\adcs-candidate-specific-facts.json')
@([pscustomobject]@{Name='V1';ExtendedKeyUsage=@('2.5.29.37.0');NoExtendedKeyUsageRestriction=$false;SchemaVersion=1;EnrolleeSuppliesSubject=$true;EnrolleeSuppliesSubjectAltName=$false})|ConvertTo-Json -Depth 6|Set-Content (Join-Path $Root 'Engagements\E1\evidence\ADCSConfigurationCollection\certificate-template-configuration.json')
@([pscustomobject]@{identityReference='EXAMPLE\Users';category='BroadLowPrivilege'})|ConvertTo-Json -Depth 4|Set-Content (Join-Path $Generated 'ADIdentityContext\ad-identity-context.json')
$Out = @(
    & $RunnerPath `
        -MSADPTRoot $Root `
        -CandidateFactsPath (Join-Path $Generated 'ADCSCandidateSpecificFacts\adcs-candidate-specific-facts.json') `
        -TemplateConfigurationPath (Join-Path $Root 'Engagements\E1\evidence\ADCSConfigurationCollection\certificate-template-configuration.json') `
        -IdentityContextPath (Join-Path $Generated 'ADIdentityContext\ad-identity-context.json') `
        -OutputDirectory (Join-Path $Generated 'ADCSCandidateESC2ESC15-RealEvidence') `
        -Quiet
)
$Terminal = @(
    $Out | Where-Object {
        $null -ne $_ -and
        $null -ne $_.PSObject.Properties['runnerVersion'] -and
        $null -ne $_.PSObject.Properties['status'] -and
        [string]$_.status -eq 'Completed'
    }
) | Select-Object -Last 1
if ($null -eq $Terminal) { throw 'Runner terminal result missing.' }
$Checks = @(
    [pscustomobject]@{Test='TerminalCompleted';Passed=($null -ne $Terminal)}
    [pscustomobject]@{Test='TwoCandidates';Passed=([int]$Terminal.totalCandidateCount -eq 2)}
    [pscustomobject]@{Test='OneEsc2';Passed=([int]$Terminal.esc2Count -eq 1)}
    [pscustomobject]@{Test='OneEsc15';Passed=([int]$Terminal.esc15Count -eq 1)}
    [pscustomobject]@{Test='VersionOneDetected';Passed=([int]$Terminal.versionOneEsc15RouteCount -eq 1)}
    [pscustomobject]@{Test='Esc2CapabilityDetected';Passed=([int]$Terminal.esc2CapabilityRouteCount -eq 1)}
)
$Checks | Format-Table -AutoSize
$Failed = @($Checks | Where-Object { -not $_.Passed })
if ($Failed.Count -gt 0) { throw "$($Failed.Count) real-evidence runner test(s) failed." }
[pscustomobject]@{Status='Passed';TestCount=$Checks.Count;RunnerVersion='1.0.1';TestVersion='1.0.1'}
