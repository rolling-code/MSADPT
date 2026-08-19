<#
.SYNOPSIS
Runs the MSADPT Milestone 2.2 synthetic Ollama reasoning validation.
.VERSION
1.0.0
#>
[CmdletBinding()]
param(
    [string]$ModelName = 'hf.co/unsloth/Qwen3.5-9B-GGUF:Q4_K_M',
    [string]$OllamaUri = 'http://localhost:11434',
    [switch]$SkipLiveModel
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$MSADPTRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ProviderPath = Join-Path $MSADPTRoot 'Integrations\Ollama\MSADPT.Ollama.psm1'
$PromptPath = Join-Path $MSADPTRoot 'Promptbooks\MSADPT-Offline-Decision-Engine-v1.2.txt'
$OutputRoot = Join-Path $PSScriptRoot 'Results'
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

function New-SyntheticPackage {
    param([switch]$NoEligibleModules)
    $Eligible = if ($NoEligibleModules) { @() } else {
        @(
            [pscustomobject][ordered]@{
                schemaVersion='1.0';name='SyntheticDelegationCollection';description='Collect synthetic delegation attributes.'
                executionClass='read_only';acceptedTargetTypes=@('syntheticDomain');requires=@('syntheticDomainPresent')
                produces=@('syntheticDelegationEvidence');requiresHumanApproval=$false
            },
            [pscustomobject][ordered]@{
                schemaVersion='1.0';name='SyntheticPrivilegedGroupCollection';description='Collect synthetic privileged group membership.'
                executionClass='read_only';acceptedTargetTypes=@('syntheticDomain');requires=@('syntheticDomainPresent')
                produces=@('syntheticPrivilegedGroupEvidence');requiresHumanApproval=$false
            }
        )
    }
    [pscustomobject][ordered]@{
        packageVersion='2.2-synthetic'
        generatedUtc=(Get-Date).ToUniversalTime().ToString('o')
        engagementState=[pscustomobject]@{RunId='SYNTHETIC-ENGAGEMENT-001';Status='Completed';DomainFQDN='example.test';AssessmentMode='ReadOnly'}
        evidence=@(
            [pscustomobject]@{path='evidence/synthetic-domain.json';name='synthetic-domain.json';content=[pscustomobject]@{DomainFQDN='example.test';DomainController='dc01.example.test';EnterpriseCA='ca01.example.test'}}
        )
        capabilities=@('syntheticDomainPresent','syntheticDomainControllerMetadata')
        executionLedger=@(
            [pscustomobject]@{module='SyntheticDomainControllerCollection';targetKey='SYNTHETIC-ENGAGEMENT-001';status='Completed';executionClass='read_only'}
        )
        eligibleModules=$Eligible
        constraints=@('Synthetic evidence only','One eligible module or Stop','Read-only','No commands','No invented targets')
    }
}

function Test-DecisionContract {
    param($Decision,$Package)
    $Errors = New-Object 'System.Collections.Generic.List[string]'
    $Required = @('schemaVersion','decision','recommendedModule','targetSelector','reason','evidenceUsed','expectedEvidence','confidence','executionClass','requiresHumanApproval')
    foreach($Name in $Required){if($Decision.PSObject.Properties.Name -notcontains $Name){$Errors.Add("Missing property: $Name")}}
    if($Errors.Count -gt 0){return [pscustomobject]@{Valid=$false;Errors=$Errors.ToArray()}}
    if(@('collect_more_evidence','stop') -notcontains [string]$Decision.decision){$Errors.Add('Invalid decision value.')}
    if([string]$Decision.executionClass -ne 'read_only'){$Errors.Add('executionClass must be read_only.')}
    if([bool]$Decision.requiresHumanApproval){$Errors.Add('requiresHumanApproval must be false.')}
    if([string]$Decision.decision -eq 'collect_more_evidence'){
        $EligibleNames=@($Package.eligibleModules|ForEach-Object{[string]$_.name})
        if($EligibleNames -notcontains [string]$Decision.recommendedModule){$Errors.Add('The selected module is not eligible.')}
        $CompletedNames=@($Package.executionLedger|Where-Object status -eq 'Completed'|ForEach-Object{[string]$_.module})
        if($CompletedNames -contains [string]$Decision.recommendedModule){$Errors.Add('The selected module is already completed.')}
        $PackageText=$Package|ConvertTo-Json -Depth 40 -Compress
        foreach($Id in @($Decision.targetSelector.identifiers)){if([string]::IsNullOrWhiteSpace([string]$Id)-or$PackageText-notmatch[regex]::Escape([string]$Id)){$Errors.Add("Target is not evidence-backed: $Id")}}
    }
    [pscustomobject]@{Valid=($Errors.Count -eq 0);Errors=$Errors.ToArray()}
}

Write-Host '=== Offline contract regression tests ===' -ForegroundColor Cyan
$Package = New-SyntheticPackage
$RegressionCases = @(
    [pscustomobject]@{Name='Valid eligible choice';Decision=[pscustomobject]@{schemaVersion='1.0';decision='collect_more_evidence';recommendedModule='SyntheticDelegationCollection';targetSelector=[pscustomobject]@{type='syntheticDomain';identifiers=@('example.test')};reason='Collect delegation evidence.';evidenceUsed=@('evidence/synthetic-domain.json');expectedEvidence=@('syntheticDelegationEvidence');confidence='high';executionClass='read_only';requiresHumanApproval=$false};Expected=$true},
    [pscustomobject]@{Name='Reject completed module';Decision=[pscustomobject]@{schemaVersion='1.0';decision='collect_more_evidence';recommendedModule='SyntheticDomainControllerCollection';targetSelector=[pscustomobject]@{type='syntheticDomain';identifiers=@('example.test')};reason='Repeat collection.';evidenceUsed=@();expectedEvidence=@();confidence='low';executionClass='read_only';requiresHumanApproval=$false};Expected=$false},
    [pscustomobject]@{Name='Reject invented module';Decision=[pscustomobject]@{schemaVersion='1.0';decision='collect_more_evidence';recommendedModule='Invoke-Exploit';targetSelector=[pscustomobject]@{type='syntheticDomain';identifiers=@('example.test')};reason='Invalid.';evidenceUsed=@();expectedEvidence=@();confidence='low';executionClass='exploit';requiresHumanApproval=$false};Expected=$false},
    [pscustomobject]@{Name='Reject invented target';Decision=[pscustomobject]@{schemaVersion='1.0';decision='collect_more_evidence';recommendedModule='SyntheticDelegationCollection';targetSelector=[pscustomobject]@{type='syntheticDomain';identifiers=@('invented.invalid')};reason='Invalid target.';evidenceUsed=@();expectedEvidence=@();confidence='low';executionClass='read_only';requiresHumanApproval=$false};Expected=$false}
)
foreach($Case in $RegressionCases){
    $Result=Test-DecisionContract -Decision $Case.Decision -Package $Package
    if($Result.Valid -ne $Case.Expected){throw "Regression failed: $($Case.Name). Errors: $($Result.Errors -join '; ')"}
    Write-Host ("[PASS] {0}" -f $Case.Name) -ForegroundColor Green
}

if($SkipLiveModel){Write-Host '[INFO] Live model test skipped.' -ForegroundColor Yellow;return}
Import-Module $ProviderPath -Force -ErrorAction Stop
Write-Host '=== Live synthetic Ollama decision ===' -ForegroundColor Cyan
$Decision=Invoke-MSADPTOllamaDecision -EvidencePackage $Package -PromptPath $PromptPath -OllamaUri $OllamaUri -Model $ModelName -TimeoutSec 300 -MaxOutputTokens 1400 -Temperature 0.0 -Verbose
$Validation=Test-DecisionContract -Decision $Decision -Package $Package
$Stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$Decision|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $OutputRoot "synthetic-decision-$Stamp.json") -Encoding UTF8
$Validation|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $OutputRoot "synthetic-validation-$Stamp.json") -Encoding UTF8
if(-not$Validation.Valid){throw "Live model decision was rejected: $($Validation.Errors -join '; ')"}
Write-Host ("Selected module: {0}" -f $Decision.recommendedModule) -ForegroundColor Cyan
Write-Host ("Reason: {0}" -f $Decision.reason)
Write-Host '[PASS] Live Ollama decision is registered, eligible, uncompleted, read-only, and evidence-backed.' -ForegroundColor Green
