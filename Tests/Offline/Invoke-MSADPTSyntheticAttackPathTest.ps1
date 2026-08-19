<#
.SYNOPSIS
Validates synthetic MSADPT attack-path hypothesis generation with local Ollama.
.VERSION
1.0.0
#>
[CmdletBinding()]
param(
    [string]$ModelName='hf.co/unsloth/Qwen3.5-9B-GGUF:Q4_K_M',
    [string]$OllamaUri='http://localhost:11434'
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$MSADPTRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ProviderPath=Join-Path $MSADPTRoot 'Integrations\Ollama\MSADPT.Ollama.psm1'
$PromptPath=Join-Path $MSADPTRoot 'Promptbooks\MSADPT-Attack-Path-Hypothesis-v1.1.txt'
$SchemaPath=Join-Path $MSADPTRoot 'Schemas\attack-path-hypothesis.schema.json'
$Results=Join-Path $PSScriptRoot 'Results';New-Item -ItemType Directory -Path $Results -Force|Out-Null
Import-Module $ProviderPath -Force
$Package=[pscustomobject][ordered]@{
 packageVersion='2.3-synthetic';generatedUtc=(Get-Date).ToUniversalTime().ToString('o')
 entities=@(
  [pscustomobject]@{type='syntheticUser';identifier='analyst01@example.test'},
  [pscustomobject]@{type='syntheticGroup';identifier='Example Operators'},
  [pscustomobject]@{type='syntheticServer';identifier='server01.example.test'}
 )
 relationships=@(
  [pscustomobject]@{relationshipId='rel-001';from='analyst01@example.test';relationshipType='MemberOf';to='Example Operators';status='Confirmed';evidenceReferences=@('evidence/synthetic-group-membership.json');doesNotProve=@('Administrative control of server01.example.test');observedUtc=(Get-Date).ToUniversalTime().ToString('o')},
  [pscustomobject]@{relationshipId='rel-002';from='Example Operators';relationshipType='PotentialLocalAdminAssignment';to='server01.example.test';status='Inconclusive';evidenceReferences=@('evidence/synthetic-gpo-link.json');doesNotProve=@('GPO applicability','Successful logon','Credential possession');observedUtc=(Get-Date).ToUniversalTime().ToString('o')}
 )
 eligibleValidationModules=@(
  [pscustomobject]@{name='SyntheticGpoApplicabilityValidation';executionClass='read_only';produces=@('syntheticGpoApplicabilityEvidence');requiresHumanApproval=$false}
 )
 evidence=@('evidence/synthetic-group-membership.json','evidence/synthetic-gpo-link.json')
 constraints=@('Synthetic only','Read-only validation','No exploitation','No invented targets','Return the hypothesis object directly','Include every required hypothesis property')
 requiredOutputProperties=@('schemaVersion','hypothesisId','status','title','sourcePrincipal','targetAsset','relationships','confirmedPrerequisites','missingPrerequisites','evidenceReferences','limitations','shortestValidation','confidence','createdUtc')
 outputSchema='Schemas/attack-path-hypothesis.schema.json'
}
$Decision=Invoke-MSADPTOllamaDecision -EvidencePackage $Package -PromptPath $PromptPath -OllamaUri $OllamaUri -Model $ModelName -TimeoutSec 300 -MaxOutputTokens 2200 -Temperature 0.0 -Verbose
$Stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$Decision|ConvertTo-Json -Depth 40|Set-Content (Join-Path $Results "synthetic-hypothesis-raw-$Stamp.json") -Encoding UTF8
$Errors=New-Object 'System.Collections.Generic.List[string]'
$Required=@('schemaVersion','hypothesisId','status','title','sourcePrincipal','targetAsset','relationships','confirmedPrerequisites','missingPrerequisites','evidenceReferences','limitations','shortestValidation','confidence','createdUtc')
foreach($Name in $Required){if($Decision.PSObject.Properties.Name-notcontains$Name){$Errors.Add("Missing property: $Name")}}
if($Errors.Count-eq0){
 if(@('Confirmed','Likely or probable','Inconclusive','Not detected','Not applicable')-notcontains[string]$Decision.status){$Errors.Add('Invalid status.')}
 if([string]$Decision.shortestValidation.module-ne'SyntheticGpoApplicabilityValidation'){$Errors.Add('Unregistered or ineligible validation module.')}
 if([string]$Decision.shortestValidation.executionClass-ne'read_only'){$Errors.Add('Validation is not read_only.')}
 if([bool]$Decision.shortestValidation.requiresHumanApproval){$Errors.Add('Synthetic read-only validation unexpectedly requires human approval.')}
 $PackageText=$Package|ConvertTo-Json -Depth 30 -Compress
 foreach($Ref in @($Decision.evidenceReferences)){if($PackageText-notmatch[regex]::Escape([string]$Ref)){$Errors.Add("Invented evidence reference: $Ref")}}
 foreach($Rel in @($Decision.relationships)){foreach($Ref in @($Rel.evidenceReferences)){if($PackageText-notmatch[regex]::Escape([string]$Ref)){$Errors.Add("Relationship uses invented evidence: $Ref")}}}
}
$SchemaSupported=$false;$SchemaValid=$null
if(Get-Command Test-Json -ErrorAction SilentlyContinue){$SchemaSupported=$true;try{$SchemaValid=($Decision|ConvertTo-Json -Depth 40|Test-Json -SchemaFile $SchemaPath -ErrorAction Stop)}catch{$SchemaValid=$false;$Errors.Add("JSON Schema rejection: $($_.Exception.Message)")}}
$Decision|ConvertTo-Json -Depth 40|Set-Content (Join-Path $Results "synthetic-hypothesis-$Stamp.json") -Encoding UTF8
[pscustomobject]@{Valid=($Errors.Count-eq0);Errors=$Errors.ToArray();SchemaSupported=$SchemaSupported;SchemaValid=$SchemaValid}|ConvertTo-Json -Depth 10|Set-Content (Join-Path $Results "synthetic-hypothesis-validation-$Stamp.json") -Encoding UTF8
if($Errors.Count-gt0){throw "Hypothesis rejected: $($Errors-join'; ')"}
Write-Host ("Status: {0}" -f $Decision.status) -ForegroundColor Cyan
Write-Host ("Title: {0}" -f $Decision.title)
Write-Host ("Shortest validation: {0}" -f $Decision.shortestValidation.module)
Write-Host '[PASS] Synthetic attack-path hypothesis is evidence-backed and policy-compatible.' -ForegroundColor Green
