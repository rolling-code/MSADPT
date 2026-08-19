<# .VERSION 0.4.1 #>
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Import-MSADPTJson { param([Parameter(Mandatory=$true)][string]$Path) Get-Content -LiteralPath $Path -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop }
function Export-MSADPTJson {
 param([Parameter(Mandatory=$true)]$InputObject,[Parameter(Mandatory=$true)][string]$Path,[int]$Depth=50)
 $parent=Split-Path -Parent $Path
 if(-not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent -Force|Out-Null}
 $tempPath=Join-Path $parent ('.'+[IO.Path]::GetFileName($Path)+'.'+[guid]::NewGuid().ToString('N')+'.tmp')
 try{
  $InputObject|ConvertTo-Json -Depth $Depth|Set-Content -LiteralPath $tempPath -Encoding UTF8
  Move-Item -LiteralPath $tempPath -Destination $Path -Force
 }finally{
  if(Test-Path -LiteralPath $tempPath){Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue}
 }
}
function Get-Property { param($Object,[string]$Name) if($null-eq$Object){return $null};$p=$Object.PSObject.Properties|Where-Object Name -eq $Name|Select-Object -First 1;if($p){,$p.Value}else{$null} }
function Test-PropertyExists { param($Object,[string]$Name) if($null-eq$Object){return $false};return ($null-ne($Object.PSObject.Properties|Where-Object Name -eq $Name|Select-Object -First 1)) }
function Get-MSADPTLatestEngagement { [CmdletBinding()]param([string]$MSADPTRoot) $e=Get-ChildItem -LiteralPath (Join-Path $MSADPTRoot 'Engagements') -Directory|Sort-Object LastWriteTime -Descending|Select-Object -First 1;if(-not$e){throw 'No engagement found.'};$e }

function Get-MSADPTModuleRegistry {
 [CmdletBinding()]param([string]$MSADPTRoot)
 $items=New-Object 'System.Collections.Generic.List[object]'
 foreach($f in @(Get-ChildItem -LiteralPath (Join-Path $MSADPTRoot 'Modules') -Filter '*.module.json' -File -Recurse)){
  $d=Import-MSADPTJson $f.FullName
  if([string]::IsNullOrWhiteSpace([string]$d.name)){throw "Manifest has no name: $($f.FullName)"}
  $items.Add([pscustomobject]@{ManifestPath=$f.FullName;Definition=$d})
 }
 $items.ToArray()
}

function ConvertTo-MSADPTVersion { param([string]$Value) try { return [version]$Value } catch { return [version]'0.0.0' } }
function Get-MSADPTManifestModuleVersion { param($Definition) if($Definition.PSObject.Properties.Name -contains 'moduleVersion'){return [string]$Definition.moduleVersion};return '0.0.0' }
function Get-MSADPTLegacyModuleVersion { param([string]$Module,$Result) if($null-ne$Result -and $Result.PSObject.Properties.Name -contains 'moduleVersion'){return [string]$Result.moduleVersion};if($Module-eq'ADCSConfigurationCollection'){return '0.1.0'};if($Module-eq'DomainControllerEnumeration'){return '0.1.0'};return '0.0.0' }
function Get-MSADPTLedgerPath { param([string]$EngagementPath) Join-Path $EngagementPath 'state\module-execution-ledger.json' }
function Get-MSADPTLedger {
 param([string]$EngagementPath)
 $path=Get-MSADPTLedgerPath $EngagementPath
 if(Test-Path -LiteralPath $path){ return @(Import-MSADPTJson $path) }
 @()
}
function Save-MSADPTLedger { param([string]$EngagementPath,[object[]]$Ledger) Export-MSADPTJson -InputObject @($Ledger) -Path (Get-MSADPTLedgerPath $EngagementPath) }

function Add-MSADPTLedgerProperty {
 param($Entry,[string]$Name,$Value)
 if($Entry.PSObject.Properties.Name-notcontains$Name){$Entry|Add-Member -MemberType NoteProperty -Name $Name -Value $Value}
}
function Normalize-MSADPTLedgerEntry {
 param($Entry)
 Add-MSADPTLedgerProperty $Entry 'ledgerId' ('ledger-'+[guid]::NewGuid().ToString('N'))
 Add-MSADPTLedgerProperty $Entry 'ledgerVersion' '1.1'
 Add-MSADPTLedgerProperty $Entry 'moduleVersion' (Get-MSADPTLegacyModuleVersion -Module ([string]$Entry.module) -Result $null)
 Add-MSADPTLedgerProperty $Entry 'superseded' $false
 Add-MSADPTLedgerProperty $Entry 'supersededBy' $null
 Add-MSADPTLedgerProperty $Entry 'refreshReason' $null
 Add-MSADPTLedgerProperty $Entry 'sourceResult' $null
 $Entry
}
function Get-MSADPTResultFingerprint {
 param([string]$ResultPath)
 $name=[IO.Path]::GetFileNameWithoutExtension($ResultPath)
 $stamp=$name -replace '^module-result-',''
 $packagePath=Join-Path (Split-Path -Parent $ResultPath) ("evidence-package-$stamp.json")
 if(Test-Path -LiteralPath $packagePath){return (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash}
 return $null
}
function Resolve-MSADPTLedgerSupersession {
 param([object[]]$Ledger)
 foreach($moduleName in @($Ledger|Where-Object{[string]$_.status-eq'Completed'}|ForEach-Object{[string]$_.module}|Sort-Object -Unique)){
  $active=@($Ledger|Where-Object{[string]$_.module-eq$moduleName -and [string]$_.status-eq'Completed' -and -not[bool]$_.superseded}|Sort-Object @{Expression={ConvertTo-MSADPTVersion ([string]$_.moduleVersion)};Descending=$true},@{Expression={[string]$_.completedUtc};Descending=$true})
  if($active.Count-le1){continue}
  $winner=$active[0]
  foreach($oldEntry in @($active|Select-Object -Skip 1)){
   $oldEntry.superseded=$true
   $oldEntry.supersededBy=[string]$winner.ledgerId
   if((ConvertTo-MSADPTVersion ([string]$oldEntry.moduleVersion))-lt(ConvertTo-MSADPTVersion ([string]$winner.moduleVersion))){
    $oldEntry.refreshReason="Collector upgraded from $($oldEntry.moduleVersion) to $($winner.moduleVersion)"
   }else{
    $oldEntry.refreshReason="Duplicate completed result reconciled to ledger entry $($winner.ledgerId)"
   }
  }
 }
 @($Ledger)
}
function Initialize-MSADPTLedger {
 [CmdletBinding()]param([string]$EngagementPath,[object[]]$Registry)
 $ledger=@(Get-MSADPTLedger $EngagementPath)
 foreach($entry in $ledger){Normalize-MSADPTLedgerEntry $entry|Out-Null}
 $resultFiles=@(Get-ChildItem -LiteralPath (Join-Path $EngagementPath 'reasoning') -Filter 'module-result-*.json' -File -ErrorAction SilentlyContinue|Sort-Object LastWriteTime)
 foreach($r in $Registry){
  $name=[string]$r.Definition.name
  foreach($resultFile in $resultFiles){
   try{$result=Import-MSADPTJson $resultFile.FullName}catch{continue}
   if([string]$result.module-ne$name -or [string]$result.status-ne'Completed'){continue}
   $version=Get-MSADPTLegacyModuleVersion -Module $name -Result $result
   $exists=@($ledger|Where-Object{[string]$_.module-eq$name -and [string]$_.moduleVersion-eq$version -and [string]$_.sourceResult-eq$resultFile.FullName}).Count-gt0
   if($exists){continue}
   $ledger+=[pscustomobject][ordered]@{ledgerId=('ledger-'+[guid]::NewGuid().ToString('N'));ledgerVersion='1.1';module=$name;moduleVersion=$version;targetKey='engagement';status='Completed';executionClass=[string]$result.executionClass;completedUtc=[string]$result.completedUtc;evidence=@($result.evidence);limitations=@($result.limitations);inputFingerprint=(Get-MSADPTResultFingerprint $resultFile.FullName);migrated=$true;sourceResult=$resultFile.FullName;superseded=$false;supersededBy=$null;refreshReason=$null}
  }
 }
 $ledger=@(Resolve-MSADPTLedgerSupersession $ledger)
 Save-MSADPTLedger -EngagementPath $EngagementPath -Ledger $ledger
 @($ledger)
}
function Get-MSADPTEvidenceIndex {
 [CmdletBinding()]param([string]$EngagementPath)
 $root=Join-Path $EngagementPath 'evidence';$index=New-Object 'System.Collections.Generic.List[object]'
 foreach($f in @(Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue)){
  $rel=$f.FullName.Substring($EngagementPath.Length).TrimStart('\','/') -replace '\\','/'
  $row=[ordered]@{path=$rel;name=$f.Name;sha256=(Get-FileHash $f.FullName -Algorithm SHA256).Hash;length=$f.Length;lastWriteUtc=$f.LastWriteTimeUtc.ToString('o')}
  if($f.Extension -eq '.json' -and $f.Length -le 2097152){try{$row.content=Import-MSADPTJson $f.FullName}catch{$row.parseError=$_.Exception.Message}}
  $index.Add([pscustomobject]$row)
 }
 $index.ToArray()
}

function Get-MSADPTCapabilities {
 param([object[]]$Evidence,[object[]]$Ledger)
 $caps=New-Object 'System.Collections.Generic.List[string]'
 $names=@($Evidence.name)
 if($names -contains 'domain-controllers.json'){$caps.Add('domainControllerDiscovery')}
 if($names -contains 'enterprise-cas.json'){$caps.Add('enterpriseCAObjectPresence')}
 foreach($l in @($Ledger|Where-Object status -eq 'Completed')){
  switch([string]$l.module){'DomainControllerEnumeration'{$caps.Add('domainControllerDirectoryMetadata')};'ADCSConfigurationCollection'{$caps.Add('certificateTemplateConfiguration');$caps.Add('certificateTemplateAclEvidence')}}
 }
 @($caps|Sort-Object -Unique)
}

function Get-MSADPTEligibleRegistry {
 param([object[]]$Registry,[string[]]$Capabilities,[object[]]$Ledger)
 $eligible=New-Object 'System.Collections.Generic.List[object]'
 foreach($r in $Registry){
  $d=$r.Definition;$requirements=@($d.requires);$missing=@($requirements|Where-Object{$Capabilities-notcontains[string]$_})
  if($missing.Count-gt0){continue}
  $installed=ConvertTo-MSADPTVersion (Get-MSADPTManifestModuleVersion $d)
  $completed=@($Ledger|Where-Object{[string]$_.module-eq[string]$d.name -and [string]$_.status-eq'Completed' -and -not[bool]$_.superseded}|Sort-Object{ConvertTo-MSADPTVersion ([string]$_.moduleVersion)} -Descending|Select-Object -First 1)
  if($completed.Count-eq0){$eligible.Add($r);continue}
  $completedVersion=ConvertTo-MSADPTVersion ([string]$completed[0].moduleVersion)
  if($installed-gt$completedVersion){$eligible.Add($r)}
 }
 $eligible.ToArray()
}
function New-MSADPTEvidencePackage {
 [CmdletBinding()]param([string]$MSADPTRoot,[string]$EngagementPath,[object[]]$Registry,[object[]]$Ledger)
 $evidence=@(Get-MSADPTEvidenceIndex $EngagementPath);$caps=@(Get-MSADPTCapabilities -Evidence $evidence -Ledger $Ledger)
 $eligible=@(Get-MSADPTEligibleRegistry -Registry $Registry -Capabilities $caps -Ledger $Ledger)
 [pscustomobject][ordered]@{
  packageVersion='2.1';generatedUtc=(Get-Date).ToUniversalTime().ToString('o');engagementPath=$EngagementPath
  engagementState=Import-MSADPTJson (Join-Path $EngagementPath 'state\engagement-state.json')
  evidence=$evidence;capabilities=$caps;executionLedger=@($Ledger);eligibleModules=@($eligible|ForEach-Object{$_.Definition})
  constraints=@('Select exactly one eligible module or Stop','Never repeat a completed module','Use only evidence-backed target identifiers','Return JSON only','Do not emit code or commands','Read-only collection only')
 }
}

function Test-MSADPTJsonSchema {
 param($Decision,[string]$SchemaPath)
 $cmd=Get-Command Test-Json -ErrorAction SilentlyContinue
 if($cmd){
  try{ $valid=($Decision|ConvertTo-Json -Depth 30|Test-Json -SchemaFile $SchemaPath -ErrorAction Stop);return [pscustomobject]@{Supported=$true;Valid=[bool]$valid;Error=$null} }
  catch{return [pscustomobject]@{Supported=$true;Valid=$false;Error=$_.Exception.Message}}
 }
 [pscustomobject]@{Supported=$false;Valid=$null;Error='Test-Json is unavailable; explicit contract validation was used.'}
}

function Test-MSADPTDecision {
 [CmdletBinding()]param($Decision,[object[]]$EligibleRegistry,$Policy,$Package,[string]$SchemaPath)
 $errors=New-Object 'System.Collections.Generic.List[string]'
 foreach($p in @('schemaVersion','decision','recommendedModule','targetSelector','reason','evidenceUsed','expectedEvidence','confidence','executionClass','requiresHumanApproval')){if(-not(Test-PropertyExists $Decision $p)){$errors.Add("Missing property: $p")}}
 $schema=Test-MSADPTJsonSchema -Decision $Decision -SchemaPath $SchemaPath;if($schema.Supported-and-not$schema.Valid){$errors.Add("JSON Schema validation failed: $($schema.Error)")}
 $choice=[string]$Decision.decision;$module=$null
 if(@('collect_more_evidence','stop')-notcontains$choice){$errors.Add("Unsupported decision: $choice")}
 if($choice-eq'collect_more_evidence'){
  $module=$EligibleRegistry|Where-Object{[string]$_.Definition.name-eq[string]$Decision.recommendedModule}|Select-Object -First 1
  if(-not$module){$errors.Add("Module is not currently eligible: $($Decision.recommendedModule)")}
  if([string]$Decision.executionClass-ne'read_only'){$errors.Add('Only read_only decisions are allowed.')}
  if([bool]$Decision.requiresHumanApproval){$errors.Add('Autonomous Milestone 2.1 decisions cannot require human approval.')}
  $ids=@($Decision.targetSelector.identifiers);$searchText=$Package|ConvertTo-Json -Depth 60 -Compress
  foreach($id in $ids){if([string]::IsNullOrWhiteSpace([string]$id)-or$searchText-notmatch[regex]::Escape([string]$id)){$errors.Add("Target identifier is not evidence-backed: $id")}}
 }
 [pscustomobject]@{Valid=($errors.Count-eq0);Errors=$errors.ToArray();Module=$module;SchemaValidation=$schema}
}

function Invoke-MSADPTRegisteredModule {
 param($RegistryEntry,[string]$MSADPTRoot,[string]$EngagementPath,[PSCredential]$Credential)
 $entry=Join-Path $MSADPTRoot ([string]$RegistryEntry.Definition.entryPoint);if(-not(Test-Path $entry)){throw "Entry point missing: $entry"}
 $p=@{EngagementPath=$EngagementPath};if($null-ne$Credential){$p.Credential=$Credential};& $entry @p
}

function Invoke-MSADPTReasoningCycle {
 [CmdletBinding()]param([string]$MSADPTRoot,[string]$EngagementPath,[ValidateSet('Ollama','Deterministic')][string]$Provider,[string]$OllamaUri='http://localhost:11434',[string]$Model='qwen3.5:9b',[PSCredential]$Credential,[switch]$DryRun)
 if([string]::IsNullOrWhiteSpace($EngagementPath)){$EngagementPath=(Get-MSADPTLatestEngagement $MSADPTRoot).FullName}
 $registry=@(Get-MSADPTModuleRegistry $MSADPTRoot);$ledger=@(Initialize-MSADPTLedger -EngagementPath $EngagementPath -Registry $registry)
 $package=New-MSADPTEvidencePackage -MSADPTRoot $MSADPTRoot -EngagementPath $EngagementPath -Registry $registry -Ledger $ledger
 $eligible=@($registry|Where-Object{$n=[string]$_.Definition.name;@($package.eligibleModules|Where-Object name -eq $n).Count-gt0})
 $dir=Join-Path $EngagementPath 'reasoning';New-Item -ItemType Directory -Path $dir -Force|Out-Null;$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
 $packagePath=Join-Path $dir "evidence-package-$stamp.json";Export-MSADPTJson $package $packagePath 60
 if($eligible.Count-eq0){$decision=[pscustomobject][ordered]@{schemaVersion='1.0';decision='stop';recommendedModule='Stop';targetSelector=[pscustomobject]@{type='engagement';identifiers=@([string]$package.engagementState.RunId)};reason='No prerequisite-satisfied uncompleted registered module remains.';evidenceUsed=@('state/module-execution-ledger.json');expectedEvidence=@();confidence='high';executionClass='read_only';requiresHumanApproval=$false}}
 elseif($Provider-eq'Deterministic'){
  $pick=$eligible|Sort-Object{switch([string]$_.Definition.name){'DomainControllerEnumeration'{1};'ADCSConfigurationCollection'{2};default{99}}}|Select-Object -First 1
  $decision=[pscustomobject][ordered]@{schemaVersion='1.0';decision='collect_more_evidence';recommendedModule=[string]$pick.Definition.name;targetSelector=[pscustomobject]@{type='engagement';identifiers=@([string]$package.engagementState.RunId)};reason='Stateful deterministic provider selected the next eligible uncompleted read-only module.';evidenceUsed=@('state/module-execution-ledger.json');expectedEvidence=@($pick.Definition.produces);confidence='high';executionClass='read_only';requiresHumanApproval=$false}
 }else{
  $tags=Invoke-RestMethod -Uri ($OllamaUri.TrimEnd('/')+'/api/tags') -TimeoutSec 10 -ErrorAction Stop
  if(@($tags.models.name)-notcontains$Model){throw "Ollama model is not installed: $Model"}
  Import-Module (Join-Path $MSADPTRoot 'Integrations\Ollama\MSADPT.Ollama.psm1') -Force
  $decision=Invoke-MSADPTOllamaDecision -EvidencePackage $package -PromptPath (Join-Path $MSADPTRoot 'Promptbooks\MSADPT-Decision-Engine-v1.1.txt') -OllamaUri $OllamaUri -Model $Model
 }
 $decisionPath=Join-Path $dir "ai-decision-$stamp.json";Export-MSADPTJson $decision $decisionPath
 $validation=Test-MSADPTDecision -Decision $decision -EligibleRegistry $eligible -Policy (Import-MSADPTJson (Join-Path $MSADPTRoot 'Policies\msadpt-policy.json')) -Package $package -SchemaPath (Join-Path $MSADPTRoot 'Schemas\ai-decision.schema.json')
 Export-MSADPTJson $validation (Join-Path $dir "decision-validation-$stamp.json") 30
 if(-not$validation.Valid){throw "Decision rejected: $($validation.Errors-join'; ')"}
 if($decision.decision-eq'stop'){return [pscustomobject]@{Status='Stopped';Decision=$decision;LedgerPath=Get-MSADPTLedgerPath $EngagementPath}}
 if($DryRun){return [pscustomobject]@{Status='ValidatedDryRun';Decision=$decision;EligibleModules=@($eligible.Definition.name);LedgerPath=Get-MSADPTLedgerPath $EngagementPath}}
 $result=Invoke-MSADPTRegisteredModule -RegistryEntry $validation.Module -MSADPTRoot $MSADPTRoot -EngagementPath $EngagementPath -Credential $Credential
 $resultPath=Join-Path $dir "module-result-$stamp.json";Export-MSADPTJson $result $resultPath
 $ledger=@(Get-MSADPTLedger $EngagementPath);foreach($entry in $ledger){Normalize-MSADPTLedgerEntry $entry|Out-Null};$newLedgerId='ledger-'+[guid]::NewGuid().ToString('N');$newVersion=if($result.PSObject.Properties.Name-contains'moduleVersion'){[string]$result.moduleVersion}else{Get-MSADPTManifestModuleVersion $validation.Module.Definition};foreach($oldEntry in @($ledger|Where-Object{[string]$_.module-eq[string]$result.module -and [string]$_.status-eq'Completed' -and -not[bool]$_.superseded})){if((ConvertTo-MSADPTVersion ([string]$oldEntry.moduleVersion))-lt(ConvertTo-MSADPTVersion $newVersion)){$oldEntry.superseded=$true;$oldEntry.supersededBy=$newLedgerId;$oldEntry.refreshReason="Collector upgraded from $($oldEntry.moduleVersion) to $newVersion"}};$ledger += [pscustomobject][ordered]@{ledgerId=$newLedgerId;ledgerVersion='1.1';module=[string]$result.module;moduleVersion=$newVersion;targetKey='engagement';status=[string]$result.status;executionClass=[string]$result.executionClass;completedUtc=[string]$result.completedUtc;evidence=@($result.evidence);limitations=@($result.limitations);inputFingerprint=(Get-FileHash $packagePath -Algorithm SHA256).Hash;migrated=$false;sourceResult=$resultPath;superseded=$false;supersededBy=$null;refreshReason=$null};Save-MSADPTLedger $EngagementPath $ledger
 [pscustomobject]@{Status='Completed';Decision=$decision;ModuleResult=$result;LedgerPath=Get-MSADPTLedgerPath $EngagementPath;ResultPath=$resultPath}
}
Export-ModuleMember -Function Invoke-MSADPTReasoningCycle,Get-MSADPTModuleRegistry,Get-MSADPTEvidenceIndex,Initialize-MSADPTLedger,Get-MSADPTEligibleRegistry
