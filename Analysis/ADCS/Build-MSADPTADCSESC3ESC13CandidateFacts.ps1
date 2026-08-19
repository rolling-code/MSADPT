<#
.SYNOPSIS
Builds candidate-specific ESC3 and ESC13 prerequisite records from preserved MSADPT ADCS evidence.
.DESCRIPTION
Consumes the unified candidate inventory and certificate-template configuration. ESC3 records model the
enrollment-agent template side and preserve CA enrollment-agent restrictions and target-template chaining
as inconclusive unless validated evidence is supplied. ESC13 records model issuance-policy OIDs and preserve
OID-object resolution, msDS-OIDToGroupLink, linked-group context, and effective enrollment as separate facts.
No AD, CA, LDAP, DNS, TCP, SMB, Kerberos, certificate, authentication, Ollama, or ledger activity occurs.
.NOTES
Version: 0.1.1
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$UnifiedCandidateInventoryPath,
    [Parameter(Mandatory=$true)][string]$TemplateConfigurationPath,
    [Parameter(Mandatory=$true)][string]$IdentityContextPath,
    [Parameter()][string]$Esc3RuntimeEvidencePath,
    [Parameter()][string]$Esc13OidEvidencePath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter()][string]$ConsoleModulePath,
    [switch]$Quiet
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$BuilderVersion='0.1.1'
$AgentEkuOid='1.3.6.1.4.1.311.20.2.1'
$AllowedStates=@('Confirmed','Not observed','Inconclusive','Not applicable')
foreach($Path in @($UnifiedCandidateInventoryPath,$TemplateConfigurationPath,$IdentityContextPath)){
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "RequiredEvidenceMissing: $Path"}
}
if(-not[string]::IsNullOrWhiteSpace($ConsoleModulePath)){Import-Module $ConsoleModulePath -Force -ErrorAction Stop}
function Write-ProgressEvent([string]$Message,[string]$Target){
    if(Get-Command Write-MSADPTConsoleEvent -ErrorAction SilentlyContinue){return Write-MSADPTConsoleEvent -Kind Action -Message $Message -Target $Target -Code 'ESC3ESC13Builder'}
    if(-not$Quiet){Write-Host "[....] ${Target}: $Message" -ForegroundColor Yellow}
}
function Read-JsonArray([string]$Path,[string]$Label){
    try{$Rows=@(Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop)}catch{throw "${Label}JsonParseFailure: $($_.Exception.Message)"}
    if($Rows.Count -eq 0){throw "${Label}Empty: $Path"};return $Rows
}
function New-Fact([string]$Id,[string]$State,[string]$Rationale,[string[]]$Sources,[string[]]$Limitations){
    if($State -notin $AllowedStates){throw "UnsupportedFactState [$Id]: $State"}
    [pscustomobject][ordered]@{id=$Id;state=$State;rationale=$Rationale;sourceEvidence=@($Sources);limitations=@($Limitations);builderVersion=$BuilderVersion}
}
function Get-Template($Rows,[string]$Name){return ($Rows|Where-Object{[string]$_.Name -eq $Name}|Select-Object -First 1)}
function Get-Context($Rows,[string]$Principal){return ($Rows|Where-Object{[string]$_.identityReference -eq $Principal}|Select-Object -First 1)}
function Get-SourceFact($Candidate,[string]$Id){return ($Candidate.facts|Where-Object{[string]$_.id -eq $Id}|Select-Object -First 1)}
function Get-Disposition($Facts,[string[]]$Required){
    $RequiredFacts=@($Facts|Where-Object{[string]$_.id -in $Required})
    if(@($RequiredFacts|Where-Object{[string]$_.state -eq 'Not observed'}).Count -gt 0){return 'Blocked'}
    if(@($RequiredFacts|Where-Object{[string]$_.state -in @('Inconclusive','Not applicable')}).Count -gt 0){return 'Incomplete evidence'}
    if(@($Required|Where-Object{$_ -notin @($RequiredFacts.id)}).Count -gt 0){return 'Incomplete evidence'}
    return 'Prerequisites satisfied'
}
$Candidates=@(Read-JsonArray $UnifiedCandidateInventoryPath 'UnifiedCandidateInventory')
$Templates=@(Read-JsonArray $TemplateConfigurationPath 'TemplateConfiguration')
$Contexts=@(Read-JsonArray $IdentityContextPath 'IdentityContext')
$Runtime=@();if(-not[string]::IsNullOrWhiteSpace($Esc3RuntimeEvidencePath)-and(Test-Path -LiteralPath $Esc3RuntimeEvidencePath -PathType Leaf)){$Runtime=@(Read-JsonArray $Esc3RuntimeEvidencePath 'Esc3RuntimeEvidence')}
$OidEvidence=@();if(-not[string]::IsNullOrWhiteSpace($Esc13OidEvidencePath)-and(Test-Path -LiteralPath $Esc13OidEvidencePath -PathType Leaf)){$OidEvidence=@(Read-JsonArray $Esc13OidEvidencePath 'Esc13OidEvidence')}
$SourceRoutes=@($Candidates|Where-Object{[string]$_.technique -eq 'ESC1'})
if($SourceRoutes.Count -eq 0){throw 'SourceEsc1RoutesEmpty'}
$Records=@();$Index=0
foreach($Route in $SourceRoutes){
    $Index++
    $Template=Get-Template $Templates ([string]$Route.template)
    if($null -eq $Template){continue}
    $Context=Get-Context $Contexts ([string]$Route.principal)
    if(-not$Quiet){$Percent=[math]::Round(($Index/$SourceRoutes.Count)*100,0);$null=Write-ProgressEvent "[$Index/$($SourceRoutes.Count) $Percent%] Building ESC3 and ESC13 route facts." "$($Route.template) | $($Route.principal)"}
    $Common=@()
    foreach($Id in @('enterpriseCaPresent','templatePublished','effectiveLowPrivilegeEnrollment','managerApprovalDisabled','authorizedSignaturesNotRequired','principalResolved')){
        $Fact=Get-SourceFact $Route $Id
        if($null-ne$Fact){$Common+=,$Fact}else{$Common+=,(New-Fact $Id 'Inconclusive' 'Source candidate did not contain this fact.' @($UnifiedCandidateInventoryPath) @())}
    }
    $IdentityCategory=if($null-ne$Context){[string]$Context.category}elseif($null-ne$Route.PSObject.Properties['identityCategory']){[string]$Route.identityCategory}else{'UnknownPrivilegeContext'}

    $Esc3Facts=@($Common)
    $HasAgentEku=@($Template.ExtendedKeyUsage)-contains$AgentEkuOid
    $Esc3Facts+=,(New-Fact 'certificateRequestAgentEku' $(if($HasAgentEku){'Confirmed'}else{'Not observed'}) 'Derived from the exact template EKU inventory.' @($TemplateConfigurationPath) @())
    $RuntimeMatch=@($Runtime|Where-Object{[string]$_.certificationAuthority -eq [string]$Route.certificationAuthority})
    foreach($Id in @('enrollmentAgentRestrictionsPermitRoute','targetTemplateChainResolved')){
        $Fact=@($RuntimeMatch|Where-Object{[string]$_.id -eq $Id}|Select-Object -First 1)
        if($Fact.Count -gt 0){$Esc3Facts+=,$Fact[0]}else{$Esc3Facts+=,(New-Fact $Id 'Inconclusive' 'No validated CA enrollment-agent restriction or target-template-chain evidence was supplied.' @($Esc3RuntimeEvidencePath) @('Collect deterministic CA runtime evidence before exposure conclusions.'))}
    }
    $Esc3Required=@('enterpriseCaPresent','templatePublished','effectiveLowPrivilegeEnrollment','certificateRequestAgentEku','managerApprovalDisabled','authorizedSignaturesNotRequired','enrollmentAgentRestrictionsPermitRoute','targetTemplateChainResolved')
    $Esc3Disposition=Get-Disposition $Esc3Facts $Esc3Required
    $Records+=,[pscustomobject][ordered]@{candidateId="ESC3|$($Route.certificationAuthority)|$($Route.template)|$($Route.principal)";technique='ESC3';certificationAuthority=$Route.certificationAuthority;template=$Route.template;principal=$Route.principal;identityCategory=$IdentityCategory;disposition=$Esc3Disposition;requiredCount=$Esc3Required.Count;satisfiedRequiredCount=@($Esc3Facts|Where-Object{[string]$_.id -in $Esc3Required -and [string]$_.state -eq 'Confirmed'}).Count;facts=@($Esc3Facts);safeFollowUp='Validate enrollment-agent restrictions and the exact target-template chain before any ESC3 conclusion.'}

    $Esc13Facts=@($Common)
    $IssuancePolicyProperty=$Template.PSObject.Properties['IssuancePolicyOids']
    if($null -eq $IssuancePolicyProperty){
        $PolicyOids=@()
        $IssuancePolicyState='Inconclusive'
        $IssuancePolicyRationale='The preserved template schema does not contain IssuancePolicyOids; presence or absence cannot be determined from this evidence.'
        $IssuancePolicyLimitations=@('A missing property is not equivalent to a confirmed empty issuance-policy list. Extend deterministic collection before an ESC13 conclusion.')
    }
    else{
        $PolicyOids=@($IssuancePolicyProperty.Value)
        $IssuancePolicyState=if($PolicyOids.Count -gt 0){'Confirmed'}else{'Not observed'}
        $IssuancePolicyRationale="Issuance-policy OID count: $($PolicyOids.Count)."
        $IssuancePolicyLimitations=@()
    }
    $Esc13Facts+=,(New-Fact 'issuancePolicyOidPresent' $IssuancePolicyState $IssuancePolicyRationale @($TemplateConfigurationPath) $IssuancePolicyLimitations)
    $OidMatches=@($OidEvidence|Where-Object{[string]$_.template -eq [string]$Route.template})
    foreach($Id in @('issuancePolicyOidObjectResolved','oidToGroupLinkPresent','linkedGroupResolved','linkedGroupPrivilegeContext','effectiveLinkedGroupEnrollmentRoute')){
        $Fact=@($OidMatches|Where-Object{[string]$_.id -eq $Id}|Select-Object -First 1)
        if($Fact.Count -gt 0){$Esc13Facts+=,$Fact[0]}else{$Esc13Facts+=,(New-Fact $Id 'Inconclusive' 'No validated OID object and linked-group evidence was supplied.' @($Esc13OidEvidencePath) @('Collect OID object, msDS-OIDToGroupLink, linked-group, and effective enrollment evidence.'))}
    }
    $Esc13Required=@('enterpriseCaPresent','templatePublished','effectiveLowPrivilegeEnrollment','issuancePolicyOidPresent','issuancePolicyOidObjectResolved','oidToGroupLinkPresent','linkedGroupResolved','linkedGroupPrivilegeContext','effectiveLinkedGroupEnrollmentRoute')
    $Esc13Disposition=Get-Disposition $Esc13Facts $Esc13Required
    $Records+=,[pscustomobject][ordered]@{candidateId="ESC13|$($Route.certificationAuthority)|$($Route.template)|$($Route.principal)";technique='ESC13';certificationAuthority=$Route.certificationAuthority;template=$Route.template;principal=$Route.principal;identityCategory=$IdentityCategory;disposition=$Esc13Disposition;requiredCount=$Esc13Required.Count;satisfiedRequiredCount=@($Esc13Facts|Where-Object{[string]$_.id -in $Esc13Required -and [string]$_.state -eq 'Confirmed'}).Count;facts=@($Esc13Facts);safeFollowUp='Resolve issuance-policy OID objects and linked groups before any ESC13 conclusion.'}
}
$DuplicateIds=@($Records|Group-Object candidateId|Where-Object{$_.Count -gt 1});if($DuplicateIds.Count -gt 0){throw "DuplicateCandidateIds: $($DuplicateIds.Count)"}
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$JsonPath=Join-Path $OutputDirectory 'adcs-esc3-esc13-candidates.json';$CsvPath=Join-Path $OutputDirectory 'adcs-esc3-esc13-candidate-summary.csv'
$Records|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $JsonPath -Encoding UTF8
$Records|Select-Object candidateId,technique,certificationAuthority,template,principal,identityCategory,disposition,requiredCount,satisfiedRequiredCount,@{N='MissingFactIds';E={@($_.facts|Where-Object{[string]$_.state -eq 'Inconclusive'}|ForEach-Object id)-join';'}},safeFollowUp|Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
[pscustomobject][ordered]@{status='Completed';builderVersion=$BuilderVersion;sourceRouteCount=$SourceRoutes.Count;candidateCount=$Records.Count;esc3Count=@($Records|Where-Object{[string]$_.technique -eq 'ESC3'}).Count;esc13Count=@($Records|Where-Object{[string]$_.technique -eq 'ESC13'}).Count;esc3AgentEkuRouteCount=@($Records|Where-Object{[string]$_.technique -eq 'ESC3' -and @($_.facts|Where-Object{[string]$_.id -eq 'certificateRequestAgentEku' -and [string]$_.state -eq 'Confirmed'}).Count -eq 1}).Count;esc13IssuancePolicyRouteCount=@($Records|Where-Object{[string]$_.technique -eq 'ESC13' -and @($_.facts|Where-Object{[string]$_.id -eq 'issuancePolicyOidPresent' -and [string]$_.state -eq 'Confirmed'}).Count -eq 1}).Count;outputPath=$JsonPath;summaryPath=$CsvPath}
