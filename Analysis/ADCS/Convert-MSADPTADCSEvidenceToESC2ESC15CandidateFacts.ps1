<#
.SYNOPSIS
Builds candidate-specific ESC2 and ESC15 prerequisite records from preserved ADCS evidence.
.DESCRIPTION
Consumes candidate-specific ESC1/ESC4 routes as the authoritative CA-template-principal route inventory,
then derives isolated ESC2 and ESC15 candidates from their embedded template and principal facts.
The output is conservative: unavailable application-policy, patch, and policy-module evidence remains
Inconclusive. No AD, CA, LDAP, network, certificate, authentication, or state-changing operation occurs.
.NOTES
Version: 0.1.2
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CandidateFactsPath,
    [Parameter(Mandatory=$true)][string]$TemplateConfigurationPath,
    [Parameter(Mandatory=$true)][string]$IdentityContextPath,
    [Parameter()][string]$Esc15RuntimeEvidencePath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter()][string]$ConsoleModulePath,
    [switch]$Quiet,
    [switch]$NoColor
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$BuilderVersion='0.1.2'
$AllowedStates=@('Confirmed','Not observed','Inconclusive','Not applicable')

foreach($Path in @($CandidateFactsPath,$TemplateConfigurationPath,$IdentityContextPath)){
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "Required evidence not found: $Path"}
}
if($ConsoleModulePath){Import-Module $ConsoleModulePath -Force -ErrorAction Stop}
function Write-Event([string]$Kind,[string]$Message,[string]$Target){
    if(Get-Command Write-MSADPTConsoleEvent -ErrorAction SilentlyContinue){
        return Write-MSADPTConsoleEvent -Kind $Kind -Message $Message -Target $Target -Code 'ESC2ESC15CandidateAction'
    }
    if(-not $Quiet){$Color=if ($Kind -eq 'Success'){'Green'}elseif ($Kind -eq 'Warning'){'DarkYellow'}else{'Yellow'};Write-Host "[$Kind] ${Target}: $Message" -ForegroundColor $Color}
}
function New-Fact([string]$Id,[string]$State,[string]$Rationale,[string[]]$Sources,[string[]]$Limitations){
    if ($State -notin $AllowedStates){throw "Unsupported fact state for ${Id}: $State"}
    [pscustomobject][ordered]@{id=$Id;state=$State;rationale=$Rationale;sourceEvidence=@($Sources);limitations=@($Limitations);builderVersion=$BuilderVersion}
}
function Get-One($Rows,[string]$Property,[string]$Value){return ($Rows|Where-Object { [string]$_.$Property -eq $Value }|Select-Object -First 1)}
function Get-Fact($Candidate,[string]$Id){return ($Candidate.facts|Where-Object { [string]$_.id -eq $Id }|Select-Object -First 1)}
function Get-Disposition($Facts,[string[]]$Required){
    $RequiredFacts=@($Facts|Where-Object { [string]$_.id -in $Required })
    $Missing=@($Required|Where-Object { $_ -notin @($RequiredFacts.id) })
    $NotObserved=@($RequiredFacts|Where-Object { [string]$_.state -eq 'Not observed' })
    $Inconclusive=@($RequiredFacts|Where-Object { [string]$_.state -in @('Inconclusive','Not applicable') })
    if ($NotObserved.Count -gt 0){'Blocked'}elseif ($Missing.Count -gt 0 -or $Inconclusive.Count -gt 0){'Incomplete evidence'}else{'Prerequisites satisfied'}
}

$SourceCandidates=@(Get-Content -LiteralPath $CandidateFactsPath -Raw|ConvertFrom-Json)
$Templates=@(Get-Content -LiteralPath $TemplateConfigurationPath -Raw|ConvertFrom-Json)
$Contexts=@(Get-Content -LiteralPath $IdentityContextPath -Raw|ConvertFrom-Json)
$Runtime=@()
if ($Esc15RuntimeEvidencePath -and (Test-Path -LiteralPath $Esc15RuntimeEvidencePath -PathType Leaf)) { $Runtime=@(Get-Content -LiteralPath $Esc15RuntimeEvidencePath -Raw|ConvertFrom-Json)}
$Routes=@($SourceCandidates|Where-Object { [string]$_.technique -eq 'ESC1' })
$Records=@()
$Index=0
foreach($Route in $Routes){
    $Index++
    $TemplateArray=@(Get-One $Templates 'Name' ([string]$Route.template));if ($TemplateArray.Count -eq 0){continue};$Template=$TemplateArray[0]
    $ContextArray=@(Get-One $Contexts 'identityReference' ([string]$Route.principal));$Context=if($ContextArray.Count){$ContextArray[0]}else{$null}
    if(-not$Quiet){$Percent=[math]::Round(($Index/$Routes.Count)*100,0);$null=Write-Event 'Action' "[$Index/$($Routes.Count) $Percent%] Building ESC2 and ESC15 route facts." "$($Route.template) | $($Route.principal)"}
    $Common=@()
    foreach($Id in @('enterpriseCaPresent','templatePublished','effectiveLowPrivilegeEnrollment','managerApprovalDisabled','authorizedSignaturesNotRequired','principalResolved')){
        $Existing=@(Get-Fact $Route $Id)
        if($Existing.Count){$Common+=,$Existing[0]}else{$Common+=,(New-Fact $Id 'Inconclusive' 'The prerequisite was not present in the source candidate.' @($CandidateFactsPath) @())}
    }
    $AnyPurpose=@($Template.ExtendedKeyUsage)-contains'2.5.29.37.0'
    $NoRestriction=[bool]$Template.NoExtendedKeyUsageRestriction
    $Esc2Facts=@($Common)
    $Esc2Facts+=,(New-Fact 'anyPurposeOrNoEkuRestriction' $(if ($AnyPurpose -or $NoRestriction){'Confirmed'}else{'Not observed'}) 'Derived from the exact template EKU evidence.' @($TemplateConfigurationPath) @('Certificate usability and trust remain separate evidence.'))
    $Esc2Required=@('enterpriseCaPresent','templatePublished','effectiveLowPrivilegeEnrollment','anyPurposeOrNoEkuRestriction','managerApprovalDisabled','authorizedSignaturesNotRequired')
    $Esc2Disposition=Get-Disposition @($Esc2Facts) $Esc2Required
    $Records+=,[pscustomobject][ordered]@{candidateId="ESC2|$($Route.certificationAuthority)|$($Route.template)|$($Route.principal)";technique='ESC2';certificationAuthority=$Route.certificationAuthority;template=$Route.template;principal=$Route.principal;identityCategory=if($Context){$Context.category}else{'UnknownPrivilegeContext'};disposition=$Esc2Disposition;requiredCount=$Esc2Required.Count;satisfiedRequiredCount=@($Esc2Facts|Where-Object { [string]$_.id -in $Esc2Required -and [string]$_.state -eq 'Confirmed' }).Count;facts=@($Esc2Facts);safeFollowUp='Validate the exact enrollment route and intended certificate use. Do not infer domain escalation from Any Purpose or no-EKU evidence alone.'}

    $Esc15Facts=@($Common)
    $Esc15Facts+=,(New-Fact 'affectedVersionOneTemplate' $(if ([int]$Template.SchemaVersion -eq 1){'Confirmed'}else{'Not observed'}) "Template schema version: $($Template.SchemaVersion)." @($TemplateConfigurationPath) @())
    $Esc15Facts+=,(New-Fact 'requesterControlsCertificateIdentity' $(if ([bool]$Template.EnrolleeSuppliesSubject -or [bool]$Template.EnrolleeSuppliesSubjectAltName){'Confirmed'}else{'Not observed'}) 'Derived from certificate-name flags.' @($TemplateConfigurationPath) @())
    $RuntimeMatch=@($Runtime|Where-Object { [string]$_.certificationAuthority -eq [string]$Route.certificationAuthority })
    foreach($Id in @('applicationPolicyRequestHandling','relevantPatchState','policyModuleRestriction')){
        $Match=@($RuntimeMatch|Where-Object { [string]$_.id -eq $Id }|Select-Object -First 1)
        if($Match.Count){$Esc15Facts+=,$Match[0]}else{$Esc15Facts+=,(New-Fact $Id 'Inconclusive' 'No validated runtime or patch evidence was supplied.' @($Esc15RuntimeEvidencePath) @('Remain inconclusive until deterministic CA and patch evidence is collected.'))}
    }
    $Esc15Required=@('enterpriseCaPresent','templatePublished','affectedVersionOneTemplate','requesterControlsCertificateIdentity','effectiveLowPrivilegeEnrollment','applicationPolicyRequestHandling','relevantPatchState','policyModuleRestriction')
    $Esc15Disposition=Get-Disposition @($Esc15Facts) $Esc15Required
    $Records+=,[pscustomobject][ordered]@{candidateId="ESC15|$($Route.certificationAuthority)|$($Route.template)|$($Route.principal)";technique='ESC15';certificationAuthority=$Route.certificationAuthority;template=$Route.template;principal=$Route.principal;identityCategory=if($Context){$Context.category}else{'UnknownPrivilegeContext'};disposition=$Esc15Disposition;requiredCount=$Esc15Required.Count;satisfiedRequiredCount=@($Esc15Facts|Where-Object { [string]$_.id -in $Esc15Required -and [string]$_.state -eq 'Confirmed' }).Count;facts=@($Esc15Facts);safeFollowUp='Collect application-policy handling, patch state, and policy-module restriction evidence before any exposure conclusion.'}
}
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$JsonPath=Join-Path $OutputDirectory 'adcs-esc2-esc15-candidates.json';$CsvPath=Join-Path $OutputDirectory 'adcs-esc2-esc15-candidate-summary.csv'
@($Records)|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $JsonPath -Encoding UTF8
@($Records)|Select-Object candidateId,technique,certificationAuthority,template,principal,identityCategory,disposition,requiredCount,satisfiedRequiredCount,@{N='MissingFactIds';E={@($_.facts|Where-Object { [string]$_.state -eq 'Inconclusive' }|ForEach-Object id)-join';'}},safeFollowUp|Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
$null=Write-Event 'Success' "Generated $($Records.Count) ESC2 and ESC15 candidate records." 'Candidate builder'
[pscustomobject][ordered]@{
    status = 'Completed'
    builderVersion = $BuilderVersion
    candidateCount = $Records.Count
    esc2Count = @($Records | Where-Object { [string]$_.technique -eq 'ESC2' }).Count
    esc15Count = @($Records | Where-Object { [string]$_.technique -eq 'ESC15' }).Count
    prerequisitesSatisfiedCount = @($Records | Where-Object { [string]$_.disposition -eq 'Prerequisites satisfied' }).Count
    blockedCount = @($Records | Where-Object { [string]$_.disposition -eq 'Blocked' }).Count
    incompleteEvidenceCount = @($Records | Where-Object { [string]$_.disposition -eq 'Incomplete evidence' }).Count
    evidence = @($JsonPath,$CsvPath)
}
