<#
.SYNOPSIS
Converts validated ADCS evidence into neutral prerequisite facts for offline correlation.
.NOTES
Version: 0.1.2
Execution class: offline_analysis
No AD, CA, network, registry, certificate, or authentication operation is performed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$TemplateConfigurationPath,
    [Parameter(Mandatory=$true)][string]$TemplateAccessPath,
    [Parameter()][string]$IdentityPrerequisitePath,
    [Parameter()][string]$CaRuntimeObservationPath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter()][string]$ConsoleModulePath,
    [switch]$Quiet,
    [switch]$NoColor
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$BuilderVersion='0.1.2'
$AllowedStates=@('Confirmed','Not observed','Inconclusive','Not applicable')
$RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$EvidenceHelperPath = Join-Path $RepositoryRoot 'Common\MSADPT.Evidence.psm1'
Import-Module $EvidenceHelperPath -Force -ErrorAction Stop

if($ConsoleModulePath){Import-Module $ConsoleModulePath -Force -ErrorAction Stop}
function Write-Step([string]$Action,[string]$Target,[int]$Current,[int]$Total){
    if(Get-Command Update-MSADPTProgress -ErrorAction SilentlyContinue){
        $null=Update-MSADPTProgress -Action $Action -Target $Target -Current $Current
    } elseif(-not $Quiet){
        Write-Host ('[....] [{0}/{1}] {2}: {3}' -f $Current,$Total,$Target,$Action) -ForegroundColor Yellow
    }
}
function Add-Fact([System.Collections.Generic.List[object]]$List,[string]$Id,[string]$State,[string]$Rationale,[string[]]$Sources,[string[]]$Limitations){
    if($State -notin $AllowedStates){throw "Unsupported fact state for ${Id}: $State"}
    $List.Add([pscustomobject][ordered]@{id=$Id;state=$State;rationale=$Rationale;sourceEvidence=@($Sources);limitations=@($Limitations);derivation='deterministic';builderVersion=$BuilderVersion})
}
function Test-True($Value){if($Value -is [bool]){return [bool]$Value};return ([string]$Value -eq 'True')}

foreach($Path in @($TemplateConfigurationPath,$TemplateAccessPath)){if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "Required evidence not found: $Path"}}
$TotalSteps=5
if(Get-Command Start-MSADPTProgress -ErrorAction SilentlyContinue){$null=Start-MSADPTProgress -Activity 'Build neutral ADCS facts' -Total $TotalSteps -Quiet:$Quiet -NoColor:$NoColor}

Write-Step 'Loading certificate template configuration' (Split-Path $TemplateConfigurationPath -Leaf) 1 $TotalSteps
$Templates=@(Get-Content -LiteralPath $TemplateConfigurationPath -Raw|ConvertFrom-Json -ErrorAction Stop)
Write-Step 'Loading template access evidence' (Split-Path $TemplateAccessPath -Leaf) 2 $TotalSteps
$Access=@(Import-Csv -LiteralPath $TemplateAccessPath)
$Identities=@()
if($IdentityPrerequisitePath -and (Test-Path -LiteralPath $IdentityPrerequisitePath -PathType Leaf)){
    Write-Step 'Loading resolved principal evidence' (Split-Path $IdentityPrerequisitePath -Leaf) 3 $TotalSteps
    $Identities=@(Get-Content -LiteralPath $IdentityPrerequisitePath -Raw|ConvertFrom-Json -ErrorAction Stop)
}else{Write-Step 'Identity prerequisite evidence unavailable' 'identity-prerequisites' 3 $TotalSteps}
$Runtime=@()
if($CaRuntimeObservationPath -and (Test-Path -LiteralPath $CaRuntimeObservationPath -PathType Leaf)){
    Write-Step 'Loading normalized CA runtime observations' (Split-Path $CaRuntimeObservationPath -Leaf) 4 $TotalSteps
    $Runtime=@(Get-Content -LiteralPath $CaRuntimeObservationPath -Raw|ConvertFrom-Json -ErrorAction Stop)
}else{Write-Step 'CA runtime observations unavailable' 'ca-runtime' 4 $TotalSteps}

Write-Step 'Deriving aggregate prerequisite facts' 'ESC1-ESC16' 5 $TotalSteps
$Facts=New-Object 'System.Collections.Generic.List[object]'
$TemplateSource=@($TemplateConfigurationPath,$TemplateAccessPath)
$Published=@($Templates|Where-Object{Test-True $_.PublishedByDiscoveredCA})
Add-Fact $Facts 'enterpriseCaPresent' $(if($Published.Count -gt 0){'Confirmed'}else{'Inconclusive'}) $(if($Published.Count -gt 0){'Published template evidence references at least one discovered enterprise CA.'}else{'No published templates were observed; CA presence cannot be concluded from these inputs alone.'}) $TemplateSource @()
Add-Fact $Facts 'templatePublished' $(if($Published.Count -gt 0){'Confirmed'}else{'Not observed'}) "Published template count: $($Published.Count)." $TemplateSource @()

$IdentitySupplyAuth=@($Published|Where-Object{((Test-True $_.EnrolleeSuppliesSubject) -or (Test-True $_.EnrolleeSuppliesSubjectAltName)) -and ((Test-True $_.HasAuthenticationCapableEku) -or (Test-True $_.NoExtendedKeyUsageRestriction))})
Add-Fact $Facts 'enrolleeSuppliesIdentity' $(if($IdentitySupplyAuth.Count -gt 0){'Confirmed'}else{'Not observed'}) "Published identity-supply authentication-capable template count: $($IdentitySupplyAuth.Count)." $TemplateSource @('This aggregate fact does not identify effective enrollment access by itself.')
Add-Fact $Facts 'authenticationCapableEku' $(if(@($Published|Where-Object{(Test-True $_.HasAuthenticationCapableEku) -or (Test-True $_.NoExtendedKeyUsageRestriction)}).Count -gt 0){'Confirmed'}else{'Not observed'}) 'Evaluated published template EKU evidence.' $TemplateSource @()
$AnyPurposeOrNoEku = @($Published | Where-Object { (Test-True $_.NoExtendedKeyUsageRestriction) -or (@($_.ExtendedKeyUsage) -contains '2.5.29.37.0') })
Add-Fact $Facts 'anyPurposeOrNoEkuRestriction' $(if($AnyPurposeOrNoEku.Count -gt 0){'Confirmed'}else{'Not observed'}) "Published Any Purpose or unrestricted-EKU template count: $($AnyPurposeOrNoEku.Count)." $TemplateSource @('EKU breadth alone does not establish authentication impact or effective enrollment.')
Add-Fact $Facts 'restrictedEku' $(if($AnyPurposeOrNoEku.Count -gt 0){'Not observed'}elseif($Published.Count -gt 0){'Confirmed'}else{'Inconclusive'}) 'Inverse aggregate of Any Purpose or unrestricted-EKU publication evidence.' $TemplateSource @()

$NoApprovalCandidates=@($IdentitySupplyAuth|Where-Object{-not(Test-True $_.ManagerApprovalRequired)})
Add-Fact $Facts 'managerApprovalDisabled' $(if($NoApprovalCandidates.Count -gt 0){'Confirmed'}else{'Not observed'}) "Candidate templates without manager approval: $($NoApprovalCandidates.Count)." $TemplateSource @()
Add-Fact $Facts 'managerApprovalRequired' $(if(@($IdentitySupplyAuth|Where-Object{Test-True $_.ManagerApprovalRequired}).Count -gt 0){'Confirmed'}else{'Not observed'}) 'Evaluated manager approval on candidate templates.' $TemplateSource @()
$NoSignatureCandidates=@($IdentitySupplyAuth|Where-Object{-not(Test-True $_.AuthorizedSignaturesRequired)})
Add-Fact $Facts 'authorizedSignaturesNotRequired' $(if($NoSignatureCandidates.Count -gt 0){'Confirmed'}else{'Not observed'}) "Candidate templates without authorized signatures: $($NoSignatureCandidates.Count)." $TemplateSource @()
Add-Fact $Facts 'authorizedSignaturesRequired' $(if(@($IdentitySupplyAuth|Where-Object{Test-True $_.AuthorizedSignaturesRequired}).Count -gt 0){'Confirmed'}else{'Not observed'}) 'Evaluated authorized signature requirements on candidate templates.' $TemplateSource @()

$CandidateNames=@($IdentitySupplyAuth|Select-Object -ExpandProperty Name -Unique)
$EnrollRows=@($Access|Where-Object{$_.TemplateName -in $CandidateNames -and (Test-True $_.AllowsEnroll)})
$LowPrivilegePattern='(?i)\\(Domain Users|Domain Computers|Authenticated Users|Everyone)$|^S-1-1-0$|^S-1-5-11$'
$LowPrivilegeEnroll=@($EnrollRows|Where-Object{[string]$_.IdentityReference -match $LowPrivilegePattern})
Add-Fact $Facts 'effectiveLowPrivilegeEnrollment' $(if($LowPrivilegeEnroll.Count -gt 0){'Confirmed'}elseif($EnrollRows.Count -gt 0){'Inconclusive'}else{'Not observed'}) "Low-privilege enrollment ACE count: $($LowPrivilegeEnroll.Count); total candidate enrollment ACE count: $($EnrollRows.Count)." $TemplateSource @('Deny ACEs, nested membership, and effective access are not fully evaluated by this aggregate fact.')
Add-Fact $Facts 'noEffectiveEnrollmentPath' $(if($EnrollRows.Count -eq 0){'Confirmed'}elseif($LowPrivilegeEnroll.Count -gt 0){'Not observed'}else{'Inconclusive'}) 'Derived from candidate enrollment ACEs.' $TemplateSource @('Named principals require identity and membership evaluation.')

$BroadControl=@($Access|Where-Object{(Test-True $_.PublishedByDiscoveredCA) -and ((Test-True $_.AllowsGenericAll) -or (Test-True $_.AllowsGenericWrite) -or (Test-True $_.AllowsWriteDacl) -or (Test-True $_.AllowsWriteOwner))})
$NonPrivControl=@($BroadControl|Where-Object{[string]$_.IdentityReference -notmatch '(?i)\\(Domain Admins|Enterprise Admins|Administrators)$'})
Add-Fact $Facts 'effectiveNonPrivilegedTemplateControl' $(if($NonPrivControl.Count -gt 0 -and $Identities.Count -gt 0){'Inconclusive'}elseif($NonPrivControl.Count -gt 0){'Inconclusive'}else{'Not observed'}) "Broad non-routine template-control ACE count: $($NonPrivControl.Count)." $TemplateSource @('ACE presence is not effective control. Principal status, deny ACEs, inheritance, and nested groups remain required.')
Add-Fact $Facts 'templatePresent' $(if($Templates.Count -gt 0){'Confirmed'}else{'Not observed'}) "Template object count: $($Templates.Count)." @($TemplateConfigurationPath) @()

$SchemaOne=@($Published|Where-Object{[int]$_.SchemaVersion -eq 1})
Add-Fact $Facts 'affectedVersionOneTemplate' $(if($SchemaOne.Count -gt 0){'Confirmed'}else{'Not observed'}) "Published version 1 template count: $($SchemaOne.Count)." @($TemplateConfigurationPath) @('Version 1 presence alone does not establish ESC15 prerequisites.')
Add-Fact $Facts 'templateNotVersionOne' $(if($SchemaOne.Count -eq 0){'Confirmed'}else{'Not observed'}) 'Inverse of published version 1 template evidence.' @($TemplateConfigurationPath) @()

$Resolved=@($Identities|Where-Object ResolutionStatus -eq 'Resolved')
Add-Fact $Facts 'principalResolved' $(if($Identities.Count -eq 0){'Inconclusive'}elseif($Resolved.Count -gt 0){'Confirmed'}else{'Not observed'}) "Resolved principal count: $($Resolved.Count); supplied principal records: $($Identities.Count)." @($IdentityPrerequisitePath) @()
Add-Fact $Facts 'nestedMembershipEvaluated' $(if(@($Resolved|Where-Object ObjectClass -eq 'group').Count -gt 0){'Confirmed'}elseif($Identities.Count -gt 0){'Not applicable'}else{'Inconclusive'}) 'Derived from resolved group records containing recursive membership evidence.' @($IdentityPrerequisitePath) @('v0.1.4 serialization validation remains pending on LAN.')

$EditFlag=@($Runtime|Where-Object{[string]$_.Setting -eq 'EditFlags' -and @($_.EnabledKnownFlags)-contains 'EDITF_ATTRIBUTESUBJECTALTNAME2'})
Add-Fact $Facts 'editfAttributeSubjectAltName2Observed' $(if($Runtime.Count -eq 0){'Inconclusive'}elseif($EditFlag.Count -gt 0){'Confirmed'}else{'Not observed'}) 'Derived from normalized CA runtime observations.' @($CaRuntimeObservationPath) @('Runtime observations are not available until the staged collector is deliberately enabled and executed on LAN.')
$Ping=@($Runtime|Where-Object{[string]$_.Setting -eq 'Ping' -and [string]$_.EvidenceStatus -eq 'Observed'})
Add-Fact $Facts 'caAcceptsRequests' $(if($Runtime.Count -eq 0){'Inconclusive'}elseif($Ping.Count -gt 0){'Inconclusive'}else{'Inconclusive'}) 'RPC ping or reachability does not prove that certificate requests are accepted.' @($CaRuntimeObservationPath) @('Must correlate successful request processing, authorization, and template access.')
$Interface=@($Runtime|Where-Object{[string]$_.Setting -eq 'InterfaceFlags'})
$Encrypted=@($Interface|Where-Object{@($_.EnabledKnownFlags)-contains 'IF_ENFORCEENCRYPTICERTREQUEST'})
Add-Fact $Facts 'encryptedRpcRequestEnforced' $(if($Runtime.Count -eq 0){'Inconclusive'}elseif($Encrypted.Count -gt 0){'Confirmed'}elseif($Interface.Count -gt 0 -and @($Interface|Where-Object EvidenceStatus -eq 'Observed').Count -gt 0){'Not observed'}else{'Inconclusive'}) 'Derived from normalized InterfaceFlags observations.' @($CaRuntimeObservationPath) @()
Add-Fact $Facts 'encryptedRpcRequestNotEnforced' $(if($Runtime.Count -eq 0){'Inconclusive'}elseif($Encrypted.Count -gt 0){'Not observed'}elseif($Interface.Count -gt 0 -and @($Interface|Where-Object EvidenceStatus -eq 'Observed').Count -gt 0){'Confirmed'}else{'Inconclusive'}) 'Inverse of the parsed IF_ENFORCEENCRYPTICERTREQUEST flag.' @($CaRuntimeObservationPath) @()

$Document=[pscustomobject][ordered]@{schemaVersion='1.0';builder='ADCSEvidenceToFacts';builderVersion=$BuilderVersion;generatedUtc=(Get-Date).ToUniversalTime().ToString('o');facts=@($Facts.ToArray());limitations=@('Aggregate facts do not replace per-template or per-principal candidate analysis.','Facts preserve uncertainty when effective permissions, runtime evidence, mapping behavior, or patch state are incomplete.','No vulnerability or exploitability conclusion is produced.')}
$Parent=Split-Path $OutputPath -Parent;if($Parent){New-Item -ItemType Directory -Path $Parent -Force|Out-Null}
Write-MSADPTJsonEvidence -Path $OutputPath -Value $Document -Depth 10
$ManifestPath = New-MSADPTEvidenceManifest -EvidenceDirectory (Split-Path -Parent $OutputPath) -ModuleId 'ADCSEvidenceToFacts' -ModuleVersion $BuilderVersion
if(Get-Command Complete-MSADPTProgress -ErrorAction SilentlyContinue){$null=Complete-MSADPTProgress -Message "Generated $($Facts.Count) neutral ADCS facts." -Outcome Success}
[pscustomobject]@{Status='Completed';BuilderVersion=$BuilderVersion;FactCount=$Facts.Count;OutputPath=$OutputPath}
