<#
.SYNOPSIS
Reduces MSADPT Directory Control candidates into evidence-backed, report-ready review families.

.DESCRIPTION
Offline-only analysis of directory-control-first-hop-candidates.csv. Version 1.0.4 corrects
principal classification so named principals are never mislabeled as unresolved SIDs. It creates
separate review families for named principals, platform control, true unresolved SIDs, focused
review, and domain-root replication rights. It preserves target-level traceability and emits a
report contract intended for the consolidated MSADPT HTML report.

This reducer never establishes effective access, exploitability, or security impact. It performs
no network activity, no directory queries, no authentication attempts, and no directory changes.

.NOTES
Version: 1.0.4
Windows PowerShell 5.1 and PowerShell 7 compatible.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DirectoryControlEvidenceDirectory,

    [string]$OutputDirectory,

    [ValidateRange(10, 10000)]
    [int]$MaximumPrioritizedFamilies = 2000,

    [ValidateRange(1, 100)]
    [int]$MaximumFamiliesPerTrustee = 25,

    [ValidateRange(1, 25)]
    [int]$MaximumRepresentativeTargets = 5,

    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ToolVersion = '1.0.4'
$ModuleId = 'Invoke-MSADPTDirectoryControlCandidateReduction'

function Write-Status {
    param([string]$State,[string]$Message,[ConsoleColor]$Color = [ConsoleColor]::Gray)
    $Text = '[{0,-12}] {1}' -f $State,$Message
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}

function Get-Field {
    param([object]$Object,[string]$Name,[object]$Default = $null)
    if ($null -eq $Object) { return $Default }
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property -or $null -eq $Property.Value) { return $Default }
    return $Property.Value
}

function ConvertTo-BooleanSafe {
    param([object]$Value)
    if ($Value -is [bool]) { return [bool]$Value }
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $false }
    return ([string]$Value).Trim().Equals('True',[StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-IntSafe {
    param([object]$Value,[int]$Default = 0)
    $Parsed = 0
    if ([int]::TryParse([string]$Value,[ref]$Parsed)) { return $Parsed }
    return $Default
}

function Write-JsonDocument {
    param([object]$Value,[string]$Path)
    $Value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $Path -Encoding UTF8
    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}

function Add-Counter {
    param([hashtable]$Table,[string]$Key,[int]$Increment = 1)
    if ([string]::IsNullOrWhiteSpace($Key)) { $Key = 'Unknown' }
    if (-not $Table.ContainsKey($Key)) { $Table[$Key] = 0 }
    $Table[$Key] = [int]$Table[$Key] + $Increment
}

function Get-StableId {
    param([string]$Prefix,[string]$Value)
    $Algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $Hash = $Algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
        return $Prefix + (([BitConverter]::ToString($Hash)).Replace('-','')).Substring(0,16)
    }
    finally { $Algorithm.Dispose() }
}

function Get-SidFromRow {
    param([object]$Row)
    foreach ($Value in @([string](Get-Field $Row 'TrusteeSid' ''),[string](Get-Field $Row 'Trustee' ''))) {
        if (-not [string]::IsNullOrWhiteSpace($Value) -and $Value.Trim() -match '^S-1-') {
            return $Value.Trim().ToUpperInvariant()
        }
    }
    return $null
}

function Get-WellKnownSidName {
    param([string]$Sid)
    $Map = @{
        'S-1-1-0'='Everyone';'S-1-3-0'='CREATOR OWNER';'S-1-5-9'='Enterprise Domain Controllers'
        'S-1-5-10'='NT AUTHORITY\SELF';'S-1-5-11'='NT AUTHORITY\Authenticated Users';'S-1-5-18'='NT AUTHORITY\SYSTEM'
        'S-1-5-32-544'='BUILTIN\Administrators';'S-1-5-32-545'='BUILTIN\Users';'S-1-5-32-546'='BUILTIN\Guests'
        'S-1-5-32-548'='BUILTIN\Account Operators';'S-1-5-32-549'='BUILTIN\Server Operators'
        'S-1-5-32-550'='BUILTIN\Print Operators';'S-1-5-32-551'='BUILTIN\Backup Operators'
        'S-1-5-32-552'='BUILTIN\Replicator';'S-1-5-32-555'='BUILTIN\Remote Desktop Users'
        'S-1-5-32-562'='BUILTIN\Distributed COM Users';'S-1-5-32-569'='BUILTIN\Cryptographic Operators'
        'S-1-5-32-573'='BUILTIN\Event Log Readers';'S-1-5-32-574'='BUILTIN\Certificate Service DCOM Access'
        'S-1-5-32-579'='BUILTIN\Access Control Assistance Operators';'S-1-5-32-580'='BUILTIN\Remote Management Users'
    }
    if (-not [string]::IsNullOrWhiteSpace($Sid) -and $Map.ContainsKey($Sid)) { return [string]$Map[$Sid] }
    return $null
}

function Get-DomainRelativeClass {
    param([string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid) -or $Sid -notmatch '^S-1-5-21-(?:\d+-){2}\d+-(\d+)$') { return $null }
    switch ([int64]$Matches[1]) {
        498 { 'EnterpriseReadOnlyDomainControllers' };500 { 'BuiltinAdministratorAccount' };512 { 'DomainAdmins' }
        516 { 'DomainControllers' };517 { 'CertPublishers' };518 { 'SchemaAdmins' };519 { 'EnterpriseAdmins' }
        521 { 'ReadOnlyDomainControllers' };525 { 'ProtectedUsers' };526 { 'KeyAdmins' };527 { 'EnterpriseKeyAdmins' }
        default { $null }
    }
}

function Get-NormalizedTrustee {
    param([object]$Row)
    $Sid = Get-SidFromRow $Row
    $Original = [string](Get-Field $Row 'Trustee' '')
    $OriginalIsSid = (-not [string]::IsNullOrWhiteSpace($Original) -and $Original.Trim() -match '^S-1-')
    $HasAuthoritativeName = (-not [string]::IsNullOrWhiteSpace($Original) -and -not $OriginalIsSid)
    $WellKnown = Get-WellKnownSidName $Sid
    $DomainClass = Get-DomainRelativeClass $Sid
    $Display = $Original
    if (-not [string]::IsNullOrWhiteSpace($WellKnown)) { $Display = $WellKnown }
    elseif ([string]::IsNullOrWhiteSpace($Display)) { $Display = $Sid }

    if (-not [string]::IsNullOrWhiteSpace($Sid)) { $Key = 'sid:' + $Sid.ToLowerInvariant() }
    elseif (-not [string]::IsNullOrWhiteSpace([string](Get-Field $Row 'TrusteeKey' ''))) { $Key = [string](Get-Field $Row 'TrusteeKey' '') }
    else { $Key = 'name:' + $Original.Trim().ToLowerInvariant() }

    $Class = 'Unresolved'
    $Context = 'IdentityResolutionRequired'
    if ($Sid -in @('S-1-5-18','S-1-5-10','S-1-3-0','S-1-5-9','S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551')) {
        $Class='ExpectedAdministrative';$Context='BuiltInAdministrative'
    }
    elseif ($DomainClass -in @('DomainAdmins','DomainControllers','SchemaAdmins','EnterpriseAdmins','ReadOnlyDomainControllers','EnterpriseReadOnlyDomainControllers','KeyAdmins','EnterpriseKeyAdmins')) {
        $Class='ExpectedAdministrative';$Context='DomainAdministrative'
    }
    elseif ($DomainClass -eq 'CertPublishers') { $Class='PlatformService';$Context='CertificateServices' }
    elseif ($Display -match '\\(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Domain Controllers|Enterprise Domain Controllers|Account Operators|Server Operators|Backup Operators|Print Operators)$') {
        $Class='ExpectedAdministrative';$Context='AdministrativeNamePattern'
    }
    elseif ($Display -match '(?i)(Exchange|Organization Management)') { $Class='PlatformService';$Context='Exchange' }
    elseif ($Display -match '(?i)(MSOL_|AzureAD|Entra|AADConnect|ADSync)') { $Class='PlatformService';$Context='IdentitySynchronization' }
    elseif ($Display -match '(?i)(RTCUniversal|Skype|Lync)') { $Class='PlatformService';$Context='UnifiedCommunications' }
    elseif ($Display -match '(?i)(Cert Publishers|Certificate)') { $Class='PlatformService';$Context='CertificateServices' }
    elseif ($HasAuthoritativeName -and -not [string]::IsNullOrWhiteSpace($Sid)) { $Class='NamedPrincipalWithSid';$Context='NamedPrincipal' }
    elseif ($HasAuthoritativeName) { $Class='NamedPrincipalWithoutSid';$Context='NamedPrincipal' }
    elseif (-not [string]::IsNullOrWhiteSpace($Sid)) { $Class='UnresolvedSid';$Context='IdentityResolutionRequired' }

    [pscustomobject][ordered]@{
        Trustee=$Display;OriginalTrustee=$Original;TrusteeSid=$Sid;TrusteeKey=$Key;PrincipalClass=$Class
        PlatformContext=$Context;DomainRelativeClass=$DomainClass;HasAuthoritativeName=$HasAuthoritativeName
        SidResolvedOffline=(-not [string]::IsNullOrWhiteSpace($WellKnown) -or -not [string]::IsNullOrWhiteSpace($DomainClass))
    }
}

function Get-Applicability {
    param([string]$Capability,[string]$TargetType)
    switch ($Capability) {
        'WriteGroupMembership' { if ($TargetType -ne 'Group') { return 'NotApplicableToTargetType' } }
        'WriteRBCD' { if ($TargetType -notin @('Computer','User')) { return 'NotApplicableToTargetType' } }
        'WriteServicePrincipalName' { if ($TargetType -notin @('Computer','User')) { return 'NotApplicableToTargetType' } }
        'WriteKeyCredentialLink' { if ($TargetType -notin @('Computer','User')) { return 'NotApplicableToTargetType' } }
        'WriteGPLink' { if ($TargetType -notin @('OrganizationalUnit','Domain','Site')) { return 'NotApplicableToTargetType' } }
        'ReplicatingDirectoryChanges' { if ($TargetType -ne 'Domain') { return 'NotApplicableToTargetType' } }
        'ReplicatingDirectoryChangesAll' { if ($TargetType -ne 'Domain') { return 'NotApplicableToTargetType' } }
        'ReplicatingDirectoryChangesFilteredSet' { if ($TargetType -ne 'Domain') { return 'NotApplicableToTargetType' } }
    }
    return 'Applicable'
}

function Get-CapabilityCategory {
    param([string]$Capability)
    if ($Capability -in @('ReplicatingDirectoryChanges','ReplicatingDirectoryChangesAll','ReplicatingDirectoryChangesFilteredSet')) { return 'DirectoryReplication' }
    switch ($Capability) {
        'WriteGroupMembership' { 'GroupMembershipControl' };'WriteRBCD' { 'DelegationControl' }
        'WriteKeyCredentialLink' { 'KeyCredentialControl' };'WriteServicePrincipalName' { 'ServiceIdentityControl' }
        'ResetPassword' { 'CredentialControl' };'WriteGPLink' { 'GpoLinkControl' }
        { $_ -in @('GenericAll','GenericWrite','WriteDacl','WriteOwner') } { 'BroadObjectControl' }
        default { 'OtherDirectoryControl' }
    }
}

function Get-ValidationQuestion {
    param([string]$Capability,[string]$PrincipalClass,[string]$PlatformContext)
    $Base = switch ($Capability) {
        'WriteDacl' { 'Is the trustee intended to modify the target ACL, and does its effective token retain this right?' }
        'WriteOwner' { 'Can the trustee become owner and subsequently alter the target security descriptor?' }
        'GenericAll' { 'Is broad control expected for this trustee and target, and is it effective after deny and token evaluation?' }
        'GenericWrite' { 'Which writable target properties produce a meaningful security path for this trustee?' }
        'ResetPassword' { 'Is password-reset control expected and usable against an active security principal?' }
        'WriteGroupMembership' { 'Can the trustee effectively change membership of the target group?' }
        'WriteRBCD' { 'Can the trustee effectively write RBCD configuration on the target principal?' }
        'WriteKeyCredentialLink' { 'Can the trustee effectively modify key credentials on the target principal?' }
        'WriteServicePrincipalName' { 'Can the trustee effectively alter SPNs on the target principal?' }
        'WriteGPLink' { 'Can the trustee effectively change GPO links on the target container?' }
        default { 'Does this observed control relationship produce effective access or a viable attack path?' }
    }
    if ($PrincipalClass -eq 'PlatformService') { return $Base + " Validate whether the $PlatformContext delegation is required, current, and bounded to the deployed architecture." }
    return $Base
}

function Get-TargetState {
    param([object]$Row)
    $Enabled = Get-Field $Row 'TargetEnabled' $null
    if ($null -eq $Enabled) { $Enabled = Get-Field $Row 'Enabled' $null }
    if ($null -ne $Enabled -and -not [string]::IsNullOrWhiteSpace([string]$Enabled)) {
        if (ConvertTo-BooleanSafe $Enabled) { return 'Enabled' } else { return 'Disabled' }
    }
    $DN = [string](Get-Field $Row 'TargetDistinguishedName' '')
    if ($DN -match '(?i)(OU=Disabled|CN=Deleted Objects)') { return 'LocationSuggestsInactive' }
    return 'Unknown'
}

function Get-TargetPrivilegeClass {
    param([object]$Row)
    $Explicit = [string](Get-Field $Row 'TargetPrivilegeClass' '')
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) { return $Explicit }
    if (ConvertTo-BooleanSafe (Get-Field $Row 'ProtectedObjectIndicatorObserved' $false)) { return 'ProtectedIndicatorObserved' }
    $Name = ([string](Get-Field $Row 'TargetName' '')) + ' ' + ([string](Get-Field $Row 'TargetSamAccountName' ''))
    if ($Name -match '(?i)(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Domain Controllers|krbtgt)') { return 'HighValueNameObserved' }
    return 'StandardOrUnknown'
}

function Get-InheritanceSource {
    param([object]$Row)
    foreach ($Field in @('InheritanceSourceDistinguishedName','InheritanceSource','SourceContainerDistinguishedName','AceSourceDistinguishedName')) {
        $Value = [string](Get-Field $Row $Field '')
        if (-not [string]::IsNullOrWhiteSpace($Value)) { return $Value }
    }
    $DN = [string](Get-Field $Row 'TargetDistinguishedName' '')
    if ($DN -match '^[^,]+,(.+)$') { return 'BestAvailableAncestor:' + $Matches[1] }
    return 'UnknownInheritanceSource'
}

function Get-BaseScore {
    param([string]$Capability)
    switch ($Capability) {
        'GenericAll' { 60 };'WriteDacl' { 58 };'WriteOwner' { 58 };'WriteRBCD' { 55 };'WriteKeyCredentialLink' { 55 }
        'ResetPassword' { 50 };'WriteGroupMembership' { 48 };'WriteServicePrincipalName' { 45 };'WriteGPLink' { 45 }
        'ReplicatingDirectoryChangesAll' { 40 };'ReplicatingDirectoryChanges' { 35 };'ReplicatingDirectoryChangesFilteredSet' { 35 }
        'GenericWrite' { 32 };default { 10 }
    }
}

function Get-RiskScore {
    param([object]$Row,[object]$Trustee,[string]$Applicability,[string]$TargetState,[string]$PrivilegeClass)
    if ($Applicability -ne 'Applicable') { return 0 }
    $Score = Get-BaseScore ([string](Get-Field $Row 'Capability' ''))
    if ((ConvertTo-IntSafe (Get-Field $Row 'DirectAceCount' 0)) -gt 0) { $Score += 20 } else { $Score += 3 }
    if ($PrivilegeClass -eq 'ProtectedIndicatorObserved') { $Score += 6 }
    elseif ($PrivilegeClass -eq 'HighValueNameObserved') { $Score += 10 }
    if ($TargetState -in @('Disabled','LocationSuggestsInactive')) { $Score -= 8 }
    if ((ConvertTo-IntSafe (Get-Field $Row 'DenyAceCount' 0)) -gt 0) { $Score -= 20 }
    if ($Trustee.PrincipalClass -eq 'ExpectedAdministrative') { $Score -= 55 }
    elseif ($Trustee.PrincipalClass -eq 'PlatformService') { $Score -= 15 }
    if ($Score -lt 0) { $Score=0 };if ($Score -gt 100) { $Score=100 }
    return [int]$Score
}

function Get-Priority {
    param([int]$Score)
    if ($Score -ge 80) { 'P1' } elseif ($Score -ge 60) { 'P2' } elseif ($Score -ge 40) { 'P3' } else { 'Informational' }
}

$EvidenceRoot = [IO.Path]::GetFullPath($DirectoryControlEvidenceDirectory)
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory=Join-Path (Split-Path -Parent $EvidenceRoot) 'DirectoryControlReduction-v1.0.4' }
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
$CandidatePath=Join-Path $EvidenceRoot 'directory-control-first-hop-candidates.csv'
if (-not (Test-Path -LiteralPath $CandidatePath -PathType Leaf)) { throw "CandidateCsvMissing: $CandidatePath" }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$Started=Get-Date
Write-Status START "Directory Control candidate reduction v$ToolVersion" Cyan
Write-Status SAFETY 'Offline only; network=None; directory queries=None; source evidence modifications=None.' Yellow
$Rows=@(Import-Csv -LiteralPath $CandidatePath)
$Loaded=Get-Date
Write-Status INPUT "Loaded $($Rows.Count) first-hop candidates." DarkCyan

$Counters=@{Suppression=@{};Principal=@{};Capability=@{};EligiblePriority=@{};SelectedPriority=@{};PlatformDisposition=@{}}
$Suppressed=New-Object 'Collections.Generic.List[object]'
$Focused=New-Object 'Collections.Generic.List[object]'
$EligibleDetails=New-Object 'Collections.Generic.List[object]'
$FamilyMap=@{};$SidSummaryMap=@{};$SidSourceMap=@{};$ReplicationMap=@{}

foreach ($Row in $Rows) {
    $Capability=[string](Get-Field $Row 'Capability' '')
    $TargetType=[string](Get-Field $Row 'TargetObjectType' 'Unknown')
    $Trustee=Get-NormalizedTrustee $Row
    $Applicability=Get-Applicability $Capability $TargetType
    $TargetState=Get-TargetState $Row
    $PrivilegeClass=Get-TargetPrivilegeClass $Row
    $InheritanceSource=Get-InheritanceSource $Row
    $DirectCount=ConvertTo-IntSafe (Get-Field $Row 'DirectAceCount' 0)
    $InheritedCount=ConvertTo-IntSafe (Get-Field $Row 'InheritedAceCount' 0)
    $DenyCount=ConvertTo-IntSafe (Get-Field $Row 'DenyAceCount' 0)
    if ($DirectCount -gt 0) { $InheritanceClass='DirectOrMixed' } else { $InheritanceClass='InheritedOnly' }
    $Score=Get-RiskScore $Row $Trustee $Applicability $TargetState $PrivilegeClass
    $Priority=Get-Priority $Score
    Add-Counter $Counters.Principal $Trustee.PrincipalClass
    Add-Counter $Counters.Capability $Capability

    $Disposition='PrioritizedEligible';$Reason=$null;$PlatformDisposition='NotPlatformControl'
    if ($Applicability -ne 'Applicable') { $Disposition='Suppressed';$Reason=$Applicability }
    elseif ($Capability -eq 'UnresolvedObjectSpecificRight') { $Disposition='Suppressed';$Reason='UnresolvedObjectSpecificRight' }
    elseif ($Trustee.PrincipalClass -eq 'ExpectedAdministrative') { $Disposition='Suppressed';$Reason='ExpectedAdministrativeControl' }
    elseif ($DenyCount -gt 0 -or [string](Get-Field $Row 'EvidenceState' '') -eq 'FocusedReviewRequired') {
        $Disposition='FocusedReviewRequired'
        if ($DenyCount -gt 0) { $Reason='DenyInteractionUnresolved' } else { $Reason='SourceFocusedReviewRequired' }
    }
    elseif ($Trustee.PrincipalClass -eq 'UnresolvedSid') { $Disposition='IdentityResolutionRequired';$Reason='UnresolvedTrusteeSid' }
    elseif ($Trustee.PrincipalClass -eq 'NamedPrincipalWithoutSid') { $Disposition='FocusedReviewRequired';$Reason='NamedPrincipalSidUnavailable' }
    elseif ($Trustee.PrincipalClass -eq 'PlatformService') {
        if ($DirectCount -gt 0 -and $PrivilegeClass -in @('ProtectedIndicatorObserved','HighValueNameObserved')) { $PlatformDisposition='PlatformControlOverSensitiveTarget' }
        elseif ($DirectCount -gt 0) { $PlatformDisposition='PlatformControlRequiringRecertification' }
        elseif ($PrivilegeClass -in @('ProtectedIndicatorObserved','HighValueNameObserved')) { $PlatformDisposition='InconclusivePlatformControl' }
        else { $PlatformDisposition='ExpectedPlatformControl' }
        if ($PlatformDisposition -eq 'ExpectedPlatformControl') { $Disposition='Suppressed';$Reason='ExpectedInheritedPlatformControl' }
        Add-Counter $Counters.PlatformDisposition $PlatformDisposition
    }

    $Detail=[pscustomobject][ordered]@{
        CandidateId=Get-Field $Row 'CandidateId' '';RiskScore=$Score;Priority=$Priority
        Trustee=$Trustee.Trustee;OriginalTrustee=$Trustee.OriginalTrustee;TrusteeSid=$Trustee.TrusteeSid;TrusteeKey=$Trustee.TrusteeKey
        PrincipalClass=$Trustee.PrincipalClass;PlatformContext=$Trustee.PlatformContext;PlatformDisposition=$PlatformDisposition
        DomainRelativeClass=$Trustee.DomainRelativeClass;HasAuthoritativeName=$Trustee.HasAuthoritativeName
        Capability=$Capability;CapabilityCategory=Get-CapabilityCategory $Capability;TargetObjectType=$TargetType
        TargetName=Get-Field $Row 'TargetName' '';TargetSamAccountName=Get-Field $Row 'TargetSamAccountName' ''
        TargetDistinguishedName=Get-Field $Row 'TargetDistinguishedName' '';TargetObjectSid=Get-Field $Row 'TargetObjectSid' ''
        TargetState=$TargetState;TargetPrivilegeClass=$PrivilegeClass;DirectAceCount=$DirectCount;InheritedAceCount=$InheritedCount
        DenyAceCount=$DenyCount;InheritanceClass=$InheritanceClass;InheritanceSource=$InheritanceSource
        ProtectedObjectIndicatorObserved=ConvertTo-BooleanSafe (Get-Field $Row 'ProtectedObjectIndicatorObserved' $false)
        AdminSDHolderProvenance='NotEstablished';AdminSDHolderEnforcement='NotEstablished';Applicability=$Applicability
        Disposition=$Disposition;ReductionReason=$Reason;ValidationQuestion=Get-ValidationQuestion $Capability $Trustee.PrincipalClass $Trustee.PlatformContext
        EffectiveAccess='NotEstablished';ImpactReproduced=$false;VulnerabilityConfirmed=$false
    }

    if ($Capability -in @('ReplicatingDirectoryChanges','ReplicatingDirectoryChangesAll','ReplicatingDirectoryChangesFilteredSet') -and $TargetType -eq 'Domain') {
        if (-not $ReplicationMap.ContainsKey($Trustee.TrusteeKey)) { $ReplicationMap[$Trustee.TrusteeKey]=[ordered]@{Trustee=$Trustee;Rights=New-Object 'Collections.Generic.HashSet[string]';CandidateIds=New-Object 'Collections.Generic.List[string]'} }
        $null=$ReplicationMap[$Trustee.TrusteeKey].Rights.Add($Capability);$ReplicationMap[$Trustee.TrusteeKey].CandidateIds.Add([string]$Detail.CandidateId)
    }

    if ($Disposition -eq 'Suppressed') { $Suppressed.Add($Detail);Add-Counter $Counters.Suppression $Reason;continue }
    if ($Disposition -eq 'FocusedReviewRequired') { $Focused.Add($Detail);continue }
    if ($Disposition -eq 'IdentityResolutionRequired') {
        $SummaryKey='{0}|{1}|{2}|{3}|{4}' -f $Trustee.TrusteeKey,$Capability,$TargetType,$InheritanceClass,$PrivilegeClass
        if (-not $SidSummaryMap.ContainsKey($SummaryKey)) { $SidSummaryMap[$SummaryKey]=[ordered]@{Key=$SummaryKey;Trustee=$Trustee;Capability=$Capability;TargetType=$TargetType;InheritanceClass=$InheritanceClass;PrivilegeClass=$PrivilegeClass;Count=0;SourceCount=New-Object 'Collections.Generic.HashSet[string]';Representatives=New-Object 'Collections.Generic.List[string]';CandidateIds=New-Object 'Collections.Generic.List[string]'} }
        $S=$SidSummaryMap[$SummaryKey];$S.Count++;$null=$S.SourceCount.Add($InheritanceSource)
        if ($S.Representatives.Count -lt $MaximumRepresentativeTargets) { $S.Representatives.Add([string]$Detail.TargetDistinguishedName);$S.CandidateIds.Add([string]$Detail.CandidateId) }
        $SourceKey=$SummaryKey+'|'+$InheritanceSource
        if (-not $SidSourceMap.ContainsKey($SourceKey)) { $SidSourceMap[$SourceKey]=[ordered]@{Key=$SourceKey;Trustee=$Trustee;Capability=$Capability;TargetType=$TargetType;InheritanceClass=$InheritanceClass;PrivilegeClass=$PrivilegeClass;InheritanceSource=$InheritanceSource;Count=0;Representatives=New-Object 'Collections.Generic.List[string]';CandidateIds=New-Object 'Collections.Generic.List[string]'} }
        $SD=$SidSourceMap[$SourceKey];$SD.Count++;if($SD.Representatives.Count -lt $MaximumRepresentativeTargets){$SD.Representatives.Add([string]$Detail.TargetDistinguishedName);$SD.CandidateIds.Add([string]$Detail.CandidateId)}
        continue
    }

    $EligibleDetails.Add($Detail);Add-Counter $Counters.EligiblePriority $Priority
    $FamilyKey='{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f $Trustee.TrusteeKey,$Capability,$TargetType,$InheritanceClass,$PrivilegeClass,$InheritanceSource,$Trustee.PlatformContext,$PlatformDisposition
    if (-not $FamilyMap.ContainsKey($FamilyKey)) { $FamilyMap[$FamilyKey]=[ordered]@{Key=$FamilyKey;Trustee=$Trustee;Capability=$Capability;TargetType=$TargetType;InheritanceClass=$InheritanceClass;PrivilegeClass=$PrivilegeClass;InheritanceSource=$InheritanceSource;PlatformDisposition=$PlatformDisposition;HighestScore=$Score;HighestPriority=$Priority;Count=0;Direct=0;Inherited=0;Sensitive=0;Enabled=0;Inactive=0;Unknown=0;Representatives=New-Object 'Collections.Generic.List[string]';CandidateIds=New-Object 'Collections.Generic.List[string]'} }
    $F=$FamilyMap[$FamilyKey];$F.Count++;if($DirectCount -gt 0){$F.Direct++}else{$F.Inherited++};if($PrivilegeClass -ne 'StandardOrUnknown'){$F.Sensitive++};if($TargetState -eq 'Enabled'){$F.Enabled++}elseif($TargetState -in @('Disabled','LocationSuggestsInactive')){$F.Inactive++}else{$F.Unknown++};if($Score -gt $F.HighestScore){$F.HighestScore=$Score;$F.HighestPriority=$Priority};if($F.Representatives.Count -lt $MaximumRepresentativeTargets){$F.Representatives.Add([string]$Detail.TargetDistinguishedName);$F.CandidateIds.Add([string]$Detail.CandidateId)}
}
$Reduced=Get-Date

$Families=New-Object 'Collections.Generic.List[object]'
foreach($Key in $FamilyMap.Keys){$F=$FamilyMap[$Key];$Families.Add([pscustomobject][ordered]@{FamilyId=Get-StableId 'FAM-' $Key;RiskScore=$F.HighestScore;Priority=$F.HighestPriority;Trustee=$F.Trustee.Trustee;TrusteeSid=$F.Trustee.TrusteeSid;TrusteeKey=$F.Trustee.TrusteeKey;PrincipalClass=$F.Trustee.PrincipalClass;PlatformContext=$F.Trustee.PlatformContext;PlatformDisposition=$F.PlatformDisposition;Capability=$F.Capability;CapabilityCategory=Get-CapabilityCategory $F.Capability;TargetObjectType=$F.TargetType;TargetPrivilegeClass=$F.PrivilegeClass;InheritanceClass=$F.InheritanceClass;InheritanceSource=$F.InheritanceSource;CandidateCount=$F.Count;DirectCandidateCount=$F.Direct;InheritedOnlyCandidateCount=$F.Inherited;SensitiveTargetCount=$F.Sensitive;EnabledTargetCount=$F.Enabled;DisabledOrInactiveTargetCount=$F.Inactive;UnknownTargetStateCount=$F.Unknown;RepresentativeTargets=([string[]]$F.Representatives.ToArray()) -join ' | ';RepresentativeCandidateIds=([string[]]$F.CandidateIds.ToArray()) -join ';';ValidationQuestion=Get-ValidationQuestion $F.Capability $F.Trustee.PrincipalClass $F.Trustee.PlatformContext;EffectiveAccess='NotEstablished';ImpactReproduced=$false;VulnerabilityConfirmed=$false})}

$SidSummaries=New-Object 'Collections.Generic.List[object]'
foreach($Key in $SidSummaryMap.Keys){$S=$SidSummaryMap[$Key];$SidSummaries.Add([pscustomobject][ordered]@{IdentityFamilyId=Get-StableId 'SID-' $Key;Trustee=$S.Trustee.Trustee;TrusteeSid=$S.Trustee.TrusteeSid;TrusteeKey=$S.Trustee.TrusteeKey;ResolutionStatus='IdentityResolutionRequired';Capability=$S.Capability;CapabilityCategory=Get-CapabilityCategory $S.Capability;TargetObjectType=$S.TargetType;InheritanceClass=$S.InheritanceClass;TargetPrivilegeClass=$S.PrivilegeClass;AffectedTargetCount=$S.Count;ObservedDelegationSourceCount=$S.SourceCount.Count;RepresentativeTargets=([string[]]$S.Representatives.ToArray()) -join ' | ';RepresentativeCandidateIds=([string[]]$S.CandidateIds.ToArray()) -join ';';ValidationQuestion='Resolve the trustee SID using authoritative identity evidence before interpreting control.';EffectiveAccess='NotEstablished';ImpactReproduced=$false;VulnerabilityConfirmed=$false})}
$SidSourceDetails=New-Object 'Collections.Generic.List[object]'
foreach($Key in $SidSourceMap.Keys){$S=$SidSourceMap[$Key];$SidSourceDetails.Add([pscustomobject][ordered]@{DelegationFamilyId=Get-StableId 'SDS-' $Key;Trustee=$S.Trustee.Trustee;TrusteeSid=$S.Trustee.TrusteeSid;Capability=$S.Capability;TargetObjectType=$S.TargetType;InheritanceClass=$S.InheritanceClass;TargetPrivilegeClass=$S.PrivilegeClass;InheritanceSource=$S.InheritanceSource;AffectedTargetCount=$S.Count;RepresentativeTargets=([string[]]$S.Representatives.ToArray()) -join ' | ';RepresentativeCandidateIds=([string[]]$S.CandidateIds.ToArray()) -join ';'})}

$Sorted=@($Families.ToArray()|Sort-Object @{Expression='RiskScore';Descending=$true},@{Expression='SensitiveTargetCount';Descending=$true},@{Expression='DirectCandidateCount';Descending=$true},Trustee,Capability)
$Selected=New-Object 'Collections.Generic.List[object]';$ByTrustee=@{};$OmittedTrustee=0
foreach($F in $Sorted){if($Selected.Count -ge $MaximumPrioritizedFamilies){break};if(-not $ByTrustee.ContainsKey($F.TrusteeKey)){$ByTrustee[$F.TrusteeKey]=0};if($ByTrustee[$F.TrusteeKey] -ge $MaximumFamiliesPerTrustee){$OmittedTrustee++;continue};$Selected.Add($F);$ByTrustee[$F.TrusteeKey]++;Add-Counter $Counters.SelectedPriority $F.Priority}
$OmittedLimit=[math]::Max(0,$Sorted.Count-$Selected.Count-$OmittedTrustee)

$Replication=New-Object 'Collections.Generic.List[object]'
foreach($Key in $ReplicationMap.Keys){$R=$ReplicationMap[$Key];$Rights=[string[]]@($R.Rights|Sort-Object);$Changes=$Rights -contains 'ReplicatingDirectoryChanges';$All=$Rights -contains 'ReplicatingDirectoryChangesAll';$Filtered=$Rights -contains 'ReplicatingDirectoryChangesFilteredSet';if($R.Trustee.PrincipalClass -eq 'UnresolvedSid'){$RD='IdentityResolutionRequired'}elseif($R.Trustee.PrincipalClass -eq 'PlatformService'){$RD='PlatformControlRequiringRecertification'}elseif($R.Trustee.PrincipalClass -eq 'ExpectedAdministrative'){$RD='ExpectedAdministrativeControl'}elseif($Changes -and $All){$RD='ReplicationCapabilityCandidate'}else{$RD='PartialReplicationRight'};$Replication.Add([pscustomobject][ordered]@{Trustee=$R.Trustee.Trustee;TrusteeSid=$R.Trustee.TrusteeSid;TrusteeKey=$R.Trustee.TrusteeKey;PrincipalClass=$R.Trustee.PrincipalClass;Rights=$Rights -join ';';HasChanges=$Changes;HasChangesAll=$All;HasFilteredSet=$Filtered;CandidateCombination=($Changes -and $All);FullSensitiveCombination=($Changes -and $All -and $Filtered);Disposition=$RD;CandidateIds=([string[]]$R.CandidateIds.ToArray()) -join ';';EffectiveAccess='NotEstablished';ImpactReproduced=$false;VulnerabilityConfirmed=$false})}

$Selected.ToArray()|Export-Csv (Join-Path $OutputDirectory 'directory-control-prioritized-families.csv') -NoTypeInformation -Encoding UTF8
$Families.ToArray()|Export-Csv (Join-Path $OutputDirectory 'directory-control-all-eligible-families.csv') -NoTypeInformation -Encoding UTF8
$EligibleDetails.ToArray()|Export-Csv (Join-Path $OutputDirectory 'directory-control-prioritized-target-details.csv') -NoTypeInformation -Encoding UTF8
$Focused.ToArray()|Export-Csv (Join-Path $OutputDirectory 'directory-control-focused-review-reduced.csv') -NoTypeInformation -Encoding UTF8
$SidSummaries.ToArray()|Export-Csv (Join-Path $OutputDirectory 'directory-control-sid-resolution-summary.csv') -NoTypeInformation -Encoding UTF8
$SidSourceDetails.ToArray()|Export-Csv (Join-Path $OutputDirectory 'directory-control-sid-resolution-delegation-details.csv') -NoTypeInformation -Encoding UTF8
$Suppressed.ToArray()|Export-Csv (Join-Path $OutputDirectory 'directory-control-suppressed.csv') -NoTypeInformation -Encoding UTF8
$Replication.ToArray()|Export-Csv (Join-Path $OutputDirectory 'directory-control-domain-replication-rights.csv') -NoTypeInformation -Encoding UTF8

$Completed=Get-Date
if($Selected.Count -gt 0){$SummaryDisposition='PrioritizedReviewAvailable'}else{$SummaryDisposition='NoPrioritizedCandidateDetected'}
$HtmlContract=[pscustomobject][ordered]@{
    SchemaVersion='1.0';SectionTitle='Directory Control';Disposition=$SummaryDisposition
    Metrics=[pscustomobject][ordered]@{InputCandidates=$Rows.Count;PrioritizedFamilies=$Selected.Count;FocusedReview=$Focused.Count;UnresolvedIdentityFamilies=$SidSummaries.Count;Suppressed=$Suppressed.Count;ReplicationTrustees=$Replication.Count;OmittedByTrusteeDiversity=$OmittedTrustee}
    RequiredSubsections=@('At-a-glance disposition','Prioritized control families','Platform delegation review','Unresolved identity families','Domain-root replication rights','Collection and interpretation limitations','Evidence links')
    EvidenceLinks=@('directory-control-prioritized-families.csv','directory-control-all-eligible-families.csv','directory-control-prioritized-target-details.csv','directory-control-focused-review-reduced.csv','directory-control-sid-resolution-summary.csv','directory-control-sid-resolution-delegation-details.csv','directory-control-domain-replication-rights.csv','directory-control-suppressed.csv','directory-control-reduction-summary.json')
    Interpretation=@('No family is a confirmed vulnerability without effective-access and impact validation.','Platform control is not automatically safe or vulnerable.','Protected-object indicators do not establish AdminSDHolder provenance or enforcement.','Additional eligible families may exist beyond per-trustee diversity limits.')
}
Write-JsonDocument $HtmlContract (Join-Path $OutputDirectory 'directory-control-html-report-contract.json')
$Summary=[pscustomobject][ordered]@{SchemaVersion='1.4';ToolVersion=$ToolVersion;Status='Completed';Disposition=$SummaryDisposition;GeneratedUtc=$Completed.ToUniversalTime().ToString('o');SourceCandidatePath=$CandidatePath;Counts=[pscustomobject][ordered]@{InputCandidates=$Rows.Count;Suppressed=$Suppressed.Count;FocusedReview=$Focused.Count;TrulyUnresolvedSidFamilies=$SidSummaries.Count;SidDelegationDetailFamilies=$SidSourceDetails.Count;PrioritizedEligibleTargetRows=$EligibleDetails.Count;EligibleFamilies=$Families.Count;PrioritizedFamilyOutput=$Selected.Count;OmittedForTrusteeDiversityLimit=$OmittedTrustee;OmittedByOutputLimit=$OmittedLimit;DomainReplicationTrustees=$Replication.Count};SelectedFamilyPriorityCounts=[pscustomobject]$Counters.SelectedPriority;SuppressionReasons=[pscustomobject]$Counters.Suppression;PrincipalClasses=[pscustomobject]$Counters.Principal;CapabilityCounts=[pscustomobject]$Counters.Capability;PlatformDispositions=[pscustomobject]$Counters.PlatformDisposition;Limits=[pscustomobject][ordered]@{MaximumPrioritizedFamilies=$MaximumPrioritizedFamilies;MaximumFamiliesPerTrustee=$MaximumFamiliesPerTrustee;MaximumRepresentativeTargets=$MaximumRepresentativeTargets;LimitAppliedAfterFamilyCollapse=$true;AdditionalEligibleFamiliesFile='directory-control-all-eligible-families.csv'};Telemetry=[pscustomobject][ordered]@{LoadSeconds=[math]::Round(($Loaded-$Started).TotalSeconds,3);ReductionSeconds=[math]::Round(($Reduced-$Loaded).TotalSeconds,3);OutputSeconds=[math]::Round(($Completed-$Reduced).TotalSeconds,3);TotalSeconds=[math]::Round(($Completed-$Started).TotalSeconds,3)};Controls=[pscustomobject][ordered]@{NamedPrincipalClassification=$true;TrueUnresolvedSidIsolation=$true;SidResolutionSummaryCollapse=$true;SidDelegationSourceDetail=$true;PlatformControlDispositions=$true;TargetStateEnrichment=$true;ProtectedObjectEvidenceLevels=$true;InheritanceSourceGrouping=$true;DomainRootReplicationCorrelation=$true;HtmlReportContract=$true};InterpretationBoundary=$HtmlContract.Interpretation;Safety=[pscustomobject][ordered]@{NetworkActivity='None';DirectoryQueries='None';AuthenticationAttempts='None';DirectoryChanges='None';RemoteChanges='None';SourceEvidenceModified=$false}}
Write-JsonDocument $Summary (Join-Path $OutputDirectory 'directory-control-reduction-summary.json')
$Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File|Where-Object{$_.Name -ne 'evidence-manifest.json'}|Sort-Object Name|ForEach-Object{[pscustomobject][ordered]@{Name=$_.Name;Size=[int64]$_.Length;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
Write-JsonDocument ([pscustomobject][ordered]@{SchemaVersion='1.0';Status='Completed';ModuleId=$ModuleId;ModuleVersion=$ToolVersion;FileCount=$Files.Count;Files=$Files}) (Join-Path $OutputDirectory 'evidence-manifest.json')
Write-Status DONE "families=$($Selected.Count); eligible-targets=$($EligibleDetails.Count); focused=$($Focused.Count); unresolved-sid-families=$($SidSummaries.Count); suppressed=$($Suppressed.Count)." Green
[pscustomobject][ordered]@{Status='Passed';ToolVersion=$ToolVersion;InputCandidates=$Rows.Count;PrioritizedFamilyOutput=$Selected.Count;PrioritizedEligibleTargetRows=$EligibleDetails.Count;FocusedReview=$Focused.Count;TrulyUnresolvedSidFamilies=$SidSummaries.Count;Suppressed=$Suppressed.Count;OutputDirectory=$OutputDirectory;SummaryPath=(Join-Path $OutputDirectory 'directory-control-reduction-summary.json');HtmlReportContractPath=(Join-Path $OutputDirectory 'directory-control-html-report-contract.json');NetworkActivity='None';RemoteChanges='None'}
