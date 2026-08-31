<#
.SYNOPSIS
Performs read-only AD CS attack-path prerequisite validation for MSADPT.
.DESCRIPTION
Consumes completed ADCSConfigurationCollection evidence, identifies evidence-backed candidate principals,
resolves them through portable LDAP searches, and exports flattened group-membership and classified
object-control evidence. Native AD and SID objects are converted to scalar values before JSON serialization.
This module does not request certificates, test authentication, modify Active Directory, or modify AD CS.
.NOTES
Version: 0.1.5
Execution class: read_only
Compatible with Windows PowerShell 5.1 and PowerShell 7 when the ActiveDirectory module is available.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EngagementPath,

    [Parameter()]
    [PSCredential]$Credential
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$EvidenceHelperPath = Join-Path $RepositoryRoot 'Common\MSADPT.Evidence.psm1'
Import-Module $EvidenceHelperPath -Force -ErrorAction Stop
$ModuleVersion = '0.1.5'
$AnalysisVersion = '1.2.0'
$EmptyGuid = [guid]::Empty
$MemberAttributeGuid = [guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'

function Test-MSADPTBooleanText {
    param($Value)
    if ($Value -is [bool]) { return [bool]$Value }
    return ([string]$Value -eq 'True')
}

function Test-MSADPTRoutinePrivilegedIdentity {
    param([string]$IdentityReference)
    return ($IdentityReference -match '(?i)\\(Domain Admins|Enterprise Admins|Administrators)$')
}

function Test-MSADPTWellKnownSid {
    param([System.Security.Principal.SecurityIdentifier]$Sid)
    if ($null -eq $Sid) { return $false }
    return ($Sid.Value -notmatch '^S-1-5-21-')
}

function ConvertTo-MSADPTLdapEscapedValue {
    param([string]$Value)
    if ($null -eq $Value) { return $null }
    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
}

function ConvertTo-MSADPTLdapSidFilterValue {
    param([System.Security.Principal.SecurityIdentifier]$Sid)
    $Bytes = New-Object byte[] $Sid.BinaryLength
    $Sid.GetBinaryForm($Bytes, 0)
    return (($Bytes | ForEach-Object { '\' + $_.ToString('X2') }) -join '')
}

function Resolve-MSADPTSid {
    param([string]$IdentityReference)
    try {
        if ($IdentityReference -match '^S-1-') {
            return [System.Security.Principal.SecurityIdentifier]$IdentityReference
        }
        return ([System.Security.Principal.NTAccount]$IdentityReference).Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        return $null
    }
}

function ConvertTo-MSADPTFlatMember {
    param($Member)
    $SidText = $null
    if ($null -ne $Member.SID) {
        if ($null -ne $Member.SID.Value) { $SidText = [string]$Member.SID.Value }
        else { $SidText = [string]$Member.SID }
    }
    return [pscustomobject][ordered]@{
        Name = [string]$Member.Name
        SamAccountName = [string]$Member.SamAccountName
        ObjectClass = [string]$Member.ObjectClass
        DistinguishedName = [string]$Member.DistinguishedName
        Sid = $SidText
    }
}

function Test-MSADPTRightsMask {
    param([int64]$Value, [int64]$Mask)
    if ($Mask -eq 0) { return $false }
    return (($Value -band $Mask) -eq $Mask)
}

function ConvertTo-MSADPTClassifiedControlAce {
    param($AccessRule)

    $RightsValue = [int64]$AccessRule.ActiveDirectoryRights
    $ObjectType = [guid]$AccessRule.ObjectType
    $IsAllow = ([string]$AccessRule.AccessControlType -eq 'Allow')
    $HasGenericAll = Test-MSADPTRightsMask $RightsValue ([int64][System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
    $HasGenericWrite = Test-MSADPTRightsMask $RightsValue ([int64][System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)
    $HasWriteDacl = Test-MSADPTRightsMask $RightsValue ([int64][System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)
    $HasWriteOwner = Test-MSADPTRightsMask $RightsValue ([int64][System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)
    $HasWriteProperty = Test-MSADPTRightsMask $RightsValue ([int64][System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)

    $Classification = 'PropertySpecificControl'
    $Reason = 'The ACE grants a property-specific write permission.'
    if (-not $IsAllow) {
        $Classification = 'DenyControl'
        $Reason = 'The ACE is a deny ACE and is preserved for effective-access analysis.'
    }
    elseif ($HasWriteDacl -or $HasWriteOwner) {
        $Classification = 'OwnerOrDaclControl'
        $Reason = 'The ACE grants WriteDacl or WriteOwner.'
    }
    elseif ($HasGenericAll -or $HasGenericWrite) {
        $Classification = 'BroadObjectControl'
        $Reason = 'The ACE grants GenericAll or GenericWrite.'
    }
    elseif ($HasWriteProperty -and $ObjectType -eq $MemberAttributeGuid) {
        $Classification = 'MembershipControl'
        $Reason = 'The ACE grants WriteProperty over the group member attribute.'
    }
    elseif ($HasWriteProperty -and $ObjectType -eq $EmptyGuid) {
        $Classification = 'BroadPropertyControl'
        $Reason = 'The ACE grants unrestricted WriteProperty.'
    }

    $Identity = [string]$AccessRule.IdentityReference.Value
    $Administrative = ($Identity -match '^(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators)$' -or (Test-MSADPTRoutinePrivilegedIdentity $Identity))

    return [pscustomobject][ordered]@{
        IdentityReference = $Identity
        AccessControlType = [string]$AccessRule.AccessControlType
        ActiveDirectoryRights = [string]$AccessRule.ActiveDirectoryRights
        ObjectType = $ObjectType.ToString()
        IsInherited = [bool]$AccessRule.IsInherited
        Classification = $Classification
        IsPrivilegedOrSystem = [bool]$Administrative
        Reason = $Reason
    }
}

function Get-MSADPTObjectControlEvidence {
    param([string]$DistinguishedName)
    try {
        $Acl = Get-Acl -LiteralPath ('AD:\' + $DistinguishedName) -ErrorAction Stop
        $AllClassified = @(
            $Acl.Access |
                Where-Object {
                    [string]$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty'
                } |
                ForEach-Object { ConvertTo-MSADPTClassifiedControlAce $_ }
        )
        $Relevant = @(
            $AllClassified |
                Where-Object {
                    $_.Classification -in @('BroadObjectControl','OwnerOrDaclControl','MembershipControl','BroadPropertyControl','DenyControl')
                }
        )
        return [pscustomobject][ordered]@{
            Owner = [string]$Acl.Owner
            RelevantEntries = $Relevant
            TotalWriteRelatedAceCount = $AllClassified.Count
            RelevantControlAceCount = $Relevant.Count
            InheritedRelevantControlAceCount = @($Relevant | Where-Object IsInherited).Count
            ExplicitRelevantControlAceCount = @($Relevant | Where-Object { -not $_.IsInherited }).Count
            Error = $null
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Owner = $null; RelevantEntries = @(); TotalWriteRelatedAceCount = 0; RelevantControlAceCount = 0
            InheritedRelevantControlAceCount = 0; ExplicitRelevantControlAceCount = 0; Error = $_.Exception.Message
        }
    }
}

function Find-MSADPTDirectoryObject {
    param(
        [System.Security.Principal.SecurityIdentifier]$Sid,
        [string]$IdentityReference,
        [hashtable]$CommonAdParameters
    )

    $Properties = @('objectSid','objectClass','sAMAccountName','userAccountControl','lastLogonTimestamp','memberOf','whenCreated','whenChanged')
    $SidError = $null
    if ($null -ne $Sid -and -not (Test-MSADPTWellKnownSid $Sid)) {
        $SidFilterValue = ConvertTo-MSADPTLdapSidFilterValue $Sid
        try {
            $Matches = @(Get-ADObject @CommonAdParameters -LDAPFilter "(objectSid=$SidFilterValue)" -Properties $Properties)
            if ($Matches.Count -eq 1) { return [pscustomobject]@{ Object=$Matches[0]; Method='LdapObjectSid'; Error=$null } }
            if ($Matches.Count -gt 1) { return [pscustomobject]@{ Object=$null; Method='LdapObjectSid'; Error='Multiple directory objects matched the SID.' } }
        }
        catch { $SidError = $_.Exception.Message }
    }

    $SamAccountName = ($IdentityReference -split '\\',2)[-1]
    if (-not [string]::IsNullOrWhiteSpace($SamAccountName)) {
        $EscapedSam = ConvertTo-MSADPTLdapEscapedValue $SamAccountName
        try {
            $Matches = @(Get-ADObject @CommonAdParameters -LDAPFilter "(sAMAccountName=$EscapedSam)" -Properties $Properties)
            if ($Matches.Count -eq 1) { return [pscustomobject]@{ Object=$Matches[0]; Method='LdapSamAccountName'; Error=$null } }
            if ($Matches.Count -gt 1) { return [pscustomobject]@{ Object=$null; Method='LdapSamAccountName'; Error='Multiple directory objects matched sAMAccountName.' } }
        }
        catch { return [pscustomobject]@{ Object=$null; Method='LdapSamAccountName'; Error=$_.Exception.Message } }
    }

    $ErrorText = if ($SidError) { $SidError } else { 'No directory object matched the SID or sAMAccountName.' }
    return [pscustomobject]@{ Object=$null; Method='LdapObjectSidThenSamAccountName'; Error=$ErrorText }
}

function Resolve-MSADPTCandidateIdentity {
    param([string]$IdentityReference, [hashtable]$CommonAdParameters)

    $Limitations = New-Object 'System.Collections.Generic.List[string]'
    $Sid = Resolve-MSADPTSid $IdentityReference
    if ($null -ne $Sid -and (Test-MSADPTWellKnownSid $Sid)) {
        return [pscustomobject][ordered]@{
            IdentityReference=$IdentityReference; ResolutionStatus='WellKnownPrincipal'; ResolutionMethod='WindowsSidTranslation'; Sid=$Sid.Value
            ObjectClass=$null; DistinguishedName=$null; Enabled=$null; WhenCreated=$null; WhenChanged=$null; LastLogonTimestamp=$null
            DirectMembers=@(); RecursiveMembers=@(); MemberOf=@(); SecurityDescriptorOwner=$null; ControlEntries=@()
            TotalWriteRelatedAceCount=0; RelevantControlAceCount=0; ExplicitRelevantControlAceCount=0; InheritedRelevantControlAceCount=0
            Limitations=@('Well-known security principal; domain object lookup is not applicable.')
        }
    }

    $Search = Find-MSADPTDirectoryObject -Sid $Sid -IdentityReference $IdentityReference -CommonAdParameters $CommonAdParameters
    if ($null -eq $Search.Object) {
        $Status = if ($Search.Error -match '^Multiple') { 'Inconclusive' } elseif ($null -eq $Sid) { 'Inconclusive' } else { 'NotFound' }
        return [pscustomobject][ordered]@{
            IdentityReference=$IdentityReference; ResolutionStatus=$Status; ResolutionMethod=$Search.Method
            Sid=if($Sid){$Sid.Value}else{$null}; ObjectClass=$null; DistinguishedName=$null; Enabled=$null; WhenCreated=$null; WhenChanged=$null
            LastLogonTimestamp=$null; DirectMembers=@(); RecursiveMembers=@(); MemberOf=@(); SecurityDescriptorOwner=$null; ControlEntries=@()
            TotalWriteRelatedAceCount=0; RelevantControlAceCount=0; ExplicitRelevantControlAceCount=0; InheritedRelevantControlAceCount=0
            Limitations=@($Search.Error)
        }
    }

    $Object = $Search.Object
    $Classes = @($Object.objectClass | ForEach-Object { [string]$_ })
    $ObjectClass = if($Classes.Count -gt 0){$Classes[-1]}else{$null}
    $Enabled = $null
    if($ObjectClass -in @('user','computer') -and $null -ne $Object.userAccountControl){$Enabled=(([int64]$Object.userAccountControl -band 2)-eq 0)}

    $DirectMembers=@(); $RecursiveMembers=@()
    if($ObjectClass -eq 'group'){
        try{$DirectMembers=@(Get-ADGroupMember @CommonAdParameters -Identity $Object.DistinguishedName | ForEach-Object { ConvertTo-MSADPTFlatMember $_ })}
        catch{$Limitations.Add('Direct membership query failed: '+$_.Exception.Message)}
        try{$RecursiveMembers=@(Get-ADGroupMember @CommonAdParameters -Identity $Object.DistinguishedName -Recursive | ForEach-Object { ConvertTo-MSADPTFlatMember $_ })}
        catch{$Limitations.Add('Recursive membership query failed: '+$_.Exception.Message)}
    }

    $Security=Get-MSADPTObjectControlEvidence $Object.DistinguishedName
    if($Security.Error){$Limitations.Add('Security descriptor query failed: '+$Security.Error)}
    $ObjectSidText=if($null-ne$Object.ObjectSid -and $null-ne$Object.ObjectSid.Value){[string]$Object.ObjectSid.Value}else{[string]$Object.ObjectSid}

    return [pscustomobject][ordered]@{
        IdentityReference=$IdentityReference; ResolutionStatus='Resolved'; ResolutionMethod=$Search.Method; Sid=$ObjectSidText
        ObjectClass=$ObjectClass; DistinguishedName=[string]$Object.DistinguishedName; Enabled=$Enabled; WhenCreated=$Object.whenCreated
        WhenChanged=$Object.whenChanged; LastLogonTimestamp=if($null-ne$Object.lastLogonTimestamp){[string]$Object.lastLogonTimestamp}else{$null}
        DirectMembers=$DirectMembers; RecursiveMembers=$RecursiveMembers; MemberOf=@($Object.memberOf|ForEach-Object{[string]$_})
        SecurityDescriptorOwner=$Security.Owner; ControlEntries=@($Security.RelevantEntries)
        TotalWriteRelatedAceCount=$Security.TotalWriteRelatedAceCount; RelevantControlAceCount=$Security.RelevantControlAceCount
        ExplicitRelevantControlAceCount=$Security.ExplicitRelevantControlAceCount; InheritedRelevantControlAceCount=$Security.InheritedRelevantControlAceCount
        Limitations=@($Limitations)
    }
}

$StatePath=Join-Path $EngagementPath 'state\engagement-state.json'
$ConfigurationPath=Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection\certificate-template-configuration.json'
$AccessPath=Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection\certificate-template-access.csv'
foreach($RequiredPath in @($StatePath,$ConfigurationPath,$AccessPath)){if(-not(Test-Path -LiteralPath $RequiredPath -PathType Leaf)){throw "Required evidence not found: $RequiredPath"}}

$State=Get-Content -LiteralPath $StatePath -Raw|ConvertFrom-Json
$Server=[string]$State.BootstrapServer
if([string]::IsNullOrWhiteSpace($Server)){throw 'BootstrapServer is missing from engagement state.'}
Import-Module ActiveDirectory -ErrorAction Stop
$CommonAdParameters=@{Server=$Server;ErrorAction='Stop'}
if($null-ne$Credential){$CommonAdParameters.Credential=$Credential}

$Configuration=@(Get-Content -LiteralPath $ConfigurationPath -Raw|ConvertFrom-Json)
$AccessRows=@(Import-Csv -LiteralPath $AccessPath)
$CandidateTemplates=@($Configuration|Where-Object{[bool]$_.PublishedByDiscoveredCA -and -not[bool]$_.ManagerApprovalRequired -and -not[bool]$_.AuthorizedSignaturesRequired -and ([bool]$_.EnrolleeSuppliesSubject -or [bool]$_.EnrolleeSuppliesSubjectAltName) -and ([bool]$_.HasAuthenticationCapableEku -or [bool]$_.NoExtendedKeyUsageRestriction)}|Select-Object -ExpandProperty Name -Unique)

$CandidateRows=New-Object 'System.Collections.Generic.List[object]'
foreach($Row in $AccessRows){
    if(-not(Test-MSADPTBooleanText $Row.PublishedByDiscoveredCA)){continue}
    $Reasons=New-Object 'System.Collections.Generic.List[string]'
    if($CandidateTemplates -contains $Row.TemplateName -and (Test-MSADPTBooleanText $Row.AllowsEnroll)){$Reasons.Add('EnrollmentOnPublishedIdentitySupplyAuthenticationTemplate')}
    $BroadTemplateControl=((Test-MSADPTBooleanText $Row.AllowsGenericAll) -or (Test-MSADPTBooleanText $Row.AllowsGenericWrite) -or (Test-MSADPTBooleanText $Row.AllowsWriteDacl) -or (Test-MSADPTBooleanText $Row.AllowsWriteOwner) -or ((Test-MSADPTBooleanText $Row.AllowsWriteProperty) -and [string]$Row.ObjectType -eq $EmptyGuid.ToString()))
    if($BroadTemplateControl){$Reasons.Add('BroadTemplateControl')}
    if($Reasons.Count -gt 0 -and -not(Test-MSADPTRoutinePrivilegedIdentity $Row.IdentityReference)){$CandidateRows.Add([pscustomobject][ordered]@{IdentityReference=[string]$Row.IdentityReference;TemplateName=[string]$Row.TemplateName;Reasons=@($Reasons);ActiveDirectoryRights=[string]$Row.ActiveDirectoryRights;ObjectType=[string]$Row.ObjectType})}
}

$CandidateIdentities=@($CandidateRows|Select-Object -ExpandProperty IdentityReference -Unique|Sort-Object)
$ResolvedIdentities=@(foreach($Identity in $CandidateIdentities){Resolve-MSADPTCandidateIdentity $Identity $CommonAdParameters})
$OutputDirectory=Join-Path $EngagementPath 'evidence\ADCSAttackPathPrerequisiteValidation'
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
Write-MSADPTJsonEvidence -Path (Join-Path $OutputDirectory 'candidate-principals.json') -Value ([object[]]$CandidateRows.ToArray()) -Depth 8
Write-MSADPTJsonEvidence -Path (Join-Path $OutputDirectory 'resolved-identity-prerequisites.json') -Value ([object[]]$ResolvedIdentities) -Depth 8
$ResolvedIdentities|Select-Object IdentityReference,ResolutionStatus,ResolutionMethod,Sid,ObjectClass,DistinguishedName,Enabled,@{N='DirectMemberCount';E={@($_.DirectMembers).Count}},@{N='RecursiveMemberCount';E={@($_.RecursiveMembers).Count}},SecurityDescriptorOwner,TotalWriteRelatedAceCount,RelevantControlAceCount,ExplicitRelevantControlAceCount,InheritedRelevantControlAceCount,WhenCreated,WhenChanged,LastLogonTimestamp|Export-Csv -LiteralPath (Join-Path $OutputDirectory 'identity-prerequisite-summary.csv') -NoTypeInformation -Encoding UTF8

$ManifestPath = New-MSADPTEvidenceManifest -EvidenceDirectory $OutputDirectory -ModuleId 'ADCSAttackPathPrerequisiteValidation' -ModuleVersion $ModuleVersion
[pscustomobject][ordered]@{
    schemaVersion='1.1';module='ADCSAttackPathPrerequisiteValidation';moduleVersion=$ModuleVersion;analysisVersion=$AnalysisVersion
    status='Completed';executionClass='read_only';candidateTemplateCount=$CandidateTemplates.Count;candidatePrincipalCount=$CandidateIdentities.Count
    resolvedPrincipalCount=@($ResolvedIdentities|Where-Object ResolutionStatus -eq 'Resolved').Count
    wellKnownPrincipalCount=@($ResolvedIdentities|Where-Object ResolutionStatus -eq 'WellKnownPrincipal').Count
    unresolvedPrincipalCount=@($ResolvedIdentities|Where-Object{$_.ResolutionStatus -notin @('Resolved','WellKnownPrincipal')}).Count
    serializationDepth=8;targetCount=$CandidateIdentities.Count;candidateRelationshipCount=$CandidateRows.Count;uniqueCandidatePrincipalCount=$CandidateIdentities.Count
    evidence=@('evidence/ADCSAttackPathPrerequisiteValidation/candidate-principals.json','evidence/ADCSAttackPathPrerequisiteValidation/resolved-identity-prerequisites.json','evidence/ADCSAttackPathPrerequisiteValidation/identity-prerequisite-summary.csv')
    limitations=@('All member and SID values are flattened before serialization.','ControlEntries contains only broad, owner/DACL, membership, unrestricted property, and deny control ACEs.','Effective control still requires deny-ACE, inheritance, ownership, and nested-group evaluation.','LastLogonTimestamp is replicated and approximate.','CA runtime settings, enrollment, authentication, and state changes are not tested or performed.','When -Credential is supplied, AD cmdlets use that credential; AD provider ACL reads use the current process identity.')
    completedUtc=(Get-Date).ToUniversalTime().ToString('o')
}
