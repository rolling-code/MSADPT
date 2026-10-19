<#
.SYNOPSIS
Collects read-only Active Directory Authentication Policy and Authentication Policy Silo evidence.

.DESCRIPTION
Collects Authentication Policy objects, Authentication Policy Silo objects, configured silo members,
policy and silo assignments on users/computers/managed service accounts, Protected Users membership,
relevant principal posture, and policy/silo ACLs through one explicitly specified ADWS-reachable domain controller.

The collector does not change policies, silos, memberships, accounts, delegation, tickets, credentials, or secrets.

.NOTES
Version: 1.0.0
Supports Windows PowerShell 5.1 and PowerShell 7 on Windows with the ActiveDirectory module.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [ValidateRange(100, 10000)]
    [int]$ResultPageSize = 500,

    [Parameter()]
    [switch]$PlanOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Version = '1.0.0'

function Write-MSADPTStatus {
    param(
        [ValidateSet('INFO', 'COLLECT', 'PASS', 'WARN', 'FAIL')]
        [string]$Level,
        [string]$Message
    )

    $Color = switch ($Level) {
        'INFO' { 'Gray' }
        'COLLECT' { 'Cyan' }
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
    }

    Write-Host ('[{0,-8}] {1}' -f $Level, $Message) -ForegroundColor $Color
}

function Resolve-MSADPTPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath(
        (Join-Path (Get-Location).Path $Path)
    )
}

function Write-MSADPTJson {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [int]$Depth = 16
    )

    ConvertTo-Json -InputObject $Value -Depth $Depth |
        Set-Content -LiteralPath $Path -Encoding UTF8
}

function Add-MSADPTError {
    param(
        [string]$Stage,
        [string]$Target,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $script:OperationalErrors.Add([pscustomobject][ordered]@{
        Stage = $Stage
        Target = $Target
        Message = $ErrorRecord.Exception.Message
        ExceptionType = $ErrorRecord.Exception.GetType().FullName
        FullyQualifiedErrorId = $ErrorRecord.FullyQualifiedErrorId
        RecordedUtc = (Get-Date).ToUniversalTime().ToString('o')
    })
}

function ConvertTo-MSADPTSidText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        return [string]$Value.Value
    }
    catch {
        return [string]$Value
    }
}

function Get-MSADPTLeafClass {
    param([AllowNull()][object]$ObjectClass)

    $Classes = @($ObjectClass | ForEach-Object { [string]$_ })
    if ($Classes.Count -eq 0) {
        return $null
    }

    return $Classes[$Classes.Count - 1]
}

function ConvertTo-MSADPTPrincipalRecord {
    param(
        [Parameter(Mandatory = $true)][object]$DirectoryObject,
        [Parameter(Mandatory = $true)][string]$EvidenceSource
    )

    $UserAccountControl = if ($null -ne $DirectoryObject.userAccountControl) {
        [int64]$DirectoryObject.userAccountControl
    }
    else {
        $null
    }

    [pscustomobject][ordered]@{
        EvidenceSource = $EvidenceSource
        Name = [string]$DirectoryObject.Name
        SamAccountName = [string]$DirectoryObject.sAMAccountName
        DistinguishedName = [string]$DirectoryObject.DistinguishedName
        ObjectClass = Get-MSADPTLeafClass -ObjectClass $DirectoryObject.objectClass
        ObjectGuid = if ($DirectoryObject.ObjectGUID) { ([guid]$DirectoryObject.ObjectGUID).Guid } else { $null }
        ObjectSid = ConvertTo-MSADPTSidText -Value $DirectoryObject.objectSid
        Enabled = if ($null -ne $DirectoryObject.enabled) { [bool]$DirectoryObject.enabled } else { $null }
        AdminCount = $DirectoryObject.adminCount
        UserAccountControl = $UserAccountControl
        AccountNotDelegated = if ($null -ne $UserAccountControl) { ($UserAccountControl -band 0x100000) -ne 0 } else { $null }
        TrustedForDelegation = if ($null -ne $UserAccountControl) { ($UserAccountControl -band 0x80000) -ne 0 } else { $null }
        TrustedToAuthForDelegation = if ($null -ne $UserAccountControl) { ($UserAccountControl -band 0x1000000) -ne 0 } else { $null }
        PasswordNeverExpires = if ($null -ne $UserAccountControl) { ($UserAccountControl -band 0x10000) -ne 0 } else { $null }
        AssignedAuthenticationPolicy = [string]$DirectoryObject.'msDS-AssignedAuthNPolicy'
        AssignedAuthenticationPolicySilo = [string]$DirectoryObject.'msDS-AssignedAuthNPolicySilo'
        AllowedToDelegateTo = @($DirectoryObject.'msDS-AllowedToDelegateTo')
        ResourceBasedConstrainedDelegationPresent = $null -ne $DirectoryObject.'msDS-AllowedToActOnBehalfOfOtherIdentity'
        SidHistory = @($DirectoryObject.sIDHistory | ForEach-Object { ConvertTo-MSADPTSidText -Value $_ })
        PasswordLastSet = $DirectoryObject.pwdLastSet
        LastLogonTimestamp = $DirectoryObject.lastLogonTimestamp
        WhenCreated = $DirectoryObject.whenCreated
        WhenChanged = $DirectoryObject.whenChanged
        SecretValuesCollected = $false
    }
}

function Get-MSADPTAclRows {
    param(
        [Parameter(Mandatory = $true)][string]$TargetType,
        [Parameter(Mandatory = $true)][string]$TargetName,
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    $Acl = Get-Acl -LiteralPath ('AD:\' + $DistinguishedName) -ErrorAction Stop

    return @(
        foreach ($Rule in $Acl.Access) {
            [pscustomobject][ordered]@{
                TargetType = $TargetType
                TargetName = $TargetName
                TargetDistinguishedName = $DistinguishedName
                Owner = [string]$Acl.Owner
                Trustee = [string]$Rule.IdentityReference
                AccessControlType = [string]$Rule.AccessControlType
                ActiveDirectoryRights = [string]$Rule.ActiveDirectoryRights
                ObjectTypeGuid = [string]$Rule.ObjectType
                InheritedObjectTypeGuid = [string]$Rule.InheritedObjectType
                IsInherited = [bool]$Rule.IsInherited
                InheritanceType = [string]$Rule.InheritanceType
                InheritanceFlags = [string]$Rule.InheritanceFlags
                PropagationFlags = [string]$Rule.PropagationFlags
            }
        }
    )
}

$OutputRoot = Resolve-MSADPTPath -Path $OutputRoot

$Plan = @(
    [pscustomobject][ordered]@{
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Read Authentication Policy and Authentication Policy Silo objects'
    }
    [pscustomobject][ordered]@{
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Read configured silo members and assigned policy/silo references'
    }
    [pscustomobject][ordered]@{
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Read Protected Users membership and relevant principal posture'
    }
    [pscustomobject][ordered]@{
        Target = $Server
        Protocol = 'ADWS / Active Directory provider'
        Ports = '9389 TCP'
        Operation = 'Read Authentication Policy and Silo ACLs'
    }
)

Write-Host ''
Write-Host '=== MSADPT Authentication Policy security collection ===' -ForegroundColor Cyan
$Plan | Format-Table -AutoSize -Wrap
Write-Host ''
Write-Host ('Output directory  : {0}' -f $OutputRoot) -ForegroundColor Gray
Write-Host ('Directory server  : {0}' -f $Server) -ForegroundColor Gray
Write-Host 'Authentication    : Current Windows session' -ForegroundColor Gray
Write-Host 'Directory writes  : None' -ForegroundColor Green
Write-Host 'Policy changes    : None' -ForegroundColor Green
Write-Host 'Silo changes      : None' -ForegroundColor Green
Write-Host 'Membership changes: None' -ForegroundColor Green
Write-Host 'Tickets requested : None' -ForegroundColor Green
Write-Host 'Passwords/secrets : Not requested' -ForegroundColor Green
Write-Host ''

if ($PlanOnly) {
    return [pscustomobject][ordered]@{
        Status = 'Planned'
        Version = $Version
        Server = $Server
        Plan = $Plan
        NetworkExecuted = $false
        DirectoryChanges = 'None'
        PolicyChanges = 0
        SiloChanges = 0
        MembershipChanges = 0
        TicketsRequested = 0
        OutputRoot = $OutputRoot
    }
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw 'ActiveDirectoryModuleMissing: install the Active Directory RSAT PowerShell module.'
}

Import-Module ActiveDirectory -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$RawDirectory = Join-Path $OutputRoot 'Raw'
New-Item -ItemType Directory -Path $RawDirectory -Force | Out-Null

$script:OperationalErrors = [System.Collections.Generic.List[object]]::new()
$StartedUtc = (Get-Date).ToUniversalTime()
$RootDse = Get-ADRootDSE -Server $Server -ErrorAction Stop
$Domain = Get-ADDomain -Server $Server -ErrorAction Stop
$DomainSearchBase = [string]$Domain.DistinguishedName
$ConfigurationNamingContext = [string]$RootDse.configurationNamingContext
$AuthNConfigurationBase = 'CN=AuthN Policy Configuration,CN=Services,{0}' -f $ConfigurationNamingContext
$AuthenticationPoliciesBase = 'CN=AuthN Policies,{0}' -f $AuthNConfigurationBase
$AuthenticationPolicySilosBase = 'CN=AuthN Silos,{0}' -f $AuthNConfigurationBase

$PolicyProperties = @(
    'displayName',
    'description',
    'msDS-UserTGTLifetime',
    'msDS-ServiceTGTLifetime',
    'msDS-ComputerTGTLifetime',
    'msDS-UserAllowedToAuthenticateFrom',
    'msDS-UserAllowedToAuthenticateTo',
    'msDS-ServiceAllowedToAuthenticateFrom',
    'msDS-ServiceAllowedToAuthenticateTo',
    'msDS-ComputerAllowedToAuthenticateTo',
    'whenCreated',
    'whenChanged'
)

$SiloProperties = @(
    'displayName',
    'description',
    'msDS-AuthNPolicySiloEnforced',
    'msDS-AuthNPolicySiloMembers',
    'msDS-UserAuthNPolicy',
    'msDS-ServiceAuthNPolicy',
    'msDS-ComputerAuthNPolicy',
    'whenCreated',
    'whenChanged'
)

$PrincipalProperties = @(
    'objectClass',
    'objectSid',
    'sAMAccountName',
    'enabled',
    'adminCount',
    'userAccountControl',
    'msDS-AssignedAuthNPolicy',
    'msDS-AssignedAuthNPolicySilo',
    'msDS-AllowedToDelegateTo',
    'msDS-AllowedToActOnBehalfOfOtherIdentity',
    'sIDHistory',
    'pwdLastSet',
    'lastLogonTimestamp',
    'whenCreated',
    'whenChanged'
)

Write-MSADPTStatus -Level COLLECT -Message 'Reading Authentication Policy objects.'
$AuthenticationPolicies = @()
try {
    $AuthenticationPolicies = @(
        Get-ADObject `
            -LDAPFilter '(objectClass=msDS-AuthNPolicy)' `
            -SearchBase $AuthenticationPoliciesBase `
            -SearchScope OneLevel `
            -Server $Server `
            -ResultPageSize $ResultPageSize `
            -Properties $PolicyProperties `
            -ErrorAction Stop |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name = $_.Name
                DisplayName = $_.displayName
                Description = $_.description
                DistinguishedName = $_.DistinguishedName
                ObjectGuid = ([guid]$_.ObjectGUID).Guid
                UserTgtLifetime = $_.'msDS-UserTGTLifetime'
                ServiceTgtLifetime = $_.'msDS-ServiceTGTLifetime'
                ComputerTgtLifetime = $_.'msDS-ComputerTGTLifetime'
                UserAllowedToAuthenticateFrom = [string]$_.'msDS-UserAllowedToAuthenticateFrom'
                UserAllowedToAuthenticateTo = [string]$_.'msDS-UserAllowedToAuthenticateTo'
                ServiceAllowedToAuthenticateFrom = [string]$_.'msDS-ServiceAllowedToAuthenticateFrom'
                ServiceAllowedToAuthenticateTo = [string]$_.'msDS-ServiceAllowedToAuthenticateTo'
                ComputerAllowedToAuthenticateTo = [string]$_.'msDS-ComputerAllowedToAuthenticateTo'
                WhenCreated = $_.whenCreated
                WhenChanged = $_.whenChanged
            }
        }
    )
}
catch {
    Add-MSADPTError -Stage 'AuthenticationPolicies' -Target $AuthenticationPoliciesBase -ErrorRecord $_
}

Write-MSADPTStatus -Level COLLECT -Message 'Reading Authentication Policy Silo objects.'
$AuthenticationPolicySilos = @()
try {
    $AuthenticationPolicySilos = @(
        Get-ADObject `
            -LDAPFilter '(objectClass=msDS-AuthNPolicySilo)' `
            -SearchBase $AuthenticationPolicySilosBase `
            -SearchScope OneLevel `
            -Server $Server `
            -ResultPageSize $ResultPageSize `
            -Properties $SiloProperties `
            -ErrorAction Stop |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name = $_.Name
                DisplayName = $_.displayName
                Description = $_.description
                DistinguishedName = $_.DistinguishedName
                ObjectGuid = ([guid]$_.ObjectGUID).Guid
                Enforced = [bool]$_.'msDS-AuthNPolicySiloEnforced'
                MemberDistinguishedNames = @($_.'msDS-AuthNPolicySiloMembers')
                MemberCount = @($_.'msDS-AuthNPolicySiloMembers').Count
                UserAuthenticationPolicy = [string]$_.'msDS-UserAuthNPolicy'
                ServiceAuthenticationPolicy = [string]$_.'msDS-ServiceAuthNPolicy'
                ComputerAuthenticationPolicy = [string]$_.'msDS-ComputerAuthNPolicy'
                WhenCreated = $_.whenCreated
                WhenChanged = $_.whenChanged
            }
        }
    )
}
catch {
    Add-MSADPTError -Stage 'AuthenticationPolicySilos' -Target $AuthenticationPolicySilosBase -ErrorRecord $_
}

Write-MSADPTStatus -Level COLLECT -Message 'Resolving Authentication Policy Silo member references.'
$SiloMemberRelationships = [System.Collections.Generic.List[object]]::new()
$UnresolvedReferences = [System.Collections.Generic.List[object]]::new()
$PrincipalIndex = @{}

foreach ($Silo in $AuthenticationPolicySilos) {
    foreach ($MemberDn in @($Silo.MemberDistinguishedNames)) {
        if ([string]::IsNullOrWhiteSpace([string]$MemberDn)) {
            continue
        }

        try {
            $MemberMatches = @(
                Get-ADObject `
                    -LDAPFilter '(objectClass=*)' `
                    -SearchBase ([string]$MemberDn) `
                    -SearchScope Base `
                    -Server $Server `
                    -ResultSetSize 2 `
                    -Properties $PrincipalProperties `
                    -ErrorAction Stop
            )

            if ($MemberMatches.Count -ne 1) {
                throw "Expected one silo member object; received $($MemberMatches.Count)."
            }

            $PrincipalRecord = ConvertTo-MSADPTPrincipalRecord `
                -DirectoryObject $MemberMatches[0] `
                -EvidenceSource 'AuthenticationPolicySiloMember'

            if ($PrincipalRecord.ObjectSid) {
                $PrincipalIndex[$PrincipalRecord.ObjectSid] = $PrincipalRecord
            }

            $SiloMemberRelationships.Add([pscustomobject][ordered]@{
                SiloName = $Silo.Name
                SiloDistinguishedName = $Silo.DistinguishedName
                SiloEnforced = $Silo.Enforced
                ConfiguredMemberDistinguishedName = [string]$MemberDn
                MemberName = $PrincipalRecord.Name
                MemberSamAccountName = $PrincipalRecord.SamAccountName
                MemberObjectClass = $PrincipalRecord.ObjectClass
                MemberObjectSid = $PrincipalRecord.ObjectSid
                AssignedAuthenticationPolicy = $PrincipalRecord.AssignedAuthenticationPolicy
                AssignedAuthenticationPolicySilo = $PrincipalRecord.AssignedAuthenticationPolicySilo
                AssignmentMatchesSilo = $PrincipalRecord.AssignedAuthenticationPolicySilo -eq $Silo.DistinguishedName
                ResolutionStatus = 'Resolved'
            })
        }
        catch {
            $UnresolvedReferences.Add([pscustomobject][ordered]@{
                ReferenceType = 'SiloMember'
                ParentName = $Silo.Name
                ParentDistinguishedName = $Silo.DistinguishedName
                ReferencedDistinguishedName = [string]$MemberDn
                ResolutionStatus = 'Unresolved'
                ErrorMessage = $_.Exception.Message
            })
        }
    }
}

Write-MSADPTStatus -Level COLLECT -Message 'Reading principals with assigned Authentication Policies or Silos.'
$AssignedPrincipals = @()
try {
    $AssignedPrincipals = @(
        Get-ADObject `
            -LDAPFilter '(|(msDS-AssignedAuthNPolicy=*)(msDS-AssignedAuthNPolicySilo=*))' `
            -SearchBase $DomainSearchBase `
            -SearchScope Subtree `
            -Server $Server `
            -ResultPageSize $ResultPageSize `
            -Properties $PrincipalProperties `
            -ErrorAction Stop |
        ForEach-Object {
            $Record = ConvertTo-MSADPTPrincipalRecord `
                -DirectoryObject $_ `
                -EvidenceSource 'AssignedPolicyOrSilo'

            if ($Record.ObjectSid) {
                $PrincipalIndex[$Record.ObjectSid] = $Record
            }

            $Record
        }
    )
}
catch {
    Add-MSADPTError -Stage 'AssignedPoliciesAndSilos' -Target $DomainSearchBase -ErrorRecord $_
}

Write-MSADPTStatus -Level COLLECT -Message 'Reading Protected Users direct and recursive membership.'
$ProtectedUsersGroup = $null
$ProtectedUsersMembership = [System.Collections.Generic.List[object]]::new()
try {
    $ProtectedUsersSid = '{0}-525' -f [string]$Domain.DomainSID
    $ProtectedUsersGroup = Get-ADGroup `
        -Identity $ProtectedUsersSid `
        -Server $Server `
        -Properties @('objectSid', 'member', 'whenChanged') `
        -ErrorAction Stop

    $ProtectedMembers = @(
        Get-ADGroupMember `
            -Identity $ProtectedUsersGroup.DistinguishedName `
            -Server $Server `
            -Recursive `
            -ErrorAction Stop
    )

    foreach ($Member in $ProtectedMembers) {
        try {
            $MemberObject = Get-ADObject `
                -Identity $Member.DistinguishedName `
                -Server $Server `
                -Properties $PrincipalProperties `
                -ErrorAction Stop

            $PrincipalRecord = ConvertTo-MSADPTPrincipalRecord `
                -DirectoryObject $MemberObject `
                -EvidenceSource 'ProtectedUsersRecursiveMember'

            if ($PrincipalRecord.ObjectSid) {
                $PrincipalIndex[$PrincipalRecord.ObjectSid] = $PrincipalRecord
            }

            $ProtectedUsersMembership.Add([pscustomobject][ordered]@{
                GroupName = $ProtectedUsersGroup.Name
                GroupDistinguishedName = $ProtectedUsersGroup.DistinguishedName
                MemberName = $PrincipalRecord.Name
                MemberSamAccountName = $PrincipalRecord.SamAccountName
                MemberDistinguishedName = $PrincipalRecord.DistinguishedName
                MemberObjectClass = $PrincipalRecord.ObjectClass
                MemberObjectSid = $PrincipalRecord.ObjectSid
                Enabled = $PrincipalRecord.Enabled
                AdminCount = $PrincipalRecord.AdminCount
                AssignedAuthenticationPolicy = $PrincipalRecord.AssignedAuthenticationPolicy
                AssignedAuthenticationPolicySilo = $PrincipalRecord.AssignedAuthenticationPolicySilo
            })
        }
        catch {
            $UnresolvedReferences.Add([pscustomobject][ordered]@{
                ReferenceType = 'ProtectedUsersMember'
                ParentName = $ProtectedUsersGroup.Name
                ParentDistinguishedName = $ProtectedUsersGroup.DistinguishedName
                ReferencedDistinguishedName = [string]$Member.DistinguishedName
                ResolutionStatus = 'Unresolved'
                ErrorMessage = $_.Exception.Message
            })
        }
    }
}
catch {
    Add-MSADPTError -Stage 'ProtectedUsersMembership' -Target $Server -ErrorRecord $_
}

Write-MSADPTStatus -Level COLLECT -Message 'Reading Authentication Policy and Silo ACLs.'
$AuthenticationPolicyAcls = [System.Collections.Generic.List[object]]::new()
$AuthenticationPolicySiloAcls = [System.Collections.Generic.List[object]]::new()

foreach ($Policy in $AuthenticationPolicies) {
    try {
        foreach ($AclRow in @(Get-MSADPTAclRows `
            -TargetType 'AuthenticationPolicy' `
            -TargetName $Policy.Name `
            -DistinguishedName $Policy.DistinguishedName)) {
            $AuthenticationPolicyAcls.Add($AclRow)
        }
    }
    catch {
        Add-MSADPTError -Stage 'AuthenticationPolicyAcl' -Target $Policy.DistinguishedName -ErrorRecord $_
    }
}

foreach ($Silo in $AuthenticationPolicySilos) {
    try {
        foreach ($AclRow in @(Get-MSADPTAclRows `
            -TargetType 'AuthenticationPolicySilo' `
            -TargetName $Silo.Name `
            -DistinguishedName $Silo.DistinguishedName)) {
            $AuthenticationPolicySiloAcls.Add($AclRow)
        }
    }
    catch {
        Add-MSADPTError -Stage 'AuthenticationPolicySiloAcl' -Target $Silo.DistinguishedName -ErrorRecord $_
    }
}

$PolicyDnSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$SiloDnSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($Policy in $AuthenticationPolicies) { $null = $PolicyDnSet.Add($Policy.DistinguishedName) }
foreach ($Silo in $AuthenticationPolicySilos) { $null = $SiloDnSet.Add($Silo.DistinguishedName) }

foreach ($Principal in $AssignedPrincipals) {
    if ($Principal.AssignedAuthenticationPolicy -and -not $PolicyDnSet.Contains($Principal.AssignedAuthenticationPolicy)) {
        $UnresolvedReferences.Add([pscustomobject][ordered]@{
            ReferenceType = 'AssignedAuthenticationPolicy'
            ParentName = $Principal.Name
            ParentDistinguishedName = $Principal.DistinguishedName
            ReferencedDistinguishedName = $Principal.AssignedAuthenticationPolicy
            ResolutionStatus = 'NotPresentInCollectedPolicyInventory'
            ErrorMessage = $null
        })
    }

    if ($Principal.AssignedAuthenticationPolicySilo -and -not $SiloDnSet.Contains($Principal.AssignedAuthenticationPolicySilo)) {
        $UnresolvedReferences.Add([pscustomobject][ordered]@{
            ReferenceType = 'AssignedAuthenticationPolicySilo'
            ParentName = $Principal.Name
            ParentDistinguishedName = $Principal.DistinguishedName
            ReferencedDistinguishedName = $Principal.AssignedAuthenticationPolicySilo
            ResolutionStatus = 'NotPresentInCollectedSiloInventory'
            ErrorMessage = $null
        })
    }
}

$ConfigurationContext = [pscustomobject][ordered]@{
    Version = $Version
    Server = $Server
    DomainSearchBase = $DomainSearchBase
    ConfigurationNamingContext = $ConfigurationNamingContext
    AuthenticationPolicyConfigurationBase = $AuthNConfigurationBase
    AuthenticationPoliciesBase = $AuthenticationPoliciesBase
    AuthenticationPolicySilosBase = $AuthenticationPolicySilosBase
    ProtectedUsersGroupDistinguishedName = if ($ProtectedUsersGroup) { $ProtectedUsersGroup.DistinguishedName } else { $null }
    DirectoryChanges = 'None'
    PolicyChanges = 0
    SiloChanges = 0
    MembershipChanges = 0
    TicketsRequested = 0
    SecretValuesCollected = $false
}

$DataFiles = [ordered]@{
    'authentication-policy-context.json' = $ConfigurationContext
    'authentication-policies.json' = @($AuthenticationPolicies)
    'authentication-policy-silos.json' = @($AuthenticationPolicySilos)
    'authentication-policy-silo-members.json' = @($SiloMemberRelationships)
    'assigned-authentication-policy-principals.json' = @($AssignedPrincipals)
    'protected-users-membership.json' = @($ProtectedUsersMembership)
    'policy-relevant-principals.json' = @($PrincipalIndex.Values | Sort-Object DistinguishedName -Unique)
    'authentication-policy-acls.json' = @($AuthenticationPolicyAcls)
    'authentication-policy-silo-acls.json' = @($AuthenticationPolicySiloAcls)
    'unresolved-policy-references.json' = @($UnresolvedReferences)
    'operational-errors.json' = @($script:OperationalErrors)
    'collection-plan.json' = @($Plan)
}

foreach ($FileName in $DataFiles.Keys) {
    Write-MSADPTJson `
        -Value $DataFiles[$FileName] `
        -Path (Join-Path $RawDirectory $FileName)
}

$CompletedUtc = (Get-Date).ToUniversalTime()
$EvidenceFiles = @(
    Get-ChildItem -LiteralPath $RawDirectory -File |
        ForEach-Object {
            [pscustomobject][ordered]@{
                RelativePath = [System.IO.Path]::GetRelativePath($OutputRoot, $_.FullName)
                Length = $_.Length
                SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        }
)

$Manifest = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    ModuleId = 'Collect-MSADPTAuthenticationPolicySecurity'
    ModuleVersion = $Version
    StartedUtc = $StartedUtc.ToString('o')
    CompletedUtc = $CompletedUtc.ToString('o')
    DurationSeconds = [math]::Round(($CompletedUtc - $StartedUtc).TotalSeconds, 3)
    Server = $Server
    AuthenticationPolicyCount = $AuthenticationPolicies.Count
    AuthenticationPolicySiloCount = $AuthenticationPolicySilos.Count
    EnforcedSiloCount = @($AuthenticationPolicySilos | Where-Object { $_.Enforced }).Count
    SiloMemberRelationshipCount = $SiloMemberRelationships.Count
    AssignedPrincipalCount = $AssignedPrincipals.Count
    ProtectedUsersMemberCount = $ProtectedUsersMembership.Count
    PolicyRelevantPrincipalCount = $PrincipalIndex.Count
    AuthenticationPolicyAclCount = $AuthenticationPolicyAcls.Count
    AuthenticationPolicySiloAclCount = $AuthenticationPolicySiloAcls.Count
    UnresolvedReferenceCount = $UnresolvedReferences.Count
    OperationalErrorCount = $script:OperationalErrors.Count
    DirectoryChanges = 'None'
    PolicyChanges = 0
    SiloChanges = 0
    MembershipChanges = 0
    TicketsRequested = 0
    SecretValuesCollected = $false
    Files = $EvidenceFiles
}

$ManifestPath = Join-Path $OutputRoot 'evidence-manifest.json'
Write-MSADPTJson -Value $Manifest -Path $ManifestPath -Depth 10

$Status = if ($script:OperationalErrors.Count -gt 0) { 'Partial' } else { 'Completed' }
$ConsoleLevel = if ($Status -eq 'Completed') { 'PASS' } else { 'WARN' }
Write-MSADPTStatus -Level $ConsoleLevel -Message "Collection complete: $OutputRoot"

[pscustomobject][ordered]@{
    Status = $Status
    Version = $Version
    OutputRoot = $OutputRoot
    Server = $Server
    AuthenticationPolicyCount = $AuthenticationPolicies.Count
    AuthenticationPolicySiloCount = $AuthenticationPolicySilos.Count
    EnforcedSiloCount = $Manifest.EnforcedSiloCount
    SiloMemberRelationshipCount = $SiloMemberRelationships.Count
    AssignedPrincipalCount = $AssignedPrincipals.Count
    ProtectedUsersMemberCount = $ProtectedUsersMembership.Count
    PolicyRelevantPrincipalCount = $PrincipalIndex.Count
    AuthenticationPolicyAclCount = $AuthenticationPolicyAcls.Count
    AuthenticationPolicySiloAclCount = $AuthenticationPolicySiloAcls.Count
    UnresolvedReferenceCount = $UnresolvedReferences.Count
    OperationalErrorCount = $script:OperationalErrors.Count
    DirectoryChanges = 'None'
    PolicyChanges = 0
    SiloChanges = 0
    MembershipChanges = 0
    ManifestPath = $ManifestPath
}
