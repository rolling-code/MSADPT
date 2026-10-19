<#
.SYNOPSIS
Collects read-only Active Directory evidence for principals configured to retrieve gMSA managed passwords.

.DESCRIPTION
Consumes a previously collected MSADPT gMSA inventory JSON file and resolves each configured retrieval principal through a specified ADWS-reachable domain controller.

For group principals, the collector expands recursive membership and records normalized principal-to-gMSA relationships. It also checks direct membership in selected privileged groups. It does not request or export msDS-ManagedPassword, credentials, tickets, passwords, or other secret values.

.NOTES
Version: 1.0.2
Supports Windows PowerShell 5.1 and PowerShell 7 on Windows with the ActiveDirectory module.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GmsaInventoryPath,

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
    [string[]]$PrivilegedGroupSamAccountName = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'Account Operators',
        'Backup Operators',
        'Server Operators',
        'Print Operators',
        'Group Policy Creator Owners',
        'Key Admins',
        'Enterprise Key Admins'
    ),

    [Parameter()]
    [switch]$PlanOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Version = '1.0.2'

function Write-MSADPTStatus {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('PLAN', 'INFO', 'COLLECT', 'PASS', 'WARN', 'FAIL')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Color = switch ($Level) {
        'PLAN' { 'Cyan' }
        'INFO' { 'Gray' }
        'COLLECT' { 'Cyan' }
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
    }

    Write-Host ('[{0,-8}] {1}' -f $Level, $Message) -ForegroundColor $Color
}

function Resolve-MSADPTLocalPath {
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

        [int]$Depth = 12
    )

    ConvertTo-Json -InputObject $Value -Depth $Depth |
        Set-Content -LiteralPath $Path -Encoding UTF8
}

function New-MSADPTOperationalError {
    param(
        [string]$Stage,
        [string]$Target,
        [string]$GmsaSamAccountName,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    [pscustomobject][ordered]@{
        Stage = $Stage
        Target = $Target
        GmsaSamAccountName = $GmsaSamAccountName
        Message = $ErrorRecord.Exception.Message
        ExceptionType = $ErrorRecord.Exception.GetType().FullName
        FullyQualifiedErrorId = $ErrorRecord.FullyQualifiedErrorId
        RecordedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function ConvertTo-MSADPTGuidString {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        return ([guid]$Value).Guid
    }
    catch {
        return [string]$Value
    }
}

function Get-MSADPTDirectoryObject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [string]$DirectoryServer,

        [Parameter(Mandatory = $true)]
        [string]$DirectorySearchBase
    )

    $Properties = @(
        'objectClass',
        'objectSid',
        'sAMAccountName',
        'userPrincipalName',
        'displayName',
        'enabled',
        'lastLogonTimestamp',
        'pwdLastSet',
        'whenCreated',
        'whenChanged'
    )

    if ($Identity -match '^S-1-') {
        $SecurityIdentifier = [System.Security.Principal.SecurityIdentifier]::new($Identity)
        $SidBytes = New-Object byte[] $SecurityIdentifier.BinaryLength
        $SecurityIdentifier.GetBinaryForm($SidBytes, 0)
        $EscapedSidBytes = ($SidBytes | ForEach-Object { '\{0:X2}' -f $_ }) -join ''
        $LdapFilter = '(objectSid={0})' -f $EscapedSidBytes

        $Matches = @(
            Get-ADObject `
                -LDAPFilter $LdapFilter `
                -SearchBase $DirectorySearchBase `
                -SearchScope Subtree `
                -Server $DirectoryServer `
                -Properties $Properties `
                -ResultSetSize 2 `
                -ErrorAction Stop
        )

        if ($Matches.Count -eq 0) {
            throw "No directory object resolved for SID: $Identity"
        }
        if ($Matches.Count -gt 1) {
            throw "Multiple directory objects resolved for SID: $Identity"
        }

        return $Matches[0]
    }

    return Get-ADObject `
        -Identity $Identity `
        -Server $DirectoryServer `
        -Properties $Properties `
        -ErrorAction Stop
}

function ConvertTo-MSADPTPrincipalRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$DirectoryObject,

        [Parameter(Mandatory = $true)]
        [string]$SourceType,

        [Parameter(Mandatory = $true)]
        [string]$ConfiguredPrincipal,

        [Parameter(Mandatory = $true)]
        [string]$GmsaSamAccountName,

        [Parameter()]
        [AllowNull()]
        [string]$ParentGroupDistinguishedName,

        [Parameter()]
        [int]$ExpansionDepth = 0
    )

    $ObjectClasses = @($DirectoryObject.objectClass | ForEach-Object { [string]$_ })
    $LeafClass = if ($ObjectClasses.Count -gt 0) {
        $ObjectClasses[$ObjectClasses.Count - 1]
    }
    else {
        [string]$DirectoryObject.ObjectClass
    }

    [pscustomobject][ordered]@{
        GmsaSamAccountName = $GmsaSamAccountName
        ConfiguredPrincipal = $ConfiguredPrincipal
        ResolutionInputType = if ($ConfiguredPrincipal -match '^S-1-') { 'SID' } else { 'DistinguishedNameOrIdentity' }
        SourceType = $SourceType
        ParentGroupDistinguishedName = $ParentGroupDistinguishedName
        ExpansionDepth = $ExpansionDepth
        DistinguishedName = [string]$DirectoryObject.DistinguishedName
        Name = [string]$DirectoryObject.Name
        SamAccountName = [string]$DirectoryObject.sAMAccountName
        UserPrincipalName = [string]$DirectoryObject.userPrincipalName
        DisplayName = [string]$DirectoryObject.displayName
        ObjectClass = $LeafClass
        ObjectGuid = ConvertTo-MSADPTGuidString -Value $DirectoryObject.ObjectGUID
        ObjectSid = if ($DirectoryObject.objectSid) { [string]$DirectoryObject.objectSid.Value } else { $null }
        Enabled = if ($null -ne $DirectoryObject.enabled) { [bool]$DirectoryObject.enabled } else { $null }
        LastLogonTimestamp = $DirectoryObject.lastLogonTimestamp
        PasswordLastSet = $DirectoryObject.pwdLastSet
        WhenCreated = $DirectoryObject.whenCreated
        WhenChanged = $DirectoryObject.whenChanged
        SecretValuesCollected = $false
    }
}

$GmsaInventoryPath = Resolve-MSADPTLocalPath -Path $GmsaInventoryPath
$OutputRoot = Resolve-MSADPTLocalPath -Path $OutputRoot

if (-not (Test-Path -LiteralPath $GmsaInventoryPath -PathType Leaf)) {
    throw "GmsaInventoryMissing: $GmsaInventoryPath"
}

$GmsaInventory = @(
    Get-Content -LiteralPath $GmsaInventoryPath -Raw |
        ConvertFrom-Json -ErrorAction Stop
)

$ConfiguredRelationshipCount = 0
foreach ($Gmsa in $GmsaInventory) {
    $ConfiguredRelationshipCount += @(
        $Gmsa.PrincipalsAllowedToRetrieveManagedPassword
    ).Count
}

$Plan = @(
    [pscustomobject][ordered]@{
        Stage = 'PrincipalResolution'
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Resolve configured gMSA retrieval principals'
        SecretValues = 'Not requested'
    }
    [pscustomobject][ordered]@{
        Stage = 'RecursiveGroupExpansion'
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Expand recursive membership for configured retrieval groups'
        SecretValues = 'Not requested'
    }
    [pscustomobject][ordered]@{
        Stage = 'PrivilegedGroupCorrelation'
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Collect selected privileged-group membership for offline intersection'
        SecretValues = 'Not requested'
    }
)

Write-Host ''
Write-Host '=== MSADPT gMSA retrieval-principal collection ===' -ForegroundColor Cyan
$Plan | Format-Table Target, Protocol, Ports, Operation, SecretValues -AutoSize -Wrap
Write-Host ''
Write-Host ("gMSA inventory     : {0}" -f $GmsaInventoryPath) -ForegroundColor Gray
Write-Host ("gMSA count         : {0}" -f $GmsaInventory.Count) -ForegroundColor Gray
Write-Host ("Configured links   : {0}" -f $ConfiguredRelationshipCount) -ForegroundColor Gray
Write-Host ("Output directory   : {0}" -f $OutputRoot) -ForegroundColor Gray
Write-Host 'Authentication     : Current Windows session' -ForegroundColor Gray
Write-Host 'Directory writes   : None' -ForegroundColor Green
Write-Host 'Managed passwords  : Not requested' -ForegroundColor Green
Write-Host 'Secret values      : Not requested' -ForegroundColor Green
Write-Host ''

if ($PlanOnly) {
    return [pscustomobject][ordered]@{
        Status = 'Planned'
        Version = $Version
        Server = $Server
        GmsaInventoryPath = $GmsaInventoryPath
        GmsaCount = $GmsaInventory.Count
        ConfiguredRelationshipCount = $ConfiguredRelationshipCount
        Plan = $Plan
        NetworkExecuted = $false
        SecretValuesRequested = $false
        DirectoryChanges = 'None'
        OutputRoot = $OutputRoot
    }
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw 'ActiveDirectoryModuleMissing: install the Active Directory RSAT PowerShell module.'
}

Import-Module ActiveDirectory -ErrorAction Stop
$DomainContext = Get-ADDomain -Server $Server -ErrorAction Stop
$DirectorySearchBase = [string]$DomainContext.DistinguishedName
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$RawDirectory = Join-Path $OutputRoot 'Raw'
New-Item -ItemType Directory -Path $RawDirectory -Force | Out-Null

$StartedUtc = (Get-Date).ToUniversalTime()
$OperationalErrors = [System.Collections.Generic.List[object]]::new()
$ConfiguredPrincipals = [System.Collections.Generic.List[object]]::new()
$ExpandedMembership = [System.Collections.Generic.List[object]]::new()
$UnresolvedPrincipals = [System.Collections.Generic.List[object]]::new()
$PrivilegedMembership = [System.Collections.Generic.List[object]]::new()
$GroupExpansionSummary = [System.Collections.Generic.List[object]]::new()
$UnavailablePrivilegedGroups = [System.Collections.Generic.List[object]]::new()

$ProcessedConfiguredRelationships = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

foreach ($Gmsa in $GmsaInventory) {
    $GmsaSamAccountName = [string]$Gmsa.SamAccountName
    $ConfiguredRetrievers = @(
        $Gmsa.PrincipalsAllowedToRetrieveManagedPassword |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            Sort-Object -Unique
    )

    Write-MSADPTStatus -Level COLLECT -Message (
        'Resolving {0} configured retrieval principal(s) for {1}' -f
        $ConfiguredRetrievers.Count,
        $GmsaSamAccountName
    )

    foreach ($ConfiguredRetriever in $ConfiguredRetrievers) {
        $RelationshipKey = '{0}|{1}' -f $GmsaSamAccountName, $ConfiguredRetriever
        if (-not $ProcessedConfiguredRelationships.Add($RelationshipKey)) {
            continue
        }

        try {
            $ResolvedPrincipal = Get-MSADPTDirectoryObject `
                -Identity ([string]$ConfiguredRetriever) `
                -DirectoryServer $Server `
                -DirectorySearchBase $DirectorySearchBase

            $ConfiguredRecord = ConvertTo-MSADPTPrincipalRecord `
                -DirectoryObject $ResolvedPrincipal `
                -SourceType 'ConfiguredPrincipal' `
                -ConfiguredPrincipal ([string]$ConfiguredRetriever) `
                -GmsaSamAccountName $GmsaSamAccountName

            $ConfiguredPrincipals.Add($ConfiguredRecord)

            if ($ConfiguredRecord.ObjectClass -eq 'group') {
                try {
                    $RecursiveMembers = @(
                        Get-ADGroupMember `
                            -Identity $ResolvedPrincipal.DistinguishedName `
                            -Server $Server `
                            -Recursive `
                            -ErrorAction Stop
                    )

                    $UniqueMemberDns = [System.Collections.Generic.HashSet[string]]::new(
                        [System.StringComparer]::OrdinalIgnoreCase
                    )

                    foreach ($RecursiveMember in $RecursiveMembers) {
                        if (-not $UniqueMemberDns.Add([string]$RecursiveMember.DistinguishedName)) {
                            continue
                        }

                        try {
                            $MemberObject = Get-MSADPTDirectoryObject `
                                -Identity ([string]$RecursiveMember.DistinguishedName) `
                                -DirectoryServer $Server `
                                -DirectorySearchBase $DirectorySearchBase

                            $MemberRecord = ConvertTo-MSADPTPrincipalRecord `
                                -DirectoryObject $MemberObject `
                                -SourceType 'RecursiveGroupMember' `
                                -ConfiguredPrincipal ([string]$ConfiguredRetriever) `
                                -GmsaSamAccountName $GmsaSamAccountName `
                                -ParentGroupDistinguishedName ([string]$ResolvedPrincipal.DistinguishedName) `
                                -ExpansionDepth 1

                            $ExpandedMembership.Add($MemberRecord)
                        }
                        catch {
                            $OperationalErrors.Add((New-MSADPTOperationalError `
                                -Stage 'RecursiveMemberResolution' `
                                -Target ([string]$RecursiveMember.DistinguishedName) `
                                -GmsaSamAccountName $GmsaSamAccountName `
                                -ErrorRecord $_))
                        }
                    }

                    $GroupExpansionSummary.Add([pscustomobject][ordered]@{
                        GmsaSamAccountName = $GmsaSamAccountName
                        ConfiguredPrincipal = [string]$ConfiguredRetriever
                        GroupDistinguishedName = [string]$ResolvedPrincipal.DistinguishedName
                        RecursiveMemberCount = $UniqueMemberDns.Count
                        ExpansionSucceeded = $true
                        Limitation = 'Get-ADGroupMember -Recursive returns leaf members and does not preserve full nested path depth.'
                    })
                }
                catch {
                    $OperationalErrors.Add((New-MSADPTOperationalError `
                        -Stage 'RecursiveGroupExpansion' `
                        -Target ([string]$ResolvedPrincipal.DistinguishedName) `
                        -GmsaSamAccountName $GmsaSamAccountName `
                        -ErrorRecord $_))

                    $GroupExpansionSummary.Add([pscustomobject][ordered]@{
                        GmsaSamAccountName = $GmsaSamAccountName
                        ConfiguredPrincipal = [string]$ConfiguredRetriever
                        GroupDistinguishedName = [string]$ResolvedPrincipal.DistinguishedName
                        RecursiveMemberCount = $null
                        ExpansionSucceeded = $false
                        Limitation = $_.Exception.Message
                    })
                }
            }
        }
        catch {
            $OperationalErrors.Add((New-MSADPTOperationalError `
                -Stage 'ConfiguredPrincipalResolution' `
                -Target ([string]$ConfiguredRetriever) `
                -GmsaSamAccountName $GmsaSamAccountName `
                -ErrorRecord $_))

            $UnresolvedPrincipals.Add([pscustomobject][ordered]@{
                GmsaSamAccountName = $GmsaSamAccountName
                ConfiguredPrincipal = [string]$ConfiguredRetriever
                ResolutionStatus = 'Unresolved'
                ErrorMessage = $_.Exception.Message
            })
        }
    }
}

Write-MSADPTStatus -Level COLLECT -Message 'Collecting selected privileged-group membership for offline correlation.'
foreach ($PrivilegedGroupName in @($PrivilegedGroupSamAccountName | Sort-Object -Unique)) {
    try {
        $PrivilegedGroup = Get-ADGroup `
            -Identity $PrivilegedGroupName `
            -Server $Server `
            -Properties @('groupScope', 'groupCategory') `
            -ErrorAction Stop

        $Members = @(
            Get-ADGroupMember `
                -Identity $PrivilegedGroup.DistinguishedName `
                -Server $Server `
                -Recursive `
                -ErrorAction Stop
        )

        foreach ($Member in $Members) {
            $PrivilegedMembership.Add([pscustomobject][ordered]@{
                PrivilegedGroupName = $PrivilegedGroup.Name
                PrivilegedGroupSamAccountName = $PrivilegedGroup.SamAccountName
                PrivilegedGroupDistinguishedName = $PrivilegedGroup.DistinguishedName
                MemberDistinguishedName = [string]$Member.DistinguishedName
                MemberName = [string]$Member.Name
                MemberSamAccountName = [string]$Member.SamAccountName
                MemberObjectClass = [string]$Member.ObjectClass
                MembershipSource = 'Recursive'
            })
        }
    }
    catch {
        $UnavailablePrivilegedGroups.Add([pscustomobject][ordered]@{
            PrivilegedGroupName = $PrivilegedGroupName
            CollectionStatus = 'UnavailableOrNotPresent'
            Message = $_.Exception.Message
            RecordedUtc = (Get-Date).ToUniversalTime().ToString('o')
        })
    }
}

$EffectiveRelationships = @(
    foreach ($ConfiguredRecord in $ConfiguredPrincipals) {
        [pscustomobject][ordered]@{
            GmsaSamAccountName = $ConfiguredRecord.GmsaSamAccountName
            ConfiguredPrincipal = $ConfiguredRecord.ConfiguredPrincipal
            EffectivePrincipalDistinguishedName = $ConfiguredRecord.DistinguishedName
            EffectivePrincipalSamAccountName = $ConfiguredRecord.SamAccountName
            EffectivePrincipalObjectClass = $ConfiguredRecord.ObjectClass
            RelationshipType = 'DirectConfiguredPrincipal'
            ViaGroupDistinguishedName = $null
            Enabled = $ConfiguredRecord.Enabled
            SecretValuesCollected = $false
        }
    }

    foreach ($ExpandedRecord in $ExpandedMembership) {
        [pscustomobject][ordered]@{
            GmsaSamAccountName = $ExpandedRecord.GmsaSamAccountName
            ConfiguredPrincipal = $ExpandedRecord.ConfiguredPrincipal
            EffectivePrincipalDistinguishedName = $ExpandedRecord.DistinguishedName
            EffectivePrincipalSamAccountName = $ExpandedRecord.SamAccountName
            EffectivePrincipalObjectClass = $ExpandedRecord.ObjectClass
            RelationshipType = 'RecursiveGroupMember'
            ViaGroupDistinguishedName = $ExpandedRecord.ParentGroupDistinguishedName
            Enabled = $ExpandedRecord.Enabled
            SecretValuesCollected = $false
        }
    }
)

$PrivilegedMemberDnSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
foreach ($MembershipRecord in $PrivilegedMembership) {
    $null = $PrivilegedMemberDnSet.Add([string]$MembershipRecord.MemberDistinguishedName)
}

$PrivilegeIntersections = @(
    foreach ($Relationship in $EffectiveRelationships) {
        if ($PrivilegedMemberDnSet.Contains([string]$Relationship.EffectivePrincipalDistinguishedName)) {
            $Groups = @(
                $PrivilegedMembership |
                    Where-Object {
                        $_.MemberDistinguishedName -eq $Relationship.EffectivePrincipalDistinguishedName
                    } |
                    Select-Object -ExpandProperty PrivilegedGroupSamAccountName -Unique
            )

            [pscustomobject][ordered]@{
                GmsaSamAccountName = $Relationship.GmsaSamAccountName
                EffectivePrincipalDistinguishedName = $Relationship.EffectivePrincipalDistinguishedName
                EffectivePrincipalSamAccountName = $Relationship.EffectivePrincipalSamAccountName
                EffectivePrincipalObjectClass = $Relationship.EffectivePrincipalObjectClass
                RelationshipType = $Relationship.RelationshipType
                ViaGroupDistinguishedName = $Relationship.ViaGroupDistinguishedName
                PrivilegedGroups = $Groups -join '; '
                Disposition = 'PrivilegedIntersectionDetected'
            }
        }
    }
)

$DataFiles = [ordered]@{
    'configured-principals.json' = @($ConfiguredPrincipals)
    'expanded-membership.json' = @($ExpandedMembership)
    'effective-principal-relationships.json' = @($EffectiveRelationships)
    'group-expansion-summary.json' = @($GroupExpansionSummary)
    'privileged-group-membership.json' = @($PrivilegedMembership)
    'privilege-intersections.json' = @($PrivilegeIntersections)
    'unavailable-privileged-groups.json' = @($UnavailablePrivilegedGroups)
    'unresolved-principals.json' = @($UnresolvedPrincipals)
    'operational-errors.json' = @($OperationalErrors)
    'collection-plan.json' = @($Plan)
}

foreach ($FileName in $DataFiles.Keys) {
    Write-MSADPTJson `
        -Value $DataFiles[$FileName] `
        -Path (Join-Path $RawDirectory $FileName)
}

$CompletedUtc = (Get-Date).ToUniversalTime()
$EvidenceFiles = @(
    Get-ChildItem -LiteralPath $RawDirectory -File -Recurse |
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
    ModuleId = 'Collect-MSADPTGmsaRetrievalPrincipals'
    ModuleVersion = $Version
    StartedUtc = $StartedUtc.ToString('o')
    CompletedUtc = $CompletedUtc.ToString('o')
    DurationSeconds = [math]::Round(($CompletedUtc - $StartedUtc).TotalSeconds, 3)
    Server = $Server
    DirectorySearchBase = $DirectorySearchBase
    SourceInventoryPath = $GmsaInventoryPath
    GmsaCount = $GmsaInventory.Count
    ConfiguredRelationshipCount = $ConfiguredRelationshipCount
    ResolvedConfiguredPrincipalCount = $ConfiguredPrincipals.Count
    UnresolvedConfiguredPrincipalCount = $UnresolvedPrincipals.Count
    ExpandedMemberRelationshipCount = $ExpandedMembership.Count
    EffectiveRelationshipCount = $EffectiveRelationships.Count
    PrivilegedGroupMembershipCount = $PrivilegedMembership.Count
    UnavailablePrivilegedGroupCount = $UnavailablePrivilegedGroups.Count
    PrivilegeIntersectionCount = $PrivilegeIntersections.Count
    OperationalErrorCount = $OperationalErrors.Count
    SecretValuesRequested = $false
    SecretValuesCollected = $false
    ManagedPasswordBlobRequested = $false
    DirectoryChanges = 'None'
    Files = $EvidenceFiles
}

$ManifestPath = Join-Path $OutputRoot 'evidence-manifest.json'
Write-MSADPTJson -Value $Manifest -Path $ManifestPath -Depth 10

$Status = if ($OperationalErrors.Count -gt 0) { 'Partial' } else { 'Completed' }
$ConsoleLevel = if ($Status -eq 'Completed') { 'PASS' } else { 'WARN' }
Write-MSADPTStatus -Level $ConsoleLevel -Message "Collection complete: $OutputRoot"

[pscustomobject][ordered]@{
    Status = $Status
    Version = $Version
    OutputRoot = $OutputRoot
    Server = $Server
    GmsaCount = $GmsaInventory.Count
    ConfiguredRelationshipCount = $ConfiguredRelationshipCount
    ResolvedConfiguredPrincipalCount = $ConfiguredPrincipals.Count
    UnresolvedConfiguredPrincipalCount = $UnresolvedPrincipals.Count
    ExpandedMemberRelationshipCount = $ExpandedMembership.Count
    EffectiveRelationshipCount = $EffectiveRelationships.Count
    PrivilegeIntersectionCount = $PrivilegeIntersections.Count
    OperationalErrorCount = $OperationalErrors.Count
    SecretValuesCollected = $false
    ManifestPath = $ManifestPath
}
