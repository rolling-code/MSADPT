<#
.SYNOPSIS
Collects read-only evidence for unresolved SIDs found in gMSA retrieval-principal configurations.

.DESCRIPTION
Consumes unresolved-principals.json from the MSADPT gMSA retrieval-principal collection, deduplicates SID references, and performs explicitly scoped Active Directory searches through one specified ADWS-reachable domain controller.

For each unique SID, the collector checks:
1. Current domain objects whose objectSid equals the SID.
2. Current domain objects whose sIDHistory contains the SID.
3. Deleted objects whose objectSid equals the SID.
4. Deleted objects whose sIDHistory contains the SID.

The collector is read-only. It does not restore deleted objects, retrieve gMSA managed-password blobs, request credentials, modify security descriptors, or make any directory change.

.NOTES
Version: 1.0.0
Supports Windows PowerShell 5.1 and PowerShell 7 on Windows with the ActiveDirectory module.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$UnresolvedPrincipalsPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter()]
    [ValidateRange(1, 10000)]
    [int]$MaximumUniqueSids = 1000,

    [Parameter()]
    [switch]$PlanOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Version = '1.0.0'

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

function ConvertTo-MSADPTLdapBinarySid {
    param([Parameter(Mandatory = $true)][string]$Sid)

    $SecurityIdentifier = [System.Security.Principal.SecurityIdentifier]::new($Sid)
    $Bytes = New-Object byte[] $SecurityIdentifier.BinaryLength
    $SecurityIdentifier.GetBinaryForm($Bytes, 0)

    return ($Bytes | ForEach-Object { '\{0:X2}' -f $_ }) -join ''
}

function New-MSADPTOperationalError {
    param(
        [string]$Stage,
        [string]$Sid,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    [pscustomobject][ordered]@{
        Stage = $Stage
        Sid = $Sid
        Message = $ErrorRecord.Exception.Message
        ExceptionType = $ErrorRecord.Exception.GetType().FullName
        FullyQualifiedErrorId = $ErrorRecord.FullyQualifiedErrorId
        RecordedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function ConvertTo-MSADPTSidMatch {
    param(
        [Parameter(Mandatory = $true)][string]$InputSid,
        [Parameter(Mandatory = $true)][string]$SearchCategory,
        [Parameter(Mandatory = $true)][object]$DirectoryObject
    )

    $ObjectClasses = @($DirectoryObject.objectClass | ForEach-Object { [string]$_ })
    $LeafClass = if ($ObjectClasses.Count -gt 0) {
        $ObjectClasses[$ObjectClasses.Count - 1]
    }
    else {
        [string]$DirectoryObject.ObjectClass
    }

    [pscustomobject][ordered]@{
        InputSid = $InputSid
        SearchCategory = $SearchCategory
        DistinguishedName = [string]$DirectoryObject.DistinguishedName
        Name = [string]$DirectoryObject.Name
        SamAccountName = [string]$DirectoryObject.sAMAccountName
        DisplayName = [string]$DirectoryObject.displayName
        ObjectClass = $LeafClass
        ObjectGuid = if ($DirectoryObject.ObjectGUID) { ([guid]$DirectoryObject.ObjectGUID).Guid } else { $null }
        ObjectSid = if ($DirectoryObject.objectSid) { [string]$DirectoryObject.objectSid.Value } else { $null }
        SidHistory = @($DirectoryObject.sIDHistory | ForEach-Object { [string]$_.Value })
        IsDeleted = [bool]$DirectoryObject.isDeleted
        LastKnownParent = [string]$DirectoryObject.lastKnownParent
        WhenCreated = $DirectoryObject.whenCreated
        WhenChanged = $DirectoryObject.whenChanged
        Enabled = if ($null -ne $DirectoryObject.enabled) { [bool]$DirectoryObject.enabled } else { $null }
        SecretValuesCollected = $false
    }
}

$UnresolvedPrincipalsPath = Resolve-MSADPTLocalPath -Path $UnresolvedPrincipalsPath
$OutputRoot = Resolve-MSADPTLocalPath -Path $OutputRoot

if (-not (Test-Path -LiteralPath $UnresolvedPrincipalsPath -PathType Leaf)) {
    throw "UnresolvedPrincipalsMissing: $UnresolvedPrincipalsPath"
}

$UnresolvedRelationships = @(
    Get-Content -LiteralPath $UnresolvedPrincipalsPath -Raw |
        ConvertFrom-Json -ErrorAction Stop
)

$UniqueSids = @(
    $UnresolvedRelationships |
        Select-Object -ExpandProperty ConfiguredPrincipal |
        Where-Object { $_ -match '^S-1-' } |
        Sort-Object -Unique
)

if ($UniqueSids.Count -eq 0) {
    throw 'No SID-form unresolved principals were found in the input evidence.'
}
if ($UniqueSids.Count -gt $MaximumUniqueSids) {
    throw "UniqueSidLimitExceeded: found $($UniqueSids.Count); limit is $MaximumUniqueSids."
}

$Plan = @(
    [pscustomobject][ordered]@{
        Stage = 'CurrentObjectSid'
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Search current objects for exact objectSid matches'
        DirectoryChanges = 'None'
    }
    [pscustomobject][ordered]@{
        Stage = 'CurrentSidHistory'
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Search current objects for exact sIDHistory matches'
        DirectoryChanges = 'None'
    }
    [pscustomobject][ordered]@{
        Stage = 'DeletedObjectSid'
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Search deleted objects for exact objectSid matches'
        DirectoryChanges = 'None'
    }
    [pscustomobject][ordered]@{
        Stage = 'DeletedSidHistory'
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Search deleted objects for exact sIDHistory matches'
        DirectoryChanges = 'None'
    }
)

Write-Host ''
Write-Host '=== MSADPT unresolved SID evidence collection ===' -ForegroundColor Cyan
$Plan | Format-Table Target, Protocol, Ports, Operation, DirectoryChanges -AutoSize -Wrap
Write-Host ''
Write-Host ("Input evidence     : {0}" -f $UnresolvedPrincipalsPath) -ForegroundColor Gray
Write-Host ("Relationship rows  : {0}" -f $UnresolvedRelationships.Count) -ForegroundColor Gray
Write-Host ("Unique SIDs        : {0}" -f $UniqueSids.Count) -ForegroundColor Gray
Write-Host ("Output directory   : {0}" -f $OutputRoot) -ForegroundColor Gray
Write-Host 'Authentication     : Current Windows session' -ForegroundColor Gray
Write-Host 'Directory writes   : None' -ForegroundColor Green
Write-Host 'Deleted restoration: Not requested' -ForegroundColor Green
Write-Host 'Managed passwords  : Not requested' -ForegroundColor Green
Write-Host 'Secret values      : Not requested' -ForegroundColor Green
Write-Host ''

if ($PlanOnly) {
    return [pscustomobject][ordered]@{
        Status = 'Planned'
        Version = $Version
        Server = $Server
        InputPath = $UnresolvedPrincipalsPath
        RelationshipCount = $UnresolvedRelationships.Count
        UniqueSidCount = $UniqueSids.Count
        Plan = $Plan
        NetworkExecuted = $false
        DirectoryChanges = 'None'
        SecretValuesRequested = $false
        OutputRoot = $OutputRoot
    }
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw 'ActiveDirectoryModuleMissing: install the Active Directory RSAT PowerShell module.'
}

Import-Module ActiveDirectory -ErrorAction Stop
$Domain = Get-ADDomain -Server $Server -ErrorAction Stop
$DomainSearchBase = [string]$Domain.DistinguishedName
$DeletedObjectsSearchBase = 'CN=Deleted Objects,{0}' -f $DomainSearchBase

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$RawDirectory = Join-Path $OutputRoot 'Raw'
New-Item -ItemType Directory -Path $RawDirectory -Force | Out-Null

$StartedUtc = (Get-Date).ToUniversalTime()
$Matches = [System.Collections.Generic.List[object]]::new()
$SidSummary = [System.Collections.Generic.List[object]]::new()
$OperationalErrors = [System.Collections.Generic.List[object]]::new()
$Properties = @(
    'objectClass',
    'objectSid',
    'sIDHistory',
    'sAMAccountName',
    'displayName',
    'enabled',
    'isDeleted',
    'lastKnownParent',
    'whenCreated',
    'whenChanged'
)

$SidIndex = 0
foreach ($Sid in $UniqueSids) {
    $SidIndex++
    Write-MSADPTStatus -Level COLLECT -Message (
        'SID {0}/{1}: {2}' -f $SidIndex, $UniqueSids.Count, $Sid
    )

    $EscapedSid = ConvertTo-MSADPTLdapBinarySid -Sid $Sid
    $CurrentObjectSidFilter = '(objectSid={0})' -f $EscapedSid
    $CurrentSidHistoryFilter = '(sIDHistory={0})' -f $EscapedSid
    $PerSidMatches = [System.Collections.Generic.List[object]]::new()

    try {
        foreach ($Object in @(Get-ADObject `
            -LDAPFilter $CurrentObjectSidFilter `
            -SearchBase $DomainSearchBase `
            -SearchScope Subtree `
            -Server $Server `
            -Properties $Properties `
            -ErrorAction Stop)) {

            $Record = ConvertTo-MSADPTSidMatch -InputSid $Sid -SearchCategory 'CurrentObjectSid' -DirectoryObject $Object
            $Matches.Add($Record)
            $PerSidMatches.Add($Record)
        }
    }
    catch {
        $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'CurrentObjectSid' -Sid $Sid -ErrorRecord $_))
    }

    try {
        foreach ($Object in @(Get-ADObject `
            -LDAPFilter $CurrentSidHistoryFilter `
            -SearchBase $DomainSearchBase `
            -SearchScope Subtree `
            -Server $Server `
            -Properties $Properties `
            -ErrorAction Stop)) {

            $Record = ConvertTo-MSADPTSidMatch -InputSid $Sid -SearchCategory 'CurrentSidHistory' -DirectoryObject $Object
            $Matches.Add($Record)
            $PerSidMatches.Add($Record)
        }
    }
    catch {
        $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'CurrentSidHistory' -Sid $Sid -ErrorRecord $_))
    }

    try {
        foreach ($Object in @(Get-ADObject `
            -LDAPFilter $CurrentObjectSidFilter `
            -SearchBase $DeletedObjectsSearchBase `
            -SearchScope OneLevel `
            -Server $Server `
            -IncludeDeletedObjects `
            -Properties $Properties `
            -ErrorAction Stop)) {

            $Record = ConvertTo-MSADPTSidMatch -InputSid $Sid -SearchCategory 'DeletedObjectSid' -DirectoryObject $Object
            $Matches.Add($Record)
            $PerSidMatches.Add($Record)
        }
    }
    catch {
        $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'DeletedObjectSid' -Sid $Sid -ErrorRecord $_))
    }

    try {
        foreach ($Object in @(Get-ADObject `
            -LDAPFilter $CurrentSidHistoryFilter `
            -SearchBase $DeletedObjectsSearchBase `
            -SearchScope OneLevel `
            -Server $Server `
            -IncludeDeletedObjects `
            -Properties $Properties `
            -ErrorAction Stop)) {

            $Record = ConvertTo-MSADPTSidMatch -InputSid $Sid -SearchCategory 'DeletedSidHistory' -DirectoryObject $Object
            $Matches.Add($Record)
            $PerSidMatches.Add($Record)
        }
    }
    catch {
        $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'DeletedSidHistory' -Sid $Sid -ErrorRecord $_))
    }

    $RelationshipCount = @(
        $UnresolvedRelationships |
            Where-Object { $_.ConfiguredPrincipal -eq $Sid }
    ).Count

    $Classification = if (@($PerSidMatches | Where-Object { $_.SearchCategory -eq 'CurrentObjectSid' }).Count -gt 0) {
        'ResolvedCurrentObjectSid'
    }
    elseif (@($PerSidMatches | Where-Object { $_.SearchCategory -eq 'CurrentSidHistory' }).Count -gt 0) {
        'ResolvedCurrentSidHistory'
    }
    elseif (@($PerSidMatches | Where-Object { $_.SearchCategory -eq 'DeletedObjectSid' }).Count -gt 0) {
        'ResolvedDeletedObjectSid'
    }
    elseif (@($PerSidMatches | Where-Object { $_.SearchCategory -eq 'DeletedSidHistory' }).Count -gt 0) {
        'ResolvedDeletedSidHistory'
    }
    else {
        'NotResolved'
    }

    $SidSummary.Add([pscustomobject][ordered]@{
        Sid = $Sid
        RelationshipCount = $RelationshipCount
        MatchCount = $PerSidMatches.Count
        Classification = $Classification
        GmsaSamAccountNames = @(
            $UnresolvedRelationships |
                Where-Object { $_.ConfiguredPrincipal -eq $Sid } |
                Select-Object -ExpandProperty GmsaSamAccountName -Unique
        )
        LdapObjectSidFilter = $CurrentObjectSidFilter
        LdapSidHistoryFilter = $CurrentSidHistoryFilter
    })
}

$DataFiles = [ordered]@{
    'sid-summary.json' = @($SidSummary)
    'sid-matches.json' = @($Matches)
    'source-relationships.json' = @($UnresolvedRelationships)
    'operational-errors.json' = @($OperationalErrors)
    'collection-plan.json' = @($Plan)
}

foreach ($FileName in $DataFiles.Keys) {
    Write-MSADPTJson -Value $DataFiles[$FileName] -Path (Join-Path $RawDirectory $FileName)
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
    ModuleId = 'Collect-MSADPTUnresolvedSidEvidence'
    ModuleVersion = $Version
    StartedUtc = $StartedUtc.ToString('o')
    CompletedUtc = $CompletedUtc.ToString('o')
    DurationSeconds = [math]::Round(($CompletedUtc - $StartedUtc).TotalSeconds, 3)
    Server = $Server
    DomainSearchBase = $DomainSearchBase
    DeletedObjectsSearchBase = $DeletedObjectsSearchBase
    SourcePath = $UnresolvedPrincipalsPath
    RelationshipCount = $UnresolvedRelationships.Count
    UniqueSidCount = $UniqueSids.Count
    ResolvedCurrentObjectSidCount = @($SidSummary | Where-Object { $_.Classification -eq 'ResolvedCurrentObjectSid' }).Count
    ResolvedCurrentSidHistoryCount = @($SidSummary | Where-Object { $_.Classification -eq 'ResolvedCurrentSidHistory' }).Count
    ResolvedDeletedObjectSidCount = @($SidSummary | Where-Object { $_.Classification -eq 'ResolvedDeletedObjectSid' }).Count
    ResolvedDeletedSidHistoryCount = @($SidSummary | Where-Object { $_.Classification -eq 'ResolvedDeletedSidHistory' }).Count
    NotResolvedCount = @($SidSummary | Where-Object { $_.Classification -eq 'NotResolved' }).Count
    MatchCount = $Matches.Count
    OperationalErrorCount = $OperationalErrors.Count
    DirectoryChanges = 'None'
    DeletedObjectsRestored = 0
    SecretValuesRequested = $false
    SecretValuesCollected = $false
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
    RelationshipCount = $UnresolvedRelationships.Count
    UniqueSidCount = $UniqueSids.Count
    ResolvedCurrentObjectSidCount = $Manifest.ResolvedCurrentObjectSidCount
    ResolvedCurrentSidHistoryCount = $Manifest.ResolvedCurrentSidHistoryCount
    ResolvedDeletedObjectSidCount = $Manifest.ResolvedDeletedObjectSidCount
    ResolvedDeletedSidHistoryCount = $Manifest.ResolvedDeletedSidHistoryCount
    NotResolvedCount = $Manifest.NotResolvedCount
    MatchCount = $Matches.Count
    OperationalErrorCount = $OperationalErrors.Count
    DirectoryChanges = 'None'
    SecretValuesCollected = $false
    ManifestPath = $ManifestPath
}
