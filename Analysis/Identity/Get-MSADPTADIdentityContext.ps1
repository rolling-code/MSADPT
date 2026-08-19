<#
.SYNOPSIS
Classifies AD principal context from preserved identity evidence and candidate routes.
.DESCRIPTION
Consumes candidate-specific ADCS facts and optional resolved identity evidence. It assigns deterministic
identity-context categories for validation planning. Classification is evidence based and intentionally
conservative. Names may provide supporting indicators, but names alone do not prove privilege.

This script performs no Active Directory, LDAP, CA, DNS, TCP, SMB, Kerberos, authentication, certificate,
registry, or ledger operation.
.NOTES
Version: 0.1.0
Execution class: offline_analysis
Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$CandidateFactsPath,
    [Parameter()][string]$IdentityPrerequisitePath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
    [Parameter()][string]$ConsoleModulePath,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ClassifierVersion = '0.1.0'
$AllowedCategories = @(
    'PrivilegedAdministrative',
    'TierZeroIndicator',
    'BroadLowPrivilege',
    'BroadComputerIdentity',
    'BuiltInIdentity',
    'ServiceIdentity',
    'ComputerIdentity',
    'SecurityGroup',
    'StandardUser',
    'EmptyGroup',
    'UnresolvedIdentity',
    'UnknownPrivilegeContext'
)

foreach ($Path in @($CandidateFactsPath)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file not found: $Path"
    }
}
if (-not [string]::IsNullOrWhiteSpace($IdentityPrerequisitePath) -and -not (Test-Path -LiteralPath $IdentityPrerequisitePath -PathType Leaf)) {
    throw "Identity prerequisite evidence not found: $IdentityPrerequisitePath"
}
if (-not [string]::IsNullOrWhiteSpace($ConsoleModulePath)) {
    if (-not (Test-Path -LiteralPath $ConsoleModulePath -PathType Leaf)) {
        throw "Console module not found: $ConsoleModulePath"
    }
    Import-Module $ConsoleModulePath -Force -ErrorAction Stop
}

function Write-MSADPTIdentityEvent {
    param(
        [ValidateSet('Info','Action','Success','Warning','Error','Muted')][string]$Kind,
        [string]$Message,
        [string]$Target,
        [string]$Code,
        [hashtable]$Data
    )
    if (Get-Command Write-MSADPTConsoleEvent -ErrorAction SilentlyContinue) {
        return Write-MSADPTConsoleEvent -Kind $Kind -Message $Message -Target $Target -Code $Code -Data $Data
    }
    $Event = [pscustomobject][ordered]@{
        TimestampUtc=(Get-Date).ToUniversalTime().ToString('o');Kind=$Kind;Code=$Code
        Message=$Message;Target=$Target;Data=if($null-ne$Data){[pscustomobject]$Data}else{$null}
    }
    if (-not $Quiet) {
        $Color = switch($Kind){'Info'{'Cyan'}'Action'{'Yellow'}'Success'{'Green'}'Warning'{'DarkYellow'}'Error'{'Red'}default{'DarkGray'}}
        Write-Host ('[{0}] {1}: {2}' -f $Kind.ToUpperInvariant(),$Target,$Message) -ForegroundColor $Color
    }
    Write-Output $Event
}

function Get-MSADPTIdentityRecord {
    param([string]$IdentityReference,$Records)
    return @(
        $Records |
            Where-Object { [string]$_.IdentityReference -eq $IdentityReference } |
            Select-Object -First 1
    )
}

function New-MSADPTIdentityClassification {
    param(
        [string]$IdentityReference,
        $IdentityRecord,
        [int]$CandidateRouteCount
    )

    $Category = 'UnknownPrivilegeContext'
    $Confidence = 'Low'
    $EvidenceBasis = New-Object 'System.Collections.Generic.List[string]'
    $Limitations = New-Object 'System.Collections.Generic.List[string]'
    $IsPrivilegedContext = $false
    $IsBroadIdentity = $false
    $IsUsableStartingPrincipal = $null
    $ValidationPriorityModifier = 0
    $ResolutionStatus = if ($null -ne $IdentityRecord) { [string]$IdentityRecord.ResolutionStatus } else { 'Not supplied' }
    $ObjectClass = if ($null -ne $IdentityRecord) { [string]$IdentityRecord.ObjectClass } else { $null }
    $Enabled = if ($null -ne $IdentityRecord -and $null -ne $IdentityRecord.PSObject.Properties['Enabled']) { $IdentityRecord.Enabled } else { $null }
    $RecursiveMemberCount = if ($null -ne $IdentityRecord -and $null -ne $IdentityRecord.PSObject.Properties['RecursiveMembers']) { @($IdentityRecord.RecursiveMembers).Count } else { $null }

    if ($IdentityReference -match '(?i)\\(Domain Admins|Enterprise Admins|Administrators|Schema Admins)$') {
        $Category = 'PrivilegedAdministrative'
        $Confidence = 'High'
        $IsPrivilegedContext = $true
        $IsUsableStartingPrincipal = $false
        $ValidationPriorityModifier = -60
        $EvidenceBasis.Add('The principal is a well-known privileged administrative group.')
        $Limitations.Add('This classification does not evaluate every delegated privilege or nested membership path.')
    }
    elseif ($IdentityReference -match '(?i)\\(Domain Users|Authenticated Users|Everyone)$|^NT AUTHORITY\\Authenticated Users$|^S-1-1-0$|^S-1-5-11$') {
        $Category = 'BroadLowPrivilege'
        $Confidence = 'High'
        $IsBroadIdentity = $true
        $IsUsableStartingPrincipal = $true
        $ValidationPriorityModifier = 30
        $EvidenceBasis.Add('The principal represents a broad user population or authenticated identity set.')
        $Limitations.Add('Effective access remains subject to deny ACEs and the exact security token used during validation.')
    }
    elseif ($IdentityReference -match '(?i)\\Domain Computers$') {
        $Category = 'BroadComputerIdentity'
        $Confidence = 'High'
        $IsBroadIdentity = $true
        $IsUsableStartingPrincipal = $true
        $ValidationPriorityModifier = 25
        $EvidenceBasis.Add('The principal represents the broad domain computer population.')
        $Limitations.Add('A broad computer route still requires a usable controlled computer account and effective access validation.')
    }
    elseif ($IdentityReference -match '^NT AUTHORITY\\|^BUILTIN\\|^S-1-5-') {
        $Category = 'BuiltInIdentity'
        $Confidence = 'High'
        $ValidationPriorityModifier = -5
        $EvidenceBasis.Add('The principal is a built-in or well-known security identity.')
        $Limitations.Add('Built-in identity scope must be interpreted according to the relevant access check.')
    }
    elseif ($null -eq $IdentityRecord -or $ResolutionStatus -eq 'Not supplied') {
        if ($IdentityReference -match '(?i)\\Svc[-_]|\\svc[-_]|service') {
            $Category = 'ServiceIdentity'
            $Confidence = 'Low'
            $ValidationPriorityModifier = 15
            $EvidenceBasis.Add('The account name contains a service-identity indicator.')
            $Limitations.Add('Naming is supporting evidence only; object class, enabled state, privilege, and ownership are unresolved.')
        }
        elseif ($IdentityReference -match '\$$') {
            $Category = 'ComputerIdentity'
            $Confidence = 'Medium'
            $ValidationPriorityModifier = 10
            $EvidenceBasis.Add('The identity reference ends with the computer-account suffix.')
            $Limitations.Add('Control of the computer account and its privilege context are unresolved.')
        }
        else {
            $Category = 'UnresolvedIdentity'
            $Confidence = 'Low'
            $ValidationPriorityModifier = 20
            $EvidenceBasis.Add('No matching identity-resolution record was supplied.')
            $Limitations.Add('The object might be stale, foreign, deleted, mistyped, or outside the collected scope.')
        }
    }
    elseif ($ResolutionStatus -eq 'NotFound') {
        $Category = 'UnresolvedIdentity'
        $Confidence = 'High'
        $IsUsableStartingPrincipal = $false
        $ValidationPriorityModifier = -20
        $EvidenceBasis.Add('The preserved identity collector returned NotFound for this principal.')
        $Limitations.Add('NotFound does not prove permanent absence; the evidence is point in time and may reflect scope or replication limitations.')
    }
    elseif ($ResolutionStatus -eq 'Resolved' -and $ObjectClass -eq 'group') {
        if ($RecursiveMemberCount -eq 0) {
            $Category = 'EmptyGroup'
            $Confidence = 'High'
            $IsUsableStartingPrincipal = $false
            $ValidationPriorityModifier = -35
            $EvidenceBasis.Add('The group resolved and no recursive members were present in the supplied evidence.')
            $Limitations.Add('The group ACL may permit future membership changes; empty membership blocks only the current member-based path.')
        }
        elseif ($IdentityReference -match '(?i)(^|\\|[-_])T0($|[-_])|Tier.?0') {
            $Category = 'TierZeroIndicator'
            $Confidence = 'Medium'
            $IsPrivilegedContext = $true
            $IsUsableStartingPrincipal = $false
            $ValidationPriorityModifier = -45
            $EvidenceBasis.Add('The group resolved and its name contains a Tier 0 indicator.')
            $EvidenceBasis.Add("Recursive member count in supplied evidence: $RecursiveMemberCount.")
            $Limitations.Add('The name indicates intended privilege but does not independently prove effective Tier 0 control.')
        }
        else {
            $Category = 'SecurityGroup'
            $Confidence = 'Medium'
            $ValidationPriorityModifier = 20
            $EvidenceBasis.Add('The principal resolved as a group with one or more recursive members.')
            $EvidenceBasis.Add("Recursive member count in supplied evidence: $RecursiveMemberCount.")
            $Limitations.Add('Member privilege, nested paths, deny ACEs, and effective access require separate evaluation.')
        }
    }
    elseif ($ResolutionStatus -eq 'Resolved' -and $ObjectClass -eq 'computer') {
        $Category = 'ComputerIdentity'
        $Confidence = 'High'
        $ValidationPriorityModifier = 15
        $IsUsableStartingPrincipal = if ($Enabled -eq $true) { $null } else { $false }
        $EvidenceBasis.Add('The principal resolved as a computer object.')
        if ($null -ne $Enabled) { $EvidenceBasis.Add("Enabled state: $Enabled.") }
        $Limitations.Add('Whether an assessor or attacker controls the computer identity is not established by object presence.')
    }
    elseif ($ResolutionStatus -eq 'Resolved' -and $ObjectClass -eq 'user') {
        if ($IdentityReference -match '(?i)\\Svc[-_]|\\svc[-_]|service') {
            $Category = 'ServiceIdentity'
            $Confidence = 'Medium'
            $ValidationPriorityModifier = 20
            $EvidenceBasis.Add('The principal resolved as a user and its name contains a service-identity indicator.')
        }
        else {
            $Category = 'StandardUser'
            $Confidence = 'Medium'
            $ValidationPriorityModifier = 15
            $EvidenceBasis.Add('The principal resolved as a user object without a deterministic administrative classification.')
        }
        if ($Enabled -eq $false) {
            $IsUsableStartingPrincipal = $false
            $ValidationPriorityModifier -= 25
            $EvidenceBasis.Add('The account is disabled in the supplied evidence.')
        }
        else {
            $IsUsableStartingPrincipal = $null
            if ($null -ne $Enabled) { $EvidenceBasis.Add("Enabled state: $Enabled.") }
        }
        $Limitations.Add('Privilege, ownership, credential availability, and actual control are not established by object class or naming.')
    }
    else {
        $Category = 'UnknownPrivilegeContext'
        $Confidence = 'Low'
        $ValidationPriorityModifier = 10
        $EvidenceBasis.Add("Resolution status '$ResolutionStatus' and object class '$ObjectClass' did not map deterministically.")
        $Limitations.Add('Additional identity and effective-control evidence is required.')
    }

    if ($Category -notin $AllowedCategories) {
        throw "Unsupported identity category for ${IdentityReference}: $Category"
    }

    [pscustomobject][ordered]@{
        identityReference=$IdentityReference
        category=$Category
        confidence=$Confidence
        resolutionStatus=$ResolutionStatus
        objectClass=$ObjectClass
        enabled=$Enabled
        recursiveMemberCount=$RecursiveMemberCount
        candidateRouteCount=$CandidateRouteCount
        isPrivilegedContext=$IsPrivilegedContext
        isBroadIdentity=$IsBroadIdentity
        isUsableStartingPrincipal=$IsUsableStartingPrincipal
        validationPriorityModifier=$ValidationPriorityModifier
        evidenceBasis=@($EvidenceBasis.ToArray())
        limitations=@($Limitations.ToArray())
        sourceIdentityEvidence=$IdentityPrerequisitePath
        classifierVersion=$ClassifierVersion
    }
}

try {
    $Candidates = @(Get-Content -LiteralPath $CandidateFactsPath -Raw | ConvertFrom-Json -ErrorAction Stop)
}
catch {
    throw "CandidateFactsJsonParseFailure: $($_.Exception.Message)"
}
$IdentityRecords = @()
if (-not [string]::IsNullOrWhiteSpace($IdentityPrerequisitePath)) {
    try {
        $IdentityRecords = @(Get-Content -LiteralPath $IdentityPrerequisitePath -Raw | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        throw "IdentityEvidenceJsonParseFailure: $($_.Exception.Message)"
    }
}

$IdentityGroups = @($Candidates | Group-Object principal)
$Events = New-Object 'System.Collections.Generic.List[object]'
$Events.Add((Write-MSADPTIdentityEvent -Kind Info -Code 'IdentityClassifierStarted' -Message ("Classifying {0} unique principal(s) from {1} candidate route(s)." -f $IdentityGroups.Count,$Candidates.Count) -Target 'Identity context classifier' -Data @{ClassifierVersion=$ClassifierVersion}))
$Classifications = New-Object 'System.Collections.Generic.List[object]'
$Current = 0
foreach ($Group in $IdentityGroups) {
    $Current++
    $IdentityReference = [string]$Group.Name
    if (-not $Quiet) {
        $Percent = if ($IdentityGroups.Count -gt 0) { [math]::Round(($Current / $IdentityGroups.Count) * 100,0) } else { 100 }
        $Events.Add((Write-MSADPTIdentityEvent -Kind Action -Code 'ClassifyIdentity' -Message ("[{0}/{1} {2}%] Evaluating identity context." -f $Current,$IdentityGroups.Count,$Percent) -Target $IdentityReference -Data @{CandidateRouteCount=$Group.Count}))
    }
    $RecordArray = @(Get-MSADPTIdentityRecord -IdentityReference $IdentityReference -Records $IdentityRecords)
    $Record = if ($RecordArray.Count -gt 0) { $RecordArray[0] } else { $null }
    $Classifications.Add((New-MSADPTIdentityClassification -IdentityReference $IdentityReference -IdentityRecord $Record -CandidateRouteCount $Group.Count))
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$JsonPath = Join-Path $OutputDirectory 'ad-identity-context.json'
$CsvPath = Join-Path $OutputDirectory 'ad-identity-context.csv'
$SummaryPath = Join-Path $OutputDirectory 'ad-identity-context-summary.json'
$EventPath = Join-Path $OutputDirectory 'ad-identity-context-events.json'

$Sorted = @($Classifications.ToArray() | Sort-Object category,identityReference)
$Sorted | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $JsonPath -Encoding UTF8
$Sorted |
    Select-Object identityReference,category,confidence,resolutionStatus,objectClass,enabled,recursiveMemberCount,candidateRouteCount,isPrivilegedContext,isBroadIdentity,isUsableStartingPrincipal,validationPriorityModifier,
        @{Name='EvidenceBasis';Expression={@($_.evidenceBasis)-join ' | '}},
        @{Name='Limitations';Expression={@($_.limitations)-join ' | '}} |
    Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8

$CategoryCounts = @(
    $Sorted |
        Group-Object category |
        Sort-Object Name |
        ForEach-Object {
            [pscustomobject]@{category=$_.Name;count=$_.Count}
        }
)
$Summary = [pscustomobject][ordered]@{
    schemaVersion='1.0';classifier='ADIdentityContext';classifierVersion=$ClassifierVersion
    status='Completed';executionClass='offline_analysis';candidateRouteCount=$Candidates.Count
    uniqueIdentityCount=$Sorted.Count;categoryCounts=@($CategoryCounts)
    privilegedContextCount=@($Sorted|Where-Object isPrivilegedContext -eq $true).Count
    broadIdentityCount=@($Sorted|Where-Object isBroadIdentity -eq $true).Count
    unresolvedIdentityCount=@($Sorted|Where-Object category -eq 'UnresolvedIdentity').Count
    evidence=@($JsonPath,$CsvPath,$EventPath)
    limitations=@('Identity context is not proof of attacker control, credential availability, or exploitability.','Naming indicators are supporting evidence only unless mapped to a well-known built-in or privileged group.','Effective privileges and nested control paths require separate deterministic evidence.')
}
$Summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
$Events.Add((Write-MSADPTIdentityEvent -Kind Success -Code 'IdentityClassifierCompleted' -Message ("Classified {0} unique identity context(s)." -f $Sorted.Count) -Target 'Identity context classifier' -Data @{SummaryPath=$SummaryPath}))
$Events.ToArray() | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $EventPath -Encoding UTF8
Write-Output $Summary
