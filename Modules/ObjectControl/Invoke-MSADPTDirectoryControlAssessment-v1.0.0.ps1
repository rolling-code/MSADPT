<#
.SYNOPSIS
Performs a targeted, read-only Active Directory directory-control assessment.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [string]$Server,
    [PSCredential]$Credential,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$StartingIdentity,
    [string]$InputAcePath,
    [ValidateRange(100, 100000)][int]$MaximumObjects = 25000,
    [ValidateRange(1, 8)][int]$MaximumDepth = 4,
    [switch]$Quiet,
    [switch]$NoColor
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-DIRECTORY-CONTROL-ASSESSMENT'
$PackageVersion = '1.0.1'

function Show-Status {
    param([string]$State, [string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray)
    if ($Quiet) { return }
    $Text = '[{0,-10}] {1}' -f $State, $Message
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}
function Get-SafeProperty {
    param([object]$Object, [string]$Name, [object]$Default = $null)
    if ($null -eq $Object) { return $Default }
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) { return $Default }
    return $Property.Value
}
function Write-JsonArray {
    param([object[]]$Value, [string]$Path)
    $Array = [object[]]@($Value)
    if ($Array.Count -eq 0) {
        [IO.File]::WriteAllText($Path, "[]`r`n", (New-Object Text.UTF8Encoding($false)))
    } else {
        $Array | ConvertTo-Json -Depth 25 | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}
function Write-JsonDocument {
    param([object]$Value, [string]$Path)
    $Value | ConvertTo-Json -Depth 25 | Set-Content -LiteralPath $Path -Encoding UTF8
    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}
function Normalize-Text {
    param([object]$Value)
    $Text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    return $Text.Trim().ToLowerInvariant()
}
function Normalize-Guid {
    param([object]$Value)
    $Text = Normalize-Text $Value
    if ($null -eq $Text) { return '00000000-0000-0000-0000-000000000000' }
    return $Text.Trim('{}')
}
function Get-TrusteeKey {
    param([object]$Ace)
    $Sid = [string](Get-SafeProperty $Ace 'TrusteeSid')
    if (-not [string]::IsNullOrWhiteSpace($Sid)) { return 'sid:' + (Normalize-Text $Sid) }
    $Dn = [string](Get-SafeProperty $Ace 'TrusteeDistinguishedName')
    if (-not [string]::IsNullOrWhiteSpace($Dn)) { return 'dn:' + (Normalize-Text $Dn) }
    return 'name:' + (Normalize-Text (Get-SafeProperty $Ace 'Trustee'))
}

$GuidMap = @{
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'WriteGroupMembership'
    'bf967a7f-0de6-11d0-a285-00aa003049e2' = 'WriteServicePrincipalName'
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = 'WriteRBCD'
    '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'WriteKeyCredentialLink'
    '00299570-246d-11d0-a768-00aa006e0529' = 'ResetPassword'
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'ReplicatingDirectoryChanges'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'ReplicatingDirectoryChangesAll'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'ReplicatingDirectoryChangesFilteredSet'
    'bf9679e8-0de6-11d0-a285-00aa003049e2' = 'WriteUserAccountControl'
    'bf9679d5-0de6-11d0-a285-00aa003049e2' = 'WriteScriptPath'
    'bf96797f-0de6-11d0-a285-00aa003049e2' = 'WriteAltSecurityIdentities'
    '20119867-1d04-4ab7-9371-cfc3d5df0afd' = 'WriteSupportedEncryptionTypes'
    'f30e3bbe-9ff0-11d1-b603-0000f80367c1' = 'WriteGPLink'
}
function Get-Capabilities {
    param([object]$Ace)
    $Rights = [string](Get-SafeProperty $Ace 'ActiveDirectoryRights')
    $Guid = Normalize-Guid (Get-SafeProperty $Ace 'ObjectTypeGuid')
    $Values = New-Object 'System.Collections.Generic.List[string]'
    foreach ($Right in @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner')) {
        if ($Rights -match $Right) { $Values.Add($Right) }
    }
    if ($GuidMap.ContainsKey($Guid)) {
        $Values.Add([string]$GuidMap[$Guid])
    } elseif ($Rights -match 'WriteProperty|ExtendedRight|Self') {
        $Values.Add('UnresolvedObjectSpecificRight')
    }
    return [object[]]@($Values.ToArray() | Sort-Object -Unique)
}
function Get-Priority {
    param([string]$Capability, [object]$Ace)
    $AdminCount = Get-SafeProperty $Ace 'TargetAdminCount'
    if ($AdminCount -eq 1 -and $Capability -in @('GenericAll','WriteDacl','WriteOwner','ResetPassword','WriteRBCD','WriteKeyCredentialLink')) { return 'P1' }
    if ($Capability -in @('WriteDacl','WriteOwner','ResetPassword','WriteRBCD','WriteKeyCredentialLink','WriteGroupMembership','WriteServicePrincipalName','ReplicatingDirectoryChangesAll')) { return 'P2' }
    return 'P3'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$Errors = New-Object 'System.Collections.Generic.List[object]'
$Objects = New-Object 'System.Collections.Generic.List[object]'
$Aces = New-Object 'System.Collections.Generic.List[object]'
Show-Status START "$PackageIdentity v$PackageVersion" Cyan
Show-Status SAFETY 'Read-only targeted high-impact assessment. Directory changes=None; impact reproduction=None.' Yellow

if (-not [string]::IsNullOrWhiteSpace($InputAcePath)) {
    $RawRows = [object[]]@(Get-Content -LiteralPath $InputAcePath -Raw | ConvertFrom-Json -ErrorAction Stop)
    foreach ($Row in $RawRows) { $Aces.Add($Row) }
    Show-Status FIXTURE "Loaded $($Aces.Count) synthetic ACE rows." DarkCyan
} else {
    Import-Module ActiveDirectory -ErrorAction Stop
    $Discovery = @{ ErrorAction = 'Stop' }
    if ($null -ne $Credential) { $Discovery.Credential = $Credential }
    $Domain = Get-ADDomain @Discovery
    if ([string]::IsNullOrWhiteSpace($Server)) {
        $Server = [string](Get-ADDomainController -Discover -Writable @Discovery).HostName
    }
    Show-Status NETWORK "Target=$Server; protocol=ADWS/LDAP; operations=read objects, ACLs, and trustee context." Magenta
    if (-not (Test-Path 'AD:\')) {
        $DriveParameters = @{ Name='AD'; PSProvider='ActiveDirectory'; Root=''; Server=$Server; ErrorAction='Stop' }
        if ($null -ne $Credential) { $DriveParameters.Credential = $Credential }
        New-PSDrive @DriveParameters | Out-Null
    }
    $Common = @{ Server=$Server; ResultSetSize=$MaximumObjects; ErrorAction='Stop' }
    if ($null -ne $Credential) { $Common.Credential = $Credential }
    $SourceObjects = New-Object 'System.Collections.Generic.List[object]'
    $Queries = @(
        { Get-ADUser -LDAPFilter '(|(adminCount=1)(servicePrincipalName=*))' -Properties adminCount,enabled,objectSid,servicePrincipalName,whenChanged @Common }
        { Get-ADGroup -LDAPFilter '(|(adminCount=1)(isCriticalSystemObject=TRUE))' -Properties adminCount,objectSid,whenChanged @Common }
        { Get-ADComputer -LDAPFilter '(|(adminCount=1)(servicePrincipalName=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))' -Properties adminCount,enabled,objectSid,whenChanged @Common }
        { Get-ADOrganizationalUnit -Filter * -Properties gPLink,whenChanged @Common }
        { Get-ADObject -Identity $Domain.DistinguishedName -Properties objectSid,whenChanged -Server $Server -ErrorAction Stop }
    )
    foreach ($Query in $Queries) {
        try { foreach ($Item in @(& $Query)) { $SourceObjects.Add($Item) } }
        catch { $Errors.Add([pscustomobject]@{ Stage='ObjectCollection'; Error=$_.Exception.Message }) }
    }
    foreach ($DirectoryObject in @($SourceObjects.ToArray() | Sort-Object DistinguishedName -Unique)) {
        $ObjectType = if ($DirectoryObject.ObjectClass -eq 'group') {'Group'} elseif ($DirectoryObject.ObjectClass -eq 'computer') {'Computer'} elseif ($DirectoryObject.ObjectClass -eq 'user') {'User'} elseif ($DirectoryObject.ObjectClass -eq 'organizationalUnit') {'OrganizationalUnit'} else {'Domain'}
        $ObjectSid = [string](Get-SafeProperty $DirectoryObject 'ObjectSid')
        $Enabled = Get-SafeProperty $DirectoryObject 'Enabled'
        $AdminCount = Get-SafeProperty $DirectoryObject 'adminCount'
        $Objects.Add([pscustomobject][ordered]@{
            ObjectType=$ObjectType; Name=[string]$DirectoryObject.Name; SamAccountName=[string](Get-SafeProperty $DirectoryObject 'SamAccountName')
            DistinguishedName=[string]$DirectoryObject.DistinguishedName; ObjectSid=$ObjectSid; Enabled=$Enabled; AdminCount=$AdminCount
            ProtectedObjectIndicatorObserved=($AdminCount -eq 1); AdminSDHolderEnforcement='NotEstablished'
        })
        try {
            $Acl = Get-Acl -LiteralPath ('AD:\' + $DirectoryObject.DistinguishedName) -ErrorAction Stop
            foreach ($Ace in @($Acl.Access)) {
                $Capabilities = @(Get-Capabilities $Ace)
                if ($Capabilities.Count -eq 0) { continue }
                $Identity = [string]$Ace.IdentityReference
                $Sid = $null
                try { $Sid = (New-Object Security.Principal.NTAccount($Identity)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { }
                $Context = $null
                if ($null -ne $Sid) {
                    try {
                        $Parameters = @{ Identity=$Sid; Server=$Server; Properties='objectSid','objectClass','samAccountName','adminCount','userAccountControl'; ErrorAction='Stop' }
                        if ($null -ne $Credential) { $Parameters.Credential = $Credential }
                        $Context = Get-ADObject @Parameters
                    } catch { }
                }
                $Aces.Add([pscustomobject][ordered]@{
                    TargetObjectType=$ObjectType; TargetName=[string]$DirectoryObject.Name; TargetSamAccountName=[string](Get-SafeProperty $DirectoryObject 'SamAccountName')
                    TargetDistinguishedName=[string]$DirectoryObject.DistinguishedName; TargetObjectSid=$ObjectSid; TargetEnabled=$Enabled; TargetAdminCount=$AdminCount
                    ProtectedObjectIndicatorObserved=($AdminCount -eq 1); AdminSDHolderEnforcement='NotEstablished'
                    Trustee=$Identity; TrusteeSid=$Sid; TrusteeDistinguishedName=if($null-ne$Context){[string]$Context.DistinguishedName}else{$null}
                    TrusteeSamAccountName=if($null-ne$Context){[string](Get-SafeProperty $Context 'samAccountName')}else{$null}; TrusteeResolved=($null-ne$Context)
                    TrusteeEnabled=if($null-ne$Context-and$null-ne(Get-SafeProperty $Context 'userAccountControl')){(([int64](Get-SafeProperty $Context 'userAccountControl') -band 2) -eq 0)}else{$null}
                    AccessControlType=[string]$Ace.AccessControlType; ActiveDirectoryRights=[string]$Ace.ActiveDirectoryRights
                    ObjectTypeGuid=[string]$Ace.ObjectType; InheritedObjectTypeGuid=[string]$Ace.InheritedObjectType
                    IsInherited=[bool]$Ace.IsInherited; InheritanceType=[string]$Ace.InheritanceType; AceOrder=$Aces.Count
                })
            }
        } catch { $Errors.Add([pscustomobject]@{ Stage='AclRead'; Target=[string]$DirectoryObject.DistinguishedName; Error=$_.Exception.Message }) }
    }
}

$Semantic = New-Object 'System.Collections.Generic.List[object]'
foreach ($Ace in [object[]]$Aces.ToArray()) {
    foreach ($Capability in @(Get-Capabilities $Ace)) {
        $Semantic.Add([pscustomobject][ordered]@{
            TrusteeKey=(Get-TrusteeKey $Ace); TrusteeSid=Get-SafeProperty $Ace 'TrusteeSid'; Trustee=Get-SafeProperty $Ace 'Trustee'
            TrusteeSamAccountName=Get-SafeProperty $Ace 'TrusteeSamAccountName'; TrusteeDistinguishedName=Get-SafeProperty $Ace 'TrusteeDistinguishedName'
            TrusteeResolved=Get-SafeProperty $Ace 'TrusteeResolved' $false; TrusteeEnabled=Get-SafeProperty $Ace 'TrusteeEnabled'
            TargetObjectType=Get-SafeProperty $Ace 'TargetObjectType'; TargetName=Get-SafeProperty $Ace 'TargetName'; TargetSamAccountName=Get-SafeProperty $Ace 'TargetSamAccountName'
            TargetDistinguishedName=Get-SafeProperty $Ace 'TargetDistinguishedName'; TargetObjectSid=Get-SafeProperty $Ace 'TargetObjectSid'; TargetAdminCount=Get-SafeProperty $Ace 'TargetAdminCount'
            ProtectedObjectIndicatorObserved=[bool](Get-SafeProperty $Ace 'ProtectedObjectIndicatorObserved' ((Get-SafeProperty $Ace 'TargetAdminCount') -eq 1))
            AdminSDHolderEnforcement=[string](Get-SafeProperty $Ace 'AdminSDHolderEnforcement' 'NotEstablished')
            Capability=$Capability; AccessControlType=[string](Get-SafeProperty $Ace 'AccessControlType' 'Allow'); IsInherited=[bool](Get-SafeProperty $Ace 'IsInherited' $false)
            ObjectTypeGuid=(Normalize-Guid (Get-SafeProperty $Ace 'ObjectTypeGuid')); AceOrder=Get-SafeProperty $Ace 'AceOrder' 0
        })
    }
}
$Candidates = New-Object 'System.Collections.Generic.List[object]'
$FocusedReview = New-Object 'System.Collections.Generic.List[object]'
$Groups = @($Semantic | Group-Object { $_.TrusteeKey + '|' + (Normalize-Text $_.TargetDistinguishedName) + '|' + $_.Capability })
foreach ($Group in $Groups) {
    $Rows = @($Group.Group); $First = $Rows[0]
    $AllowRows = @($Rows | Where-Object { $_.AccessControlType -eq 'Allow' })
    $DenyRows = @($Rows | Where-Object { $_.AccessControlType -eq 'Deny' })
    $EvidenceState = if ($First.Capability -eq 'UnresolvedObjectSpecificRight' -or $DenyRows.Count -gt 0) {'FocusedReviewRequired'} else {'SemanticControlCandidate'}
    $Candidate = [pscustomobject][ordered]@{
        CandidateId=('DIR-{0:D6}' -f $Candidates.Count); Priority=(Get-Priority $First.Capability $First)
        TrusteeKey=$First.TrusteeKey; TrusteeSid=$First.TrusteeSid; Trustee=$First.Trustee
        TargetObjectType=$First.TargetObjectType; TargetName=$First.TargetName; TargetSamAccountName=$First.TargetSamAccountName
        TargetDistinguishedName=$First.TargetDistinguishedName; TargetObjectSid=$First.TargetObjectSid; Capability=$First.Capability
        AllowAceCount=$AllowRows.Count; DenyAceCount=$DenyRows.Count
        DirectAceCount=@($Rows | Where-Object { -not $_.IsInherited }).Count; InheritedAceCount=@($Rows | Where-Object { $_.IsInherited }).Count
        DenyInteraction=if($DenyRows.Count -gt 0){'Unresolved'}else{'NotObserved'}
        ProtectedObjectIndicatorObserved=$First.ProtectedObjectIndicatorObserved; AdminSDHolderEnforcement=$First.AdminSDHolderEnforcement
        EvidenceState=$EvidenceState; EffectiveAccess='NotEstablished'; ImpactReproduced=$false
    }
    $Candidates.Add($Candidate)
    if ($EvidenceState -eq 'FocusedReviewRequired') { $FocusedReview.Add($Candidate) }
}

$Paths = New-Object 'System.Collections.Generic.List[object]'
# Current-identity reachability is deliberately separate from identity-neutral candidates.
# Name-only starting identities are not equated to SID-keyed trustees without deterministic SID evidence.
$Disposition = if ($Errors.Count -gt 0 -and $Candidates.Count -eq 0) {'Inconclusive'} elseif ($Candidates.Count -eq 0) {'NotDetected'} elseif ($FocusedReview.Count -gt 0) {'FocusedReviewRequired'} else {'CandidateDetected'}

Write-JsonArray $Objects.ToArray() (Join-Path $OutputDirectory 'directory-object-inventory.json')
Write-JsonArray $Aces.ToArray() (Join-Path $OutputDirectory 'directory-control-ace-inventory.json')
[object[]]$Aces.ToArray() | Export-Csv (Join-Path $OutputDirectory 'directory-control-ace-inventory.csv') -NoTypeInformation -Encoding UTF8
Write-JsonArray $Candidates.ToArray() (Join-Path $OutputDirectory 'directory-control-first-hop-candidates.json')
[object[]]$Candidates.ToArray() | Export-Csv (Join-Path $OutputDirectory 'directory-control-first-hop-candidates.csv') -NoTypeInformation -Encoding UTF8
Write-JsonArray $FocusedReview.ToArray() (Join-Path $OutputDirectory 'directory-control-focused-review.json')
[object[]]$FocusedReview.ToArray() | Export-Csv (Join-Path $OutputDirectory 'directory-control-focused-review.csv') -NoTypeInformation -Encoding UTF8
Write-JsonArray $Paths.ToArray() (Join-Path $OutputDirectory 'directory-control-current-identity-paths.json')
Write-JsonArray $Errors.ToArray() (Join-Path $OutputDirectory 'directory-control-operational-errors.json')

$Summary = [pscustomobject][ordered]@{
    SchemaVersion='1.0'; PackageIdentity=$PackageIdentity; PackageVersion=$PackageVersion
    Status=if($Errors.Count){'CompletedWithErrors'}else{'Completed'}; Disposition=$Disposition; GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
    Scope='TargetedHighImpactDirectoryObjects'; ScopeCompleteness='NotCompleteDomainWideAclInventory'
    Counts=[pscustomobject][ordered]@{
        Objects=$Objects.Count; AceRows=$Aces.Count
        AllowAceRows=@($Aces.ToArray() | Where-Object { [string](Get-SafeProperty $_ 'AccessControlType' 'Allow') -eq 'Allow' }).Count
        DenyAceRows=@($Aces.ToArray() | Where-Object { [string](Get-SafeProperty $_ 'AccessControlType' 'Allow') -eq 'Deny' }).Count
        FirstHopCandidates=$Candidates.Count; FocusedReview=$FocusedReview.Count; CurrentIdentityPaths=$Paths.Count; OperationalErrors=$Errors.Count
    }
    Controls=[pscustomobject][ordered]@{
        SidFirstNormalization=$true; AllowAndDenyPreserved=$true; DenyPrecedenceAutomaticallyClaimed=$false
        ProtectedObjectIndicatorCollected=$true; AdminSDHolderEnforcementAutomaticallyClaimed=$false
        IdentityNeutralCandidates=$true; CurrentIdentityReachabilitySeparated=$true
    }
    InterpretationBoundary=@('Candidates are not vulnerabilities.','Deny interaction, effective access, protected-object behavior, and downstream impact remain unproven unless separately validated.','NotDetected is limited to the targeted assessed scope.')
    Safety=[pscustomobject]@{DirectoryQueries=if($InputAcePath){'None'}else{'Read-only'};DirectoryChanges='None';ImpactReproduction='None';RemoteExecution='None'}
}
Write-JsonDocument $Summary (Join-Path $OutputDirectory 'directory-control-summary.json')
$Files = @(Get-ChildItem -LiteralPath $OutputDirectory -File | Where-Object { $_.Name -ne 'evidence-manifest.json' } | Sort-Object Name | ForEach-Object { [pscustomobject]@{Name=$_.Name;Size=$_.Length;SHA256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash} })
Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status=if($Errors.Count){'CompletedWithErrors'}else{'Completed'};ModuleId='Invoke-MSADPTDirectoryControlAssessment';ModuleVersion=$PackageVersion;FileCount=$Files.Count;Files=$Files}) (Join-Path $OutputDirectory 'evidence-manifest.json')
Show-Status DONE "Disposition=$Disposition; ACEs=$($Aces.Count); candidates=$($Candidates.Count); focused-review=$($FocusedReview.Count); paths=$($Paths.Count)." Green
[pscustomobject][ordered]@{Status=if($Errors.Count){'PassedWithErrors'}else{'Passed'};PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;Disposition=$Disposition;AceCount=$Aces.Count;CandidateCount=$Candidates.Count;FocusedReviewCount=$FocusedReview.Count;CurrentIdentityPathCount=$Paths.Count;OperationalErrorCount=$Errors.Count;OutputDirectory=$OutputDirectory;SummaryPath=(Join-Path $OutputDirectory 'directory-control-summary.json');ManifestPath=(Join-Path $OutputDirectory 'evidence-manifest.json');DirectoryChanges='None'}
