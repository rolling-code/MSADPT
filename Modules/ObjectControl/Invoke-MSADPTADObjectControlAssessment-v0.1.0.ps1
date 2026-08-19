<#
.SYNOPSIS
Runs the MSADPT Active Directory object-control and ACL baseline in one command.
.DESCRIPTION
Discovers the current domain and a writable domain controller, inventories high-impact users, groups,
computers, the domain root, and selected containers, evaluates explicit allow ACEs for dangerous rights,
resolves trustee state, correlates enabled and privileged targets, and produces structured JSON, CSV,
and one HTML report.

This baseline is read-only. It does not reset passwords, modify group membership, write SPNs, modify
RBCD descriptors, add key credentials, change owners or DACLs, or perform any directory write.
.NOTES
Version: 0.1.0
Package identity: MSADPT-AD-OBJECT-CONTROL-ASSESSMENT
#>
[CmdletBinding()]
param(
    [string]$Server,
    [PSCredential]$Credential,
    [string]$OutputDirectory,
    [ValidateRange(100,100000)][int]$MaximumObjects = 25000,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-AD-OBJECT-CONTROL-ASSESSMENT'
$PackageVersion = '0.1.0'
$OperationalErrors = New-Object 'System.Collections.Generic.List[object]'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray)
    if ($Quiet) { return }
    $Text = '[{0,-10}] {1}' -f $Status,$Message
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}
function Get-FirstTextValue {
    param([object]$Value)
    foreach ($Item in @($Value)) {
        $Text = [string]$Item
        if ($null -ne $Text -and $Text.Trim().Length -gt 0) { return $Text.Trim() }
    }
    return $null
}
function Add-OperationalError {
    param([string]$Stage,[string]$Target,[string]$ErrorText)
    $OperationalErrors.Add([pscustomobject][ordered]@{
        Stage=$Stage;Target=$Target;Status='Failed';Error=$ErrorText
    })
}
function Write-JsonArray {
    param([object[]]$Rows,[string]$Path,[int]$Depth=15)
    $Array = @($Rows)
    if ($Array.Count -eq 0) {
        [IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))
    }
    else {
        $Array | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    $Check = @(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
    if ($Check.Count -ne $Array.Count) { throw "JsonArrayRoundTripMismatch: $Path" }
}
function Write-JsonDocument {
    param([object]$Document,[string]$Path,[int]$Depth=15)
    $Document | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}
function Convert-HtmlText {
    param([object]$Value)
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}
function Get-ObjectTypeFromClass {
    param([object]$ObjectClass)
    $Classes = @($ObjectClass | ForEach-Object { [string]$_ })
    if ($Classes -contains 'user' -and $Classes -notcontains 'computer') { return 'User' }
    if ($Classes -contains 'computer') { return 'Computer' }
    if ($Classes -contains 'group') { return 'Group' }
    if ($Classes -contains 'organizationalUnit') { return 'OrganizationalUnit' }
    if ($Classes -contains 'domainDNS') { return 'Domain' }
    return 'DirectoryObject'
}
function Get-RiskRights {
    param([string]$Rights,[string]$ObjectType)
    $Detected = New-Object 'System.Collections.Generic.List[string]'
    if ($Rights -match 'GenericAll') { $Detected.Add('GenericAll') }
    if ($Rights -match 'GenericWrite') { $Detected.Add('GenericWrite') }
    if ($Rights -match 'WriteDacl') { $Detected.Add('WriteDacl') }
    if ($Rights -match 'WriteOwner') { $Detected.Add('WriteOwner') }
    if ($Rights -match 'WriteProperty') { $Detected.Add('WriteProperty') }
    if ($Rights -match 'ExtendedRight') { $Detected.Add('ExtendedRight') }
    if ($Rights -match 'Self') { $Detected.Add('Self') }
    if ($ObjectType -eq 'Group' -and $Rights -match 'WriteProperty|GenericWrite|GenericAll') { $Detected.Add('PotentialMembershipControl') }
    if ($ObjectType -eq 'Computer' -and $Rights -match 'WriteProperty|GenericWrite|GenericAll') { $Detected.Add('PotentialRBCDOrSPNControl') }
    if ($ObjectType -eq 'User' -and $Rights -match 'WriteProperty|GenericWrite|GenericAll|ExtendedRight') { $Detected.Add('PotentialUserControl') }
    return @($Detected.ToArray() | Sort-Object -Unique)
}
function Get-TrusteeContext {
    param([string]$IdentityReference,[string]$Server,[PSCredential]$Credential)
    $Result = [ordered]@{
        IdentityReference=$IdentityReference;Resolved=$false;ObjectType=$null
        SamAccountName=$null;Enabled=$null;DistinguishedName=$null;AdminCount=$null
    }
    try {
        $Sid = $null
        try {
            $Account = New-Object Security.Principal.NTAccount($IdentityReference)
            $Sid = $Account.Translate([Security.Principal.SecurityIdentifier]).Value
        }
        catch { }
        if ($null -ne $Sid) {
            $Parameters = @{Identity=$Sid;Server=$Server;Properties='objectClass','samAccountName','adminCount','userAccountControl';ErrorAction='Stop'}
            if ($null -ne $Credential) { $Parameters.Credential=$Credential }
            $Object = Get-ADObject @Parameters
            $ObjectType = Get-ObjectTypeFromClass $Object.ObjectClass
            $Enabled = $null
            if ($ObjectType -in @('User','Computer')) {
                $Disabled = (([int64]$Object.userAccountControl -band 2) -ne 0)
                $Enabled = -not $Disabled
            }
            $Result.Resolved=$true;$Result.ObjectType=$ObjectType;$Result.SamAccountName=[string]$Object.samAccountName
            $Result.Enabled=$Enabled;$Result.DistinguishedName=[string]$Object.DistinguishedName;$Result.AdminCount=$Object.adminCount
        }
    }
    catch { }
    return [pscustomobject]$Result
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Import-Module ActiveDirectory -ErrorAction Stop

    $Discovery = @{ErrorAction='Stop'}
    if ($null -ne $Credential) { $Discovery.Credential=$Credential }
    $Domain = Get-ADDomain @Discovery
    $Forest = Get-ADForest @Discovery
    if ($null -eq $Server -or $Server.Trim().Length -eq 0) {
        $Dc = Get-ADDomainController -Discover -Writable @Discovery
        $Server = Get-FirstTextValue $Dc.HostName
    }
    else { $Server=$Server.Trim() }
    if ($null -eq $Server -or $Server.Length -eq 0) { throw 'No usable writable domain controller was discovered.' }

    if ($null -eq $OutputDirectory -or $OutputDirectory.Trim().Length -eq 0) {
        $SafeDomain = [string]$Domain.DNSRoot -replace '[^A-Za-z0-9.-]','_'
        $OutputDirectory = Join-Path (Get-Location) ('MSADPT-AD-Object-Control-{0}-{1}' -f $SafeDomain,(Get-Date -Format 'yyyyMMdd-HHmmss'))
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) { throw "OutputDirectoryNotEmpty: $OutputDirectory" }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    Write-Step 'NETWORK' 'Planned live directory operations follow.' Magenta
    Write-Step 'TARGET' "$Server; Protocol=LDAP/ADWS; Ports=389 and 9389" DarkCyan
    Write-Step 'OPERATIONS' 'Read directory objects, security descriptors, trustee identities, enabled state, and privilege context.' DarkCyan
    Write-Step 'CHANGES' 'Directory writes=None; password resets=None; membership changes=None; SPN/RBCD/key-credential writes=None.' DarkCyan

    if (-not (Test-Path 'AD:\')) {
        $DriveParameters = @{Name='AD';PSProvider='ActiveDirectory';Root='';Server=$Server;ErrorAction='Stop'}
        if ($null -ne $Credential) { $DriveParameters.Credential=$Credential }
        New-PSDrive @DriveParameters | Out-Null
    }

    $Common = @{Server=$Server;ResultSetSize=$MaximumObjects;ErrorAction='Stop'}
    if ($null -ne $Credential) { $Common.Credential=$Credential }
    Write-Step 'QUERY' 'Collecting high-impact users, groups, computers, OUs, and domain-root objects.' Yellow
    $Objects = New-Object 'System.Collections.Generic.List[object]'

    try {
        $Users = @(Get-ADUser -LDAPFilter '(|(adminCount=1)(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' -Properties 'adminCount','enabled','servicePrincipalName','whenChanged' @Common)
        foreach ($Item in $Users) { $Objects.Add($Item) }
    } catch { Add-OperationalError 'UserCollection' $Server $_.Exception.Message }
    try {
        $Groups = @(Get-ADGroup -LDAPFilter '(|(adminCount=1)(isCriticalSystemObject=TRUE))' -Properties 'adminCount','groupScope','groupCategory','whenChanged' @Common)
        foreach ($Item in $Groups) { $Objects.Add($Item) }
    } catch { Add-OperationalError 'GroupCollection' $Server $_.Exception.Message }
    try {
        $Computers = @(Get-ADComputer -LDAPFilter '(|(adminCount=1)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(servicePrincipalName=*))' -Properties 'adminCount','enabled','operatingSystem','whenChanged' @Common)
        foreach ($Item in $Computers) { $Objects.Add($Item) }
    } catch { Add-OperationalError 'ComputerCollection' $Server $_.Exception.Message }
    try {
        $Ous = @(Get-ADOrganizationalUnit -Filter * -Properties 'gPLink','whenChanged' @Common)
        foreach ($Item in $Ous) { $Objects.Add($Item) }
    } catch { Add-OperationalError 'OuCollection' $Server $_.Exception.Message }
    try {
        $DomainRoot = Get-ADObject -Identity $Domain.DistinguishedName -Properties 'objectClass','whenChanged' -Server $Server -ErrorAction Stop
        $Objects.Add($DomainRoot)
    } catch { Add-OperationalError 'DomainRootCollection' $Server $_.Exception.Message }

    $UniqueObjects = @($Objects.ToArray() | Sort-Object DistinguishedName -Unique)
    Write-Step 'OK' "Collected $($UniqueObjects.Count) unique high-impact directory object(s)." Green

    $ObjectRows = New-Object 'System.Collections.Generic.List[object]'
    $AceRows = New-Object 'System.Collections.Generic.List[object]'
    $CandidateRows = New-Object 'System.Collections.Generic.List[object]'
    $TrusteeCache = @{}
    $Index = 0

    foreach ($Object in $UniqueObjects) {
        $Index++
        if ($Index -eq 1 -or $Index % 250 -eq 0 -or $Index -eq $UniqueObjects.Count) {
            $Percent = if ($UniqueObjects.Count -gt 0) { [int](($Index/[double]$UniqueObjects.Count)*100) } else { 100 }
            Write-Step 'PROCESS' "ACL evaluation $Index/$($UniqueObjects.Count) ($Percent%): $($Object.Name)" DarkCyan
        }
        $ObjectType = Get-ObjectTypeFromClass $Object.ObjectClass
        $Enabled = $null
        if ($null -ne $Object.PSObject.Properties['Enabled']) { $Enabled=[bool]$Object.Enabled }
        $ObjectRows.Add([pscustomobject][ordered]@{
            ObjectType=$ObjectType;Name=[string]$Object.Name;SamAccountName=[string]$Object.SamAccountName
            DistinguishedName=[string]$Object.DistinguishedName;Enabled=$Enabled;AdminCount=$Object.adminCount
            WhenChangedUtc=if($null-ne$Object.whenChanged){([datetime]$Object.whenChanged).ToUniversalTime().ToString('o')}else{$null}
        })

        try {
            $Acl = Get-Acl -LiteralPath ("AD:\{0}" -f $Object.DistinguishedName) -ErrorAction Stop
            foreach ($Ace in @($Acl.Access)) {
                if ([string]$Ace.AccessControlType -ne 'Allow') { continue }
                $Rights = [string]$Ace.ActiveDirectoryRights
                $RiskRights = @(Get-RiskRights $Rights $ObjectType)
                if ($RiskRights.Count -eq 0) { continue }
                $Identity = [string]$Ace.IdentityReference
                if (-not $TrusteeCache.ContainsKey($Identity)) {
                    $TrusteeCache[$Identity] = Get-TrusteeContext $Identity $Server $Credential
                }
                $Trustee = $TrusteeCache[$Identity]
                $RoutineAdministrative = ($Identity -match '(?i)\\(Domain Admins|Enterprise Admins|Administrators)$' -or $Identity -eq 'NT AUTHORITY\SYSTEM')
                $AceRow = [pscustomobject][ordered]@{
                    TargetObjectType=$ObjectType;TargetName=[string]$Object.Name;TargetSamAccountName=[string]$Object.SamAccountName
                    TargetDistinguishedName=[string]$Object.DistinguishedName;TargetEnabled=$Enabled;TargetAdminCount=$Object.adminCount
                    Trustee=$Identity;TrusteeResolved=$Trustee.Resolved;TrusteeObjectType=$Trustee.ObjectType
                    TrusteeSamAccountName=$Trustee.SamAccountName;TrusteeEnabled=$Trustee.Enabled;TrusteeAdminCount=$Trustee.AdminCount
                    ActiveDirectoryRights=$Rights;RiskRights=$RiskRights;ObjectTypeGuid=[string]$Ace.ObjectType
                    IsInherited=[bool]$Ace.IsInherited;InheritanceType=[string]$Ace.InheritanceType
                    RoutineAdministrative=$RoutineAdministrative
                }
                $AceRows.Add($AceRow)

                if (-not $RoutineAdministrative -and $Trustee.Enabled -ne $false) {
                    $Priority = 'P3'
                    if ($Object.adminCount -eq 1 -and $RiskRights -contains 'GenericAll') { $Priority='P1' }
                    elseif ($Object.adminCount -eq 1 -or $RiskRights -contains 'WriteDacl' -or $RiskRights -contains 'WriteOwner') { $Priority='P2' }
                    $CandidateRows.Add([pscustomobject][ordered]@{
                        CandidateId=('ACL-{0:D6}' -f $CandidateRows.Count);Priority=$Priority
                        Trustee=$Identity;TrusteeSamAccountName=$Trustee.SamAccountName;TrusteeEnabled=$Trustee.Enabled
                        TargetObjectType=$ObjectType;TargetName=[string]$Object.Name;TargetSamAccountName=[string]$Object.SamAccountName
                        TargetDistinguishedName=[string]$Object.DistinguishedName;TargetAdminCount=$Object.adminCount
                        RiskRights=$RiskRights;IsInherited=[bool]$Ace.IsInherited
                        EvidenceState='Directory control candidate; behavioral validation pending'
                        NextValidator='ADObjectControlBehavioralValidation'
                        Interpretation='The ACE grants a potentially dangerous control right. Effective impact, prerequisite identity control, and a reversible real-world operation remain unproven.'
                    })
                }
            }
        }
        catch {
            Add-OperationalError 'AclRead' ([string]$Object.DistinguishedName) $_.Exception.Message
        }
    }

    $ObjectsJson=Join-Path $OutputDirectory 'ad-object-inventory.json';$ObjectsCsv=Join-Path $OutputDirectory 'ad-object-inventory.csv'
    $AcesJson=Join-Path $OutputDirectory 'dangerous-ace-inventory.json';$AcesCsv=Join-Path $OutputDirectory 'dangerous-ace-inventory.csv'
    $CandidatesJson=Join-Path $OutputDirectory 'object-control-candidates.json';$CandidatesCsv=Join-Path $OutputDirectory 'object-control-candidates.csv'
    $ErrorsJson=Join-Path $OutputDirectory 'operational-errors.json'
    Write-JsonArray $ObjectRows.ToArray() $ObjectsJson;$ObjectRows|Export-Csv $ObjectsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $AceRows.ToArray() $AcesJson;$AceRows|Export-Csv $AcesCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $CandidateRows.ToArray() $CandidatesJson;$CandidateRows|Export-Csv $CandidatesCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $OperationalErrors.ToArray() $ErrorsJson

    $PriorityCounts = @($CandidateRows | Group-Object Priority | Sort-Object Name | ForEach-Object { [pscustomobject]@{Priority=$_.Name;Count=$_.Count} })
    $Summary=[pscustomobject][ordered]@{
        SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Status=if($OperationalErrors.Count-gt0){'CompletedWithErrors'}else{'Completed'}
        GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        Domain=[pscustomobject]@{DnsRoot=[string]$Domain.DNSRoot;Forest=[string]$Forest.Name;Server=$Server}
        Counts=[pscustomobject]@{Objects=$ObjectRows.Count;DangerousAceRows=$AceRows.Count;Candidates=$CandidateRows.Count;OperationalErrors=$OperationalErrors.Count}
        PriorityCounts=$PriorityCounts
        InterpretationBoundary=@(
            'An ACE is a control-path lead, not proof that the trustee is compromised or controllable.',
            'Object-specific ExtendedRight and WriteProperty GUIDs require deterministic semantic resolution.',
            'Inherited administrative rights may be expected and are retained as evidence but suppressed from active candidates.',
            'A confirmed vulnerability requires a real reversible operation and demonstrated security impact.'
        )
        Safety=[pscustomobject]@{NetworkActivity='Read-only LDAP and ADWS queries';DirectoryChanges='None';PasswordResets='None';MembershipChanges='None';SpnWrites='None';RbcdWrites='None';KeyCredentialWrites='None';OllamaActivity='None'}
    }
    $SummaryPath=Join-Path $OutputDirectory 'ad-object-control-summary.json';Write-JsonDocument $Summary $SummaryPath

    $TopCandidates=@($CandidateRows|Sort-Object Priority,TargetObjectType,TargetName|Select-Object -First 100)
    $CandidateHtml=($TopCandidates|ForEach-Object{'<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>'-f(Convert-HtmlText $_.Priority),(Convert-HtmlText $_.Trustee),(Convert-HtmlText $_.TargetObjectType),(Convert-HtmlText $_.TargetName),(Convert-HtmlText ($_.RiskRights-join', ')),(Convert-HtmlText $_.EvidenceState)})-join"`n"
    $ReportPath=Join-Path $OutputDirectory 'MSADPT-AD-Object-Control-Report.html'
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT AD Object Control Assessment</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body><h1>MSADPT Active Directory Object-Control Assessment</h1><div class="card"><b>Status:</b> $(Convert-HtmlText $Summary.Status)<br><b>Domain:</b> $(Convert-HtmlText $Domain.DNSRoot)<br><b>Objects:</b> $($ObjectRows.Count)<br><b>Dangerous ACE rows:</b> $($AceRows.Count)<br><b>Candidates:</b> $($CandidateRows.Count)<br><b>Directory changes:</b> None</div><h2>Top Candidate Paths</h2><table><tr><th>Priority</th><th>Trustee</th><th>Target Type</th><th>Target</th><th>Rights</th><th>State</th></tr>$CandidateHtml</table><h2>Evidence</h2><ul><li><a href="ad-object-inventory.csv">Object inventory</a></li><li><a href="dangerous-ace-inventory.csv">Dangerous ACE inventory</a></li><li><a href="object-control-candidates.csv">Candidates</a></li><li><a href="operational-errors.json">Operational errors</a></li><li><a href="ad-object-control-summary.json">Structured summary</a></li></ul><p class="note">Candidates are not vulnerabilities. MSADPT requires a real reversible operation demonstrating impact before reporting a finding.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File|Where-Object{$_.Name-ne'evidence-manifest.json'}|Sort-Object Name)
    $ManifestRows=@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json';Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=$ManifestRows.Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "Object-control assessment complete: objects=$($ObjectRows.Count), ACEs=$($AceRows.Count), candidates=$($CandidateRows.Count), errors=$($OperationalErrors.Count)." Green
    [pscustomobject][ordered]@{
        Status=if($OperationalErrors.Count-gt0){'PassedWithErrors'}else{'Passed'}
        PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;Domain=[string]$Domain.DNSRoot;DomainController=$Server
        ObjectCount=$ObjectRows.Count;DangerousAceCount=$AceRows.Count;CandidateCount=$CandidateRows.Count
        P1Count=@($CandidateRows|Where-Object{$_.Priority-eq'P1'}).Count
        P2Count=@($CandidateRows|Where-Object{$_.Priority-eq'P2'}).Count
        P3Count=@($CandidateRows|Where-Object{$_.Priority-eq'P3'}).Count
        OperationalErrorCount=$OperationalErrors.Count;OutputDirectory=$OutputDirectory
        HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath
        DirectoryChanges='None';PasswordResets='None';MembershipChanges='None';OllamaActivity='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
