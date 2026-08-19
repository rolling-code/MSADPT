<#
.SYNOPSIS
Collects a reusable, evidence-first Active Directory SPN and Kerberos baseline for MSADPT.
.DESCRIPTION
Auto-discovers the current domain and a writable domain controller. Inventories user and computer
SPNs, AS-REP candidates, delegation configuration, encryption-type settings, and duplicate SPNs.
Exports normalized JSON and CSV evidence, a neutral validation-candidate inventory, and a manifest.

This collector performs read-only Active Directory queries. It does not request or extract Kerberos
tickets, collect password material, authenticate to discovered services, or modify Active Directory.
.NOTES
Version: 0.1.1
Package identity: MSADPT-KERBEROS-SPN-BASELINE-COLLECTION
#>
[CmdletBinding()]
param(
    [string]$Server,
    [PSCredential]$Credential,
    [string]$OutputDirectory,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-KERBEROS-SPN-BASELINE-COLLECTION'
$PackageVersion = '0.1.1'

function Write-Step {
    param(
        [string]$Status,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    if ($Quiet) { return }
    $Text = '[{0,-8}] {1}' -f $Status, $Message
    if ($NoColor) { Write-Host $Text }
    else { Write-Host $Text -ForegroundColor $Color }
}

function Get-FirstTextValue {
    param([object]$Value)

    foreach ($Item in @($Value)) {
        $Text = [string]$Item
        if ($null -ne $Text -and $Text.Trim().Length -gt 0) {
            return $Text.Trim()
        }
    }

    return $null
}

function Convert-LastLogonTimestamp {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    try {
        $Number = [int64]$Value
        if ($Number -le 0) { return $null }
        return [DateTime]::FromFileTimeUtc($Number).ToString('o')
    }
    catch {
        return $null
    }
}

function Convert-DateToUtcText {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    try {
        return ([DateTime]$Value).ToUniversalTime().ToString('o')
    }
    catch {
        return $null
    }
}

function Convert-EncryptionTypes {
    param([object]$Value)

    $Number = 0
    if ($null -ne $Value) {
        try { $Number = [int]$Value }
        catch { $Number = 0 }
    }

    $Types = New-Object 'System.Collections.Generic.List[string]'
    if (($Number -band 1) -ne 0) { $Types.Add('DES_CBC_CRC') }
    if (($Number -band 2) -ne 0) { $Types.Add('DES_CBC_MD5') }
    if (($Number -band 4) -ne 0) { $Types.Add('RC4_HMAC') }
    if (($Number -band 8) -ne 0) { $Types.Add('AES128_CTS_HMAC_SHA1_96') }
    if (($Number -band 16) -ne 0) { $Types.Add('AES256_CTS_HMAC_SHA1_96') }
    if (($Number -band 32) -ne 0) { $Types.Add('FAST_SUPPORTED') }
    if (($Number -band 64) -ne 0) { $Types.Add('COMPOUND_IDENTITY_SUPPORTED') }
    if (($Number -band 128) -ne 0) { $Types.Add('CLAIMS_SUPPORTED') }

    return [pscustomobject][ordered]@{
        Raw = $Number
        Types = @($Types.ToArray())
        Rc4Explicit = (($Number -band 4) -ne 0)
        AesExplicit = (($Number -band 24) -ne 0)
        DesExplicit = (($Number -band 3) -ne 0)
        Unspecified = ($Number -eq 0)
    }
}

function Convert-Spn {
    param([string]$Spn)

    $ServiceClass = $null
    $HostName = $null
    $Port = $null
    $ServiceName = $null

    if ($Spn -match '^([^/]+)/([^/:]+)(?::([0-9]+))?(?:/(.+))?$') {
        $ServiceClass = [string]$Matches[1]
        $HostName = [string]$Matches[2]
        if ($Matches[3]) { $Port = [int]$Matches[3] }
        if ($Matches[4]) { $ServiceName = [string]$Matches[4] }
    }

    return [pscustomobject][ordered]@{
        Spn = $Spn
        NormalizedSpn = $Spn.ToLowerInvariant()
        ServiceClass = $ServiceClass
        Host = $HostName
        Port = $Port
        ServiceName = $ServiceName
        ParseStatus = if ($null -ne $ServiceClass) { 'Parsed' } else { 'Unparsed' }
    }
}

function Write-JsonFile {
    param(
        [object]$InputObject,
        [string]$Path,
        [int]$Depth = 12
    )

    $InputObject |
        ConvertTo-Json -Depth $Depth |
        Set-Content -LiteralPath $Path -Encoding UTF8

    $null = Get-Content -LiteralPath $Path -Raw |
        ConvertFrom-Json -ErrorAction Stop
}

function New-ObjectEvidenceRow {
    param(
        [ValidateSet('User','Computer')]
        [string]$ObjectType,
        [object]$DirectoryObject,
        [object]$EncryptionContext,
        [string[]]$Spns
    )

    $AllowedTargets = @(
        $DirectoryObject.'msDS-AllowedToDelegateTo' |
            ForEach-Object { [string]$_ } |
            Where-Object { $null -ne $_ -and $_.Length -gt 0 }
    )

    return [pscustomobject][ordered]@{
        ObjectType = $ObjectType
        SamAccountName = [string]$DirectoryObject.SamAccountName
        DistinguishedName = [string]$DirectoryObject.DistinguishedName
        Enabled = [bool]$DirectoryObject.Enabled
        UserPrincipalName = if ($ObjectType -eq 'User') { [string]$DirectoryObject.UserPrincipalName } else { $null }
        Description = if ($ObjectType -eq 'User') { [string]$DirectoryObject.Description } else { $null }
        AdminCount = if ($ObjectType -eq 'User') { $DirectoryObject.AdminCount } else { $null }
        DoesNotRequirePreAuth = if ($ObjectType -eq 'User') { [bool]$DirectoryObject.DoesNotRequirePreAuth } else { $false }
        TrustedForDelegation = [bool]$DirectoryObject.TrustedForDelegation
        TrustedToAuthForDelegation = [bool]$DirectoryObject.TrustedToAuthForDelegation
        AccountNotDelegated = [bool]$DirectoryObject.AccountNotDelegated
        AllowedToDelegateTo = $AllowedTargets
        RbcdConfigured = ($null -ne $DirectoryObject.'msDS-AllowedToActOnBehalfOfOtherIdentity')
        SpnCount = $Spns.Count
        SupportedEncryptionTypesRaw = $EncryptionContext.Raw
        SupportedEncryptionTypes = @($EncryptionContext.Types)
        Rc4Explicit = $EncryptionContext.Rc4Explicit
        AesExplicit = $EncryptionContext.AesExplicit
        DesExplicit = $EncryptionContext.DesExplicit
        EncryptionTypesUnspecified = $EncryptionContext.Unspecified
        PasswordLastSetUtc = if ($ObjectType -eq 'User') { Convert-DateToUtcText $DirectoryObject.PasswordLastSet } else { $null }
        LastLogonTimestampUtc = Convert-LastLogonTimestamp $DirectoryObject.LastLogonTimestamp
        OperatingSystem = if ($ObjectType -eq 'Computer') { [string]$DirectoryObject.OperatingSystem } else { $null }
        OperatingSystemVersion = if ($ObjectType -eq 'Computer') { [string]$DirectoryObject.OperatingSystemVersion } else { $null }
        WhenCreatedUtc = Convert-DateToUtcText $DirectoryObject.WhenCreated
        WhenChangedUtc = Convert-DateToUtcText $DirectoryObject.WhenChanged
    }
}

function New-SpnEvidenceRow {
    param(
        [ValidateSet('User','Computer')]
        [string]$OwnerType,
        [object]$DirectoryObject,
        [object]$EncryptionContext,
        [string]$Spn
    )

    $Parsed = Convert-Spn $Spn

    return [pscustomobject][ordered]@{
        Spn = $Parsed.Spn
        NormalizedSpn = $Parsed.NormalizedSpn
        ServiceClass = $Parsed.ServiceClass
        Host = $Parsed.Host
        Port = $Parsed.Port
        ServiceName = $Parsed.ServiceName
        ParseStatus = $Parsed.ParseStatus
        OwnerType = $OwnerType
        OwnerSamAccountName = [string]$DirectoryObject.SamAccountName
        OwnerDistinguishedName = [string]$DirectoryObject.DistinguishedName
        OwnerEnabled = [bool]$DirectoryObject.Enabled
        OwnerAdminCount = if ($OwnerType -eq 'User') { $DirectoryObject.AdminCount } else { $null }
        OwnerPasswordLastSetUtc = if ($OwnerType -eq 'User') { Convert-DateToUtcText $DirectoryObject.PasswordLastSet } else { $null }
        Rc4Explicit = $EncryptionContext.Rc4Explicit
        AesExplicit = $EncryptionContext.AesExplicit
        DesExplicit = $EncryptionContext.DesExplicit
        EncryptionTypesUnspecified = $EncryptionContext.Unspecified
    }
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Import-Module ActiveDirectory -ErrorAction Stop

    $DiscoveryParameters = @{ ErrorAction = 'Stop' }
    if ($null -ne $Credential) { $DiscoveryParameters.Credential = $Credential }

    $Domain = Get-ADDomain @DiscoveryParameters
    $Forest = Get-ADForest @DiscoveryParameters

    if ($null -eq $Server -or $Server.Trim().Length -eq 0) {
        $DiscoveredDc = Get-ADDomainController -Discover -Writable @DiscoveryParameters
        $Server = Get-FirstTextValue $DiscoveredDc.HostName
    }
    else {
        $Server = $Server.Trim()
    }

    if ($null -eq $Server -or $Server.Length -eq 0) {
        throw 'Writable domain-controller discovery returned no usable hostname.'
    }

    $ValidationParameters = @{
        Identity = $Server
        Server = $Server
        ErrorAction = 'Stop'
    }
    if ($null -ne $Credential) { $ValidationParameters.Credential = $Credential }

    $ValidatedDc = Get-ADDomainController @ValidationParameters
    $Server = Get-FirstTextValue $ValidatedDc.HostName
    if ($null -eq $Server -or $Server.Length -eq 0) {
        throw 'Domain-controller validation returned no scalar hostname.'
    }

    if ($null -eq $OutputDirectory -or $OutputDirectory.Trim().Length -eq 0) {
        $SafeDomain = ([string]$Domain.DNSRoot -replace '[^A-Za-z0-9.-]','_')
        $OutputDirectory = Join-Path (Get-Location) (
            'MSADPT-Kerberos-SPN-Baseline-{0}-{1}' -f $SafeDomain,(Get-Date -Format 'yyyyMMdd-HHmmss')
        )
    }

    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        $ExistingFiles = @(Get-ChildItem -LiteralPath $OutputDirectory -File -Recurse -ErrorAction SilentlyContinue)
        if ($ExistingFiles.Count -gt 0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Write-Step 'OK' "Domain=$($Domain.DNSRoot); DC=$Server; output=$OutputDirectory" Green

    $CommonParameters = @{
        Server = $Server
        ResultSetSize = $null
        ErrorAction = 'Stop'
    }
    if ($null -ne $Credential) { $CommonParameters.Credential = $Credential }

    Write-Step 'QUERY' 'Collecting user SPN, AS-REP, and delegation candidates.' Yellow
    $Users = @(
        Get-ADUser `
            -LDAPFilter '(|(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*))' `
            -Properties @(
                'ServicePrincipalName','DoesNotRequirePreAuth','TrustedForDelegation',
                'TrustedToAuthForDelegation','AccountNotDelegated','AdminCount','MemberOf',
                'PasswordLastSet','LastLogonTimestamp','Enabled','msDS-SupportedEncryptionTypes',
                'msDS-AllowedToDelegateTo','UserPrincipalName','Description','WhenCreated','WhenChanged'
            ) @CommonParameters
    )
    Write-Step 'OK' "Collected $($Users.Count) user candidate object(s)." Green

    Write-Step 'QUERY' 'Collecting computer SPNs and delegation candidates.' Yellow
    $Computers = @(
        Get-ADComputer `
            -LDAPFilter '(|(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))' `
            -Properties @(
                'ServicePrincipalName','TrustedForDelegation','TrustedToAuthForDelegation',
                'AccountNotDelegated','msDS-AllowedToDelegateTo',
                'msDS-AllowedToActOnBehalfOfOtherIdentity','msDS-SupportedEncryptionTypes',
                'OperatingSystem','OperatingSystemVersion','Enabled','LastLogonTimestamp',
                'WhenCreated','WhenChanged'
            ) @CommonParameters
    )
    Write-Step 'OK' "Collected $($Computers.Count) computer candidate object(s)." Green

    $ObjectRows = New-Object 'System.Collections.Generic.List[object]'
    $SpnRows = New-Object 'System.Collections.Generic.List[object]'

    $TotalObjects = $Users.Count + $Computers.Count
    $ProcessedObjects = 0

    foreach ($User in $Users) {
        $ProcessedObjects++
        if (-not $Quiet -and ($ProcessedObjects -eq 1 -or $ProcessedObjects % 250 -eq 0 -or $ProcessedObjects -eq $TotalObjects)) {
            $Percent = [int](($ProcessedObjects / [double]$TotalObjects) * 100)
            Write-Step 'PROCESS' "User/computer normalization: $ProcessedObjects/$TotalObjects ($Percent%)." DarkCyan
        }

        $Encryption = Convert-EncryptionTypes $User.'msDS-SupportedEncryptionTypes'
        $Spns = @(
            $User.ServicePrincipalName |
                ForEach-Object { [string]$_ } |
                Where-Object { $null -ne $_ -and $_.Length -gt 0 } |
                Sort-Object -Unique
        )

        $ObjectRows.Add((New-ObjectEvidenceRow -ObjectType User -DirectoryObject $User -EncryptionContext $Encryption -Spns $Spns))
        foreach ($Spn in $Spns) {
            $SpnRows.Add((New-SpnEvidenceRow -OwnerType User -DirectoryObject $User -EncryptionContext $Encryption -Spn $Spn))
        }
    }

    foreach ($Computer in $Computers) {
        $ProcessedObjects++
        if (-not $Quiet -and ($ProcessedObjects % 250 -eq 0 -or $ProcessedObjects -eq $TotalObjects)) {
            $Percent = [int](($ProcessedObjects / [double]$TotalObjects) * 100)
            Write-Step 'PROCESS' "User/computer normalization: $ProcessedObjects/$TotalObjects ($Percent%)." DarkCyan
        }

        $Encryption = Convert-EncryptionTypes $Computer.'msDS-SupportedEncryptionTypes'
        $Spns = @(
            $Computer.ServicePrincipalName |
                ForEach-Object { [string]$_ } |
                Where-Object { $null -ne $_ -and $_.Length -gt 0 } |
                Sort-Object -Unique
        )

        $ObjectRows.Add((New-ObjectEvidenceRow -ObjectType Computer -DirectoryObject $Computer -EncryptionContext $Encryption -Spns $Spns))
        foreach ($Spn in $Spns) {
            $SpnRows.Add((New-SpnEvidenceRow -OwnerType Computer -DirectoryObject $Computer -EncryptionContext $Encryption -Spn $Spn))
        }
    }

    $DuplicateGroups = @(
        $SpnRows |
            Group-Object NormalizedSpn |
            Where-Object { $_.Count -gt 1 }
    )

    $DuplicateRows = @(
        foreach ($Group in $DuplicateGroups) {
            foreach ($Row in @($Group.Group)) {
                [pscustomobject][ordered]@{
                    NormalizedSpn = [string]$Group.Name
                    DuplicateCount = [int]$Group.Count
                    Spn = [string]$Row.Spn
                    OwnerType = [string]$Row.OwnerType
                    OwnerSamAccountName = [string]$Row.OwnerSamAccountName
                    OwnerDistinguishedName = [string]$Row.OwnerDistinguishedName
                }
            }
        }
    )

    $CandidateRows = New-Object 'System.Collections.Generic.List[object]'

    foreach ($Row in $ObjectRows) {
        if ([bool]$Row.DoesNotRequirePreAuth) {
            $CandidateRows.Add([pscustomobject]@{
                CandidateType='ASREP';ObjectType=$Row.ObjectType;SamAccountName=$Row.SamAccountName
                Priority='P1';Reason='Kerberos pre-authentication disabled';EvidenceState='Confirmed configuration'
            })
        }
        if ([bool]$Row.TrustedForDelegation) {
            $CandidateRows.Add([pscustomobject]@{
                CandidateType='UnconstrainedDelegation';ObjectType=$Row.ObjectType;SamAccountName=$Row.SamAccountName
                Priority=if($Row.ObjectType -eq 'User'){'P1'}else{'P2'}
                Reason='TRUSTED_FOR_DELEGATION enabled';EvidenceState='Confirmed configuration'
            })
        }
        if ([bool]$Row.TrustedToAuthForDelegation -or @($Row.AllowedToDelegateTo).Count -gt 0) {
            $CandidateRows.Add([pscustomobject]@{
                CandidateType='ConstrainedDelegation';ObjectType=$Row.ObjectType;SamAccountName=$Row.SamAccountName
                Priority='P2';Reason='Protocol transition or delegation targets configured';EvidenceState='Confirmed configuration'
            })
        }
        if ([bool]$Row.RbcdConfigured) {
            $CandidateRows.Add([pscustomobject]@{
                CandidateType='RBCD';ObjectType=$Row.ObjectType;SamAccountName=$Row.SamAccountName
                Priority='P2';Reason='RBCD security descriptor present';EvidenceState='Trustee resolution pending'
            })
        }
    }

    foreach ($Row in @($SpnRows | Where-Object { $_.OwnerType -eq 'User' })) {
        $Priority = 'P3'
        if ($Row.OwnerAdminCount -eq 1) { $Priority = 'P1' }
        elseif ($Row.DesExplicit -or $Row.Rc4Explicit -or $Row.EncryptionTypesUnspecified) { $Priority = 'P2' }

        $CandidateRows.Add([pscustomobject]@{
            CandidateType='Kerberoast';ObjectType='User';SamAccountName=$Row.OwnerSamAccountName
            Priority=$Priority;Reason=('User-owned SPN: {0}' -f $Row.Spn);EvidenceState='Ticket-request validation pending'
        })
    }

    foreach ($Group in $DuplicateGroups) {
        $Owners = @($Group.Group.OwnerSamAccountName | Sort-Object -Unique) -join ','
        $CandidateRows.Add([pscustomobject]@{
            CandidateType='DuplicateSPN';ObjectType='Multiple';SamAccountName=$Owners
            Priority='P2';Reason=('Duplicate SPN: {0}' -f $Group.Name);EvidenceState='Confirmed duplicate registration'
        })
    }

    $ObjectsJson = Join-Path $OutputDirectory 'kerberos-directory-objects.json'
    $ObjectsCsv = Join-Path $OutputDirectory 'kerberos-directory-objects.csv'
    $SpnsJson = Join-Path $OutputDirectory 'spn-inventory.json'
    $SpnsCsv = Join-Path $OutputDirectory 'spn-inventory.csv'
    $DuplicatesJson = Join-Path $OutputDirectory 'duplicate-spns.json'
    $DuplicatesCsv = Join-Path $OutputDirectory 'duplicate-spns.csv'
    $CandidatesJson = Join-Path $OutputDirectory 'kerberos-validation-candidates.json'
    $CandidatesCsv = Join-Path $OutputDirectory 'kerberos-validation-candidates.csv'

    Write-JsonFile -InputObject $ObjectRows.ToArray() -Path $ObjectsJson
    $ObjectRows | Export-Csv -LiteralPath $ObjectsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonFile -InputObject $SpnRows.ToArray() -Path $SpnsJson
    $SpnRows | Export-Csv -LiteralPath $SpnsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonFile -InputObject @($DuplicateRows) -Path $DuplicatesJson
    @($DuplicateRows) | Export-Csv -LiteralPath $DuplicatesCsv -NoTypeInformation -Encoding UTF8
    Write-JsonFile -InputObject $CandidateRows.ToArray() -Path $CandidatesJson
    $CandidateRows | Export-Csv -LiteralPath $CandidatesCsv -NoTypeInformation -Encoding UTF8

    $Summary = [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        PackageIdentity = $PackageIdentity
        PackageVersion = $PackageVersion
        Status = 'Completed'
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Domain = [pscustomobject][ordered]@{
            DnsRoot = [string]$Domain.DNSRoot
            DomainMode = [string]$Domain.DomainMode
            Forest = [string]$Forest.Name
            ForestMode = [string]$Forest.ForestMode
            Server = $Server
        }
        Counts = [pscustomobject][ordered]@{
            UserObjects = @($ObjectRows | Where-Object { $_.ObjectType -eq 'User' }).Count
            ComputerObjects = @($ObjectRows | Where-Object { $_.ObjectType -eq 'Computer' }).Count
            SpnRecords = $SpnRows.Count
            UserSpnRecords = @($SpnRows | Where-Object { $_.OwnerType -eq 'User' }).Count
            DuplicateSpnGroups = $DuplicateGroups.Count
            AsRepCandidates = @($CandidateRows | Where-Object { $_.CandidateType -eq 'ASREP' }).Count
            UnconstrainedDelegationCandidates = @($CandidateRows | Where-Object { $_.CandidateType -eq 'UnconstrainedDelegation' }).Count
            ConstrainedDelegationCandidates = @($CandidateRows | Where-Object { $_.CandidateType -eq 'ConstrainedDelegation' }).Count
            RbcdCandidates = @($CandidateRows | Where-Object { $_.CandidateType -eq 'RBCD' }).Count
            KerberoastCandidates = @($CandidateRows | Where-Object { $_.CandidateType -eq 'Kerberoast' }).Count
            ValidationCandidates = $CandidateRows.Count
        }
        Outputs = [pscustomobject][ordered]@{
            ObjectsJson = $ObjectsJson
            ObjectsCsv = $ObjectsCsv
            SpnsJson = $SpnsJson
            SpnsCsv = $SpnsCsv
            DuplicatesJson = $DuplicatesJson
            DuplicatesCsv = $DuplicatesCsv
            CandidatesJson = $CandidatesJson
            CandidatesCsv = $CandidatesCsv
        }
        Limitations = @(
            'SPN presence is not proof of crackable password material.',
            'Encryption types set to zero may use domain defaults and are not automatically RC4-only.',
            'Delegation configuration requires privilege, reachability, and ticket-flow validation.',
            'RBCD security descriptors require trustee resolution before impact assessment.'
        )
        Safety = [pscustomobject][ordered]@{
            NetworkActivity = 'Read-only Active Directory queries'
            DirectoryChanges = 'None'
            TicketRequests = 'None'
            TicketExtraction = 'None'
            PasswordMaterial = 'None'
            OllamaActivity = 'None'
        }
    }

    $SummaryPath = Join-Path $OutputDirectory 'kerberos-spn-baseline-summary.json'
    Write-JsonFile -InputObject $Summary -Path $SummaryPath

    $EvidenceFiles = @(Get-ChildItem -LiteralPath $OutputDirectory -File | Sort-Object Name)
    $ManifestRows = @(
        foreach ($File in $EvidenceFiles) {
            [pscustomobject][ordered]@{
                Name = $File.Name
                Size = [int64]$File.Length
                SHA256 = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
            }
        }
    )
    $ManifestPath = Join-Path $OutputDirectory 'evidence-manifest.json'
    Write-JsonFile -InputObject ([pscustomobject]@{
        SchemaVersion='1.0';Status='Completed';FileCount=$ManifestRows.Count;Files=$ManifestRows
    }) -Path $ManifestPath

    Write-Step 'DONE' (
        'Baseline complete: SPNs={0}, user SPNs={1}, duplicates={2}, candidates={3}.' -f
        $SpnRows.Count,$Summary.Counts.UserSpnRecords,$DuplicateGroups.Count,$CandidateRows.Count
    ) Green

    [pscustomobject][ordered]@{
        Status = 'Passed'
        PackageIdentity = $PackageIdentity
        PackageVersion = $PackageVersion
        DomainDNSRoot = [string]$Domain.DNSRoot
        DomainController = $Server
        UserObjectCount = $Summary.Counts.UserObjects
        ComputerObjectCount = $Summary.Counts.ComputerObjects
        SpnRecordCount = $Summary.Counts.SpnRecords
        UserSpnRecordCount = $Summary.Counts.UserSpnRecords
        DuplicateSpnGroupCount = $Summary.Counts.DuplicateSpnGroups
        AsRepCandidateCount = $Summary.Counts.AsRepCandidates
        UnconstrainedDelegationCandidateCount = $Summary.Counts.UnconstrainedDelegationCandidates
        ConstrainedDelegationCandidateCount = $Summary.Counts.ConstrainedDelegationCandidates
        RbcdCandidateCount = $Summary.Counts.RbcdCandidates
        KerberoastCandidateCount = $Summary.Counts.KerberoastCandidates
        ValidationCandidateCount = $Summary.Counts.ValidationCandidates
        OutputDirectory = $OutputDirectory
        SummaryPath = $SummaryPath
        ManifestPath = $ManifestPath
        DirectoryChanges = 'None'
        TicketRequests = 'None'
        PasswordMaterial = 'None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
