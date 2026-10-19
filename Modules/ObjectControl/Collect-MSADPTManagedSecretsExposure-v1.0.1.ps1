<#
.SYNOPSIS
Collects read-only Active Directory evidence for Windows LAPS, legacy Microsoft LAPS, and group managed service account exposure analysis.

.DESCRIPTION
Collects reusable metadata for offline security analysis without reading managed local administrator passwords, encrypted password blobs, gMSA managed-password blobs, or private secrets.

The collector records:
- Domain and forest context
- Windows LAPS and legacy LAPS schema availability
- Computer coverage metadata and password-expiration timestamps only
- gMSA inventory, encryption settings, SPNs, password age, and configured retrieval principals
- Domain-root and OU access-control entries relevant to delegated secret access and object control
- Structured operational errors and SHA-256 evidence manifest

No password value, encrypted password value, managed-password blob, credential, or private key is requested or exported.

.NOTES
Version: 1.0.1
Supports Windows PowerShell 5.1 and PowerShell 7 on Windows with the ActiveDirectory module.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot,

    [Parameter()]
    [string]$Server,

    [Parameter()]
    [ValidateRange(100, 10000)]
    [int]$ResultPageSize = 500,

    [Parameter()]
    [switch]$SkipDelegationAcl,

    [Parameter()]
    [switch]$PlanOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Version = '1.0.1'

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
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Depth = 12
    )

    ConvertTo-Json -InputObject $Value -Depth $Depth |
        Set-Content -LiteralPath $Path -Encoding UTF8
}

function New-MSADPTOperationalError {
    param(
        [string]$Stage,
        [string]$Target,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    [pscustomobject][ordered]@{
        Stage = $Stage
        Target = $Target
        Message = $ErrorRecord.Exception.Message
        ExceptionType = $ErrorRecord.Exception.GetType().FullName
        FullyQualifiedErrorId = $ErrorRecord.FullyQualifiedErrorId
        RecordedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Get-MSADPTAdParameters {
    param([hashtable]$BaseParameters)

    $Parameters = @{}
    foreach ($Key in $BaseParameters.Keys) {
        $Parameters[$Key] = $BaseParameters[$Key]
    }

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $Parameters['Server'] = $Server
    }

    return $Parameters
}

$OutputRoot = Resolve-MSADPTLocalPath -Path $OutputRoot
$DeclaredTarget = if ([string]::IsNullOrWhiteSpace($Server)) {
    'Current domain through the Active Directory module'
}
else {
    $Server
}

$Plan = @(
    [pscustomobject][ordered]@{
        Stage = 'DirectoryContext'
        Target = $DeclaredTarget
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Read forest, domain, RootDSE, and schema metadata'
        SecretValues = 'Not requested'
    }
    [pscustomobject][ordered]@{
        Stage = 'LapsCoverage'
        Target = $DeclaredTarget
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Read computer metadata and LAPS expiration timestamps only'
        SecretValues = 'Not requested'
    }
    [pscustomobject][ordered]@{
        Stage = 'GmsaInventory'
        Target = $DeclaredTarget
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Read gMSA metadata and configured retrieval principals'
        SecretValues = 'Managed-password blobs not requested'
    }
    if (-not $SkipDelegationAcl) {
        [pscustomobject][ordered]@{
            Stage = 'DelegatedAccess'
            Target = 'Domain root and organizational units'
            Protocol = 'ADWS / Active Directory provider'
            Ports = '9389 TCP'
            Operation = 'Read access-control entries for offline effective-access correlation'
            SecretValues = 'Not requested'
        }
    }
)

Write-Host ''
Write-Host '=== MSADPT managed-secrets exposure collection ===' -ForegroundColor Cyan
$Plan | Format-Table Target, Protocol, Ports, Operation, SecretValues -AutoSize -Wrap
Write-Host ''
Write-Host ('Output directory : {0}' -f $OutputRoot) -ForegroundColor Gray
Write-Host 'Authentication   : Current Windows session' -ForegroundColor Gray
Write-Host 'Directory writes : None' -ForegroundColor Green
Write-Host 'Password values  : Not requested' -ForegroundColor Green
Write-Host 'gMSA blobs       : Not requested' -ForegroundColor Green
Write-Host ''

if ($PlanOnly) {
    return [pscustomobject][ordered]@{
        Status = 'Planned'
        Version = $Version
        Plan = $Plan
        NetworkExecuted = $false
        OutputRoot = $OutputRoot
        SecretValuesRequested = $false
        DelegationAclSkipped = [bool]$SkipDelegationAcl
        DirectoryChanges = 'None'
    }
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw 'ActiveDirectoryModuleMissing: install the Active Directory RSAT PowerShell module.'
}

Import-Module ActiveDirectory -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$RawDirectory = Join-Path $OutputRoot 'Raw'
New-Item -ItemType Directory -Path $RawDirectory -Force | Out-Null

$StartedUtc = (Get-Date).ToUniversalTime()
$OperationalErrors = [System.Collections.Generic.List[object]]::new()

$Domain = $null
$Forest = $null
$RootDse = $null

try {
    $DomainParameters = Get-MSADPTAdParameters -BaseParameters @{ ErrorAction = 'Stop' }
    $Domain = Get-ADDomain @DomainParameters
}
catch {
    throw "DomainDiscoveryFailed: $($_.Exception.Message)"
}

try {
    $ForestParameters = Get-MSADPTAdParameters -BaseParameters @{ ErrorAction = 'Stop' }
    $Forest = Get-ADForest @ForestParameters
}
catch {
    throw "ForestDiscoveryFailed: $($_.Exception.Message)"
}

try {
    $RootDseParameters = Get-MSADPTAdParameters -BaseParameters @{ ErrorAction = 'Stop' }
    $RootDse = Get-ADRootDSE @RootDseParameters
}
catch {
    throw "RootDseDiscoveryFailed: $($_.Exception.Message)"
}

$Context = [pscustomobject][ordered]@{
    DomainDnsRoot = $Domain.DNSRoot
    DomainDistinguishedName = $Domain.DistinguishedName
    DomainMode = [string]$Domain.DomainMode
    ForestName = $Forest.Name
    ForestMode = [string]$Forest.ForestMode
    SchemaNamingContext = [string]$RootDse.schemaNamingContext
    ConfigurationNamingContext = [string]$RootDse.configurationNamingContext
    SelectedServer = if ($Server) { $Server } else { $null }
    CollectorComputer = $env:COMPUTERNAME
    CollectorIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    SecretValuesRequested = $false
    DirectoryChanges = 'None'
}

Write-MSADPTStatus -Level COLLECT -Message 'Reading LAPS schema attribute availability.'
$LapsAttributeNames = @(
    'msLAPS-Password'
    'msLAPS-EncryptedPassword'
    'msLAPS-PasswordExpirationTime'
    'msLAPS-EncryptedPasswordHistory'
    'ms-Mcs-AdmPwd'
    'ms-Mcs-AdmPwdExpirationTime'
)

$SchemaAttributes = @(
    foreach ($AttributeName in $LapsAttributeNames) {
        try {
            $SchemaParameters = Get-MSADPTAdParameters -BaseParameters @{
                LDAPFilter = "(lDAPDisplayName=$AttributeName)"
                SearchBase = [string]$RootDse.schemaNamingContext
                Properties = @('lDAPDisplayName', 'schemaIDGUID', 'attributeSecurityGUID', 'searchFlags', 'isSingleValued')
                ResultPageSize = $ResultPageSize
                ErrorAction = 'Stop'
            }
            $SchemaObject = Get-ADObject @SchemaParameters | Select-Object -First 1

            [pscustomobject][ordered]@{
                LdapDisplayName = $AttributeName
                Present = $null -ne $SchemaObject
                DistinguishedName = if ($SchemaObject) { $SchemaObject.DistinguishedName } else { $null }
                SchemaIdGuid = if ($SchemaObject -and $SchemaObject.schemaIDGUID) { ([guid]$SchemaObject.schemaIDGUID).Guid } else { $null }
                AttributeSecurityGuid = if ($SchemaObject -and $SchemaObject.attributeSecurityGUID) { ([guid]$SchemaObject.attributeSecurityGUID).Guid } else { $null }
                SearchFlags = if ($SchemaObject) { $SchemaObject.searchFlags } else { $null }
                ConfidentialBitSet = if ($SchemaObject) { ([int]$SchemaObject.searchFlags -band 128) -eq 128 } else { $null }
                IsSingleValued = if ($SchemaObject) { $SchemaObject.isSingleValued } else { $null }
            }
        }
        catch {
            $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'SchemaAttribute' -Target $AttributeName -ErrorRecord $_))
        }
    }
)

Write-MSADPTStatus -Level COLLECT -Message 'Reading computer LAPS coverage metadata without password values.'
$ComputerProperties = [System.Collections.Generic.List[string]]::new()
foreach ($PropertyName in @(
    'DNSHostName'
    'Enabled'
    'OperatingSystem'
    'OperatingSystemVersion'
    'LastLogonDate'
    'PasswordLastSet'
)) {
    $ComputerProperties.Add($PropertyName)
}

$WindowsLapsExpirationAttribute = @(
    $SchemaAttributes |
        Where-Object {
            $_.LdapDisplayName -eq 'msLAPS-PasswordExpirationTime' -and
            $_.Present
        }
).Count -gt 0

$LegacyLapsExpirationAttribute = @(
    $SchemaAttributes |
        Where-Object {
            $_.LdapDisplayName -eq 'ms-Mcs-AdmPwdExpirationTime' -and
            $_.Present
        }
).Count -gt 0

if ($WindowsLapsExpirationAttribute) {
    $ComputerProperties.Add('msLAPS-PasswordExpirationTime')
}
if ($LegacyLapsExpirationAttribute) {
    $ComputerProperties.Add('ms-Mcs-AdmPwdExpirationTime')
}

Write-MSADPTStatus -Level INFO -Message (
    'Computer query properties selected from schema: {0}' -f
    ($ComputerProperties -join ', ')
)

$Computers = @()
try {
    $Computers = @(
        $ComputerParameters = Get-MSADPTAdParameters -BaseParameters @{
            Filter = '*'
            Properties = $ComputerProperties
            ResultPageSize = $ResultPageSize
            ErrorAction = 'Stop'
        }
        Get-ADComputer @ComputerParameters |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name = $_.Name
                SamAccountName = $_.SamAccountName
                DNSHostName = $_.DNSHostName
                DistinguishedName = $_.DistinguishedName
                Enabled = [bool]$_.Enabled
                OperatingSystem = $_.OperatingSystem
                OperatingSystemVersion = $_.OperatingSystemVersion
                LastLogonDate = $_.LastLogonDate
                PasswordLastSet = $_.PasswordLastSet
                WindowsLapsExpirationTime = if ($WindowsLapsExpirationAttribute) { $_.'msLAPS-PasswordExpirationTime' } else { $null }
                LegacyLapsExpirationTime = if ($LegacyLapsExpirationAttribute) { $_.'ms-Mcs-AdmPwdExpirationTime' } else { $null }
                WindowsLapsExpirationPresent = if ($WindowsLapsExpirationAttribute) { $null -ne $_.'msLAPS-PasswordExpirationTime' } else { $false }
                LegacyLapsExpirationPresent = if ($LegacyLapsExpirationAttribute) { $null -ne $_.'ms-Mcs-AdmPwdExpirationTime' } else { $false }
                SecretValuesCollected = $false
            }
        }
    )
}
catch {
    $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'ComputerCoverage' -Target $Domain.DNSRoot -ErrorRecord $_))
}

Write-MSADPTStatus -Level COLLECT -Message 'Reading gMSA metadata without managed-password blobs.'
$GmsaAccounts = @()
try {
    $GmsaAccounts = @(
        $GmsaParameters = Get-MSADPTAdParameters -BaseParameters @{
            Filter = '*'
            Properties = @(
                'DNSHostName'
                'Enabled'
                'ServicePrincipalNames'
                'PrincipalsAllowedToRetrieveManagedPassword'
                'msDS-SupportedEncryptionTypes'
                'PasswordLastSet'
                'whenCreated'
                'whenChanged'
            )
            ResultPageSize = $ResultPageSize
            ErrorAction = 'Stop'
        }
        Get-ADServiceAccount @GmsaParameters |
        Where-Object { $_.ObjectClass -eq 'msDS-GroupManagedServiceAccount' } |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name = $_.Name
                SamAccountName = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
                DNSHostName = $_.DNSHostName
                Enabled = [bool]$_.Enabled
                ServicePrincipalNames = @($_.ServicePrincipalNames)
                PrincipalsAllowedToRetrieveManagedPassword = @(
                    $_.PrincipalsAllowedToRetrieveManagedPassword |
                        ForEach-Object { [string]$_ }
                )
                SupportedEncryptionTypes = $_.'msDS-SupportedEncryptionTypes'
                PasswordLastSet = $_.PasswordLastSet
                WhenCreated = $_.whenCreated
                WhenChanged = $_.whenChanged
                ManagedPasswordBlobCollected = $false
            }
        }
    )
}
catch {
    $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'GmsaInventory' -Target $Domain.DNSRoot -ErrorRecord $_))
}

$DelegationTargets = [System.Collections.Generic.List[object]]::new()
$DelegationAces = @()

if ($SkipDelegationAcl) {
    Write-MSADPTStatus -Level INFO -Message 'Skipping delegated ACL collection because -SkipDelegationAcl was specified.'
}
else {
    Write-MSADPTStatus -Level COLLECT -Message 'Reading domain-root and OU access-control entries.'
    $DelegationTargets = [System.Collections.Generic.List[object]]::new()
    $DelegationTargets.Add([pscustomobject]@{
        ObjectType = 'DomainRoot'
        Name = $Domain.DNSRoot
        DistinguishedName = $Domain.DistinguishedName
    })

    try {
        $OuParameters = Get-MSADPTAdParameters -BaseParameters @{
            Filter = '*'
            Properties = @('Name')
            ResultPageSize = $ResultPageSize
            ErrorAction = 'Stop'
        }
        foreach ($Ou in @(Get-ADOrganizationalUnit @OuParameters)) {
            $DelegationTargets.Add([pscustomobject]@{
                ObjectType = 'OrganizationalUnit'
                Name = $Ou.Name
                DistinguishedName = $Ou.DistinguishedName
            })
        }
    }
    catch {
        $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'OuDiscovery' -Target $Domain.DNSRoot -ErrorRecord $_))
    }

    $DelegationAces = @(
        foreach ($DelegationTarget in $DelegationTargets) {
            try {
                $Acl = Get-Acl -LiteralPath ('AD:\' + $DelegationTarget.DistinguishedName) -ErrorAction Stop

                foreach ($AccessRule in $Acl.Access) {
                    [pscustomobject][ordered]@{
                        TargetObjectType = $DelegationTarget.ObjectType
                        TargetName = $DelegationTarget.Name
                        TargetDistinguishedName = $DelegationTarget.DistinguishedName
                        Owner = [string]$Acl.Owner
                        IdentityReference = [string]$AccessRule.IdentityReference
                        AccessControlType = [string]$AccessRule.AccessControlType
                        ActiveDirectoryRights = [string]$AccessRule.ActiveDirectoryRights
                        ObjectTypeGuid = [string]$AccessRule.ObjectType
                        InheritedObjectTypeGuid = [string]$AccessRule.InheritedObjectType
                        IsInherited = [bool]$AccessRule.IsInherited
                        InheritanceType = [string]$AccessRule.InheritanceType
                        InheritanceFlags = [string]$AccessRule.InheritanceFlags
                        PropagationFlags = [string]$AccessRule.PropagationFlags
                    }
                }
            }
            catch {
                $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'DelegationAcl' -Target $DelegationTarget.DistinguishedName -ErrorRecord $_))
            }
        }
    )
}
$DataFiles = [ordered]@{
    'directory-context.json' = $Context
    'laps-schema-attributes.json' = @($SchemaAttributes)
    'computer-laps-coverage.json' = @($Computers)
    'gmsa-inventory.json' = @($GmsaAccounts)
    'delegation-targets.json' = @($DelegationTargets)
    'delegation-aces.json' = @($DelegationAces)
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

$Summary = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    ModuleId = 'Collect-MSADPTManagedSecretsExposure'
    ModuleVersion = $Version
    StartedUtc = $StartedUtc.ToString('o')
    CompletedUtc = $CompletedUtc.ToString('o')
    DurationSeconds = [math]::Round(($CompletedUtc - $StartedUtc).TotalSeconds, 3)
    Domain = $Domain.DNSRoot
    ComputerCount = $Computers.Count
    WindowsLapsExpirationPresentCount = @($Computers | Where-Object { $_.WindowsLapsExpirationPresent }).Count
    LegacyLapsExpirationPresentCount = @($Computers | Where-Object { $_.LegacyLapsExpirationPresent }).Count
    GmsaCount = $GmsaAccounts.Count
    DelegationTargetCount = $DelegationTargets.Count
    DelegationAceCount = $DelegationAces.Count
    DelegationAclSkipped = [bool]$SkipDelegationAcl
    OperationalErrorCount = $OperationalErrors.Count
    SecretValuesRequested = $false
    SecretValuesCollected = $false
    DirectoryChanges = 'None'
    Files = $EvidenceFiles
}

$ManifestPath = Join-Path $OutputRoot 'evidence-manifest.json'
Write-MSADPTJson -Value $Summary -Path $ManifestPath -Depth 10

$Status = if ($OperationalErrors.Count -gt 0) { 'Partial' } else { 'Completed' }
$ConsoleLevel = if ($Status -eq 'Completed') { 'PASS' } else { 'WARN' }
Write-MSADPTStatus -Level $ConsoleLevel -Message "Collection complete: $OutputRoot"

[pscustomobject][ordered]@{
    Status = $Status
    Version = $Version
    OutputRoot = $OutputRoot
    Domain = $Domain.DNSRoot
    ComputerCount = $Computers.Count
    WindowsLapsExpirationPresentCount = $Summary.WindowsLapsExpirationPresentCount
    LegacyLapsExpirationPresentCount = $Summary.LegacyLapsExpirationPresentCount
    GmsaCount = $GmsaAccounts.Count
    DelegationTargetCount = $DelegationTargets.Count
    DelegationAceCount = $DelegationAces.Count
    DelegationAclSkipped = [bool]$SkipDelegationAcl
    OperationalErrorCount = $OperationalErrors.Count
    SecretValuesCollected = $false
    ManifestPath = $ManifestPath
}
