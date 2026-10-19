<#
.SYNOPSIS
Collects read-only Active Directory Certificate Services directory evidence for offline exposure analysis.

.DESCRIPTION
Collects enterprise CA registration objects, published certificate templates, template configuration, template and CA ACLs, NTAuth certificates, AIA objects, CDP objects, and PKI container metadata from Active Directory through one explicitly specified ADWS-reachable domain controller.

The collector does not submit certificate requests, contact certification-authority RPC or web-enrollment endpoints, retrieve private keys, export certificates with private keys, modify templates, change ACLs, or write to Active Directory.

.NOTES
Version: 1.0.2
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
$Version = '1.0.2'

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
        [int]$Depth = 14
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

function ConvertTo-MSADPTCertificateMetadata {
    param(
        [AllowNull()]
        [object[]]$CertificateValues,
        [string]$SourceObjectDistinguishedName,
        [string]$SourceAttribute
    )

    $Records = [System.Collections.Generic.List[object]]::new()

    foreach ($CertificateValue in @($CertificateValues)) {
        if ($null -eq $CertificateValue) {
            continue
        }

        try {
            $CertificateBytes = if ($CertificateValue -is [byte[]]) {
                $CertificateValue
            }
            else {
                [byte[]]$CertificateValue
            }

            $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificateBytes)
            $Records.Add([pscustomobject][ordered]@{
                SourceObjectDistinguishedName = $SourceObjectDistinguishedName
                SourceAttribute = $SourceAttribute
                Subject = $Certificate.Subject
                Issuer = $Certificate.Issuer
                SerialNumber = $Certificate.SerialNumber
                Thumbprint = $Certificate.Thumbprint
                NotBefore = $Certificate.NotBefore
                NotAfter = $Certificate.NotAfter
                SignatureAlgorithm = $Certificate.SignatureAlgorithm.FriendlyName
                PublicKeyAlgorithm = $Certificate.PublicKey.Oid.FriendlyName
                PublicKeySize = $Certificate.PublicKey.Key.KeySize
                HasPrivateKey = $Certificate.HasPrivateKey
                RawCertificateExported = $false
                PrivateKeyExported = $false
            })
        }
        catch {
            $Records.Add([pscustomobject][ordered]@{
                SourceObjectDistinguishedName = $SourceObjectDistinguishedName
                SourceAttribute = $SourceAttribute
                Subject = $null
                Issuer = $null
                SerialNumber = $null
                Thumbprint = $null
                NotBefore = $null
                NotAfter = $null
                SignatureAlgorithm = $null
                PublicKeyAlgorithm = $null
                PublicKeySize = $null
                HasPrivateKey = $false
                RawCertificateExported = $false
                PrivateKeyExported = $false
                ParseError = $_.Exception.Message
            })
        }
    }

    return @($Records)
}

function ConvertTo-MSADPTAclRecords {
    param(
        [Parameter(Mandatory = $true)][string]$ObjectType,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    $Acl = Get-Acl -LiteralPath ('AD:\' + $DistinguishedName) -ErrorAction Stop

    return @(
        foreach ($Rule in $Acl.Access) {
            [pscustomobject][ordered]@{
                TargetObjectType = $ObjectType
                TargetName = $Name
                TargetDistinguishedName = $DistinguishedName
                Owner = [string]$Acl.Owner
                IdentityReference = [string]$Rule.IdentityReference
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

$OutputRoot = Resolve-MSADPTLocalPath -Path $OutputRoot

$Plan = @(
    [pscustomobject][ordered]@{
        Stage = 'PKIContext'
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Read configuration naming context and PKI containers'
    }
    [pscustomobject][ordered]@{
        Stage = 'EnterpriseCAs'
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Read pKIEnrollmentService objects and published template names'
    }
    [pscustomobject][ordered]@{
        Stage = 'CertificateTemplates'
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Read certificate-template flags, EKUs, policy, validity, and supersedence'
    }
    [pscustomobject][ordered]@{
        Stage = 'PKIAccessControl'
        Target = $Server
        Protocol = 'ADWS / Active Directory provider'
        Ports = '9389 TCP'
        Operation = 'Read CA, template, and PKI-container ACLs'
    }
    [pscustomobject][ordered]@{
        Stage = 'TrustAndPublication'
        Target = $Server
        Protocol = 'ADWS'
        Ports = '9389 TCP'
        Operation = 'Read NTAuth, AIA, and CDP object metadata and certificate metadata'
    }
)

Write-Host ''
Write-Host '=== MSADPT AD CS directory exposure collection ===' -ForegroundColor Cyan
$Plan | Format-Table Target, Protocol, Ports, Operation -AutoSize -Wrap
Write-Host ''
Write-Host ('Output directory    : {0}' -f $OutputRoot) -ForegroundColor Gray
Write-Host ('Directory server    : {0}' -f $Server) -ForegroundColor Gray
Write-Host 'Authentication      : Current Windows session' -ForegroundColor Gray
Write-Host 'Directory writes    : None' -ForegroundColor Green
Write-Host 'Certificate requests: None' -ForegroundColor Green
Write-Host 'CA RPC              : Not contacted' -ForegroundColor Green
Write-Host 'Web enrollment      : Not contacted' -ForegroundColor Green
Write-Host 'Private keys        : Not requested or exported' -ForegroundColor Green
Write-Host ''

if ($PlanOnly) {
    return [pscustomobject][ordered]@{
        Status = 'Planned'
        Version = $Version
        Server = $Server
        Plan = $Plan
        NetworkExecuted = $false
        DirectoryChanges = 'None'
        CertificateRequestsSubmitted = 0
        PrivateKeysCollected = 0
        OutputRoot = $OutputRoot
    }
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw 'ActiveDirectoryModuleMissing: install the Active Directory RSAT PowerShell module.'
}

Import-Module ActiveDirectory -ErrorAction Stop
$RootDse = Get-ADRootDSE -Server $Server -ErrorAction Stop
$ConfigurationNamingContext = [string]$RootDse.configurationNamingContext
$PublicKeyServicesBase = 'CN=Public Key Services,CN=Services,{0}' -f $ConfigurationNamingContext
$EnrollmentServicesBase = 'CN=Enrollment Services,{0}' -f $PublicKeyServicesBase
$CertificateTemplatesBase = 'CN=Certificate Templates,{0}' -f $PublicKeyServicesBase
$NtAuthBase = 'CN=NTAuthCertificates,{0}' -f $PublicKeyServicesBase
$AiaBase = 'CN=AIA,{0}' -f $PublicKeyServicesBase
$CdpBase = 'CN=CDP,{0}' -f $PublicKeyServicesBase

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$RawDirectory = Join-Path $OutputRoot 'Raw'
New-Item -ItemType Directory -Path $RawDirectory -Force | Out-Null

$StartedUtc = (Get-Date).ToUniversalTime()
$OperationalErrors = [System.Collections.Generic.List[object]]::new()
$CertificateMetadata = [System.Collections.Generic.List[object]]::new()

$Context = [pscustomobject][ordered]@{
    Server = $Server
    ConfigurationNamingContext = $ConfigurationNamingContext
    PublicKeyServicesBase = $PublicKeyServicesBase
    EnrollmentServicesBase = $EnrollmentServicesBase
    CertificateTemplatesBase = $CertificateTemplatesBase
    NtAuthBase = $NtAuthBase
    AiaBase = $AiaBase
    CdpBase = $CdpBase
    CollectorComputer = $env:COMPUTERNAME
    CollectorIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    DirectoryChanges = 'None'
    CertificateRequestsSubmitted = 0
    PrivateKeysCollected = 0
}

Write-MSADPTStatus -Level COLLECT -Message 'Reading enterprise certification-authority registration objects.'
$EnterpriseCAs = @()
try {
    $EnterpriseCAs = @(
        Get-ADObject `
            -LDAPFilter '(objectClass=pKIEnrollmentService)' `
            -SearchBase $EnrollmentServicesBase `
            -SearchScope OneLevel `
            -Server $Server `
            -ResultPageSize $ResultPageSize `
            -Properties @(
                'cACertificate',
                'certificateTemplates',
                'dNSHostName',
                'displayName',
                'flags',
                'msPKI-Enrollment-Servers',
                'whenCreated',
                'whenChanged'
            ) `
            -ErrorAction Stop |
        ForEach-Object {
            foreach ($CertificateRecord in @(ConvertTo-MSADPTCertificateMetadata `
                -CertificateValues @($_.cACertificate) `
                -SourceObjectDistinguishedName $_.DistinguishedName `
                -SourceAttribute 'cACertificate')) {
                $CertificateMetadata.Add($CertificateRecord)
            }

            [pscustomobject][ordered]@{
                Name = $_.Name
                DisplayName = $_.displayName
                DistinguishedName = $_.DistinguishedName
                DNSHostName = $_.dNSHostName
                PublishedCertificateTemplates = @($_.certificateTemplates)
                PublishedTemplateCount = @($_.certificateTemplates).Count
                EnrollmentServerInformation = @($_.'msPKI-Enrollment-Servers')
                Flags = $_.flags
                WhenCreated = $_.whenCreated
                WhenChanged = $_.whenChanged
                CaRpcContacted = $false
                WebEnrollmentContacted = $false
            }
        }
    )
}
catch {
    $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'EnterpriseCAs' -Target $EnrollmentServicesBase -ErrorRecord $_))
}

Write-MSADPTStatus -Level COLLECT -Message 'Reading certificate-template configuration.'
$CertificateTemplates = @()
try {
    $CertificateTemplates = @(
        Get-ADObject `
            -LDAPFilter '(objectClass=pKICertificateTemplate)' `
            -SearchBase $CertificateTemplatesBase `
            -SearchScope OneLevel `
            -Server $Server `
            -ResultPageSize $ResultPageSize `
            -Properties @(
                'displayName',
                'flags',
                'pKIExtendedKeyUsage',
                'msPKI-Certificate-Name-Flag',
                'msPKI-Enrollment-Flag',
                'msPKI-Private-Key-Flag',
                'msPKI-Minimal-Key-Size',
                'msPKI-RA-Signature',
                'msPKI-RA-Application-Policies',
                'msPKI-Certificate-Application-Policy',
                'msPKI-Template-Schema-Version',
                'msPKI-Template-Minor-Revision',
                'pKIKeyUsage',
                'pKIExpirationPeriod',
                'pKIOverlapPeriod',
                'pKIDefaultKeySpec',
                'pKIMaxIssuingDepth',
                'pKICriticalExtensions',
                'whenCreated',
                'whenChanged'
            ) `
            -ErrorAction Stop |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name = $_.Name
                DisplayName = $_.displayName
                DistinguishedName = $_.DistinguishedName
                Flags = $_.flags
                ExtendedKeyUsage = @($_.pKIExtendedKeyUsage)
                CertificateApplicationPolicy = @($_.'msPKI-Certificate-Application-Policy')
                CertificateNameFlag = $_.'msPKI-Certificate-Name-Flag'
                EnrollmentFlag = $_.'msPKI-Enrollment-Flag'
                PrivateKeyFlag = $_.'msPKI-Private-Key-Flag'
                MinimalKeySize = $_.'msPKI-Minimal-Key-Size'
                RequiredAuthorizedSignatures = $_.'msPKI-RA-Signature'
                RaApplicationPolicies = @($_.'msPKI-RA-Application-Policies')
                TemplateSchemaVersion = $_.'msPKI-Template-Schema-Version'
                TemplateMinorRevision = $_.'msPKI-Template-Minor-Revision'
                KeyUsage = $_.pKIKeyUsage
                ExpirationPeriod = $_.pKIExpirationPeriod
                OverlapPeriod = $_.pKIOverlapPeriod
                DefaultKeySpec = $_.pKIDefaultKeySpec
                MaxIssuingDepth = $_.pKIMaxIssuingDepth
                CriticalExtensions = @($_.pKICriticalExtensions)
                WhenCreated = $_.whenCreated
                WhenChanged = $_.whenChanged
            }
        }
    )
}
catch {
    $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'CertificateTemplates' -Target $CertificateTemplatesBase -ErrorRecord $_))
}

Write-MSADPTStatus -Level COLLECT -Message 'Reading NTAuth, AIA, and CDP publication objects.'
$NtAuthObjects = @()
$AiaObjects = @()
$CdpObjects = @()

try {
    $NtAuthObjects = @(
        Get-ADObject `
            -LDAPFilter '(objectClass=certificationAuthority)' `
            -SearchBase $NtAuthBase `
            -SearchScope OneLevel `
            -Server $Server `
            -Properties @('cACertificate', 'whenCreated', 'whenChanged') `
            -ErrorAction Stop |
        ForEach-Object {
            foreach ($CertificateRecord in @(ConvertTo-MSADPTCertificateMetadata `
                -CertificateValues @($_.cACertificate) `
                -SourceObjectDistinguishedName $_.DistinguishedName `
                -SourceAttribute 'cACertificate')) {
                $CertificateMetadata.Add($CertificateRecord)
            }

            [pscustomobject][ordered]@{
                Name = $_.Name
                DistinguishedName = $_.DistinguishedName
                CertificateCount = @($_.cACertificate).Count
                WhenCreated = $_.whenCreated
                WhenChanged = $_.whenChanged
            }
        }
    )
}
catch {
    $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'NTAuth' -Target $NtAuthBase -ErrorRecord $_))
}

try {
    $AiaObjects = @(
        Get-ADObject `
            -LDAPFilter '(objectClass=certificationAuthority)' `
            -SearchBase $AiaBase `
            -SearchScope OneLevel `
            -Server $Server `
            -Properties @('cACertificate', 'crossCertificatePair', 'whenCreated', 'whenChanged') `
            -ErrorAction Stop |
        ForEach-Object {
            foreach ($CertificateRecord in @(ConvertTo-MSADPTCertificateMetadata `
                -CertificateValues @($_.cACertificate) `
                -SourceObjectDistinguishedName $_.DistinguishedName `
                -SourceAttribute 'cACertificate')) {
                $CertificateMetadata.Add($CertificateRecord)
            }

            [pscustomobject][ordered]@{
                Name = $_.Name
                DistinguishedName = $_.DistinguishedName
                CertificateCount = @($_.cACertificate).Count
                CrossCertificatePairCount = @($_.crossCertificatePair).Count
                WhenCreated = $_.whenCreated
                WhenChanged = $_.whenChanged
            }
        }
    )
}
catch {
    $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'AIA' -Target $AiaBase -ErrorRecord $_))
}

try {
    $CdpObjects = @(
        Get-ADObject `
            -LDAPFilter '(objectClass=cRLDistributionPoint)' `
            -SearchBase $CdpBase `
            -SearchScope Subtree `
            -Server $Server `
            -Properties @('certificateRevocationList', 'deltaRevocationList', 'whenCreated', 'whenChanged') `
            -ErrorAction Stop |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name = $_.Name
                DistinguishedName = $_.DistinguishedName
                CertificateRevocationListPresent = $null -ne $_.certificateRevocationList
                DeltaRevocationListPresent = $null -ne $_.deltaRevocationList
                CertificateRevocationListLength = if ($_.certificateRevocationList) { @($_.certificateRevocationList).Count } else { 0 }
                DeltaRevocationListLength = if ($_.deltaRevocationList) { @($_.deltaRevocationList).Count } else { 0 }
                RawCrlExported = $false
                WhenCreated = $_.whenCreated
                WhenChanged = $_.whenChanged
            }
        }
    )
}
catch {
    $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'CDP' -Target $CdpBase -ErrorRecord $_))
}

Write-MSADPTStatus -Level COLLECT -Message 'Reading PKI container, CA, and template ACLs.'
$PkiContainerAcls = [System.Collections.Generic.List[object]]::new()
$CaAcls = [System.Collections.Generic.List[object]]::new()
$TemplateAcls = [System.Collections.Generic.List[object]]::new()

foreach ($ContainerTarget in @(
    [pscustomobject]@{ Type = 'PublicKeyServices'; Name = 'Public Key Services'; DistinguishedName = $PublicKeyServicesBase }
    [pscustomobject]@{ Type = 'EnrollmentServicesContainer'; Name = 'Enrollment Services'; DistinguishedName = $EnrollmentServicesBase }
    [pscustomobject]@{ Type = 'CertificateTemplatesContainer'; Name = 'Certificate Templates'; DistinguishedName = $CertificateTemplatesBase }
    [pscustomobject]@{ Type = 'NTAuthContainer'; Name = 'NTAuthCertificates'; DistinguishedName = $NtAuthBase }
    [pscustomobject]@{ Type = 'AIAContainer'; Name = 'AIA'; DistinguishedName = $AiaBase }
    [pscustomobject]@{ Type = 'CDPContainer'; Name = 'CDP'; DistinguishedName = $CdpBase }
)) {
    try {
        foreach ($AclRecord in @(ConvertTo-MSADPTAclRecords `
            -ObjectType $ContainerTarget.Type `
            -Name $ContainerTarget.Name `
            -DistinguishedName $ContainerTarget.DistinguishedName)) {
            $PkiContainerAcls.Add($AclRecord)
        }
    }
    catch {
        $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'PKIContainerACL' -Target $ContainerTarget.DistinguishedName -ErrorRecord $_))
    }
}

foreach ($Ca in $EnterpriseCAs) {
    try {
        foreach ($AclRecord in @(ConvertTo-MSADPTAclRecords `
            -ObjectType 'EnterpriseCA' `
            -Name $Ca.Name `
            -DistinguishedName $Ca.DistinguishedName)) {
            $CaAcls.Add($AclRecord)
        }
    }
    catch {
        $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'EnterpriseCAACL' -Target $Ca.DistinguishedName -ErrorRecord $_))
    }
}

$TemplateIndex = 0
foreach ($Template in $CertificateTemplates) {
    $TemplateIndex++
    if ($TemplateIndex -eq 1 -or $TemplateIndex -eq $CertificateTemplates.Count -or ($TemplateIndex % 25) -eq 0) {
        Write-MSADPTStatus -Level INFO -Message (
            'Template ACL progress: {0}/{1}' -f $TemplateIndex, $CertificateTemplates.Count
        )
    }

    try {
        foreach ($AclRecord in @(ConvertTo-MSADPTAclRecords `
            -ObjectType 'CertificateTemplate' `
            -Name $Template.Name `
            -DistinguishedName $Template.DistinguishedName)) {
            $TemplateAcls.Add($AclRecord)
        }
    }
    catch {
        $OperationalErrors.Add((New-MSADPTOperationalError -Stage 'CertificateTemplateACL' -Target $Template.DistinguishedName -ErrorRecord $_))
    }
}

$PublishedTemplateNames = @(
    $EnterpriseCAs |
        ForEach-Object { $_.PublishedCertificateTemplates } |
        Sort-Object -Unique
)

$DataFiles = [ordered]@{
    'adcs-context.json' = $Context
    'enterprise-cas.json' = @($EnterpriseCAs)
    'certificate-templates.json' = @($CertificateTemplates)
    'published-template-names.json' = @($PublishedTemplateNames)
    'ntauth-objects.json' = @($NtAuthObjects)
    'aia-objects.json' = @($AiaObjects)
    'cdp-objects.json' = @($CdpObjects)
    'certificate-metadata.json' = @($CertificateMetadata)
    'pki-container-acls.json' = @($PkiContainerAcls)
    'enterprise-ca-acls.json' = @($CaAcls)
    'certificate-template-acls.json' = @($TemplateAcls)
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
    ModuleId = 'Collect-MSADPTADCSDirectoryExposure'
    ModuleVersion = $Version
    StartedUtc = $StartedUtc.ToString('o')
    CompletedUtc = $CompletedUtc.ToString('o')
    DurationSeconds = [math]::Round(($CompletedUtc - $StartedUtc).TotalSeconds, 3)
    Server = $Server
    ConfigurationNamingContext = $ConfigurationNamingContext
    EnterpriseCaCount = $EnterpriseCAs.Count
    CertificateTemplateCount = $CertificateTemplates.Count
    PublishedTemplateNameCount = $PublishedTemplateNames.Count
    NtAuthObjectCount = $NtAuthObjects.Count
    AiaObjectCount = $AiaObjects.Count
    CdpObjectCount = $CdpObjects.Count
    CertificateMetadataCount = $CertificateMetadata.Count
    PkiContainerAclCount = $PkiContainerAcls.Count
    EnterpriseCaAclCount = $CaAcls.Count
    CertificateTemplateAclCount = $TemplateAcls.Count
    OperationalErrorCount = $OperationalErrors.Count
    CertificateRequestsSubmitted = 0
    CaRpcContacted = $false
    WebEnrollmentContacted = $false
    DirectoryChanges = 'None'
    PrivateKeysCollected = 0
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
    EnterpriseCaCount = $EnterpriseCAs.Count
    CertificateTemplateCount = $CertificateTemplates.Count
    PublishedTemplateNameCount = $PublishedTemplateNames.Count
    NtAuthObjectCount = $NtAuthObjects.Count
    AiaObjectCount = $AiaObjects.Count
    CdpObjectCount = $CdpObjects.Count
    CertificateMetadataCount = $CertificateMetadata.Count
    PkiContainerAclCount = $PkiContainerAcls.Count
    EnterpriseCaAclCount = $CaAcls.Count
    CertificateTemplateAclCount = $TemplateAcls.Count
    OperationalErrorCount = $OperationalErrors.Count
    CertificateRequestsSubmitted = 0
    CaRpcContacted = $false
    WebEnrollmentContacted = $false
    DirectoryChanges = 'None'
    PrivateKeysCollected = 0
    ManifestPath = $ManifestPath
}
