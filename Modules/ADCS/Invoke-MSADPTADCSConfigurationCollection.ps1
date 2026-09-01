<#
.SYNOPSIS
Collects read-only Active Directory Certificate Services configuration evidence for MSADPT.

.DESCRIPTION
Collects enterprise CA publication data, certificate-template attributes, interpreted security-relevant
flags, and certificate-template ACL entries. It distinguishes templates present in Active Directory from
templates published by discovered enterprise CAs.

This collector does not enroll certificates, modify AD CS, query CA runtime registry settings, test web
enrollment endpoints, or claim that an ESC condition is present or exploitable.

.PARAMETER EngagementPath
Path to an existing MSADPT engagement containing state\engagement-state.json.

.PARAMETER Credential
Optional authorized Active Directory credential. If omitted, the current Windows identity is used.

.OUTPUTS
Returns a structured MSADPT module-result object and writes JSON/CSV evidence below the engagement.

.NOTES
Version: 0.2.2
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
$CollectorVersion = '0.2.2'
$PermissionEvaluationVersion = '1.1.0'

$EnrollExtendedRightGuid = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$AutoEnrollExtendedRightGuid = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
$EmptyGuid = [guid]::Empty

function Get-MSADPTInt64Value {
    param($Value)

    if ($null -eq $Value) {
        return [int64]0
    }

    return [int64]$Value
}

function Test-MSADPTBitFlag {
    param(
        [int64]$Value,
        [int64]$Flag
    )

    return (($Value -band $Flag) -eq $Flag)
}

function Test-MSADPTRightsMask {
    param(
        [int64]$Value,
        [int64]$Mask
    )
    if ($Mask -eq 0) {
        return $false
    }
    return (($Value -band $Mask) -eq $Mask)
}

function Convert-MSADPTLargeIntegerPeriod {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        $Bytes = [byte[]]$Value
        if ($Bytes.Length -ne 8) {
            return $null
        }

        $Ticks = [BitConverter]::ToInt64($Bytes, 0)
        if ($Ticks -eq [int64]::MinValue) {
            return $null
        }

        return [TimeSpan]::FromTicks([math]::Abs($Ticks)).ToString()
    }
    catch {
        return $null
    }
}

function Get-MSADPTTemplateAccessEntry {
    param($AccessRule)

    $RightsText = [string]$AccessRule.ActiveDirectoryRights
    $ObjectType = [guid]$AccessRule.ObjectType
    $IsAllow = ([string]$AccessRule.AccessControlType -eq 'Allow')

    # ActiveDirectoryRights contains composite masks. Require the complete requested mask;
    # testing for any overlapping bit causes GenericRead to be misclassified as GenericWrite/GenericAll.
    $RightsValue = [int64]$AccessRule.ActiveDirectoryRights
    $HasExtendedRight = Test-MSADPTRightsMask -Value $RightsValue -Mask ([int64][System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)
    $HasGenericAll = Test-MSADPTRightsMask -Value $RightsValue -Mask ([int64][System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
    $HasGenericWrite = Test-MSADPTRightsMask -Value $RightsValue -Mask ([int64][System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)
    $HasWriteDacl = Test-MSADPTRightsMask -Value $RightsValue -Mask ([int64][System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)
    $HasWriteOwner = Test-MSADPTRightsMask -Value $RightsValue -Mask ([int64][System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)
    $HasWriteProperty = Test-MSADPTRightsMask -Value $RightsValue -Mask ([int64][System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)

    $AllowsAllExtendedRights = $IsAllow -and $HasExtendedRight -and ($ObjectType -eq $EmptyGuid)
    $AllowsEnroll = $IsAllow -and $HasExtendedRight -and (($ObjectType -eq $EnrollExtendedRightGuid) -or $AllowsAllExtendedRights)
    $AllowsAutoEnroll = $IsAllow -and $HasExtendedRight -and (($ObjectType -eq $AutoEnrollExtendedRightGuid) -or $AllowsAllExtendedRights)

    [pscustomobject][ordered]@{
        PermissionEvaluationVersion = $PermissionEvaluationVersion
        IdentityReference       = [string]$AccessRule.IdentityReference.Value
        AccessControlType       = [string]$AccessRule.AccessControlType
        ActiveDirectoryRights   = $RightsText
        ObjectType              = $ObjectType.ToString()
        InheritedObjectType     = ([guid]$AccessRule.InheritedObjectType).ToString()
        IsInherited             = [bool]$AccessRule.IsInherited
        InheritanceType         = [string]$AccessRule.InheritanceType
        AllowsEnroll            = $AllowsEnroll
        AllowsAutoEnroll        = $AllowsAutoEnroll
        AllowsAllExtendedRights = $AllowsAllExtendedRights
        AllowsGenericAll        = ($IsAllow -and $HasGenericAll)
        AllowsGenericWrite      = ($IsAllow -and $HasGenericWrite)
        AllowsWriteDacl         = ($IsAllow -and $HasWriteDacl)
        AllowsWriteOwner        = ($IsAllow -and $HasWriteOwner)
        AllowsWriteProperty     = ($IsAllow -and $HasWriteProperty)
    }
}

$StatePath = Join-Path $EngagementPath 'state\engagement-state.json'
if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
    throw "Engagement state not found: $StatePath"
}

$State = Get-Content -LiteralPath $StatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$Server = [string]$State.BootstrapServer
if ([string]::IsNullOrWhiteSpace($Server)) {
    throw 'BootstrapServer is missing from engagement state.'
}

Import-Module ActiveDirectory -ErrorAction Stop

$CommonAdParameters = @{
    Server      = $Server
    ErrorAction = 'Stop'
}
if ($null -ne $Credential) {
    $CommonAdParameters.Credential = $Credential
}

$RootDse = Get-ADRootDSE @CommonAdParameters
$ConfigurationNamingContext = [string]$RootDse.ConfigurationNamingContext
$TemplateBase = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}' -f $ConfigurationNamingContext
$EnrollmentServicesBase = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,{0}' -f $ConfigurationNamingContext

$CaParameters = @{
    SearchBase  = $EnrollmentServicesBase
    LDAPFilter  = '(objectClass=pKIEnrollmentService)'
    Properties  = @('displayName', 'dNSHostName', 'certificateTemplates')
    Server      = $Server
    ErrorAction = 'Stop'
}
if ($null -ne $Credential) {
    $CaParameters.Credential = $Credential
}

$EnterpriseCas = @(
    Get-ADObject @CaParameters |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name               = [string]$_.Name
                DisplayName        = [string]$_.DisplayName
                DnsHostName        = [string]$_.dNSHostName
                DistinguishedName  = [string]$_.DistinguishedName
                PublishedTemplates = @($_.certificateTemplates | ForEach-Object { [string]$_ } | Sort-Object -Unique)
            }
        }
)

$PublicationIndex = @{}
foreach ($Ca in $EnterpriseCas) {
    foreach ($PublishedTemplate in @($Ca.PublishedTemplates)) {
        if ([string]::IsNullOrWhiteSpace($PublishedTemplate)) {
            continue
        }

        if (-not $PublicationIndex.ContainsKey($PublishedTemplate)) {
            $PublicationIndex[$PublishedTemplate] = New-Object 'System.Collections.Generic.List[string]'
        }

        $PublicationIndex[$PublishedTemplate].Add($Ca.Name)
    }
}

$TemplateParameters = @{
    SearchBase  = $TemplateBase
    LDAPFilter  = '(objectClass=pKICertificateTemplate)'
    Properties  = @(
        'displayName',
        'flags',
        'msPKI-Template-Schema-Version',
        'msPKI-Template-Minor-Revision',
        'msPKI-Enrollment-Flag',
        'msPKI-Certificate-Name-Flag',
        'msPKI-Private-Key-Flag',
        'msPKI-RA-Signature',
        'msPKI-RA-Application-Policies',
        'pKIExtendedKeyUsage',
        'pKIExpirationPeriod',
        'pKIOverlapPeriod',
        'whenCreated',
        'whenChanged'
    )
    Server      = $Server
    ErrorAction = 'Stop'
}
if ($null -ne $Credential) {
    $TemplateParameters.Credential = $Credential
}

$Templates = @(Get-ADObject @TemplateParameters)
$Rows = New-Object 'System.Collections.Generic.List[object]'
$AccessRows = New-Object 'System.Collections.Generic.List[object]'

foreach ($Template in $Templates) {
    $TemplateName = [string]$Template.Name
    $PublishingCas = @()
    if ($PublicationIndex.ContainsKey($TemplateName)) {
        $PublishingCas = @($PublicationIndex[$TemplateName].ToArray() | Sort-Object -Unique)
    }

    $TemplateFlags = Get-MSADPTInt64Value $Template.flags
    $EnrollmentFlags = Get-MSADPTInt64Value $Template.'msPKI-Enrollment-Flag'
    $CertificateNameFlags = Get-MSADPTInt64Value $Template.'msPKI-Certificate-Name-Flag'
    $PrivateKeyFlags = Get-MSADPTInt64Value $Template.'msPKI-Private-Key-Flag'
    $AuthorizedSignatureCount = Get-MSADPTInt64Value $Template.'msPKI-RA-Signature'
    $Ekus = @($Template.pKIExtendedKeyUsage | ForEach-Object { [string]$_ } | Sort-Object -Unique)

    $Acl = Get-Acl -LiteralPath ('AD:\' + $Template.DistinguishedName) -ErrorAction Stop
    $AccessEntries = @(
        $Acl.Access |
            ForEach-Object { Get-MSADPTTemplateAccessEntry -AccessRule $_ }
    )

    foreach ($AccessEntry in $AccessEntries) {
        $AccessRows.Add([pscustomobject][ordered]@{
            PermissionEvaluationVersion = $PermissionEvaluationVersion
            TemplateName            = $TemplateName
            TemplateDisplayName     = [string]$Template.DisplayName
            PublishedByDiscoveredCA = ($PublishingCas.Count -gt 0)
            PublishingCAs           = ($PublishingCas -join ';')
            IdentityReference       = $AccessEntry.IdentityReference
            AccessControlType       = $AccessEntry.AccessControlType
            ActiveDirectoryRights   = $AccessEntry.ActiveDirectoryRights
            ObjectType              = $AccessEntry.ObjectType
            IsInherited             = $AccessEntry.IsInherited
            AllowsEnroll            = $AccessEntry.AllowsEnroll
            AllowsAutoEnroll        = $AccessEntry.AllowsAutoEnroll
            AllowsAllExtendedRights = $AccessEntry.AllowsAllExtendedRights
            AllowsGenericAll        = $AccessEntry.AllowsGenericAll
            AllowsGenericWrite      = $AccessEntry.AllowsGenericWrite
            AllowsWriteDacl         = $AccessEntry.AllowsWriteDacl
            AllowsWriteOwner        = $AccessEntry.AllowsWriteOwner
            AllowsWriteProperty     = $AccessEntry.AllowsWriteProperty
        })
    }

    $AuthenticationCapableEkus = @(
        $Ekus | Where-Object {
            $_ -in @(
                '1.3.6.1.5.5.7.3.2',
                '1.3.6.1.4.1.311.20.2.2',
                '1.3.6.1.5.2.3.4',
                '2.5.29.37.0'
            )
        }
    )

    $Rows.Add([pscustomobject][ordered]@{
        PermissionEvaluationVersion       = $PermissionEvaluationVersion
        Name                              = $TemplateName
        DisplayName                       = [string]$Template.DisplayName
        DistinguishedName                 = [string]$Template.DistinguishedName
        TemplatePresentInDirectory        = $true
        PublishedByDiscoveredCA           = ($PublishingCas.Count -gt 0)
        PublishingCAs                     = $PublishingCas
        TemplateFlagsRaw                  = $TemplateFlags
        IsMachineTemplate                 = Test-MSADPTBitFlag -Value $TemplateFlags -Flag 0x40
        IsCaTemplate                      = Test-MSADPTBitFlag -Value $TemplateFlags -Flag 0x80
        IsCrossCaTemplate                 = Test-MSADPTBitFlag -Value $TemplateFlags -Flag 0x800
        SchemaVersion                     = Get-MSADPTInt64Value $Template.'msPKI-Template-Schema-Version'
        MinorRevision                     = Get-MSADPTInt64Value $Template.'msPKI-Template-Minor-Revision'
        EnrollmentFlagsRaw                = $EnrollmentFlags
        ManagerApprovalRequired           = Test-MSADPTBitFlag -Value $EnrollmentFlags -Flag 0x2
        PublishToDs                       = Test-MSADPTBitFlag -Value $EnrollmentFlags -Flag 0x8
        AutoEnrollmentAllowedByTemplate   = Test-MSADPTBitFlag -Value $EnrollmentFlags -Flag 0x20
        CertificateNameFlagsRaw           = $CertificateNameFlags
        EnrolleeSuppliesSubject            = Test-MSADPTBitFlag -Value $CertificateNameFlags -Flag 0x1
        EnrolleeSuppliesSubjectAltName     = Test-MSADPTBitFlag -Value $CertificateNameFlags -Flag 0x10000
        SubjectAltRequireDomainDns         = Test-MSADPTBitFlag -Value $CertificateNameFlags -Flag 0x400000
        SubjectAltRequireUpn               = Test-MSADPTBitFlag -Value $CertificateNameFlags -Flag 0x2000000
        SubjectRequireDnsAsCn              = Test-MSADPTBitFlag -Value $CertificateNameFlags -Flag 0x10000000
        SubjectRequireCommonName           = Test-MSADPTBitFlag -Value $CertificateNameFlags -Flag 0x40000000
        PrivateKeyFlagsRaw                 = $PrivateKeyFlags
        ExportablePrivateKey               = Test-MSADPTBitFlag -Value $PrivateKeyFlags -Flag 0x10
        StrongKeyProtectionRequired        = Test-MSADPTBitFlag -Value $PrivateKeyFlags -Flag 0x20
        AuthorizedSignatureCount           = $AuthorizedSignatureCount
        AuthorizedSignaturesRequired       = ($AuthorizedSignatureCount -gt 0)
        RaApplicationPolicies              = @($Template.'msPKI-RA-Application-Policies' | ForEach-Object { [string]$_ })
        ExtendedKeyUsage                   = $Ekus
        AuthenticationCapableEkus          = $AuthenticationCapableEkus
        HasAuthenticationCapableEku        = ($AuthenticationCapableEkus.Count -gt 0)
        NoExtendedKeyUsageRestriction      = ($Ekus.Count -eq 0)
        ValidityPeriod                     = Convert-MSADPTLargeIntegerPeriod $Template.pKIExpirationPeriod
        RenewalOverlapPeriod               = Convert-MSADPTLargeIntegerPeriod $Template.pKIOverlapPeriod
        SecurityDescriptorOwner            = [string]$Acl.Owner
        AccessEntryCount                    = $AccessEntries.Count
        AllowEnrollIdentityCount            = @($AccessEntries | Where-Object AllowsEnroll | Select-Object -ExpandProperty IdentityReference -Unique).Count
        AllowAutoEnrollIdentityCount        = @($AccessEntries | Where-Object AllowsAutoEnroll | Select-Object -ExpandProperty IdentityReference -Unique).Count
        AllowTemplateControlIdentityCount   = @($AccessEntries | Where-Object { $_.AllowsGenericAll -or $_.AllowsGenericWrite -or $_.AllowsWriteDacl -or $_.AllowsWriteOwner -or $_.AllowsWriteProperty } | Select-Object -ExpandProperty IdentityReference -Unique).Count
        AccessEntries                       = $AccessEntries
        WhenCreated                         = $Template.whenCreated
        WhenChanged                         = $Template.whenChanged
    })
}

$OutputDirectory = Join-Path $EngagementPath 'evidence\ADCSConfigurationCollection'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$CaEvidencePath = Join-Path $OutputDirectory 'enterprise-ca-publication.json'
$TemplateEvidencePath = Join-Path $OutputDirectory 'certificate-template-configuration.json'
$TemplateSummaryPath = Join-Path $OutputDirectory 'certificate-template-summary.csv'
$AccessEvidencePath = Join-Path $OutputDirectory 'certificate-template-access.csv'

Write-MSADPTJsonEvidence -Path $CaEvidencePath -Value ([object[]]$EnterpriseCas) -Depth 20
Write-MSADPTJsonEvidence -Path $TemplateEvidencePath -Value ([object[]]$Rows.ToArray()) -Depth 30

$Rows.ToArray() |
    Select-Object PermissionEvaluationVersion, Name, DisplayName, TemplatePresentInDirectory, PublishedByDiscoveredCA,
        @{Name='PublishingCAs';Expression={ $_.PublishingCAs -join ';' }},
        SchemaVersion, MinorRevision, ManagerApprovalRequired, EnrolleeSuppliesSubject,
        EnrolleeSuppliesSubjectAltName, ExportablePrivateKey, AuthorizedSignatureCount,
        AuthorizedSignaturesRequired, HasAuthenticationCapableEku, NoExtendedKeyUsageRestriction,
        @{Name='ExtendedKeyUsage';Expression={ $_.ExtendedKeyUsage -join ';' }},
        SecurityDescriptorOwner, AccessEntryCount, AllowEnrollIdentityCount,
        AllowAutoEnrollIdentityCount, AllowTemplateControlIdentityCount, WhenCreated, WhenChanged |
    Export-Csv -LiteralPath $TemplateSummaryPath -NoTypeInformation -Encoding UTF8

$AccessRows.ToArray() |
    Export-Csv -LiteralPath $AccessEvidencePath -NoTypeInformation -Encoding UTF8

$ManifestPath = New-MSADPTEvidenceManifest -EvidenceDirectory $OutputDirectory -ModuleId 'ADCSConfigurationCollection' -ModuleVersion $CollectorVersion
$PublishedTemplateCount = @($Rows.ToArray() | Where-Object PublishedByDiscoveredCA).Count
$UnpublishedTemplateCount = $Rows.Count - $PublishedTemplateCount

[pscustomobject][ordered]@{
    schemaVersion          = '1.0'
    module                 = 'ADCSConfigurationCollection'
    moduleVersion          = $CollectorVersion
    permissionEvaluationVersion = $PermissionEvaluationVersion
    status                 = 'Completed'
    executionClass         = 'read_only'
    enterpriseCaCount      = $EnterpriseCas.Count
    directoryTemplateCount = $Rows.Count
    publishedTemplateCount = $PublishedTemplateCount
    unpublishedTemplateCount = $UnpublishedTemplateCount
    targetCount            = $Rows.Count
    evidence               = @(
        'evidence/ADCSConfigurationCollection/enterprise-ca-publication.json',
        'evidence/ADCSConfigurationCollection/certificate-template-configuration.json',
        'evidence/ADCSConfigurationCollection/certificate-template-summary.csv',
        'evidence/ADCSConfigurationCollection/certificate-template-access.csv'
    )
    limitations            = @(
        'Collection records directory configuration, CA publication lists, and template ACL evidence but does not claim an ESC condition or exploitability.',
        'CA runtime registry settings, CA security descriptors, issuance-policy mappings, web enrollment endpoints, and RPC/DCOM reachability are not tested by this module.',
        'ACL permission masks are interpreted per ACE with full-mask matching; effective access still requires nested-group, deny-ACE, authentication, issuance, and CA-policy evaluation.',
        'No certificate enrollment, authentication attempt, template modification, or CA modification is performed.',
        'When -Credential is supplied, AD cmdlets use that credential; AD provider ACL reads use the current process identity.'
    )
    completedUtc           = (Get-Date).ToUniversalTime().ToString('o')
}
