<#
.SYNOPSIS
Analyzes MSADPT managed-secrets evidence entirely offline.

.DESCRIPTION
Merges:
- Managed-secrets inventory evidence containing computer LAPS coverage and gMSA metadata.
- Delegation evidence containing domain-root and organizational-unit access-control entries.

The analyzer does not read Active Directory, contact the network, retrieve LAPS passwords, retrieve gMSA managed-password blobs, or modify any object.

.NOTES
Version: 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$InventoryEvidenceDirectory,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DelegationEvidenceDirectory,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$InactiveComputerDays = 90
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Version = '1.0.0'

function Resolve-MSADPTLocalPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath(
        (Join-Path (Get-Location).Path $Path)
    )
}

function Read-MSADPTJson {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "EvidenceMissing: $Path"
    }

    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function ConvertTo-MSADPTHtmlText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Convert-MSADPTEncryptionTypes {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return [pscustomobject][ordered]@{
            RawValue = $Value
            Algorithms = @()
            HasRc4 = $false
            HasAes128 = $false
            HasAes256 = $false
            Disposition = 'Inconclusive'
        }
    }

    $NumericValue = [int]$Value
    $Algorithms = [System.Collections.Generic.List[string]]::new()

    if (($NumericValue -band 1) -eq 1) { $Algorithms.Add('DES_CBC_CRC') }
    if (($NumericValue -band 2) -eq 2) { $Algorithms.Add('DES_CBC_MD5') }
    if (($NumericValue -band 4) -eq 4) { $Algorithms.Add('RC4_HMAC') }
    if (($NumericValue -band 8) -eq 8) { $Algorithms.Add('AES128_CTS_HMAC_SHA1_96') }
    if (($NumericValue -band 16) -eq 16) { $Algorithms.Add('AES256_CTS_HMAC_SHA1_96') }

    $HasRc4 = ($NumericValue -band 4) -eq 4
    $HasAes128 = ($NumericValue -band 8) -eq 8
    $HasAes256 = ($NumericValue -band 16) -eq 16

    $Disposition = if ($HasAes128 -and $HasAes256 -and -not $HasRc4) {
        'AESOnly'
    }
    elseif ($HasAes128 -and $HasAes256 -and $HasRc4) {
        'AESAndRC4'
    }
    elseif ($HasRc4 -and -not ($HasAes128 -or $HasAes256)) {
        'RC4Only'
    }
    else {
        'ReviewRequired'
    }

    return [pscustomobject][ordered]@{
        RawValue = $NumericValue
        Algorithms = @($Algorithms)
        HasRc4 = $HasRc4
        HasAes128 = $HasAes128
        HasAes256 = $HasAes256
        Disposition = $Disposition
    }
}

$InventoryEvidenceDirectory = Resolve-MSADPTLocalPath -Path $InventoryEvidenceDirectory
$DelegationEvidenceDirectory = Resolve-MSADPTLocalPath -Path $DelegationEvidenceDirectory
$OutputDirectory = Resolve-MSADPTLocalPath -Path $OutputDirectory
$InventoryRaw = Join-Path $InventoryEvidenceDirectory 'Raw'
$DelegationRaw = Join-Path $DelegationEvidenceDirectory 'Raw'

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

Write-Host '[ANALYZE     ] Offline managed-secrets exposure analysis' -ForegroundColor Cyan
Write-Host ("               Inventory evidence  : {0}" -f $InventoryEvidenceDirectory) -ForegroundColor Gray
Write-Host ("               Delegation evidence : {0}" -f $DelegationEvidenceDirectory) -ForegroundColor Gray
Write-Host ("               Output              : {0}" -f $OutputDirectory) -ForegroundColor Gray
Write-Host '               Network             : None' -ForegroundColor Gray
Write-Host '               AD queries          : None' -ForegroundColor Gray
Write-Host '               Secret values       : Not present and not requested' -ForegroundColor Gray

$Context = Read-MSADPTJson -Path (Join-Path $InventoryRaw 'directory-context.json')
$SchemaAttributes = @(Read-MSADPTJson -Path (Join-Path $InventoryRaw 'laps-schema-attributes.json'))
$Computers = @(Read-MSADPTJson -Path (Join-Path $InventoryRaw 'computer-laps-coverage.json'))
$GmsaAccounts = @(Read-MSADPTJson -Path (Join-Path $InventoryRaw 'gmsa-inventory.json'))
$InventoryErrors = @(Read-MSADPTJson -Path (Join-Path $InventoryRaw 'operational-errors.json'))
$DelegationAces = @(Read-MSADPTJson -Path (Join-Path $DelegationRaw 'delegation-aces.json'))
$DelegationErrors = @(Read-MSADPTJson -Path (Join-Path $DelegationRaw 'operational-errors.json'))

$GeneratedUtc = (Get-Date).ToUniversalTime()
$InactiveThresholdUtc = $GeneratedUtc.AddDays(-1 * $InactiveComputerDays)

$WindowsLapsSchemaPresent = @(
    $SchemaAttributes |
        Where-Object {
            $_.LdapDisplayName -in @(
                'msLAPS-Password'
                'msLAPS-EncryptedPassword'
                'msLAPS-PasswordExpirationTime'
            ) -and
            $_.Present
        }
).Count -gt 0

$LegacyLapsSchemaPresent = @(
    $SchemaAttributes |
        Where-Object {
            $_.LdapDisplayName -eq 'ms-Mcs-AdmPwd' -and
            $_.Present
        }
).Count -gt 0

$LapsComputerAssessment = @(
    foreach ($Computer in $Computers) {
        $LastLogonDate = $null
        if ($Computer.LastLogonDate) {
            $LastLogonDate = [datetime]$Computer.LastLogonDate
        }

        $IsInactive = if ($null -eq $LastLogonDate) {
            $true
        }
        else {
            $LastLogonDate.ToUniversalTime() -lt $InactiveThresholdUtc
        }

        $LegacyExpirationPresent = [bool]$Computer.LegacyLapsExpirationPresent
        $WindowsExpirationPresent = [bool]$Computer.WindowsLapsExpirationPresent

        $CoverageDisposition = if (-not [bool]$Computer.Enabled) {
            'NotApplicableDisabled'
        }
        elseif ($LegacyExpirationPresent -or $WindowsExpirationPresent) {
            'Covered'
        }
        elseif ($IsInactive) {
            'InconclusiveInactiveOrStale'
        }
        else {
            'LikelyCoverageGap'
        }

        [pscustomobject][ordered]@{
            Name = $Computer.Name
            SamAccountName = $Computer.SamAccountName
            DNSHostName = $Computer.DNSHostName
            DistinguishedName = $Computer.DistinguishedName
            Enabled = [bool]$Computer.Enabled
            OperatingSystem = $Computer.OperatingSystem
            OperatingSystemVersion = $Computer.OperatingSystemVersion
            LastLogonDate = $Computer.LastLogonDate
            PasswordLastSet = $Computer.PasswordLastSet
            WindowsLapsExpirationPresent = $WindowsExpirationPresent
            LegacyLapsExpirationPresent = $LegacyExpirationPresent
            IsInactiveByThreshold = $IsInactive
            InactiveThresholdDays = $InactiveComputerDays
            CoverageDisposition = $CoverageDisposition
            SecretValuesCollected = $false
        }
    }
)

$GmsaAssessment = @(
    foreach ($Gmsa in $GmsaAccounts) {
        $RetrieverPrincipals = @($Gmsa.PrincipalsAllowedToRetrieveManagedPassword)
        $EncryptionAssessment = Convert-MSADPTEncryptionTypes -Value $Gmsa.SupportedEncryptionTypes

        $RetrieverDisposition = if (-not [bool]$Gmsa.Enabled) {
            'NotApplicableDisabled'
        }
        elseif ($RetrieverPrincipals.Count -eq 0) {
            'InconclusiveNoConfiguredRetriever'
        }
        elseif ($RetrieverPrincipals.Count -gt 3) {
            'ReviewBroadConfiguredScope'
        }
        else {
            'ConfiguredScopePresent'
        }

        [pscustomobject][ordered]@{
            Name = $Gmsa.Name
            SamAccountName = $Gmsa.SamAccountName
            DistinguishedName = $Gmsa.DistinguishedName
            DNSHostName = $Gmsa.DNSHostName
            Enabled = [bool]$Gmsa.Enabled
            ServicePrincipalNameCount = @($Gmsa.ServicePrincipalNames).Count
            ServicePrincipalNames = @($Gmsa.ServicePrincipalNames) -join '; '
            RetrieverPrincipalCount = $RetrieverPrincipals.Count
            RetrieverPrincipals = $RetrieverPrincipals -join '; '
            RetrieverDisposition = $RetrieverDisposition
            SupportedEncryptionTypes = $EncryptionAssessment.RawValue
            EncryptionAlgorithms = $EncryptionAssessment.Algorithms -join '; '
            EncryptionDisposition = $EncryptionAssessment.Disposition
            HasRc4 = $EncryptionAssessment.HasRc4
            HasAes128 = $EncryptionAssessment.HasAes128
            HasAes256 = $EncryptionAssessment.HasAes256
            PasswordLastSet = $Gmsa.PasswordLastSet
            WhenCreated = $Gmsa.WhenCreated
            WhenChanged = $Gmsa.WhenChanged
            ManagedPasswordBlobCollected = $false
        }
    }
)

$LegacyPasswordSchema = @(
    $SchemaAttributes |
        Where-Object {
            $_.LdapDisplayName -eq 'ms-Mcs-AdmPwd' -and
            $_.Present
        } |
        Select-Object -First 1
)
$LegacyPasswordGuid = if ($LegacyPasswordSchema.Count -gt 0) {
    [string]$LegacyPasswordSchema[0].SchemaIdGuid
}
else {
    $null
}

$LegacyExpirationSchema = @(
    $SchemaAttributes |
        Where-Object {
            $_.LdapDisplayName -eq 'ms-Mcs-AdmPwdExpirationTime' -and
            $_.Present
        } |
        Select-Object -First 1
)
$LegacyExpirationGuid = if ($LegacyExpirationSchema.Count -gt 0) {
    [string]$LegacyExpirationSchema[0].SchemaIdGuid
}
else {
    $null
}

$PotentialSecretDelegationAces = @(
    foreach ($Ace in $DelegationAces) {
        if ([string]$Ace.AccessControlType -ne 'Allow') {
            continue
        }

        $Rights = [string]$Ace.ActiveDirectoryRights
        $ObjectTypeGuid = [string]$Ace.ObjectTypeGuid

        $IsBroadControl = $Rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner'
        $CanReadProperty = $Rights -match 'ReadProperty|GenericRead|GenericAll'
        $CanWriteProperty = $Rights -match 'WriteProperty|GenericWrite|GenericAll'
        $IsLegacyPasswordAttribute = (
            -not [string]::IsNullOrWhiteSpace($LegacyPasswordGuid) -and
            $ObjectTypeGuid -eq $LegacyPasswordGuid
        )
        $IsLegacyExpirationAttribute = (
            -not [string]::IsNullOrWhiteSpace($LegacyExpirationGuid) -and
            $ObjectTypeGuid -eq $LegacyExpirationGuid
        )

        if (
            $IsBroadControl -or
            ($CanReadProperty -and $IsLegacyPasswordAttribute) -or
            ($CanWriteProperty -and $IsLegacyExpirationAttribute)
        ) {
            $Reason = if ($IsBroadControl) {
                'Broad object-control right'
            }
            elseif ($CanReadProperty -and $IsLegacyPasswordAttribute) {
                'Legacy LAPS password attribute read candidate'
            }
            else {
                'Legacy LAPS expiration attribute write candidate'
            }

            [pscustomobject][ordered]@{
                TargetObjectType = $Ace.TargetObjectType
                TargetName = $Ace.TargetName
                TargetDistinguishedName = $Ace.TargetDistinguishedName
                IdentityReference = $Ace.IdentityReference
                ActiveDirectoryRights = $Rights
                ObjectTypeGuid = $ObjectTypeGuid
                IsInherited = [bool]$Ace.IsInherited
                InheritanceType = $Ace.InheritanceType
                CandidateReason = $Reason
                Disposition = 'CandidateRequiresEffectiveAccessValidation'
            }
        }
    }
)

$Findings = [System.Collections.Generic.List[object]]::new()

$LikelyCoverageGapCount = @(
    $LapsComputerAssessment |
        Where-Object { $_.CoverageDisposition -eq 'LikelyCoverageGap' }
).Count
$InactiveMissingCount = @(
    $LapsComputerAssessment |
        Where-Object { $_.CoverageDisposition -eq 'InconclusiveInactiveOrStale' }
).Count

if ($LikelyCoverageGapCount -gt 0) {
    $Findings.Add([pscustomobject][ordered]@{
        Disposition = 'Likely'
        Area = 'LegacyLapsCoverage'
        Object = $Context.DomainDnsRoot
        Evidence = "$LikelyCoverageGapCount enabled, recently active computer objects lack collected LAPS expiration metadata."
        Limitation = 'Expiration metadata absence does not alone prove a reusable or unmanaged local administrator password.'
        RecommendedValidation = 'Review the exported computer candidates by operating system, OU, business role, and policy applicability.'
    })
}

if ($InactiveMissingCount -gt 0) {
    $Findings.Add([pscustomobject][ordered]@{
        Disposition = 'Inconclusive'
        Area = 'LegacyLapsCoverage'
        Object = $Context.DomainDnsRoot
        Evidence = "$InactiveMissingCount enabled computer objects without LAPS expiration metadata are inactive or lack a last-logon timestamp under the configured threshold."
        Limitation = 'Stale and special-purpose objects may not require active LAPS policy.'
        RecommendedValidation = 'Recertify stale computer accounts before treating them as LAPS deployment failures.'
    })
}

foreach ($GmsaRecord in @($GmsaAssessment | Where-Object { $_.RetrieverDisposition -match 'Inconclusive|Review' })) {
    $Disposition = if ($GmsaRecord.RetrieverDisposition -eq 'ReviewBroadConfiguredScope') {
        'Likely'
    }
    else {
        'Inconclusive'
    }

    $Findings.Add([pscustomobject][ordered]@{
        Disposition = $Disposition
        Area = 'GmsaRetrievalScope'
        Object = $GmsaRecord.SamAccountName
        Evidence = "Configured retrieval-principal count: $($GmsaRecord.RetrieverPrincipalCount)."
        Limitation = 'Configured principals have not yet been expanded through nested group membership or validated against business need.'
        RecommendedValidation = 'Expand configured principals offline and correlate effective membership, privilege, and service ownership.'
    })
}

if (@($GmsaAssessment | Where-Object { $_.HasRc4 }).Count -gt 0) {
    $Findings.Add([pscustomobject][ordered]@{
        Disposition = 'Likely'
        Area = 'GmsaKerberosEncryption'
        Object = $Context.DomainDnsRoot
        Evidence = "$(@($GmsaAssessment | Where-Object { $_.HasRc4 }).Count) gMSA objects advertise RC4 together with or instead of AES."
        Limitation = 'The directory flag permits an encryption type; it does not prove that observed tickets currently use that type.'
        RecommendedValidation = 'Correlate with service compatibility and captured Kerberos ticket encryption before remediation.'
    })
}

if ($PotentialSecretDelegationAces.Count -gt 0) {
    $Findings.Add([pscustomobject][ordered]@{
        Disposition = 'Inconclusive'
        Area = 'DelegatedSecretAccess'
        Object = $Context.DomainDnsRoot
        Evidence = "$($PotentialSecretDelegationAces.Count) ACL entries are candidates for LAPS-related read, write, or broader object-control paths."
        Limitation = 'ACE presence does not establish effective access. Group membership, inheritance applicability, denies, object type, and target computer scope require correlation.'
        RecommendedValidation = 'Feed candidate ACEs into Directory Control effective-access evaluation before creating remediation work.'
    })
}

$LapsComputerAssessment |
    Export-Csv -LiteralPath (Join-Path $OutputDirectory 'laps-computer-assessment.csv') -NoTypeInformation -Encoding UTF8
$GmsaAssessment |
    Export-Csv -LiteralPath (Join-Path $OutputDirectory 'gmsa-assessment.csv') -NoTypeInformation -Encoding UTF8
$PotentialSecretDelegationAces |
    Export-Csv -LiteralPath (Join-Path $OutputDirectory 'managed-secret-delegation-candidates.csv') -NoTypeInformation -Encoding UTF8
$Findings |
    Export-Csv -LiteralPath (Join-Path $OutputDirectory 'managed-secrets-findings.csv') -NoTypeInformation -Encoding UTF8

$Summary = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    AnalyzerVersion = $Version
    GeneratedUtc = $GeneratedUtc.ToString('o')
    Domain = $Context.DomainDnsRoot
    WindowsLapsSchemaPresent = $WindowsLapsSchemaPresent
    LegacyLapsSchemaPresent = $LegacyLapsSchemaPresent
    ComputerCount = $Computers.Count
    EnabledComputerCount = @($LapsComputerAssessment | Where-Object { $_.Enabled }).Count
    CoveredEnabledComputerCount = @($LapsComputerAssessment | Where-Object { $_.Enabled -and $_.CoverageDisposition -eq 'Covered' }).Count
    LikelyCoverageGapCount = $LikelyCoverageGapCount
    InconclusiveInactiveOrStaleCount = $InactiveMissingCount
    DisabledComputerCount = @($LapsComputerAssessment | Where-Object { -not $_.Enabled }).Count
    GmsaCount = $GmsaAssessment.Count
    EnabledGmsaCount = @($GmsaAssessment | Where-Object { $_.Enabled }).Count
    GmsaWithoutConfiguredRetrieverCount = @($GmsaAssessment | Where-Object { $_.RetrieverPrincipalCount -eq 0 }).Count
    GmsaWithRc4Count = @($GmsaAssessment | Where-Object { $_.HasRc4 }).Count
    GmsaWithAes128Count = @($GmsaAssessment | Where-Object { $_.HasAes128 }).Count
    GmsaWithAes256Count = @($GmsaAssessment | Where-Object { $_.HasAes256 }).Count
    DelegationAceCount = $DelegationAces.Count
    DelegationCandidateCount = $PotentialSecretDelegationAces.Count
    InventoryOperationalErrorCount = $InventoryErrors.Count
    DelegationOperationalErrorCount = $DelegationErrors.Count
    FindingCount = $Findings.Count
    SecretValuesPresent = $false
    ImpactReproduced = $false
    VulnerabilityConfirmed = $false
}

$Summary |
    ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath (Join-Path $OutputDirectory 'managed-secrets-summary.json') -Encoding UTF8

$LapsRows = @(
    $LapsComputerAssessment |
        Group-Object -Property CoverageDisposition |
        Sort-Object -Property Name |
        ForEach-Object {
            '<tr><td>{0}</td><td>{1}</td></tr>' -f (ConvertTo-MSADPTHtmlText $_.Name), (ConvertTo-MSADPTHtmlText $_.Count)
        }
) -join [Environment]::NewLine

$GmsaRows = @(
    foreach ($GmsaRecord in $GmsaAssessment) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (ConvertTo-MSADPTHtmlText $GmsaRecord.SamAccountName), (ConvertTo-MSADPTHtmlText $GmsaRecord.Enabled), (ConvertTo-MSADPTHtmlText $GmsaRecord.RetrieverPrincipalCount), (ConvertTo-MSADPTHtmlText $GmsaRecord.EncryptionDisposition), (ConvertTo-MSADPTHtmlText $GmsaRecord.RetrieverDisposition)
    }
) -join [Environment]::NewLine

$FindingRows = @(
    foreach ($Finding in $Findings) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (ConvertTo-MSADPTHtmlText $Finding.Disposition), (ConvertTo-MSADPTHtmlText $Finding.Area), (ConvertTo-MSADPTHtmlText $Finding.Object), (ConvertTo-MSADPTHtmlText $Finding.Evidence)
    }
) -join [Environment]::NewLine

if ([string]::IsNullOrWhiteSpace($LapsRows)) {
    $LapsRows = '<tr><td colspan="2">No computer assessment data was available.</td></tr>'
}
if ([string]::IsNullOrWhiteSpace($GmsaRows)) {
    $GmsaRows = '<tr><td colspan="5">No gMSA evidence was available.</td></tr>'
}
if ([string]::IsNullOrWhiteSpace($FindingRows)) {
    $FindingRows = '<tr><td colspan="4">No findings were generated.</td></tr>'
}

$Html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MSADPT Managed Secrets Exposure</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:28px;color:#17202a}h1,h2{color:#0b5cab}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.card{border:1px solid #ccd6dd;border-radius:8px;padding:14px}.n{font-size:26px;font-weight:700}table{border-collapse:collapse;width:100%;margin-bottom:18px}th,td{border:1px solid #ccd6dd;padding:6px;text-align:left;vertical-align:top}th{background:#eaf2f8}.boundary{border-left:5px solid #d68910;padding:12px;background:#fff8e7}@media(max-width:800px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<h1>Managed Secrets Exposure</h1>
<p>Domain: $(ConvertTo-MSADPTHtmlText $Context.DomainDnsRoot)</p>
<div class="grid">
<div class="card"><div class="n">$($Summary.ComputerCount)</div>computer objects</div>
<div class="card"><div class="n">$($Summary.CoveredEnabledComputerCount)</div>enabled computers with LAPS expiration metadata</div>
<div class="card"><div class="n">$($Summary.LikelyCoverageGapCount)</div>recent enabled coverage candidates</div>
<div class="card"><div class="n">$($Summary.GmsaCount)</div>gMSA objects</div>
</div>
<p class="boundary"><strong>Interpretation boundary:</strong> No LAPS password or gMSA managed-password value was requested or collected. Expiration metadata and configured principals support coverage analysis, not proof of password compromise. ACL entries are candidates until effective access and target applicability are validated. Impact was not reproduced and vulnerabilities are not automatically confirmed.</p>
<h2>LAPS coverage dispositions</h2>
<table><thead><tr><th>Disposition</th><th>Count</th></tr></thead><tbody>$LapsRows</tbody></table>
<h2>gMSA inventory</h2>
<table><thead><tr><th>Account</th><th>Enabled</th><th>Configured retrievers</th><th>Encryption</th><th>Retriever disposition</th></tr></thead><tbody>$GmsaRows</tbody></table>
<h2>Evidence-based follow-up</h2>
<table><thead><tr><th>Disposition</th><th>Area</th><th>Object</th><th>Evidence</th></tr></thead><tbody>$FindingRows</tbody></table>
</body>
</html>
"@

$HtmlPath = Join-Path $OutputDirectory 'MSADPT-Managed-Secrets-Exposure.html'
[System.IO.File]::WriteAllText(
    $HtmlPath,
    $Html,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host ("[PASS        ] Managed-secrets analysis complete: {0}" -f $OutputDirectory) -ForegroundColor Green

[pscustomobject][ordered]@{
    Status = 'Completed'
    Version = $Version
    OutputDirectory = $OutputDirectory
    ComputerCount = $Summary.ComputerCount
    CoveredEnabledComputerCount = $Summary.CoveredEnabledComputerCount
    LikelyCoverageGapCount = $Summary.LikelyCoverageGapCount
    InconclusiveInactiveOrStaleCount = $Summary.InconclusiveInactiveOrStaleCount
    GmsaCount = $Summary.GmsaCount
    GmsaWithRc4Count = $Summary.GmsaWithRc4Count
    DelegationCandidateCount = $Summary.DelegationCandidateCount
    FindingCount = $Summary.FindingCount
    SummaryPath = Join-Path $OutputDirectory 'managed-secrets-summary.json'
    HtmlReportPath = $HtmlPath
}
