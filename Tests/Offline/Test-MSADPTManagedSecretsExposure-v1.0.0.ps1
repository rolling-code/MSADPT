<#
.SYNOPSIS
Runs an offline regression test for the managed-secrets exposure analyzer.
.NOTES
Version: 1.0.0
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Failures = [System.Collections.Generic.List[string]]::new()
$TemporaryRoot = Join-Path $env:TEMP ('MSADPT-ManagedSecrets-Test-' + [guid]::NewGuid().ToString('N'))

try {
    $InventoryRaw = Join-Path $TemporaryRoot 'Inventory\Raw'
    $DelegationRaw = Join-Path $TemporaryRoot 'Delegation\Raw'
    New-Item -ItemType Directory -Path $InventoryRaw, $DelegationRaw -Force | Out-Null

    $Now = (Get-Date).ToUniversalTime()
    $InventoryFixtures = [ordered]@{
        'directory-context.json' = [pscustomobject]@{ DomainDnsRoot = 'example.test' }
        'laps-schema-attributes.json' = @(
            [pscustomobject]@{ LdapDisplayName = 'ms-Mcs-AdmPwd'; Present = $true; SchemaIdGuid = '11111111-1111-1111-1111-111111111111' }
            [pscustomobject]@{ LdapDisplayName = 'ms-Mcs-AdmPwdExpirationTime'; Present = $true; SchemaIdGuid = '22222222-2222-2222-2222-222222222222' }
            [pscustomobject]@{ LdapDisplayName = 'msLAPS-Password'; Present = $false; SchemaIdGuid = $null }
        )
        'computer-laps-coverage.json' = @(
            [pscustomobject]@{ Name = 'PC01'; SamAccountName = 'PC01$'; DNSHostName = 'pc01.example.test'; DistinguishedName = 'CN=PC01,DC=example,DC=test'; Enabled = $true; OperatingSystem = 'Windows 11 Enterprise'; OperatingSystemVersion = '10.0'; LastLogonDate = $Now.AddDays(-1).ToString('o'); PasswordLastSet = $Now.AddDays(-10).ToString('o'); WindowsLapsExpirationPresent = $false; LegacyLapsExpirationPresent = $true }
            [pscustomobject]@{ Name = 'PC02'; SamAccountName = 'PC02$'; DNSHostName = 'pc02.example.test'; DistinguishedName = 'CN=PC02,DC=example,DC=test'; Enabled = $true; OperatingSystem = 'Windows 11 Enterprise'; OperatingSystemVersion = '10.0'; LastLogonDate = $Now.AddDays(-2).ToString('o'); PasswordLastSet = $Now.AddDays(-10).ToString('o'); WindowsLapsExpirationPresent = $false; LegacyLapsExpirationPresent = $false }
            [pscustomobject]@{ Name = 'PC03'; SamAccountName = 'PC03$'; DNSHostName = 'pc03.example.test'; DistinguishedName = 'CN=PC03,DC=example,DC=test'; Enabled = $true; OperatingSystem = 'Windows 10 Enterprise'; OperatingSystemVersion = '10.0'; LastLogonDate = $Now.AddDays(-200).ToString('o'); PasswordLastSet = $Now.AddDays(-200).ToString('o'); WindowsLapsExpirationPresent = $false; LegacyLapsExpirationPresent = $false }
        )
        'gmsa-inventory.json' = @(
            [pscustomobject]@{ Name = 'svc-app'; SamAccountName = 'svc-app$'; DistinguishedName = 'CN=svc-app,CN=Managed Service Accounts,DC=example,DC=test'; DNSHostName = 'app.example.test'; Enabled = $true; ServicePrincipalNames = @('HTTP/app.example.test'); PrincipalsAllowedToRetrieveManagedPassword = @('CN=APP-SERVERS,DC=example,DC=test'); SupportedEncryptionTypes = 28; PasswordLastSet = $Now.AddDays(-5).ToString('o'); WhenCreated = $Now.AddYears(-1).ToString('o'); WhenChanged = $Now.AddDays(-5).ToString('o') }
        )
        'operational-errors.json' = @()
    }

    foreach ($FixtureName in $InventoryFixtures.Keys) {
        ConvertTo-Json -InputObject $InventoryFixtures[$FixtureName] -Depth 10 |
            Set-Content -LiteralPath (Join-Path $InventoryRaw $FixtureName) -Encoding UTF8
    }

    $DelegationFixtures = [ordered]@{
        'delegation-aces.json' = @(
            [pscustomobject]@{ TargetObjectType = 'OrganizationalUnit'; TargetName = 'Workstations'; TargetDistinguishedName = 'OU=Workstations,DC=example,DC=test'; IdentityReference = 'EXAMPLE\Helpdesk'; AccessControlType = 'Allow'; ActiveDirectoryRights = 'ReadProperty'; ObjectTypeGuid = '11111111-1111-1111-1111-111111111111'; IsInherited = $false; InheritanceType = 'Descendents' }
        )
        'operational-errors.json' = @()
    }

    foreach ($FixtureName in $DelegationFixtures.Keys) {
        ConvertTo-Json -InputObject $DelegationFixtures[$FixtureName] -Depth 10 |
            Set-Content -LiteralPath (Join-Path $DelegationRaw $FixtureName) -Encoding UTF8
    }

    $AnalyzerPath = Join-Path $RepositoryRoot 'Modules\ObjectControl\Analyze-MSADPTManagedSecretsExposure-v1.0.0.ps1'
    if (-not (Test-Path -LiteralPath $AnalyzerPath -PathType Leaf)) {
        $Failures.Add("Missing analyzer: $AnalyzerPath")
    }
    else {
        $Tokens = $null
        $ParserErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $AnalyzerPath,
            [ref]$Tokens,
            [ref]$ParserErrors
        )

        if (@($ParserErrors).Count -gt 0) {
            $Failures.Add('Analyzer contains parser errors.')
        }
    }

    if ($Failures.Count -eq 0) {
        $SavedLocation = Get-Location
        try {
            Set-Location -LiteralPath $TemporaryRoot
            $Result = & $AnalyzerPath -InventoryEvidenceDirectory '.\Inventory' -DelegationEvidenceDirectory '.\Delegation' -OutputDirectory '.\Output' -InactiveComputerDays 90
        }
        finally {
            Set-Location -LiteralPath $SavedLocation
        }

        $SummaryPath = Join-Path $TemporaryRoot 'Output\managed-secrets-summary.json'
        $Summary = Get-Content -LiteralPath $SummaryPath -Raw | ConvertFrom-Json

        if ($Result.Status -ne 'Completed') { $Failures.Add('Analyzer status was not Completed.') }
        if ($Summary.ComputerCount -ne 3) { $Failures.Add('Expected three computers.') }
        if ($Summary.CoveredEnabledComputerCount -ne 1) { $Failures.Add('Expected one covered enabled computer.') }
        if ($Summary.LikelyCoverageGapCount -ne 1) { $Failures.Add('Expected one likely coverage candidate.') }
        if ($Summary.InconclusiveInactiveOrStaleCount -ne 1) { $Failures.Add('Expected one inactive or stale candidate.') }
        if ($Summary.GmsaCount -ne 1) { $Failures.Add('Expected one gMSA.') }
        if ($Summary.GmsaWithRc4Count -ne 1) { $Failures.Add('Expected RC4 flag decoding for encryption value 28.') }
        if ($Summary.DelegationCandidateCount -ne 1) { $Failures.Add('Expected one delegation candidate.') }

        foreach ($OutputName in @(
            'laps-computer-assessment.csv'
            'gmsa-assessment.csv'
            'managed-secret-delegation-candidates.csv'
            'managed-secrets-findings.csv'
            'managed-secrets-summary.json'
            'MSADPT-Managed-Secrets-Exposure.html'
        )) {
            if (-not (Test-Path -LiteralPath (Join-Path $TemporaryRoot ('Output\' + $OutputName)) -PathType Leaf)) {
                $Failures.Add("Missing output: $OutputName")
            }
        }
    }

    if ($Failures.Count -gt 0) {
        $Failures | ForEach-Object { Write-Host "[FAIL] $_" -ForegroundColor Red }
        throw "Regression failures: $($Failures.Count)"
    }

    Write-Host '[PASS] Managed-secrets exposure analyzer regression passed.' -ForegroundColor Green
    [pscustomobject][ordered]@{
        Status = 'Passed'
        Version = '1.0.0'
        FailureCount = 0
    }
}
finally {
    if (Test-Path -LiteralPath $TemporaryRoot) {
        Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force
    }
}
