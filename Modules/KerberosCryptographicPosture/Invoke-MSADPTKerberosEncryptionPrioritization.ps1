<#
.SYNOPSIS
Correlates and prioritizes MSADPT Kerberos encryption posture evidence offline.

.DESCRIPTION
Reads the static Kerberos account encryption posture evidence and, when present, the Kerberos encryption usage
manifest and normalized event evidence from an existing MSADPT engagement. It separates traditional user service
accounts, managed service accounts, computer accounts, and protected or delegated identities. It produces a short,
actionable prioritized review list without treating every AES-plus-RC4 computer account as an individual finding.

This module is offline. It performs no network activity, Active Directory query, Security log query, Kerberos ticket
request, password operation, credential access, or remote change.

.NOTES
Version: 0.1.0
Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EngagementDirectory,

    [ValidateRange(1, 1000)]
    [int]$MaximumActionableAccounts = 100,

    [ValidateRange(30, 3650)]
    [int]$StalePasswordDays = 730,

    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ModuleVersion = '0.1.0'

function Show-Status {
    param(
        [string]$State,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    $text = '[{0,-12}] {1}' -f $State, $Message
    if ($NoColor) {
        Write-Host $text
    }
    else {
        Write-Host $text -ForegroundColor $Color
    }
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Value
    )

    $json = ConvertTo-Json -InputObject $Value -Depth 16 -WarningAction Stop
    if ([string]::IsNullOrWhiteSpace($json)) {
        $json = '[]'
    }

    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}

function Write-CsvFile {
    param(
        [string]$Path,
        [object[]]$Rows,
        [string[]]$Headers
    )

    if ($Rows.Count -gt 0) {
        $Rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    }
    else {
        $headerLine = ($Headers | ForEach-Object { '"{0}"' -f $_ }) -join ','
        Set-Content -LiteralPath $Path -Value $headerLine -Encoding UTF8
    }
}

function Get-AccountCategory {
    param([object]$Account)

    if ([bool]$Account.ManagedServiceAccount -or $Account.ObjectClass -in @('msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount')) {
        return 'ManagedServiceAccount'
    }

    if ($Account.ObjectClass -eq 'user') {
        return 'UserServiceAccount'
    }

    if ($Account.ObjectClass -eq 'computer') {
        return 'ComputerAccount'
    }

    return 'Other'
}

function Get-PasswordAgeDays {
    param([object]$Account)

    if ($null -eq $Account.PasswordLastSetUtc -or [string]::IsNullOrWhiteSpace([string]$Account.PasswordLastSetUtc)) {
        return $null
    }

    try {
        $passwordDate = [datetime]::Parse([string]$Account.PasswordLastSetUtc).ToUniversalTime()
        return [int][math]::Floor(((Get-Date).ToUniversalTime() - $passwordDate).TotalDays)
    }
    catch {
        return $null
    }
}

function Get-ObservedUsageState {
    param(
        [object]$Account,
        [object[]]$UsageEvents,
        [string]$TelemetryDisposition
    )

    if ($TelemetryDisposition -eq 'Inconclusive') {
        return [pscustomobject]@{
            State = 'BehaviorUnknown'
            RC4EventCount = 0
            RC4TicketCount = 0
            RC4SessionKeyCount = 0
        }
    }

    $name = [string]$Account.SamAccountName
    $matches = @($UsageEvents | Where-Object {
        $_.Account -eq $name -or $_.Target -eq $name -or
        ([string]$_.Account).TrimEnd('$') -eq $name.TrimEnd('$') -or
        ([string]$_.Target).TrimEnd('$') -eq $name.TrimEnd('$')
    })

    $rc4Matches = @($matches | Where-Object { $_.ObservedRC4Ticket -or $_.ObservedRC4SessionKey })
    if ($rc4Matches.Count -gt 0) {
        return [pscustomobject]@{
            State = 'ConfirmedRC4Usage'
            RC4EventCount = $rc4Matches.Count
            RC4TicketCount = @($rc4Matches | Where-Object { $_.ObservedRC4Ticket }).Count
            RC4SessionKeyCount = @($rc4Matches | Where-Object { $_.ObservedRC4SessionKey }).Count
        }
    }

    return [pscustomobject]@{
        State = 'NotDetectedInAvailableTelemetry'
        RC4EventCount = 0
        RC4TicketCount = 0
        RC4SessionKeyCount = 0
    }
}

function Get-PriorityAssessment {
    param(
        [object]$Account,
        [string]$Category,
        [object]$Usage,
        [Nullable[int]]$PasswordAgeDays,
        [int]$StaleThresholdDays
    )

    $score = 0
    $reasons = New-Object 'System.Collections.Generic.List[string]'

    if ($Usage.State -eq 'ConfirmedRC4Usage') {
        $score += 100
        $reasons.Add('RC4 use was confirmed in available KDC telemetry.')
    }

    if ($Category -eq 'UserServiceAccount') {
        $score += 30
        $reasons.Add('Traditional user account has one or more SPNs.')
    }
    elseif ($Category -eq 'ManagedServiceAccount') {
        $score += 5
        $reasons.Add('Password-managed service account is separated from traditional user service accounts.')
    }

    switch ([string]$Account.EncryptionClassification) {
        'ExplicitRC4Enabled' {
            $score += 50
            $reasons.Add('Account is explicitly configured for RC4 without explicit AES capability.')
        }
        'DESConfigured' {
            $score += 60
            $reasons.Add('Account is explicitly configured for DES.')
        }
        'EncryptionTypesNotConfigured' {
            $score += 25
            $reasons.Add('Encryption types are not explicitly configured and AES readiness requires validation.')
        }
        'ExplicitAESAndRC4Enabled' {
            $score += 10
            $reasons.Add('Account permits both AES and RC4; actual RC4 use is not established by static posture.')
        }
    }

    if ([bool]$Account.PotentiallyProtected) {
        $score += 25
        $reasons.Add('Account is marked with adminCount=1 and may be protected or privileged.')
    }

    if ([bool]$Account.TrustedForDelegation) {
        $score += 20
        $reasons.Add('Account is trusted for unconstrained delegation.')
    }

    if ([bool]$Account.TrustedToAuthForDelegation) {
        $score += 15
        $reasons.Add('Account is configured for protocol transition delegation.')
    }

    if ([bool]$Account.PasswordNeverExpires -and $Category -eq 'UserServiceAccount') {
        $score += 10
        $reasons.Add('Traditional user service-account password is configured not to expire.')
    }

    if ($null -ne $PasswordAgeDays -and $PasswordAgeDays -ge $StaleThresholdDays -and $Category -eq 'UserServiceAccount') {
        $score += 15
        $reasons.Add("Traditional user service-account password age is at least $StaleThresholdDays days.")
    }

    $priority = if ($score -ge 100) {
        'ImmediateReview'
    }
    elseif ($score -ge 60) {
        'HighPriorityReview'
    }
    elseif ($score -ge 35) {
        'FocusedReview'
    }
    elseif ($score -ge 20) {
        'MigrationReadinessReview'
    }
    else {
        'GroupedObservation'
    }

    return [pscustomobject]@{
        Score = $score
        Priority = $priority
        Reasons = [string[]]$reasons.ToArray()
    }
}

$EngagementDirectory = [IO.Path]::GetFullPath($EngagementDirectory)
if (-not (Test-Path -LiteralPath $EngagementDirectory -PathType Container)) {
    throw "EngagementDirectoryMissing: $EngagementDirectory"
}

$StaticDirectory = Join-Path $EngagementDirectory 'evidence\KerberosAccountEncryptionPosture'
$StaticPath = Join-Path $StaticDirectory 'kerberos-account-encryption-posture.json'
$StaticManifestPath = Join-Path $StaticDirectory 'evidence-manifest.json'
$UsageDirectory = Join-Path $EngagementDirectory 'evidence\KerberosEncryptionUsage'
$UsageManifestPath = Join-Path $UsageDirectory 'evidence-manifest.json'
$UsageEventsPath = Join-Path $UsageDirectory 'kerberos-encryption-events.json'

foreach ($requiredPath in @($StaticPath, $StaticManifestPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "RequiredEvidenceMissing: $requiredPath"
    }
}

$OutputDirectory = Join-Path $EngagementDirectory 'analysis\KerberosEncryptionPrioritization'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

Show-Status 'START' "MSADPT Kerberos Encryption Prioritization v$ModuleVersion" Cyan
Show-Status 'BOUNDARY' 'Offline evidence correlation only. Network=None; AD queries=None; ticket requests=None; remote changes=None.' Green
Show-Status 'LOAD' 'Loading static account posture and available KDC telemetry evidence.' DarkCyan

$staticManifest = Get-Content -LiteralPath $StaticManifestPath -Raw | ConvertFrom-Json
$accounts = @(Get-Content -LiteralPath $StaticPath -Raw | ConvertFrom-Json)

$telemetryManifest = $null
$usageEvents = @()
$telemetryDisposition = 'NotAvailable'
if (Test-Path -LiteralPath $UsageManifestPath -PathType Leaf) {
    $telemetryManifest = Get-Content -LiteralPath $UsageManifestPath -Raw | ConvertFrom-Json
    $telemetryDisposition = [string]$telemetryManifest.Disposition
}
if (Test-Path -LiteralPath $UsageEventsPath -PathType Leaf) {
    $usageEvents = @(Get-Content -LiteralPath $UsageEventsPath -Raw | ConvertFrom-Json)
}

$prioritized = New-Object 'System.Collections.Generic.List[object]'
$processed = 0
foreach ($account in $accounts) {
    $processed++
    if (($processed % 500) -eq 0) {
        Show-Status 'PROGRESS' "$processed/$($accounts.Count) accounts correlated" DarkGray
    }

    $category = Get-AccountCategory -Account $account
    $passwordAge = Get-PasswordAgeDays -Account $account
    $usage = Get-ObservedUsageState -Account $account -UsageEvents $usageEvents -TelemetryDisposition $telemetryDisposition
    $assessment = Get-PriorityAssessment -Account $account -Category $category -Usage $usage -PasswordAgeDays $passwordAge -StaleThresholdDays $StalePasswordDays

    $prioritized.Add([pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        SamAccountName = [string]$account.SamAccountName
        ObjectClass = [string]$account.ObjectClass
        AccountCategory = $category
        Enabled = [bool]$account.Enabled
        ServicePrincipalNameCount = [int]$account.ServicePrincipalNameCount
        EncryptionClassification = [string]$account.EncryptionClassification
        ReadinessState = [string]$account.ReadinessState
        StaticDisposition = [string]$account.Disposition
        TelemetryState = $usage.State
        ConfirmedRC4EventCount = $usage.RC4EventCount
        ConfirmedRC4TicketCount = $usage.RC4TicketCount
        ConfirmedRC4SessionKeyCount = $usage.RC4SessionKeyCount
        PasswordLastSetUtc = $account.PasswordLastSetUtc
        PasswordAgeDays = $passwordAge
        PasswordNeverExpires = [bool]$account.PasswordNeverExpires
        PotentiallyProtected = [bool]$account.PotentiallyProtected
        TrustedForDelegation = [bool]$account.TrustedForDelegation
        TrustedToAuthForDelegation = [bool]$account.TrustedToAuthForDelegation
        PriorityScore = $assessment.Score
        Priority = $assessment.Priority
        Reasons = $assessment.Reasons
        FinalDisposition = if ($usage.State -eq 'ConfirmedRC4Usage') {
            'ConfirmedRC4Usage'
        }
        elseif ($category -eq 'UserServiceAccount' -and $account.EncryptionClassification -eq 'EncryptionTypesNotConfigured') {
            'UserServiceAccountRequiresValidation'
        }
        elseif ($category -eq 'UserServiceAccount' -and $account.EncryptionClassification -eq 'ExplicitAESAndRC4Enabled') {
            'UserServiceAccountRC4CapableButNotObserved'
        }
        elseif ($category -eq 'ManagedServiceAccount' -and $account.EncryptionClassification -eq 'ExplicitAESAndRC4Enabled') {
            'ManagedServiceAccountMigrationCandidate'
        }
        elseif ($category -eq 'ComputerAccount' -and $account.EncryptionClassification -eq 'EncryptionTypesNotConfigured') {
            'ComputerAccountRequiresValidation'
        }
        elseif ($category -eq 'ComputerAccount' -and $account.EncryptionClassification -eq 'ExplicitAESAndRC4Enabled') {
            'ComputerAccountPolicyObservation'
        }
        else {
            'NoPriorityLegacyConditionDetected'
        }
        Limitations = 'Static capability does not prove usage. BehaviorUnknown means KDC telemetry was unavailable or inconclusive.'
    })
}

$allRows = [object[]]$prioritized.ToArray()
$actionableRows = @($allRows | Where-Object {
    $_.Priority -in @('ImmediateReview', 'HighPriorityReview', 'FocusedReview', 'MigrationReadinessReview') -and
    ($_.AccountCategory -ne 'ComputerAccount' -or $_.EncryptionClassification -eq 'EncryptionTypesNotConfigured' -or $_.TelemetryState -eq 'ConfirmedRC4Usage')
} | Sort-Object -Property @{ Expression = 'PriorityScore'; Descending = $true }, SamAccountName | Select-Object -First $MaximumActionableAccounts)

$userServiceRows = @($allRows | Where-Object { $_.AccountCategory -eq 'UserServiceAccount' })
$managedRows = @($allRows | Where-Object { $_.AccountCategory -eq 'ManagedServiceAccount' })
$computerRows = @($allRows | Where-Object { $_.AccountCategory -eq 'ComputerAccount' })

$categorySummary = @($allRows | Group-Object AccountCategory, EncryptionClassification | ForEach-Object {
    [pscustomobject][ordered]@{
        AccountCategory = [string]$_.Group[0].AccountCategory
        EncryptionClassification = [string]$_.Group[0].EncryptionClassification
        AccountCount = $_.Count
        ConfirmedRC4UsageCount = @($_.Group | Where-Object { $_.TelemetryState -eq 'ConfirmedRC4Usage' }).Count
        ProtectedOrPrivilegedCount = @($_.Group | Where-Object { $_.PotentiallyProtected }).Count
        DelegationConfiguredCount = @($_.Group | Where-Object { $_.TrustedForDelegation -or $_.TrustedToAuthForDelegation }).Count
    }
} | Sort-Object AccountCategory, EncryptionClassification)

$computerPolicySummary = [pscustomobject][ordered]@{
    AccountCount = $computerRows.Count
    AESOnlyCount = @($computerRows | Where-Object { $_.EncryptionClassification -eq 'ExplicitAESOnly' }).Count
    AESAndRC4Count = @($computerRows | Where-Object { $_.EncryptionClassification -eq 'ExplicitAESAndRC4Enabled' }).Count
    RC4OnlyCount = @($computerRows | Where-Object { $_.EncryptionClassification -eq 'ExplicitRC4Enabled' }).Count
    DESConfiguredCount = @($computerRows | Where-Object { $_.EncryptionClassification -eq 'DESConfigured' }).Count
    NotConfiguredCount = @($computerRows | Where-Object { $_.EncryptionClassification -eq 'EncryptionTypesNotConfigured' }).Count
    Interpretation = 'Computer accounts are summarized as cryptographic policy posture unless confirmed RC4 usage or another elevated condition is present.'
}

$analysisSummary = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    ModuleVersion = $ModuleVersion
    StaticAccountCount = $accounts.Count
    TelemetryDisposition = $telemetryDisposition
    TelemetrySuccessfulSourceCount = if ($null -ne $telemetryManifest) { [int]$telemetryManifest.SuccessfulSourceCount } else { 0 }
    TelemetryFailedSourceCount = if ($null -ne $telemetryManifest) { [int]$telemetryManifest.FailedSourceCount } else { 0 }
    UserServiceAccountCount = $userServiceRows.Count
    ManagedServiceAccountCount = $managedRows.Count
    ComputerAccountCount = $computerRows.Count
    ActionableReviewCount = $actionableRows.Count
    ConfirmedRC4UsageAccountCount = @($allRows | Where-Object { $_.TelemetryState -eq 'ConfirmedRC4Usage' }).Count
    UserServiceAccountRequiresValidationCount = @($allRows | Where-Object { $_.FinalDisposition -eq 'UserServiceAccountRequiresValidation' }).Count
    UserServiceAccountRC4CapableCount = @($allRows | Where-Object { $_.FinalDisposition -eq 'UserServiceAccountRC4CapableButNotObserved' }).Count
    ManagedServiceAccountMigrationCandidateCount = @($allRows | Where-Object { $_.FinalDisposition -eq 'ManagedServiceAccountMigrationCandidate' }).Count
    ComputerAccountPolicyObservationCount = @($allRows | Where-Object { $_.FinalDisposition -eq 'ComputerAccountPolicyObservation' }).Count
    ComputerAccountRequiresValidationCount = @($allRows | Where-Object { $_.FinalDisposition -eq 'ComputerAccountRequiresValidation' }).Count
    ComputerPolicySummary = $computerPolicySummary
    OverallDisposition = if (@($allRows | Where-Object { $_.TelemetryState -eq 'ConfirmedRC4Usage' }).Count -gt 0) {
        'ConfirmedRC4Usage'
    }
    elseif ($actionableRows.Count -gt 0) {
        'FocusedReviewRequired'
    }
    elseif ($telemetryDisposition -eq 'Inconclusive') {
        'StaticPostureCollectedBehaviorUnknown'
    }
    else {
        'NoPriorityLegacyConditionDetected'
    }
    Limitations = 'Prioritization is evidence triage, not vulnerability confirmation. Inconclusive KDC telemetry prevents conclusions about actual RC4 ticket or session-key use.'
}

$PrioritizedPath = Join-Path $OutputDirectory 'kerberos-prioritized-account-review.json'
$PrioritizedCsvPath = Join-Path $OutputDirectory 'kerberos-prioritized-account-review.csv'
$SummaryPath = Join-Path $OutputDirectory 'kerberos-encryption-correlation-summary.json'
$CategoryPath = Join-Path $OutputDirectory 'kerberos-encryption-category-summary.json'
$ManifestPath = Join-Path $OutputDirectory 'evidence-manifest.json'

Write-JsonFile -Path $PrioritizedPath -Value $actionableRows
Write-CsvFile -Path $PrioritizedCsvPath -Rows $actionableRows -Headers @(
    'SamAccountName','ObjectClass','AccountCategory','EncryptionClassification','ReadinessState','TelemetryState',
    'PasswordAgeDays','PasswordNeverExpires','PotentiallyProtected','TrustedForDelegation',
    'TrustedToAuthForDelegation','PriorityScore','Priority','FinalDisposition'
)
Write-JsonFile -Path $SummaryPath -Value $analysisSummary
Write-JsonFile -Path $CategoryPath -Value $categorySummary

$files = @($PrioritizedPath, $PrioritizedCsvPath, $SummaryPath, $CategoryPath) | ForEach-Object {
    [pscustomobject]@{
        Name = Split-Path -Leaf $_
        Size = (Get-Item -LiteralPath $_).Length
        SHA256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash
    }
}

$manifest = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    Status = 'Completed'
    ModuleId = 'KerberosEncryptionPrioritization'
    ModuleVersion = $ModuleVersion
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    StaticEvidenceManifest = $StaticManifestPath
    TelemetryEvidenceManifest = if (Test-Path -LiteralPath $UsageManifestPath) { $UsageManifestPath } else { $null }
    AccountCount = $accounts.Count
    ActionableReviewCount = $actionableRows.Count
    TelemetryDisposition = $telemetryDisposition
    OverallDisposition = $analysisSummary.OverallDisposition
    NetworkActivity = 'None'
    ActiveDirectoryQueries = 'None'
    SecurityLogQueries = 'None'
    TicketRequests = 'None'
    PasswordOperations = 'None'
    RemoteChanges = 'None'
    Files = $files
}
Write-JsonFile -Path $ManifestPath -Value $manifest

Show-Status 'DONE' "accounts=$($accounts.Count); users=$($userServiceRows.Count); managed=$($managedRows.Count); computers=$($computerRows.Count); actionable=$($actionableRows.Count); telemetry=$telemetryDisposition; disposition=$($analysisSummary.OverallDisposition)" Green

[pscustomobject][ordered]@{
    Status = 'Completed'
    Version = $ModuleVersion
    AccountCount = $accounts.Count
    UserServiceAccountCount = $userServiceRows.Count
    ManagedServiceAccountCount = $managedRows.Count
    ComputerAccountCount = $computerRows.Count
    ActionableReviewCount = $actionableRows.Count
    TelemetryDisposition = $telemetryDisposition
    OverallDisposition = $analysisSummary.OverallDisposition
    OutputDirectory = $OutputDirectory
    PrioritizedReviewPath = $PrioritizedPath
    SummaryPath = $SummaryPath
    ManifestPath = $ManifestPath
    NetworkActivity = 'None'
    RemoteChanges = 'None'
}
