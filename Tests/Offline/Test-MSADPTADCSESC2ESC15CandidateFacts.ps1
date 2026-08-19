<#
.SYNOPSIS
Tests candidate-specific ESC2 and ESC15 generation.
.NOTES
Version: 1.0.4
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BuilderPath,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [string]$ConsoleModulePath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Tokens = $null
$ParseErrors = $null
$null = [Management.Automation.Language.Parser]::ParseFile(
    $BuilderPath,
    [ref]$Tokens,
    [ref]$ParseErrors
)
if ($ParseErrors.Count -gt 0) {
    throw "Builder parse failed: $($ParseErrors.Message -join '; ')"
}

if (Test-Path -LiteralPath $OutputRoot) {
    Remove-Item -LiteralPath $OutputRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

$CandidatePath = Join-Path $OutputRoot 'routes.json'
$TemplatePath = Join-Path $OutputRoot 'templates.json'
$ContextPath = Join-Path $OutputRoot 'contexts.json'
$ResultRoot = Join-Path $OutputRoot 'results'

function New-SyntheticFact {
    param([string]$Id,[string]$State)
    [pscustomobject]@{
        id = $Id
        state = $State
        rationale = 'synthetic'
        sourceEvidence = @('synthetic')
        limitations = @()
    }
}

$CommonFacts = @(
    (New-SyntheticFact -Id 'enterpriseCaPresent' -State 'Confirmed')
    (New-SyntheticFact -Id 'templatePublished' -State 'Confirmed')
    (New-SyntheticFact -Id 'effectiveLowPrivilegeEnrollment' -State 'Confirmed')
    (New-SyntheticFact -Id 'managerApprovalDisabled' -State 'Confirmed')
    (New-SyntheticFact -Id 'authorizedSignaturesNotRequired' -State 'Confirmed')
    (New-SyntheticFact -Id 'principalResolved' -State 'Confirmed')
)

$Routes = @(
    [pscustomobject]@{
        technique='ESC1';certificationAuthority='CA1';template='AnyPurpose'
        principal='EXAMPLE\Domain Users';facts=$CommonFacts
    }
    [pscustomobject]@{
        technique='ESC1';certificationAuthority='CA1';template='Version1'
        principal='EXAMPLE\AppGroup';facts=$CommonFacts
    }
)
$Templates = @(
    [pscustomobject]@{
        Name='AnyPurpose';ExtendedKeyUsage=@('2.5.29.37.0');NoExtendedKeyUsageRestriction=$false
        SchemaVersion=2;EnrolleeSuppliesSubject=$false;EnrolleeSuppliesSubjectAltName=$false
    }
    [pscustomobject]@{
        Name='Version1';ExtendedKeyUsage=@('1.3.6.1.5.5.7.3.1');NoExtendedKeyUsageRestriction=$false
        SchemaVersion=1;EnrolleeSuppliesSubject=$true;EnrolleeSuppliesSubjectAltName=$false
    }
)
$Contexts = @(
    [pscustomobject]@{identityReference='EXAMPLE\Domain Users';category='BroadLowPrivilege'}
    [pscustomobject]@{identityReference='EXAMPLE\AppGroup';category='SecurityGroup'}
)

$Routes | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $CandidatePath -Encoding UTF8
$Templates | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $TemplatePath -Encoding UTF8
$Contexts | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ContextPath -Encoding UTF8

$Output = @(
    & $BuilderPath `
        -CandidateFactsPath $CandidatePath `
        -TemplateConfigurationPath $TemplatePath `
        -IdentityContextPath $ContextPath `
        -OutputDirectory $ResultRoot `
        -ConsoleModulePath $ConsoleModulePath `
        -Quiet
)
$Terminal = @(
    $Output | Where-Object {
        [string]$_.builderVersion -eq '0.1.2' -and
        [string]$_.status -eq 'Completed'
    }
) | Select-Object -Last 1
if ($null -eq $Terminal) {
    $ObservedTerminalObjects = @(
        $Output | Where-Object { $null -ne $_.PSObject.Properties['builderVersion'] }
    )
    $ObservedSummary = if ($ObservedTerminalObjects.Count -gt 0) {
        @($ObservedTerminalObjects | ForEach-Object { "builderVersion=$($_.builderVersion);status=$($_.status)" }) -join ' | '
    }
    else {
        'No object with a builderVersion property was returned.'
    }
    throw "Builder terminal result missing. Observed: $ObservedSummary"
}

$ResultPath = Join-Path $ResultRoot 'adcs-esc2-esc15-candidates.json'
$Rows = @(Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json)
$Esc2AnyPurpose = $Rows | Where-Object { $_.candidateId -like 'ESC2*AnyPurpose*' } | Select-Object -First 1
$Esc15Version1 = $Rows | Where-Object { $_.candidateId -like 'ESC15*Version1*' } | Select-Object -First 1

$Checks = @(
    [pscustomobject]@{Test='FourRecords';Passed=($Rows.Count -eq 4)}
    [pscustomobject]@{Test='TerminalCountsValid';Passed=([int]$Terminal.candidateCount -eq 4 -and [int]$Terminal.esc2Count -eq 2 -and [int]$Terminal.esc15Count -eq 2)}
    [pscustomobject]@{Test='Esc2AnyPurposeSatisfied';Passed=([string]$Esc2AnyPurpose.disposition -eq 'Prerequisites satisfied')}
    [pscustomobject]@{Test='Esc15Version1Incomplete';Passed=([string]$Esc15Version1.disposition -eq 'Incomplete evidence')}
    [pscustomobject]@{
        Test='Esc15PatchStateMissing'
        Passed=(@($Esc15Version1.facts | Where-Object {
            [string]$_.id -eq 'relevantPatchState' -and [string]$_.state -eq 'Inconclusive'
        }).Count -eq 1)
    }
    [pscustomobject]@{
        Test='NoVulnerabilityClaim'
        Passed=((Get-Content -LiteralPath $ResultPath -Raw) -notmatch '(?i)"disposition"\s*:\s*"vulnerable"')
    }
)

$Checks | Format-Table -AutoSize
$Failed = @($Checks | Where-Object { -not $_.Passed })
if ($Failed.Count -gt 0) {
    $Failed | Format-List Test,Passed
    throw "$($Failed.Count) ESC2 and ESC15 test(s) failed."
}

[pscustomobject]@{
    Status='Passed';TestCount=$Checks.Count;BuilderVersion='0.1.2';TestVersion='1.0.4';CandidateCount=$Rows.Count
}
