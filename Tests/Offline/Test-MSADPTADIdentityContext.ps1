<#
.SYNOPSIS
Tests the offline MSADPT AD identity-context classifier.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ClassifierPath,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [Parameter()][string]$ConsoleModulePath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ClassifierPath -PathType Leaf)) {
    throw "Classifier not found: $ClassifierPath"
}

$Tokens = $null
$ParseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    $ClassifierPath,
    [ref]$Tokens,
    [ref]$ParseErrors
)
if ($ParseErrors.Count -gt 0) {
    throw "Classifier parse failed: $($ParseErrors.Message -join '; ')"
}

if (Test-Path -LiteralPath $OutputRoot) {
    Remove-Item -LiteralPath $OutputRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

$CandidatesPath = Join-Path $OutputRoot 'candidates.json'
$IdentitiesPath = Join-Path $OutputRoot 'identities.json'

$Candidates = @(
    [pscustomobject]@{candidateId='ESC1|CA|T1|EXAMPLE\Domain Admins';technique='ESC1';principal='EXAMPLE\Domain Admins'},
    [pscustomobject]@{candidateId='ESC1|CA|T1|NT AUTHORITY\Authenticated Users';technique='ESC1';principal='NT AUTHORITY\Authenticated Users'},
    [pscustomobject]@{candidateId='ESC1|CA|T1|EXAMPLE\Domain Computers';technique='ESC1';principal='EXAMPLE\Domain Computers'},
    [pscustomobject]@{candidateId='ESC1|CA|T1|EXAMPLE\EmptyGroup';technique='ESC1';principal='EXAMPLE\EmptyGroup'},
    [pscustomobject]@{candidateId='ESC1|CA|T1|EXAMPLE\sec-Scep-Servers';technique='ESC1';principal='EXAMPLE\sec-Scep-Servers'},
    [pscustomobject]@{candidateId='ESC1|CA|T1|EXAMPLE\Svc-App';technique='ESC1';principal='EXAMPLE\Svc-App'},
    [pscustomobject]@{candidateId='ESC4|CA|T2|EXAMPLE\SERVER01$';technique='ESC4';principal='EXAMPLE\SERVER01$'},
    [pscustomobject]@{candidateId='ESC1|CA|T1|EXAMPLE\Missing';technique='ESC1';principal='EXAMPLE\Missing'}
)

$Identities = @(
    [pscustomobject]@{IdentityReference='EXAMPLE\EmptyGroup';ResolutionStatus='Resolved';ObjectClass='group';Enabled=$null;RecursiveMembers=@()},
    [pscustomobject]@{IdentityReference='EXAMPLE\sec-Scep-Servers';ResolutionStatus='Resolved';ObjectClass='group';Enabled=$null;RecursiveMembers=@([pscustomobject]@{Name='Svc-App'})},
    [pscustomobject]@{IdentityReference='EXAMPLE\Svc-App';ResolutionStatus='Resolved';ObjectClass='user';Enabled=$true;RecursiveMembers=@()},
    [pscustomobject]@{IdentityReference='EXAMPLE\SERVER01$';ResolutionStatus='Resolved';ObjectClass='computer';Enabled=$true;RecursiveMembers=@()},
    [pscustomobject]@{IdentityReference='EXAMPLE\Missing';ResolutionStatus='NotFound';ObjectClass=$null;Enabled=$null;RecursiveMembers=@()}
)

$Candidates | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $CandidatesPath -Encoding UTF8
$Identities | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $IdentitiesPath -Encoding UTF8

$AnalysisRoot = Join-Path $OutputRoot 'Analysis'
$Output = @(
    & $ClassifierPath `
        -CandidateFactsPath $CandidatesPath `
        -IdentityPrerequisitePath $IdentitiesPath `
        -OutputDirectory $AnalysisRoot `
        -ConsoleModulePath $ConsoleModulePath `
        -Quiet
)

$Terminal = @(
    $Output |
        Where-Object {
            $null -ne $_.PSObject.Properties['classifierVersion'] -and
            [string]$_.status -eq 'Completed'
        }
) | Select-Object -Last 1

if ($null -eq $Terminal) {
    throw 'ClassifierTerminalResultMissing'
}

$ContextPath = Join-Path $AnalysisRoot 'ad-identity-context.json'
$SummaryPath = Join-Path $AnalysisRoot 'ad-identity-context-summary.json'
$Rows = @(Get-Content -LiteralPath $ContextPath -Raw | ConvertFrom-Json)
$Summary = Get-Content -LiteralPath $SummaryPath -Raw | ConvertFrom-Json

function Get-Classification {
    param([string]$Identity)
    return @(
        $Rows |
            Where-Object { [string]$_.identityReference -eq $Identity } |
            Select-Object -First 1
    )
}

$DomainAdmins = @(Get-Classification 'EXAMPLE\Domain Admins')[0]
$AuthenticatedUsers = @(Get-Classification 'NT AUTHORITY\Authenticated Users')[0]
$DomainComputers = @(Get-Classification 'EXAMPLE\Domain Computers')[0]
$EmptyGroup = @(Get-Classification 'EXAMPLE\EmptyGroup')[0]
$SecurityGroup = @(Get-Classification 'EXAMPLE\sec-Scep-Servers')[0]
$ServiceIdentity = @(Get-Classification 'EXAMPLE\Svc-App')[0]
$ComputerIdentity = @(Get-Classification 'EXAMPLE\SERVER01$')[0]
$MissingIdentity = @(Get-Classification 'EXAMPLE\Missing')[0]

$ProhibitedProperties = @(
    'attackerControlsIdentity',
    'credentialAvailable',
    'isExploitable',
    'vulnerable',
    'severity'
)
$RowsWithProhibitedProperties = @(
    $Rows |
        Where-Object {
            $PropertyNames = @($_.PSObject.Properties.Name)
            @($ProhibitedProperties | Where-Object { $_ -in $PropertyNames }).Count -gt 0
        }
)
$AllowedCategories = @(
    'PrivilegedAdministrative','TierZeroIndicator','BroadLowPrivilege','BroadComputerIdentity',
    'BuiltInIdentity','ServiceIdentity','ComputerIdentity','SecurityGroup','StandardUser',
    'EmptyGroup','UnresolvedIdentity','UnknownPrivilegeContext'
)

$Checks = @(
    [pscustomobject]@{Test='ClassifierParsed';Passed=($ParseErrors.Count -eq 0)},
    [pscustomobject]@{Test='TerminalCompleted';Passed=([string]$Terminal.status -eq 'Completed')},
    [pscustomobject]@{Test='EightIdentitiesClassified';Passed=($Rows.Count -eq 8)},
    [pscustomobject]@{Test='DomainAdminsPrivileged';Passed=([string]$DomainAdmins.category -eq 'PrivilegedAdministrative')},
    [pscustomobject]@{Test='AuthenticatedUsersBroad';Passed=([string]$AuthenticatedUsers.category -eq 'BroadLowPrivilege')},
    [pscustomobject]@{Test='DomainComputersBroad';Passed=([string]$DomainComputers.category -eq 'BroadComputerIdentity')},
    [pscustomobject]@{Test='EmptyGroupDetected';Passed=([string]$EmptyGroup.category -eq 'EmptyGroup')},
    [pscustomobject]@{Test='SecurityGroupDetected';Passed=([string]$SecurityGroup.category -eq 'SecurityGroup')},
    [pscustomobject]@{Test='ServiceIdentityDetected';Passed=([string]$ServiceIdentity.category -eq 'ServiceIdentity')},
    [pscustomobject]@{Test='ComputerIdentityDetected';Passed=([string]$ComputerIdentity.category -eq 'ComputerIdentity')},
    [pscustomobject]@{Test='NotFoundUnresolved';Passed=([string]$MissingIdentity.category -eq 'UnresolvedIdentity')},
    [pscustomobject]@{Test='PrivilegedModifierNegative';Passed=([int]$DomainAdmins.validationPriorityModifier -lt 0)},
    [pscustomobject]@{Test='BroadModifierPositive';Passed=([int]$AuthenticatedUsers.validationPriorityModifier -gt 0)},
    [pscustomobject]@{Test='AllowedCategoriesOnly';Passed=(@($Rows | Where-Object { [string]$_.category -notin $AllowedCategories }).Count -eq 0)},
    [pscustomobject]@{Test='NoProhibitedControlProperties';Passed=($RowsWithProhibitedProperties.Count -eq 0)},
    [pscustomobject]@{Test='SummaryCountsMatch';Passed=([int]$Summary.uniqueIdentityCount -eq $Rows.Count)}
)

$Checks | Format-Table -AutoSize
$Failed = @($Checks | Where-Object { -not $_.Passed })
if ($Failed.Count -gt 0) {
    $Failed | Format-List Test,Passed
    throw "$($Failed.Count) identity-context classifier test(s) failed."
}

[pscustomobject][ordered]@{
    Status = 'Passed'
    TestCount = $Checks.Count
    ClassifierVersion = '0.1.0'
    TestVersion = '1.0.1'
    IdentityCount = $Rows.Count
    OutputRoot = $AnalysisRoot
}
