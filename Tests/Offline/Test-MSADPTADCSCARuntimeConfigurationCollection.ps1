<#
.SYNOPSIS
Runs offline structural and safety tests for ADCSCARuntimeConfigurationCollection v0.1.1.
.NOTES
Version: 1.0.2
This test parses the staged collector and disabled manifest. It does not execute the collector,
contact Active Directory, query a certification authority, probe TCP ports, or invoke certutil.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ModulePath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DisabledManifestPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

foreach ($Path in @($ModulePath, $DisabledManifestPath)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file not found: $Path"
    }
}

$Tokens = $null
$Errors = $null
$Ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $ModulePath,
    [ref]$Tokens,
    [ref]$Errors
)

if ($Errors.Count -gt 0) {
    throw "Module parse failed: $($Errors.Message -join '; ')"
}

$Manifest = Get-Content -LiteralPath $DisabledManifestPath -Raw | ConvertFrom-Json
$Source = Get-Content -LiteralPath $ModulePath -Raw

$Commands = @(
    $Ast.FindAll(
        {
            param($Node)
            $Node -is [System.Management.Automation.Language.CommandAst]
        },
        $true
    ) |
        ForEach-Object {
            $_.GetCommandName()
        }
)

$Functions = @(
    $Ast.FindAll(
        {
            param($Node)
            $Node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        },
        $true
    ).Name
)

# Build the source token without expanding a test-scope $CaConfiguration variable.
# The StartInfo regexes are single-quoted for the same StrictMode-safe reason.
$ExplicitCaConfigurationPattern = [regex]::Escape("'-config', " + '$CaConfiguration')
$StartInfoArgumentsPattern = '\$StartInfo\.Arguments'
$StartInfoArgumentListPattern = '\$StartInfo\.ArgumentList'

$Checks = [ordered]@{
    ModuleVersion = (
        [string]$Manifest.moduleVersion -eq '0.1.1'
    )
    ManifestVersion = (
        [string]$Manifest.manifestVersion -eq '1.0.1'
    )
    ManifestIsDisabled = (
        $DisabledManifestPath -like '*.module.json.disabled'
    )
    ReadOnly = (
        [string]$Manifest.executionClass -eq 'read_only'
    )
    RequiresPublication = (
        @($Manifest.requires) -contains 'enterpriseCaPublication'
    )
    HasBoundedTcpProbe = (
        $Functions -contains 'Test-MSADPTTcpPort'
    )
    HasBoundedProcessRunner = (
        $Functions -contains 'Invoke-MSADPTReadOnlyProcess'
    )
    UsesPowerShell51CompatibleArguments = (
        $Source -match $StartInfoArgumentsPattern -and
        $Source -notmatch $StartInfoArgumentListPattern
    )
    HasExplicitCaConfiguration = (
        $Source -match $ExplicitCaConfigurationPattern
    )
    UsesReadOnlyCertutilQueries = (
        $Source -match "'-getreg'"
    )
    NoCertRequestSubmission = (
        $Source -notmatch '(?i)-submit|-request|-enroll'
    )
    NoInvokeCommand = (
        $Commands -notcontains 'Invoke-Command'
    )
    NoRegistryWrites = (
        @(
            $Commands |
                Where-Object {
                    $_ -match '^(Set|New|Remove)-ItemProperty$'
                }
        ).Count -eq 0
    )
    NoADWrites = (
        @(
            $Commands |
                Where-Object {
                    $_ -match '^(Set|Add|Remove|New|Move|Rename)-AD'
                }
        ).Count -eq 0
    )
    NoServiceChanges = (
        @(
            $Commands |
                Where-Object {
                    $_ -match '^(Start|Stop|Restart|Set)-Service$'
                }
        ).Count -eq 0
    )
    BlocksEnrollment = (
        @($Manifest.doesNotPerform) -contains 'certificateEnrollment'
    )
    BlocksStateChange = (
        @($Manifest.doesNotPerform) -contains 'stateChange'
    )
    BoundedJsonDepth = (
        $Source -match 'ConvertTo-Json -Depth 12'
    )
}

$Results = foreach ($Check in $Checks.GetEnumerator()) {
    [pscustomobject]@{
        Test = $Check.Key
        Passed = [bool]$Check.Value
    }
}

$Results | Format-Table -AutoSize

$Failed = @(
    $Results |
        Where-Object {
            -not $_.Passed
        }
)

if ($Failed.Count -gt 0) {
    throw "$($Failed.Count) offline CA-runtime test(s) failed."
}

[pscustomobject]@{
    Status = 'Passed'
    TestCount = $Results.Count
    TestVersion = '1.0.2'
    ModuleVersion = [string]$Manifest.moduleVersion
    ManifestVersion = [string]$Manifest.manifestVersion
    ManifestEnabled = $false
    ModulePath = $ModulePath
    DisabledManifestPath = $DisabledManifestPath
}
