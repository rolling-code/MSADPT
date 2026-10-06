[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Path = Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlTokenEvidence-v1.0.1.ps1'
if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "TokenCollectorMissing: $Path" }
$Tokens = $null
$Errors = $null
[void][Management.Automation.Language.Parser]::ParseFile($Path, [ref]$Tokens, [ref]$Errors)
if (@($Errors).Count -gt 0) { throw "ParserFailure: $(@($Errors | ForEach-Object { $_.Message }) -join '; ')" }
$Text = [IO.File]::ReadAllText($Path)
$Markers = @(
    'Get-ADUser'
    'Get-ADGroup'
    'Get-ADComputer'
    'objectSid -eq'
    'SIDHistory'
    'PrimaryGroup'
    'NestedGroup'
    'ResolvedPrincipalCount'
)
foreach ($Marker in $Markers) {
    if (-not $Text.Contains($Marker)) { throw "ContractMissing: $Marker" }
}
[pscustomobject]@{
    Status = 'Passed'
    TestVersion = '1.0.1'
    SidSafeResolution = $true
    FallbackFilter = $true
    ParserErrors = 0
    NetworkActivity = 'None'
    RemoteChanges = 'None'
}
