[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Path = Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlSchemaClassMap-v1.0.0.ps1'
if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "SchemaCollectorMissing: $Path" }
$Tokens = $null
$Errors = $null
[void][Management.Automation.Language.Parser]::ParseFile($Path, [ref]$Tokens, [ref]$Errors)
if (@($Errors).Count -gt 0) { throw "ParserFailure: $(@($Errors | ForEach-Object { $_.Message }) -join '; ')" }
$Text = [IO.File]::ReadAllText($Path)
foreach ($Marker in @('classSchema','schemaIDGUID','lDAPDisplayName','directory-control-schema-class-map.csv','ReadOnlyADQueries')) {
    if (-not $Text.Contains($Marker)) { throw "ContractMissing: $Marker" }
}
[pscustomobject]@{
    Status = 'Passed'
    TestVersion = '1.0.0'
    ParserErrors = 0
    SchemaGuidContract = $true
    NetworkActivity = 'None'
    RemoteChanges = 'None'
}
