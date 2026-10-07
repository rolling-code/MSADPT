[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Paths = @(
    (Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlEffectiveAccessPipeline-v1.0.3.ps1')
    (Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlSchemaClassMap-v1.0.1.ps1')
    (Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlTokenEvidence-v1.0.1.ps1')
    (Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlEffectiveAccess-v1.0.2.ps1')
)

$Patterns = @(
    'Write-Host\$'
    'Write-Output\$'
    'ForegroundColor\$'
    'LiteralPath\$'
    'Get-Content\$'
    'Test-Path\$'
    'Import-Csv\$'
    'Get-FileHash\$'
)

$Defects = New-Object 'System.Collections.Generic.List[object]'
foreach ($Path in $Paths) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "RequiredFileMissing: $Path"
    }

    $Tokens = $null
    $Errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$Tokens, [ref]$Errors)
    if (@($Errors).Count -gt 0) {
        throw "ParserFailure[$Path]: $(@($Errors | ForEach-Object { $_.Message }) -join '; ')"
    }

    foreach ($Pattern in $Patterns) {
        foreach ($Match in @(Select-String -LiteralPath $Path -Pattern $Pattern)) {
            $Defects.Add([pscustomobject]@{
                Path = $Path
                LineNumber = $Match.LineNumber
                Pattern = $Pattern
                Line = $Match.Line
            })
        }
    }
}

if ($Defects.Count -gt 0) {
    $Defects | Format-Table -AutoSize | Out-String | Write-Host
    throw "RuntimeSpacingDefectsDetected: $($Defects.Count)"
}

[pscustomobject]@{
    Status = 'Passed'
    TestVersion = '1.0.0'
    ParsedFileCount = $Paths.Count
    ParserErrorCount = 0
    RuntimeSpacingDefectCount = 0
    NetworkActivity = 'None'
    RemoteChanges = 'None'
}
