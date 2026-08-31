Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-MSADPTJsonEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object]$Value,
        [int]$Depth = 30
    )

    $Parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($Parent)) {
        New-Item -ItemType Directory -Path $Parent -Force | Out-Null
    }

    if ($Value -is [System.Array] -and @($Value).Count -eq 0) {
        [IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))
    }
    else {
        $Value | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    }

    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}

function New-MSADPTEvidenceManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
        [Parameter(Mandatory=$true)][string]$ModuleId,
        [Parameter(Mandatory=$true)][string]$ModuleVersion,
        [string]$Status = 'Completed'
    )

    $ManifestPath = Join-Path $EvidenceDirectory 'evidence-manifest.json'
    $Files = @(
        Get-ChildItem -LiteralPath $EvidenceDirectory -File |
            Where-Object { $_.Name -ne 'evidence-manifest.json' } |
            Sort-Object Name |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = $_.Name
                    Size = [int64]$_.Length
                    SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                }
            }
    )

    $Manifest = [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        Status = $Status
        ModuleId = $ModuleId
        ModuleVersion = $ModuleVersion
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
        FileCount = $Files.Count
        Files = $Files
    }
    Write-MSADPTJsonEvidence -Path $ManifestPath -Value $Manifest
    return $ManifestPath
}

function Test-MSADPTEvidenceManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ManifestPath)

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { return $false }
    try {
        $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
        $Base = Split-Path -Parent $ManifestPath
        foreach ($File in @($Manifest.Files)) {
            $Path = Join-Path $Base ([string]$File.Name)
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
            if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne [string]$File.SHA256) { return $false }
        }
        return $true
    }
    catch { return $false }
}


function Move-MSADPTExistingOutputToArchive {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $Parent = Split-Path -Parent $Path
    $Leaf = Split-Path -Leaf $Path
    $ArchivePath = Join-Path $Parent ($Leaf + '.archive-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Move-Item -LiteralPath $Path -Destination $ArchivePath -Force
    return $ArchivePath
}

Export-ModuleMember -Function Write-MSADPTJsonEvidence,New-MSADPTEvidenceManifest,Test-MSADPTEvidenceManifest,Move-MSADPTExistingOutputToArchive