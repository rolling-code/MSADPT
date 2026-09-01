<#
.SYNOPSIS
Runs the complete offline MSADPT ADCS evidence-to-candidate pipeline.
.DESCRIPTION
Invokes the ADCS fact builder, validates its terminal result, invokes the ESC1 through ESC16
prerequisite correlator, and exports a compact pipeline summary. This script reads only previously
collected evidence and performs no Active Directory, CA, network, registry, certificate, or
authentication operation.
.NOTES
Version: 0.1.1
Execution class: offline_analysis
Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$FactBuilderPath,
    [Parameter(Mandatory = $true)][string]$CorrelationEnginePath,
    [Parameter(Mandatory = $true)][string]$CatalogPath,
    [Parameter(Mandatory = $true)][string]$TemplateConfigurationPath,
    [Parameter(Mandatory = $true)][string]$TemplateAccessPath,
    [Parameter()][string]$IdentityPrerequisitePath,
    [Parameter()][string]$CaRuntimeObservationPath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter()][string]$ConsoleModulePath,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$EvidenceHelperPath = Join-Path $RepositoryRoot 'Common\MSADPT.Evidence.psm1'
Import-Module $EvidenceHelperPath -Force -ErrorAction Stop
$PipelineVersion = '0.1.1'

foreach ($Path in @(
    $FactBuilderPath,
    $CorrelationEnginePath,
    $CatalogPath,
    $TemplateConfigurationPath,
    $TemplateAccessPath
)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file not found: $Path"
    }
}

if (-not [string]::IsNullOrWhiteSpace($ConsoleModulePath)) {
    Import-Module $ConsoleModulePath -Force -ErrorAction Stop
}

function Write-PipelineEvent {
    param(
        [ValidateSet('Info','Action','Success','Warning','Error','Muted')][string]$Kind,
        [string]$Message,
        [string]$Target,
        [string]$Code,
        [hashtable]$Data
    )

    if (Get-Command Write-MSADPTConsoleEvent -ErrorAction SilentlyContinue) {
        return Write-MSADPTConsoleEvent -Kind $Kind -Message $Message -Target $Target -Code $Code -Data $Data
    }

    $Event = [pscustomobject][ordered]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        Kind = $Kind
        Code = $Code
        Message = $Message
        Target = $Target
        Data = if ($null -ne $Data) { [pscustomobject]$Data } else { $null }
    }

    if (-not $Quiet) {
        $Color = switch ($Kind) {
            'Info' { 'Cyan' }
            'Action' { 'Yellow' }
            'Success' { 'Green' }
            'Warning' { 'DarkYellow' }
            'Error' { 'Red' }
            default { 'DarkGray' }
        }
        $Text = if ([string]::IsNullOrWhiteSpace($Target)) {
            '[{0}] {1}' -f $Kind.ToUpperInvariant(),$Message
        }
        else {
            '[{0}] {1}: {2}' -f $Kind.ToUpperInvariant(),$Target,$Message
        }
        Write-Host $Text -ForegroundColor $Color
    }

    Write-Output $Event
}

$ArchivedOutputPath = Move-MSADPTExistingOutputToArchive -Path $OutputRoot
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

$FactOutputDirectory = Join-Path $OutputRoot 'Facts'
$CorrelationOutputDirectory = Join-Path $OutputRoot 'Correlation'
$FactsPath = Join-Path $FactOutputDirectory 'adcs-facts.json'
$PipelineSummaryPath = Join-Path $OutputRoot 'adcs-offline-pipeline-summary.json'
$PipelineCsvPath = Join-Path $OutputRoot 'adcs-offline-technique-summary.csv'
$EventPath = Join-Path $OutputRoot 'adcs-offline-pipeline-events.json'

$Events = New-Object 'System.Collections.Generic.List[object]'
$Events.Add((Write-PipelineEvent -Kind Info -Code 'PipelineStarted' -Message 'Starting the offline ADCS evidence-to-candidate pipeline.' -Target 'MSADPT ADCS' -Data @{PipelineVersion=$PipelineVersion}))

$FactBuilderArguments = @{
    TemplateConfigurationPath = $TemplateConfigurationPath
    TemplateAccessPath = $TemplateAccessPath
    OutputPath = $FactsPath
    Quiet = [bool]$Quiet
    NoColor = [bool]$NoColor
}
if (-not [string]::IsNullOrWhiteSpace($IdentityPrerequisitePath)) {
    $FactBuilderArguments.IdentityPrerequisitePath = $IdentityPrerequisitePath
}
if (-not [string]::IsNullOrWhiteSpace($CaRuntimeObservationPath)) {
    $FactBuilderArguments.CaRuntimeObservationPath = $CaRuntimeObservationPath
}
if (-not [string]::IsNullOrWhiteSpace($ConsoleModulePath)) {
    $FactBuilderArguments.ConsoleModulePath = $ConsoleModulePath
}

$Events.Add((Write-PipelineEvent -Kind Action -Code 'BuildFacts' -Message 'Converting preserved ADCS evidence into neutral prerequisite facts.' -Target 'Fact builder' -Data $null))
$FactBuilderOutput = @(& $FactBuilderPath @FactBuilderArguments)
$FactBuilderResult = @(
    $FactBuilderOutput |
        Where-Object {
            $null -ne $_ -and
            $null -ne $_.PSObject.Properties['BuilderVersion'] -and
            [string]$_.Status -eq 'Completed'
        }
) | Select-Object -Last 1

if ($null -eq $FactBuilderResult) {
    $Events.Add((Write-PipelineEvent -Kind Error -Code 'FactBuilderTerminalResultMissing' -Message 'The fact builder did not return a completed terminal result.' -Target 'Fact builder' -Data $null))
    throw 'FactBuilderTerminalResultMissing: The fact builder did not return a completed terminal result.'
}

$FactsDocument = Get-Content -LiteralPath $FactsPath -Raw | ConvertFrom-Json -ErrorAction Stop
$Facts = @($FactsDocument.facts)
$Events.Add((Write-PipelineEvent -Kind Success -Code 'FactsBuilt' -Message ("Generated {0} neutral prerequisite facts." -f $Facts.Count) -Target 'Fact builder' -Data @{FactCount=$Facts.Count;BuilderVersion=$FactBuilderResult.BuilderVersion}))

$Events.Add((Write-PipelineEvent -Kind Action -Code 'CorrelateTechniques' -Message 'Evaluating ESC1 through ESC16 prerequisite states.' -Target 'Correlation engine' -Data $null))
$CorrelationOutput = @(
    & $CorrelationEnginePath `
        -CatalogPath $CatalogPath `
        -FactsPath $FactsPath `
        -OutputDirectory $CorrelationOutputDirectory
)
$CorrelationResult = @(
    $CorrelationOutput |
        Where-Object {
            $null -ne $_ -and
            $null -ne $_.PSObject.Properties['engineVersion'] -and
            [string]$_.status -eq 'Completed'
        }
) | Select-Object -Last 1

if ($null -eq $CorrelationResult) {
    $Events.Add((Write-PipelineEvent -Kind Error -Code 'CorrelationTerminalResultMissing' -Message 'The correlation engine did not return a completed terminal result.' -Target 'Correlation engine' -Data $null))
    throw 'CorrelationTerminalResultMissing: The correlation engine did not return a completed terminal result.'
}

$CandidatePath = Join-Path $CorrelationOutputDirectory 'adcs-technique-candidates.json'
$Candidates = @(Get-Content -LiteralPath $CandidatePath -Raw | ConvertFrom-Json -ErrorAction Stop)
foreach ($Candidate in $Candidates) {
    $Kind = switch ([string]$Candidate.Disposition) {
        'Prerequisites satisfied' { 'Warning' }
        'Blocked' { 'Success' }
        'Incomplete evidence' { 'Muted' }
        'Not applicable' { 'Info' }
        default { 'Warning' }
    }
    $Message = '{0}; {1}/{2} required prerequisite(s) satisfied.' -f $Candidate.Disposition,$Candidate.SatisfiedRequiredCount,$Candidate.RequiredCount
    $Events.Add((Write-PipelineEvent -Kind $Kind -Code 'TechniqueDisposition' -Message $Message -Target ([string]$Candidate.Technique) -Data @{Category=$Candidate.Category;RuntimeDependent=$Candidate.RuntimeDependent}))
}

$Summary = [pscustomobject][ordered]@{
    schemaVersion = '1.0'
    pipeline = 'ADCSOfflineEvidenceToCandidate'
    pipelineVersion = $PipelineVersion
    status = 'Completed'
    executionClass = 'offline_analysis'
    builderVersion = [string]$FactBuilderResult.BuilderVersion
    engineVersion = [string]$CorrelationResult.engineVersion
    catalogVersion = [string]$FactsDocument.schemaVersion
    factCount = $Facts.Count
    techniqueCount = $Candidates.Count
    prerequisitesSatisfiedCount = @($Candidates | Where-Object Disposition -eq 'Prerequisites satisfied').Count
    blockedCount = @($Candidates | Where-Object Disposition -eq 'Blocked').Count
    incompleteEvidenceCount = @($Candidates | Where-Object Disposition -eq 'Incomplete evidence').Count
    notApplicableCount = @($Candidates | Where-Object Disposition -eq 'Not applicable').Count
    runtimeEvidenceProvided = (-not [string]::IsNullOrWhiteSpace($CaRuntimeObservationPath) -and (Test-Path -LiteralPath $CaRuntimeObservationPath -PathType Leaf))
    factsPath = $FactsPath
    candidatesPath = $CandidatePath
    techniqueSummaryPath = $PipelineCsvPath
    eventPath = $EventPath
    limitations = @(
        'This pipeline produces prerequisite candidates, not vulnerability or exploitability declarations.',
        'Aggregate facts do not replace per-template, per-principal, patch-state, or effective-permission analysis.',
        'Runtime-dependent techniques remain incomplete when CA-runtime observations are unavailable.'
    )
    completedUtc = (Get-Date).ToUniversalTime().ToString('o')
}

$Candidates |
    Select-Object Technique,Title,Category,RuntimeDependent,Disposition,RequiredCount,SatisfiedRequiredCount,
        @{Name='MissingOrInconclusiveRequiredCount';Expression={@($_.MissingOrInconclusiveRequired).Count}},
        @{Name='NotObservedRequiredCount';Expression={@($_.NotObservedRequired).Count}},
        @{Name='ConfirmedBlockingEvidenceCount';Expression={@($_.ConfirmedBlockingEvidence).Count}},
        SafeFollowUp |
    Export-Csv -LiteralPath $PipelineCsvPath -NoTypeInformation -Encoding UTF8

$Events.Add((Write-PipelineEvent -Kind Success -Code 'PipelineCompleted' -Message ("Completed with {0} fact(s) and {1} technique disposition(s)." -f $Facts.Count,$Candidates.Count) -Target 'MSADPT ADCS' -Data @{SummaryPath=$PipelineSummaryPath}))
Write-MSADPTJsonEvidence -Path $PipelineSummaryPath -Value $Summary -Depth 8
Write-MSADPTJsonEvidence -Path $EventPath -Value ([object[]]$Events.ToArray()) -Depth 8
$ManifestPath = New-MSADPTEvidenceManifest -EvidenceDirectory $OutputRoot -ModuleId 'ADCSOfflineEvidenceToCandidate' -ModuleVersion $PipelineVersion

Write-Output $Summary
