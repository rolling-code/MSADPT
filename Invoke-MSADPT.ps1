[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Plan','Audit','Analyze','Resume')]
    [string]$Mode,
    [string]$EngagementDirectory,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$RegistryPath = Join-Path $Root 'Catalogs\module-registry.json'
$CoveragePath = Join-Path $Root 'Catalogs\attack-surface-coverage.json'
$Registry = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json -ErrorAction Stop
$Coverage = Get-Content -LiteralPath $CoveragePath -Raw | ConvertFrom-Json -ErrorAction Stop

function Show {
    param([string]$State,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray)
    $Text = '[{0,-12}] {1}' -f $State,$Message
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}

$Integrated = @($Registry.Modules | Where-Object { $_.OrchestrationState -eq 'Integrated' })
$Standalone = @($Registry.Modules | Where-Object { $_.OrchestrationState -eq 'AvailableStandalone' })
Show -State 'START' -Message "MSADPT public orchestrator mode=$Mode" -Color Cyan
Show -State 'SAFETY' -Message 'Automatic execution is limited to modules explicitly marked Integrated.' -Color Yellow

if ($Mode -eq 'Plan') {
    Show -State 'PLAN' -Message "Registered=$($Registry.ModuleCount); integrated=$($Integrated.Count); standalone=$($Standalone.Count); attack-families=$(@($Coverage.Families).Count)." -Color Green
    $Registry.Modules | Sort-Object Category,ModuleId | Select-Object ModuleId,Version,Category,ComponentType,OrchestrationState,SafetyClass,EntryPoint
    return
}

if ([string]::IsNullOrWhiteSpace($EngagementDirectory)) {
    $EngagementDirectory = Join-Path $Root ('Engagements\MSADPT-Assessment-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

New-Item -ItemType Directory -Path $EngagementDirectory -Force | Out-Null
foreach ($Name in @('evidence','analysis','reports','state')) {
    New-Item -ItemType Directory -Path (Join-Path $EngagementDirectory $Name) -Force | Out-Null
}

$Ledger = [pscustomobject]@{
    SchemaVersion = '1.0'
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    Mode = $Mode
    AttackFamilies = @($Coverage.Families | ForEach-Object { [pscustomobject]@{Id=$_.Id;Name=$_.Name;State='NotStarted';Evidence=@();Limitations=@()} })
    Modules = @($Registry.Modules | ForEach-Object { [pscustomobject]@{ModuleId=$_.ModuleId;Version=$_.Version;State=if($_.OrchestrationState -eq 'Integrated'){'Planned'}else{'NotStarted'};EntryPoint=$_.EntryPoint} })
}
$LedgerPath = Join-Path $EngagementDirectory 'state\coverage-ledger.json'
$Ledger | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $LedgerPath -Encoding UTF8

$ExecutionPlan = [pscustomobject]@{
    SchemaVersion = '1.0'
    Mode = $Mode
    AutomaticExecutionPolicy = 'IntegratedOnly'
    IntegratedModules = $Integrated
    NetworkOperations = @()
    DirectoryChanges = @('Create local engagement directories and state files only')
}
$PlanPath = Join-Path $EngagementDirectory 'state\execution-plan.json'
$ExecutionPlan | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $PlanPath -Encoding UTF8
Show -State 'NETWORK' -Message 'No live module was automatically executed by this initial public orchestrator.' -Color DarkCyan
Show -State 'DONE' -Message "Engagement initialized: $EngagementDirectory" -Color Green

[pscustomobject]@{
    Status = 'Passed'
    Mode = $Mode
    EngagementDirectory = $EngagementDirectory
    RegistryModuleCount = $Registry.ModuleCount
    IntegratedModuleCount = $Integrated.Count
    StandaloneModuleCount = $Standalone.Count
    CoverageLedgerPath = $LedgerPath
    ExecutionPlanPath = $PlanPath
    LiveModulesExecuted = 0
}