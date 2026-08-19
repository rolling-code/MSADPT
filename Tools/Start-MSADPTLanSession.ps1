<#
.SYNOPSIS
Starts or resumes a controlled MSADPT LAN assessment session.
.DESCRIPTION
Provides a reusable, environment-agnostic session state machine for Active Directory assessments.
The default action is offline preflight. Network-capable stages require explicit switches and never
implicitly invoke a later stage. Deterministic evidence remains authoritative; Ollama is advisory only.

The launcher does not hard-code a forest, domain, CA, collector, engagement, or Ollama model.
.NOTES
Version: 0.1.1
Execution class: controlled_session_orchestration
PowerShell: Windows PowerShell 5.1 and PowerShell 7
#>
[CmdletBinding(DefaultParameterSetName='Preflight')]
param(
    [string]$MSADPTRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT',
    [string]$EngagementRoot,
    [string]$SessionRoot,

    [Parameter(ParameterSetName='Preflight')]
    [switch]$PreflightOnly,

    [Parameter(Mandatory=$true,ParameterSetName='ValidateLan')]
    [switch]$ValidateLanContext,

    [Parameter(Mandatory=$true,ParameterSetName='DryRun')]
    [switch]$RunCollectorDryRun,

    [Parameter(Mandatory=$true,ParameterSetName='DryRun')]
    [Parameter(Mandatory=$true,ParameterSetName='ApprovedRun')]
    [string]$CollectorScriptPath,

    [Parameter(ParameterSetName='DryRun')]
    [Parameter(ParameterSetName='ApprovedRun')]
    [hashtable]$CollectorParameters,

    [Parameter(Mandatory=$true,ParameterSetName='ApprovedRun')]
    [switch]$RunApprovedCollector,

    [Parameter(Mandatory=$true,ParameterSetName='ApprovedRun')]
    [string]$ApprovalToken,

    [Parameter(Mandatory=$true,ParameterSetName='Rebuild')]
    [switch]$RebuildOfflineAnalysis,

    [Parameter(Mandatory=$true,ParameterSetName='Rebuild')]
    [string]$AnalysisScriptPath,

    [Parameter(ParameterSetName='Rebuild')]
    [hashtable]$AnalysisParameters,

    [Parameter(Mandatory=$true,ParameterSetName='Ollama')]
    [switch]$ValidateOllamaReadiness,

    [Parameter(ParameterSetName='Ollama')]
    [uri]$OllamaEndpoint = 'http://127.0.0.1:11434',

    [Parameter(ParameterSetName='Ollama')]
    [string]$OllamaModel,

    [switch]$Resume,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$LauncherVersion = '0.1.1'
$PackageIdentity = 'MSADPT-LAN-SESSION-LAUNCHER'

if ([string]::IsNullOrWhiteSpace($SessionRoot)) {
    $SessionRoot = Join-Path $MSADPTRoot 'Sessions\Current'
}
$StatePath = Join-Path $SessionRoot 'session-state.json'
$EventPath = Join-Path $SessionRoot 'session-events.jsonl'
$PreflightPath = Join-Path $SessionRoot 'preflight-report.json'
$LanContextPath = Join-Path $SessionRoot 'lan-context.json'
$OllamaPath = Join-Path $SessionRoot 'ollama-readiness.json'
$LockPath = Join-Path $SessionRoot '.session.lock'
$CompletedStages = New-Object 'Collections.Generic.List[string]'

function Write-SessionEvent {
    param(
        [ValidateSet('START','INFO','CHECK','OK','WARNING','FAIL','DONE')][string]$Status,
        [string]$Message,
        [string]$Stage
    )
    $Color = switch ($Status) {
        'OK' { 'Green' }
        'DONE' { 'Green' }
        'WARNING' { 'DarkYellow' }
        'FAIL' { 'Red' }
        'START' { 'Cyan' }
        default { 'Yellow' }
    }
    if (-not $Quiet) {
        Write-Host ('[{0,-7}] {1}' -f $Status,$Message) -ForegroundColor $Color
    }
    $Event = [pscustomobject][ordered]@{
        timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        stage = $Stage
        status = $Status
        message = $Message
    }
    $Event | ConvertTo-Json -Compress | Add-Content -LiteralPath $EventPath -Encoding UTF8
}

function Save-SessionState {
    param([string]$CurrentStage,[string]$Status,[object]$Details)
    $State = [pscustomobject][ordered]@{
        schemaVersion = '1.0'
        packageIdentity = $PackageIdentity
        launcherVersion = $LauncherVersion
        updatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        machine = $env:COMPUTERNAME
        user = $env:USERNAME
        msadptRoot = $MSADPTRoot
        engagementRoot = $EngagementRoot
        sessionRoot = $SessionRoot
        currentStage = $CurrentStage
        status = $Status
        completedStages = @($CompletedStages | ForEach-Object { $_ })
        details = $Details
    }
    $State | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $StatePath -Encoding UTF8
}

function Add-CompletedStage {
    param([string]$Stage)
    if (-not $CompletedStages.Contains($Stage)) {
        $CompletedStages.Add($Stage)
    }
}

function Get-ScriptMetadata {
    param([string]$Path)
    $Tokens = $null
    $ParseErrors = $null
    $Ast = [Management.Automation.Language.Parser]::ParseFile($Path,[ref]$Tokens,[ref]$ParseErrors)
    $CommandInfo = Get-Command -Name $Path -ErrorAction Stop
    [pscustomobject][ordered]@{
        path = $Path
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
        parseErrorCount = $ParseErrors.Count
        supportsShouldProcess = ('WhatIf' -in @($CommandInfo.Parameters.Keys))
        parameterNames = @($CommandInfo.Parameters.Keys | Sort-Object)
        astExtentLength = $Ast.Extent.Text.Length
    }
}

function Invoke-ScriptWithParameters {
    param([string]$Path,[hashtable]$Parameters,[switch]$WhatIfMode)
    $InvokeParams = @{}
    if ($null -ne $Parameters) {
        foreach ($Key in $Parameters.Keys) { $InvokeParams[$Key] = $Parameters[$Key] }
    }
    if ($WhatIfMode) { $InvokeParams['WhatIf'] = $true }
    & $Path @InvokeParams
}

function Invoke-OfflinePreflight {
    $Stage = 'OfflinePreflight'
    Write-SessionEvent 'START' 'Running repository and workstation preflight.' $Stage
    $Checks = New-Object 'Collections.Generic.List[object]'
    function Add-PreflightCheck([string]$Id,[string]$Status,[string]$Message,[string]$Evidence) {
        $Checks.Add([pscustomobject]@{id=$Id;status=$Status;message=$Message;evidence=$Evidence})
        Write-SessionEvent $(if($Status -eq 'Passed'){'OK'}elseif($Status -eq 'Warning'){'WARNING'}else{'FAIL'}) $Message $Stage
    }

    if (Test-Path -LiteralPath $MSADPTRoot -PathType Container) {
        Add-PreflightCheck 'RepositoryRoot' 'Passed' 'MSADPT repository root found.' $MSADPTRoot
    }
    else {
        Add-PreflightCheck 'RepositoryRoot' 'Blocked' 'MSADPT repository root is missing.' $MSADPTRoot
    }

    $PowerShellInfo = "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
    Add-PreflightCheck 'PowerShell' 'Passed' "PowerShell runtime: $PowerShellInfo" $null

    $PathRoot = [IO.Path]::GetPathRoot($MSADPTRoot)
    $DriveName = if ([string]::IsNullOrWhiteSpace($PathRoot)) {
        $null
    }
    else {
        $PathRoot.TrimEnd([char[]]@([char]':',[char]92,[char]47))
    }
    $Drive = if ([string]::IsNullOrWhiteSpace($DriveName)) {
        $null
    }
    else {
        Get-PSDrive -Name $DriveName -ErrorAction SilentlyContinue
    }
    if ($null -ne $Drive) {
        $FreeGiB = [math]::Round($Drive.Free / 1GB,2)
        $DiskStatus = if ($Drive.Free -ge 1GB) { 'Passed' } else { 'Warning' }
        Add-PreflightCheck 'DiskSpace' $DiskStatus "Free disk space: $FreeGiB GiB" $Drive.Root
    }

    $ScriptFiles = @(
        Get-ChildItem -LiteralPath $MSADPTRoot -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\.backup-' }
    )
    $ParseFailures = @()
    foreach ($ScriptFile in $ScriptFiles) {
        $Tokens = $null
        $Errors = $null
        $null = [Management.Automation.Language.Parser]::ParseFile($ScriptFile.FullName,[ref]$Tokens,[ref]$Errors)
        if ($Errors.Count -gt 0) {
            $ParseFailures += ,[pscustomobject]@{path=$ScriptFile.FullName;errors=@($Errors.Message)}
        }
    }
    $ParseStatus = if ($ParseFailures.Count -eq 0) { 'Passed' } else { 'Blocked' }
    Add-PreflightCheck 'RepositoryParse' $ParseStatus "Parsed $($ScriptFiles.Count) PowerShell scripts; failures=$($ParseFailures.Count)." $null

    $BackupFiles = @(Get-ChildItem -LiteralPath $MSADPTRoot -Filter '*.backup-*' -File -Recurse -ErrorAction SilentlyContinue)
    Add-PreflightCheck 'BackupInventory' $(if($BackupFiles.Count -eq 0){'Passed'}else{'Warning'}) "Timestamped backup files: $($BackupFiles.Count)." $null

    $LockStatus = if (Test-Path -LiteralPath $LockPath -PathType Leaf) { 'Warning' } else { 'Passed' }
    Add-PreflightCheck 'SessionLock' $LockStatus $(if($LockStatus -eq 'Warning'){'Existing session lock detected.'}else{'No stale session lock detected.'}) $LockPath

    if (-not [string]::IsNullOrWhiteSpace($EngagementRoot)) {
        Add-PreflightCheck 'EngagementRoot' $(if(Test-Path -LiteralPath $EngagementRoot -PathType Container){'Passed'}else{'Blocked'}) 'Explicit engagement root evaluated.' $EngagementRoot
    }
    else {
        Add-PreflightCheck 'EngagementRoot' 'Warning' 'No explicit engagement root was supplied.' $null
    }

    $Blocked = @($Checks | Where-Object { $_.status -eq 'Blocked' }).Count
    $Report = [pscustomobject][ordered]@{
        schemaVersion='1.0';launcherVersion=$LauncherVersion;stage=$Stage
        status=if($Blocked -eq 0){'Passed'}else{'Blocked'}
        generatedUtc=(Get-Date).ToUniversalTime().ToString('o')
        powershell=$PowerShellInfo
        scriptCount=$ScriptFiles.Count
        parseFailureCount=$ParseFailures.Count
        parseFailures=@($ParseFailures)
        checks=@($Checks | ForEach-Object { $_ })
        networkActivity='None';collectorActivity='None';ledgerChanges='None';ollamaActivity='None'
    }
    $Report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $PreflightPath -Encoding UTF8
    if ($Blocked -gt 0) { throw "OfflinePreflightBlocked: $Blocked blocking check(s)." }
    Add-CompletedStage $Stage
    Save-SessionState $Stage 'Passed' $Report
    Write-SessionEvent 'DONE' 'Offline preflight passed.' $Stage
    return $Report
}

function Invoke-LanContextValidation {
    $Stage = 'LanContextValidation'
    Write-SessionEvent 'START' 'Validating neutral LAN and domain context.' $Stage
    $Context = [ordered]@{
        schemaVersion='1.0';launcherVersion=$LauncherVersion;generatedUtc=(Get-Date).ToUniversalTime().ToString('o')
        computerName=$env:COMPUTERNAME;userName=$env:USERNAME;userDomain=$env:USERDOMAIN
        logonServer=$env:LOGONSERVER;dnsDomain=$env:USERDNSDOMAIN
        powershellEdition=$PSVersionTable.PSEdition;powershellVersion=[string]$PSVersionTable.PSVersion
        activeDirectoryModuleAvailable=[bool](Get-Module -ListAvailable -Name ActiveDirectory | Select-Object -First 1)
        domainContextValidated=$false;forestContextValidated=$false;domainController=$null;globalCatalog=$null
        limitations=@()
    }
    try {
        $CurrentDomain = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $Context['domainDnsName'] = $CurrentDomain.Name
        $Context['domainMode'] = [string]$CurrentDomain.DomainMode
        $Context['domainController'] = $CurrentDomain.FindDomainController().Name
        $Context['domainContextValidated'] = $true
    }
    catch { $Context.limitations += "Domain context unavailable: $($_.Exception.Message)" }
    try {
        $CurrentForest = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $Context['forestName'] = $CurrentForest.Name
        $Context['forestMode'] = [string]$CurrentForest.ForestMode
        $Context['globalCatalog'] = $CurrentForest.FindGlobalCatalog().Name
        $Context['forestContextValidated'] = $true
    }
    catch { $Context.limitations += "Forest context unavailable: $($_.Exception.Message)" }
    $Status = if ($Context.domainContextValidated -and $Context.forestContextValidated) { 'Passed' } else { 'Inconclusive' }
    $Context['status'] = $Status
    ([pscustomobject]$Context) | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $LanContextPath -Encoding UTF8
    if ($Status -ne 'Passed') { throw 'LanContextInconclusive: Domain and forest context were not both validated.' }
    Add-CompletedStage $Stage
    Save-SessionState $Stage 'Passed' ([pscustomobject]$Context)
    Write-SessionEvent 'DONE' 'LAN and domain context validated.' $Stage
    return [pscustomobject]$Context
}

function Invoke-CollectorDryRun {
    $Stage = 'CollectorDryRun'
    Write-SessionEvent 'START' 'Validating collector and executing WhatIf dry run.' $Stage
    if (-not (Test-Path -LiteralPath $CollectorScriptPath -PathType Leaf)) { throw "CollectorMissing: $CollectorScriptPath" }
    $Metadata = Get-ScriptMetadata $CollectorScriptPath
    if ($Metadata.parseErrorCount -gt 0) { throw "CollectorParseFailure: $CollectorScriptPath" }
    if ('WhatIf' -notin $Metadata.parameterNames) { throw 'CollectorDryRunUnsupported: Collector does not expose WhatIf.' }
    $Output = @(Invoke-ScriptWithParameters -Path $CollectorScriptPath -Parameters $CollectorParameters -WhatIfMode)
    $Evidence = [pscustomobject]@{metadata=$Metadata;output=@($Output);collectorExecuted=$false;whatIf=$true}
    Add-CompletedStage $Stage
    Save-SessionState $Stage 'Passed' $Evidence
    Write-SessionEvent 'DONE' 'Collector dry run completed with WhatIf.' $Stage
    return $Evidence
}

function Invoke-ApprovedCollector {
    $Stage = 'ApprovedCollectorRun'
    if ($ApprovalToken -ne 'RUN-ONE-APPROVED-COLLECTOR') { throw 'InvalidApprovalToken' }
    if (-not $CompletedStages.Contains('CollectorDryRun')) { throw 'DryRunCheckpointMissing: Complete and review a dry run in this session first.' }
    Write-SessionEvent 'START' 'Executing one explicitly approved collector.' $Stage
    if (-not (Test-Path -LiteralPath $CollectorScriptPath -PathType Leaf)) { throw "CollectorMissing: $CollectorScriptPath" }
    $Metadata = Get-ScriptMetadata $CollectorScriptPath
    if ($Metadata.parseErrorCount -gt 0) { throw "CollectorParseFailure: $CollectorScriptPath" }
    $Output = @(Invoke-ScriptWithParameters -Path $CollectorScriptPath -Parameters $CollectorParameters)
    $Evidence = [pscustomobject]@{metadata=$Metadata;output=@($Output);collectorExecuted=$true;approvalTokenValidated=$true}
    Add-CompletedStage $Stage
    Save-SessionState $Stage 'Passed' $Evidence
    Write-SessionEvent 'DONE' 'Approved collector run completed once.' $Stage
    return $Evidence
}

function Invoke-AnalysisRebuild {
    $Stage = 'OfflineAnalysisRebuild'
    Write-SessionEvent 'START' 'Running explicitly selected offline analysis script.' $Stage
    if (-not (Test-Path -LiteralPath $AnalysisScriptPath -PathType Leaf)) { throw "AnalysisScriptMissing: $AnalysisScriptPath" }
    $Metadata = Get-ScriptMetadata $AnalysisScriptPath
    if ($Metadata.parseErrorCount -gt 0) { throw "AnalysisParseFailure: $AnalysisScriptPath" }
    $Output = @(Invoke-ScriptWithParameters -Path $AnalysisScriptPath -Parameters $AnalysisParameters)
    $Evidence = [pscustomobject]@{metadata=$Metadata;output=@($Output);networkActivityExpected='None'}
    Add-CompletedStage $Stage
    Save-SessionState $Stage 'Passed' $Evidence
    Write-SessionEvent 'DONE' 'Offline analysis rebuild completed.' $Stage
    return $Evidence
}

function Invoke-OllamaReadiness {
    $Stage = 'OllamaReadiness'
    Write-SessionEvent 'START' 'Validating local Ollama availability using synthetic content only.' $Stage
    $Result = [ordered]@{
        schemaVersion='1.0';endpoint=[string]$OllamaEndpoint;model=$OllamaModel
        syntheticPromptOnly=$true;available=$false;modelAvailable=$false;jsonResponseValidated=$false
        deterministicFallback='Available';error=$null
    }
    try {
        $Tags = Invoke-RestMethod -Method Get -Uri ([uri]::new($OllamaEndpoint,'/api/tags')) -TimeoutSec 5
        $Result.available = $true
        if (-not [string]::IsNullOrWhiteSpace($OllamaModel)) {
            $Result.modelAvailable = @($Tags.models | Where-Object { [string]$_.name -eq $OllamaModel }).Count -gt 0
        }
        else { $Result.modelAvailable = $true }
        $Result.jsonResponseValidated = $null -ne $Tags.models
    }
    catch { $Result.error = $_.Exception.Message }
    ([pscustomobject]$Result) | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OllamaPath -Encoding UTF8
    if (-not $Result.available) { Write-SessionEvent 'WARNING' 'Ollama unavailable; deterministic workflow remains available.' $Stage }
    Add-CompletedStage $Stage
    Save-SessionState $Stage 'PassedWithFallback' ([pscustomobject]$Result)
    Write-SessionEvent 'DONE' 'Ollama readiness validation completed.' $Stage
    return [pscustomobject]$Result
}

New-Item -ItemType Directory -Path $SessionRoot -Force | Out-Null
if ($Resume -and (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
    $PriorState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -ErrorAction Stop
    foreach ($Stage in @($PriorState.completedStages)) { if (-not [string]::IsNullOrWhiteSpace([string]$Stage)) { $CompletedStages.Add([string]$Stage) } }
    Write-SessionEvent 'INFO' "Resumed session with $($CompletedStages.Count) completed checkpoint(s)." 'Resume'
}
elseif (-not $Resume -and (Test-Path -LiteralPath $LockPath -PathType Leaf)) {
    throw "SessionLockExists: $LockPath. Use -Resume after reviewing session-state.json, or remove the stale lock deliberately."
}

[IO.File]::WriteAllText($LockPath,"$PID|$((Get-Date).ToUniversalTime().ToString('o'))",[Text.UTF8Encoding]::new($false))
Write-SessionEvent 'START' "Starting $PackageIdentity v$LauncherVersion using parameter set $($PSCmdlet.ParameterSetName)." 'Session'
try {
    $Result = switch ($PSCmdlet.ParameterSetName) {
        'Preflight' { Invoke-OfflinePreflight }
        'ValidateLan' { Invoke-LanContextValidation }
        'DryRun' { Invoke-CollectorDryRun }
        'ApprovedRun' { Invoke-ApprovedCollector }
        'Rebuild' { Invoke-AnalysisRebuild }
        'Ollama' { Invoke-OllamaReadiness }
        default { throw "UnsupportedParameterSet: $($PSCmdlet.ParameterSetName)" }
    }
    Write-SessionEvent 'DONE' "Stage completed: $($PSCmdlet.ParameterSetName)." 'Session'
    [pscustomobject][ordered]@{
        Status='Passed';PackageIdentity=$PackageIdentity;LauncherVersion=$LauncherVersion
        ParameterSet=$PSCmdlet.ParameterSetName;CompletedStages=@($CompletedStages|ForEach-Object{$_})
        SessionRoot=$SessionRoot;StatePath=$StatePath;EventPath=$EventPath;Result=$Result
    }
}
catch {
    Save-SessionState $PSCmdlet.ParameterSetName 'Failed' ([pscustomobject]@{error=$_.Exception.Message})
    Write-SessionEvent 'FAIL' $_.Exception.Message 'Session'
    throw
}
finally {
    if (Test-Path -LiteralPath $LockPath -PathType Leaf) { Remove-Item -LiteralPath $LockPath -Force }
}
