<#
.SYNOPSIS
Ollama provider bridge for MSADPT. Sends evidence packages to a local Ollama model and returns JSON decisions only.

.DESCRIPTION
Validates the local Ollama endpoint and requested model, submits a non-streaming structured-output request,
disables model thinking to preserve the output-token budget for the final JSON decision, validates completion,
detects truncation, parses only the final message content, and returns a decision object with provider metadata.

The provider does not execute model-generated commands or code. Decision authorization remains the
responsibility of the MSADPT reasoning controller and policy engine.

.VERSION
0.2.0
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-MSADPTOllamaPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $Property = $InputObject.PSObject.Properties |
        Where-Object { $_.Name -eq $Name } |
        Select-Object -First 1

    if ($null -ne $Property) {
        return ,$Property.Value
    }

    return $null
}

function Get-MSADPTOllamaInstalledModels {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OllamaUri,

        [Parameter()]
        [ValidateRange(1, 120)]
        [int]$TimeoutSec = 10
    )

    $TagsUri = $OllamaUri.TrimEnd('/') + '/api/tags'

    try {
        $Tags = Invoke-RestMethod -Method Get -Uri $TagsUri -TimeoutSec $TimeoutSec -ErrorAction Stop
    }
    catch {
        throw "Ollama API readiness check failed at $TagsUri. $($_.Exception.Message)"
    }

    $Models = Get-MSADPTOllamaPropertyValue -InputObject $Tags -Name 'models'
    if ($null -eq $Models) {
        return @()
    }

    return @($Models | ForEach-Object { [string]$_.name })
}

function Invoke-MSADPTOllamaDecision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $EvidencePackage,

        [Parameter(Mandatory = $true)]
        [string]$PromptPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OllamaUri,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Model,

        [Parameter()]
        [ValidateRange(10, 1800)]
        [int]$TimeoutSec = 300,

        [Parameter()]
        [ValidateRange(256, 8192)]
        [int]$MaxOutputTokens = 2400,

        [Parameter()]
        [ValidateRange(0.0, 2.0)]
        [double]$Temperature = 0.0
    )

    if (-not (Test-Path -LiteralPath $PromptPath -PathType Leaf)) {
        throw "Promptbook not found: $PromptPath"
    }

    $InstalledModels = @(Get-MSADPTOllamaInstalledModels -OllamaUri $OllamaUri)
    if ($InstalledModels -notcontains $Model) {
        $VisibleModels = if ($InstalledModels.Count -gt 0) {
            $InstalledModels -join ', '
        }
        else {
            '<none>'
        }

        throw "Ollama model is not installed: $Model. Installed models: $VisibleModels"
    }

    $SystemPrompt = Get-Content -LiteralPath $PromptPath -Raw -ErrorAction Stop
    $EvidenceJson = $EvidencePackage | ConvertTo-Json -Depth 60 -Compress
    $UserPrompt = @"
Evaluate the supplied MSADPT evidence package.
Return one JSON decision object only.
Do not include Markdown, code fences, commentary, reasoning, or executable instructions.

EVIDENCE PACKAGE:
$EvidenceJson
"@

    $Body = [ordered]@{
        model  = $Model
        stream = $false
        think  = $false
        format = 'json'
        options = [ordered]@{
            temperature = $Temperature
            num_predict = $MaxOutputTokens
        }
        messages = @(
            [ordered]@{
                role    = 'system'
                content = $SystemPrompt
            },
            [ordered]@{
                role    = 'user'
                content = $UserPrompt
            }
        )
    }

    $ChatUri = $OllamaUri.TrimEnd('/') + '/api/chat'
    $RequestJson = $Body | ConvertTo-Json -Depth 70 -Compress
    $RequestStartedUtc = (Get-Date).ToUniversalTime()

    try {
        $Response = Invoke-RestMethod `
            -Method Post `
            -Uri $ChatUri `
            -ContentType 'application/json' `
            -Body $RequestJson `
            -TimeoutSec $TimeoutSec `
            -ErrorAction Stop
    }
    catch {
        throw "Ollama request failed at $ChatUri using model $Model. $($_.Exception.Message)"
    }

    $RequestCompletedUtc = (Get-Date).ToUniversalTime()
    $Done = [bool](Get-MSADPTOllamaPropertyValue -InputObject $Response -Name 'done')
    $DoneReason = [string](Get-MSADPTOllamaPropertyValue -InputObject $Response -Name 'done_reason')
    $ResponseModel = [string](Get-MSADPTOllamaPropertyValue -InputObject $Response -Name 'model')

    if (-not $Done) {
        throw "Ollama did not report a completed response. Model=$ResponseModel; DoneReason=$DoneReason"
    }

    if ($DoneReason -eq 'length') {
        throw "Ollama stopped because the output-token limit was reached. The JSON decision may be truncated. Model=$ResponseModel; MaxOutputTokens=$MaxOutputTokens"
    }

    if ($null -eq $Response.message) {
        throw "Ollama returned no message object. Model=$ResponseModel; DoneReason=$DoneReason"
    }

    $ThinkingContent = [string](Get-MSADPTOllamaPropertyValue -InputObject $Response.message -Name 'thinking')
    $FinalContent = [string](Get-MSADPTOllamaPropertyValue -InputObject $Response.message -Name 'content')

    if ([string]::IsNullOrWhiteSpace($FinalContent)) {
        $ThinkingLength = if ($null -eq $ThinkingContent) { 0 } else { $ThinkingContent.Length }
        throw "Ollama returned no final message content. Model=$ResponseModel; DoneReason=$DoneReason; ThinkingCharacters=$ThinkingLength"
    }

    try {
        $Decision = $FinalContent | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Ollama final content was not valid JSON. Model=$ResponseModel; DoneReason=$DoneReason; ContentLength=$($FinalContent.Length); Error=$($_.Exception.Message); Content=$FinalContent"
    }

    $ProviderMetadata = [pscustomobject][ordered]@{
        Provider            = 'Ollama'
        ProviderModuleVersion = '0.2.0'
        Endpoint            = $ChatUri
        RequestedModel      = $Model
        ResponseModel       = $ResponseModel
        ThinkingDisabled    = $true
        ThinkingCharacters  = if ($null -eq $ThinkingContent) { 0 } else { $ThinkingContent.Length }
        ContentCharacters   = $FinalContent.Length
        Done                = $Done
        DoneReason          = $DoneReason
        RequestStartedUtc   = $RequestStartedUtc.ToString('o')
        RequestCompletedUtc = $RequestCompletedUtc.ToString('o')
        ElapsedMilliseconds = [math]::Round(($RequestCompletedUtc - $RequestStartedUtc).TotalMilliseconds, 0)
        TotalDurationNs     = Get-MSADPTOllamaPropertyValue -InputObject $Response -Name 'total_duration'
        LoadDurationNs      = Get-MSADPTOllamaPropertyValue -InputObject $Response -Name 'load_duration'
        PromptEvalCount     = Get-MSADPTOllamaPropertyValue -InputObject $Response -Name 'prompt_eval_count'
        PromptEvalDurationNs = Get-MSADPTOllamaPropertyValue -InputObject $Response -Name 'prompt_eval_duration'
        EvalCount           = Get-MSADPTOllamaPropertyValue -InputObject $Response -Name 'eval_count'
        EvalDurationNs      = Get-MSADPTOllamaPropertyValue -InputObject $Response -Name 'eval_duration'
    }

    # Preserve the strict decision contract. Provider diagnostics are available through
    # the verbose stream and are not added to the JSON decision object because the
    # decision schema rejects additional properties.
    Write-Verbose ("Ollama provider metadata: {0}" -f ($ProviderMetadata | ConvertTo-Json -Depth 10 -Compress))

    return $Decision
}

Export-ModuleMember -Function Invoke-MSADPTOllamaDecision, Get-MSADPTOllamaInstalledModels
