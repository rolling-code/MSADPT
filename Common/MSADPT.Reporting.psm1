Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function ConvertTo-MSADPTHtmlText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-MSADPTObjectProperty {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    $Property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $Property) { return $Default }
    return $Property.Value
}

function New-MSADPTReportSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ModuleId,
        [Parameter(Mandatory)][string]$ModuleVersion,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('NotStarted','Planned','Completed','CompletedWithLimitations','Reused','Blocked','Failed','NotApplicable')][string]$ExecutionStatus,
        [ValidateSet('Plan','Audit','Analyze','Resume','Standalone')][string]$Mode = 'Standalone',
        [ValidateSet('Quick','Full','Standalone','NotApplicable')][string]$Profile = 'Standalone',
        [AllowNull()][string]$Target,
        [AllowNull()][string]$StartedUtc,
        [AllowNull()][string]$CompletedUtc,
        [AllowNull()][Nullable[double]]$DurationSeconds,
        [bool]$ReusedEvidence = $false,
        [bool]$NetworkExecuted = $false,
        [ValidateSet('None','Attempted','Completed','Unknown')][string]$DirectoryChanges = 'None',
        [Parameter(Mandatory)][ValidateSet('Confirmed','Likely or probable','Inconclusive','Not detected','Not applicable')][string]$Disposition,
        [Parameter(Mandatory)][string]$Summary,
        [ValidateSet('High','Medium','Low','NotApplicable')][string]$Confidence = 'Medium',
        [bool]$EvidenceComplete = $false,
        [object[]]$Metrics = @(),
        [object[]]$Findings = @(),
        [object[]]$EvidenceLinks = @(),
        [string[]]$Limitations = @(),
        [string[]]$Recommendations = @()
    )

    [pscustomobject][ordered]@{
        schemaVersion = '1.0'
        moduleId = $ModuleId
        moduleVersion = $ModuleVersion
        title = $Title
        category = $Category
        execution = [pscustomobject][ordered]@{
            status = $ExecutionStatus
            mode = $Mode
            profile = $Profile
            target = $Target
            startedUtc = $StartedUtc
            completedUtc = $CompletedUtc
            durationSeconds = $DurationSeconds
            reusedEvidence = $ReusedEvidence
            networkExecuted = $NetworkExecuted
            directoryChanges = $DirectoryChanges
        }
        posture = [pscustomobject][ordered]@{
            disposition = $Disposition
            summary = $Summary
            confidence = $Confidence
            evidenceComplete = $EvidenceComplete
        }
        metrics = @($Metrics)
        findings = @($Findings)
        evidenceLinks = @($EvidenceLinks)
        limitations = @($Limitations)
        recommendations = @($Recommendations)
        generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Test-MSADPTReportSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object]$Section,
        [string]$EvidenceRoot
    )

    process {
        $Errors = [Collections.Generic.List[string]]::new()
        $Warnings = [Collections.Generic.List[string]]::new()

        foreach ($RequiredName in @('schemaVersion','moduleId','moduleVersion','title','category','execution','posture','metrics','findings','evidenceLinks','limitations','recommendations','generatedUtc')) {
            if ($null -eq $Section.PSObject.Properties[$RequiredName]) {
                $Errors.Add("Missing required property: $RequiredName")
            }
        }

        if ($Errors.Count -eq 0) {
            if ([string]$Section.schemaVersion -ne '1.0') { $Errors.Add('schemaVersion must be 1.0.') }
            if ([string]::IsNullOrWhiteSpace([string]$Section.moduleId)) { $Errors.Add('moduleId is empty.') }
            if ([string]::IsNullOrWhiteSpace([string]$Section.moduleVersion)) { $Errors.Add('moduleVersion is empty.') }
            if ([string]::IsNullOrWhiteSpace([string]$Section.title)) { $Errors.Add('title is empty.') }
            if ([string]::IsNullOrWhiteSpace([string]$Section.posture.summary)) { $Errors.Add('posture.summary is empty.') }

            $AllowedDispositions = @('Confirmed','Likely or probable','Inconclusive','Not detected','Not applicable')
            if ([string]$Section.posture.disposition -notin $AllowedDispositions) {
                $Errors.Add("Unsupported posture disposition: $($Section.posture.disposition)")
            }

            foreach ($Finding in @($Section.findings)) {
                foreach ($FindingProperty in @('id','title','disposition','summary','evidence','limitations','recommendation','priority')) {
                    if ($null -eq $Finding.PSObject.Properties[$FindingProperty]) {
                        $Errors.Add("Finding is missing property '$FindingProperty'.")
                    }
                }
            }

            foreach ($Link in @($Section.evidenceLinks)) {
                foreach ($LinkProperty in @('label','relativePath','mediaType','exists')) {
                    if ($null -eq $Link.PSObject.Properties[$LinkProperty]) {
                        $Errors.Add("Evidence link is missing property '$LinkProperty'.")
                    }
                }

                if ($EvidenceRoot -and $null -ne $Link.PSObject.Properties['relativePath']) {
                    $ResolvedPath = Join-Path $EvidenceRoot ([string]$Link.relativePath)
                    $ActualExists = Test-Path -LiteralPath $ResolvedPath -PathType Leaf
                    if ([bool]$Link.exists -ne $ActualExists) {
                        $Warnings.Add("Evidence existence mismatch: $($Link.relativePath)")
                    }
                }
            }
        }

        [pscustomobject][ordered]@{
            valid = $Errors.Count -eq 0
            moduleId = if ($Section.PSObject.Properties['moduleId']) { [string]$Section.moduleId } else { $null }
            errorCount = $Errors.Count
            warningCount = $Warnings.Count
            errors = @($Errors)
            warnings = @($Warnings)
        }
    }
}

function ConvertTo-MSADPTReportSectionHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object]$Section,
        [string]$EvidenceLinkPrefix = ''
    )

    process {
        $Validation = Test-MSADPTReportSection -Section $Section
        if (-not $Validation.valid) {
            throw "Invalid report-section contract for '$($Validation.moduleId)': $($Validation.errors -join '; ')"
        }

        $DispositionClass = switch ([string]$Section.posture.disposition) {
            'Confirmed' { 'confirmed' }
            'Likely or probable' { 'likely' }
            'Inconclusive' { 'inconclusive' }
            'Not detected' { 'not-detected' }
            'Not applicable' { 'not-applicable' }
        }

        $MetricHtml = @(
            foreach ($Metric in @($Section.metrics)) {
                $State = ConvertTo-MSADPTHtmlText (Get-MSADPTObjectProperty -InputObject $Metric -Name 'state' -Default 'Informational')
                '<div class="msadpt-metric {0}"><div class="msadpt-metric-value">{1}</div><div class="msadpt-metric-label">{2}</div><div class="msadpt-metric-description">{3}</div></div>' -f `
                    $State.ToLowerInvariant(), `
                    (ConvertTo-MSADPTHtmlText (Get-MSADPTObjectProperty -InputObject $Metric -Name 'value')), `
                    (ConvertTo-MSADPTHtmlText (Get-MSADPTObjectProperty -InputObject $Metric -Name 'label')), `
                    (ConvertTo-MSADPTHtmlText (Get-MSADPTObjectProperty -InputObject $Metric -Name 'description'))
            }
        ) -join ''

        $FindingHtml = if (@($Section.findings).Count -eq 0) {
            '<p class="msadpt-muted">No findings were emitted by this module.</p>'
        }
        else {
            @(
                foreach ($Finding in @($Section.findings)) {
                    $EvidenceItems = @($Finding.evidence | ForEach-Object { '<li>{0}</li>' -f (ConvertTo-MSADPTHtmlText $_) }) -join ''
                    $LimitationItems = @($Finding.limitations | ForEach-Object { '<li>{0}</li>' -f (ConvertTo-MSADPTHtmlText $_) }) -join ''
                    '<article class="msadpt-finding"><h4>{0}</h4><p><b>Disposition:</b> {1} &nbsp; <b>Priority:</b> {2}</p><p>{3}</p><details><summary>Evidence and limitations</summary><h5>Evidence</h5><ul>{4}</ul><h5>Limitations</h5><ul>{5}</ul><h5>Recommendation</h5><p>{6}</p></details></article>' -f `
                        (ConvertTo-MSADPTHtmlText $Finding.title), `
                        (ConvertTo-MSADPTHtmlText $Finding.disposition), `
                        (ConvertTo-MSADPTHtmlText $Finding.priority), `
                        (ConvertTo-MSADPTHtmlText $Finding.summary), `
                        $EvidenceItems, $LimitationItems, `
                        (ConvertTo-MSADPTHtmlText $Finding.recommendation)
                }
            ) -join ''
        }

        $EvidenceHtml = @(
            foreach ($Link in @($Section.evidenceLinks)) {
                $RelativePath = ([string]$Link.relativePath) -replace '\\','/'
                $Prefix = ([string]$EvidenceLinkPrefix) -replace '\\','/'
                if ($Prefix -and -not $Prefix.EndsWith('/')) {
                    $Prefix += '/'
                }
                $LinkTarget = $Prefix + $RelativePath.TrimStart('/')

                '<li><a href="{0}">{1}</a> <span class="msadpt-muted">({2}; exists: {3})</span></li>' -f `
                    (ConvertTo-MSADPTHtmlText $LinkTarget), `
                    (ConvertTo-MSADPTHtmlText $Link.label), `
                    (ConvertTo-MSADPTHtmlText $Link.mediaType), `
                    ([string][bool]$Link.exists).ToLowerInvariant()
            }
        ) -join ''

        $LimitationHtml = @($Section.limitations | ForEach-Object { '<li>{0}</li>' -f (ConvertTo-MSADPTHtmlText $_) }) -join ''
        $RecommendationHtml = @($Section.recommendations | ForEach-Object { '<li>{0}</li>' -f (ConvertTo-MSADPTHtmlText $_) }) -join ''

        @"
<section class="msadpt-report-section" id="module-$([Net.WebUtility]::UrlEncode([string]$Section.moduleId))">
  <header><div><h2>$(ConvertTo-MSADPTHtmlText $Section.title)</h2><div class="msadpt-muted">$(ConvertTo-MSADPTHtmlText $Section.moduleId) v$(ConvertTo-MSADPTHtmlText $Section.moduleVersion) - $(ConvertTo-MSADPTHtmlText $Section.category)</div></div><span class="msadpt-disposition $DispositionClass">$(ConvertTo-MSADPTHtmlText $Section.posture.disposition)</span></header>
  <p class="msadpt-summary">$(ConvertTo-MSADPTHtmlText $Section.posture.summary)</p>
  <div class="msadpt-execution"><b>Status:</b> $(ConvertTo-MSADPTHtmlText $Section.execution.status) &nbsp; <b>Target:</b> $(ConvertTo-MSADPTHtmlText $Section.execution.target) &nbsp; <b>Evidence complete:</b> $([string][bool]$Section.posture.evidenceComplete)</div>
  <div class="msadpt-metrics">$MetricHtml</div>
  <h3>Findings</h3>$FindingHtml
  <h3>Evidence links</h3><ul>$EvidenceHtml</ul>
  <h3>Collection and interpretation limitations</h3><ul>$LimitationHtml</ul>
  <h3>Recommended follow-up</h3><ul>$RecommendationHtml</ul>
</section>
"@
    }
}

Export-ModuleMember -Function @(
    'New-MSADPTReportSection',
    'Test-MSADPTReportSection',
    'ConvertTo-MSADPTReportSectionHtml',
    'ConvertTo-MSADPTHtmlText'
)
