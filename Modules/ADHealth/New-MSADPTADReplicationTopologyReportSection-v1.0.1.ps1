<#
.SYNOPSIS
Builds a normalized MSADPT report section from saved AD replication-topology evidence.
.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CollectionDirectory,
    [string]$OutputDirectory,
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [ValidateSet('Plan','Audit','Analyze','Resume','Standalone')][string]$Mode = 'Analyze',
    [ValidateSet('Quick','Full','Standalone','NotApplicable')][string]$Profile = 'Standalone',
    [switch]$OpenHtml,
    [switch]$NoColor
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Version='1.0.1'
function Say([string]$State,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray){if($NoColor){Write-Host ('[{0,-8}] {1}'-f $State,$Message)}else{Write-Host ('[{0,-8}] {1}'-f $State,$Message)-ForegroundColor $Color}}
function Full([string]$Path){if([IO.Path]::IsPathRooted($Path)){[IO.Path]::GetFullPath($Path)}else{[IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))}}
function Metric($Id,$Label,$Value,$State,$Description){[pscustomobject][ordered]@{id=$Id;label=$Label;value=$Value;state=$State;description=$Description}}
function Finding {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Disposition,
        [Parameter(Mandatory)][string]$Summary,
        [string[]]$Evidence = @(),
        [string[]]$Limitations = @(),
        [string]$Recommendation = '',
        [Parameter(Mandatory)][string]$Priority
    )
    [pscustomobject][ordered]@{id=$Id;title=$Title;disposition=$Disposition;summary=$Summary;evidence=@($Evidence);limitations=@($Limitations);recommendation=$Recommendation;priority=$Priority}
}
$Started=(Get-Date).ToUniversalTime();$CollectionDirectory=Full $CollectionDirectory;$RepositoryRoot=Full $RepositoryRoot
if(-not(Test-Path -LiteralPath $CollectionDirectory -PathType Container)){throw "Collection directory not found: $CollectionDirectory"}
$Raw=Join-Path $CollectionDirectory 'Raw';if(-not(Test-Path -LiteralPath $Raw -PathType Container)){throw "Raw evidence directory not found: $Raw"}
if([string]::IsNullOrWhiteSpace($OutputDirectory)){$OutputDirectory=Join-Path $CollectionDirectory 'Analysis'};$OutputDirectory=Full $OutputDirectory;New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$Reporting=Join-Path $RepositoryRoot 'Common\MSADPT.Reporting.psm1';$Analyzer=Join-Path $RepositoryRoot 'Modules\ADHealth\Analyze-MSADPTADReplicationTopology-v1.1.2.ps1'
foreach($Required in @($Reporting,$Analyzer)){if(-not(Test-Path -LiteralPath $Required -PathType Leaf)){throw "Required component missing: $Required"}}
Import-Module $Reporting -Force
$Analysis=Join-Path $OutputDirectory 'ReplicationTopology';New-Item -ItemType Directory -Path $Analysis -Force|Out-Null
Say INFO "Collection: $CollectionDirectory" Cyan;Say INFO 'Network activity: None; directory changes: None.' Green;Say ANALYZE 'Running validated offline replication-topology analyzer.' Cyan
$AnalyzerResult=& $Analyzer -EvidenceDirectory $CollectionDirectory -OutputDirectory $Analysis
$SummaryPath=Join-Path $Analysis 'replication-topology-summary.json';if(-not(Test-Path -LiteralPath $SummaryPath)){throw "Replication summary not created: $SummaryPath"}
$Summary=Get-Content -LiteralPath $SummaryPath -Raw|ConvertFrom-Json
$FindingsCsv=Join-Path $Analysis 'replication-topology-findings.csv';$AnalyzerFindings=if(Test-Path -LiteralPath $FindingsCsv){@(Import-Csv -LiteralPath $FindingsCsv)}else{@()}
$ManifestPath=Join-Path $CollectionDirectory 'evidence-manifest.json';$Manifest=if(Test-Path -LiteralPath $ManifestPath){Get-Content -LiteralPath $ManifestPath -Raw|ConvertFrom-Json}else{$null}
$ModuleVersion=if($Manifest -and $Manifest.PSObject.Properties['ModuleVersion']){[string]$Manifest.ModuleVersion}else{'Unknown'}
$Target=if($Manifest -and $Manifest.PSObject.Properties['Server']){[string]$Manifest.Server}else{[string]$Summary.Forest}
$Metrics=@(
 Metric 'controllers-discovered' 'Controllers discovered' $Summary.DiscoveredControllerCount 'Informational' 'Domain controllers represented by the collection.'
 Metric 'controllers-assessed' 'Controllers assessed' $Summary.AssessedControllerCount $(if($Summary.AssessedControllerCount-eq$Summary.DiscoveredControllerCount){'Good'}else{'Attention'}) 'Controllers with structured partner metadata.'
 Metric 'controllers-unavailable' 'Controllers unavailable' $Summary.UnavailableControllerCount $(if($Summary.UnavailableControllerCount){'Unavailable'}else{'Good'}) 'Controllers unavailable through the structured collection path.'
 Metric 'relationships' 'Replication relationships' $Summary.RelationshipCount 'Informational' 'Structured replication relationships analyzed.'
 Metric 'healthy' 'Healthy relationships' $Summary.HealthyCount 'Good' 'Relationships within the evidence-aware timing threshold.'
 Metric 'delayed' 'Delayed relationships' $Summary.DelayedCount $(if($Summary.DelayedCount){'Attention'}else{'Good'}) 'Relationships exceeding the timing threshold without a confirmed replication result failure.'
 Metric 'failed' 'Failed relationships' $Summary.FailedCount $(if($Summary.FailedCount){'Attention'}else{'Good'}) 'Relationships with a nonzero replication result.'
 Metric 'missing-naming-contexts' 'Missing naming contexts' $Summary.MissingNamingContextCount $(if($Summary.MissingNamingContextCount){'Unavailable'}else{'Good'}) 'Expected naming contexts absent from structured partner evidence.'
)
$Findings=[Collections.Generic.List[object]]::new()
foreach($Row in $AnalyzerFindings){
    $FindingDisposition=if($Row.Disposition-eq'Failed'){'Confirmed'}elseif($Row.Disposition-eq'Delayed'){'Likely or probable'}else{'Inconclusive'}
    $FindingPriority=if($Row.Disposition-eq'Failed'){'High'}elseif($Row.Disposition-eq'Delayed'){'Normal'}else{'Informational'}
    $Findings.Add((Finding `
        -Id ("replication-{0}" -f ($Findings.Count+1)) `
        -Title ("{0}: {1}" -f $Row.Area,$Row.Object) `
        -Disposition $FindingDisposition `
        -Summary ([string]$Row.Evidence) `
        -Evidence @('Analyzer finding derived from saved point-in-time evidence.') `
        -Limitations @('The finding must be confirmed against current replication state before remediation.') `
        -Recommendation ([string]$Row.RecommendedValidation) `
        -Priority $FindingPriority))
}
if($Findings.Count-eq0){
    $Findings.Add((Finding `
        -Id 'replication-no-adverse-finding' `
        -Title 'No adverse replication relationship was detected' `
        -Disposition 'Not detected' `
        -Summary 'No failed, delayed, coverage-gap, or naming-context finding was emitted by the offline analyzer.' `
        -Evidence @("Relationships analyzed: $($Summary.RelationshipCount).","Controllers assessed: $($Summary.AssessedControllerCount) of $($Summary.DiscoveredControllerCount).") `
        -Limitations @('This conclusion is bounded by controller and naming-context coverage in the saved evidence.') `
        -Recommendation 'Recollect only when the evidence age or coverage no longer supports the decision.' `
        -Priority 'Informational'))
}
$Disposition=if($Summary.OverallDisposition-eq'Failed'){'Confirmed'}elseif($Summary.OverallDisposition-eq'Inconclusive'){'Inconclusive'}else{'Not detected'}
$ExecutionStatus=if($Disposition-eq'Inconclusive'){'CompletedWithLimitations'}else{'Completed'};$Complete=$Disposition-ne'Inconclusive'
$SummaryText=if($Disposition-eq'Confirmed'){'One or more replication relationships show a nonzero replication result in saved evidence.'}elseif($Disposition-eq'Inconclusive'){'Replication evidence was analyzed, but controller or naming-context coverage prevents a complete topology conclusion.'}else{'No failed or delayed structured replication relationship was detected within the assessed evidence.'}
$EvidenceFiles=@('Raw/forest.json','Raw/domain-controllers.json','Raw/sites.json','Raw/subnets.json','Raw/site-links.json','Raw/partner-metadata.json','Raw/reachability.json','Raw/operational-errors.json','evidence-manifest.json','Analysis/ReplicationTopology/replication-topology-summary.json','Analysis/ReplicationTopology/replication-topology-findings.csv','Analysis/ReplicationTopology/controller-coverage.csv','Analysis/ReplicationTopology/replication-relationships.csv')
$Links=@(foreach($Relative in $EvidenceFiles){$Media=if($Relative.EndsWith('.csv')){'text/csv'}else{'application/json'};[pscustomobject][ordered]@{label=[IO.Path]::GetFileName($Relative);relativePath=$Relative;mediaType=$Media;exists=Test-Path -LiteralPath (Join-Path $CollectionDirectory ($Relative-replace'/','\'))-PathType Leaf}})
$Limitations=@('This is point-in-time evidence; delayed or failed relationships require current confirmation before remediation.','Unavailable ADWS coverage does not prove a controller or replication failure.','Missing structured evidence is reported as inconclusive, not healthy or absent.')
$Recommendations=@('Confirm current replication state for any failed or delayed relationship before remediation.','Use an approved alternate collection path for controllers without structured coverage.','Retain controller and naming-context coverage alongside all posture conclusions.')
$Completed=(Get-Date).ToUniversalTime();$Section=New-MSADPTReportSection -ModuleId 'Analyze-MSADPTADReplicationTopology' -ModuleVersion ([string]$Summary.AnalyzerVersion) -Title 'AD Replication Topology' -Category 'Directory.Replication' -ExecutionStatus $ExecutionStatus -Mode $Mode -Profile $Profile -Target $Target -StartedUtc $Started.ToString('o') -CompletedUtc $Completed.ToString('o') -DurationSeconds ([math]::Round(($Completed-$Started).TotalSeconds,3)) -ReusedEvidence $true -NetworkExecuted $false -DirectoryChanges None -Disposition $Disposition -Summary $SummaryText -Confidence High -EvidenceComplete $Complete -Metrics $Metrics -Findings @($Findings) -EvidenceLinks $Links -Limitations $Limitations -Recommendations $Recommendations
$Validation=Test-MSADPTReportSection -Section $Section -EvidenceRoot $CollectionDirectory;if(-not$Validation.valid){throw "Report-section validation failed: $($Validation.errors-join'; ')"}
$Json=Join-Path $OutputDirectory 'ad-replication-topology-report-section.json';$Html=Join-Path $OutputDirectory 'ad-replication-topology-report-section.html';$ValidationPath=Join-Path $OutputDirectory 'ad-replication-topology-report-section-validation.json'
ConvertTo-Json -InputObject $Section -Depth 16|Set-Content -LiteralPath $Json -Encoding UTF8;ConvertTo-Json -InputObject $Validation -Depth 8|Set-Content -LiteralPath $ValidationPath -Encoding UTF8
$Fragment=ConvertTo-MSADPTReportSectionHtml -Section $Section -EvidenceLinkPrefix '../';[IO.File]::WriteAllText($Html,$Fragment,(New-Object Text.UTF8Encoding($false)))
foreach($Path in @($Json,$Html,$ValidationPath)){if(-not(Test-Path -LiteralPath $Path)-or(Get-Item $Path).Length-eq0){throw "Output validation failed: $Path"}}
Say PASS ("Report section completed: disposition={0}; findings={1}; evidenceComplete={2}."-f$Disposition,$Findings.Count,$Complete) Green;Say REPORT $Html Cyan;if($OpenHtml){Start-Process $Html}
[pscustomobject][ordered]@{Status='Completed';Version=$Version;ModuleVersion=$ModuleVersion;AnalyzerVersion=[string]$Summary.AnalyzerVersion;Disposition=$Disposition;ExecutionStatus=$ExecutionStatus;ControllerCount=[int]$Summary.DiscoveredControllerCount;AssessedControllerCount=[int]$Summary.AssessedControllerCount;RelationshipCount=[int]$Summary.RelationshipCount;FindingCount=$Findings.Count;EvidenceComplete=$Complete;ValidationErrors=$Validation.errorCount;ValidationWarnings=$Validation.warningCount;ReportSectionJsonPath=$Json;ReportSectionHtmlPath=$Html;ValidationPath=$ValidationPath;NetworkActivity='None';DirectoryChanges='None'}
