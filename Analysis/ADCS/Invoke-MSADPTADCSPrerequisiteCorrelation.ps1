<#
.SYNOPSIS
Correlates normalized ADCS facts with the ESC1 through ESC16 prerequisite catalog offline.
.NOTES
Version: 0.1.1
Execution class: offline_analysis
No network, Active Directory, CA, registry, certutil, or state-changing operation is performed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CatalogPath,
    [Parameter(Mandatory=$true)][string]$FactsPath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
foreach($Path in @($CatalogPath,$FactsPath)){if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "Required file not found: $Path"}}
$Catalog=Get-Content -LiteralPath $CatalogPath -Raw|ConvertFrom-Json -ErrorAction Stop
$FactsDocument=Get-Content -LiteralPath $FactsPath -Raw|ConvertFrom-Json -ErrorAction Stop
if([string]$Catalog.schemaVersion -ne '1.0.0'){throw "Unsupported catalog schema: $($Catalog.schemaVersion)"}
$AllowedStates=@('Confirmed','Not observed','Inconclusive','Not applicable')
$Facts=@{}
foreach($Fact in @($FactsDocument.facts)){
    $Id=[string]$Fact.id
    if([string]::IsNullOrWhiteSpace($Id)){throw 'A fact is missing its id.'}
    if($Facts.ContainsKey($Id)){throw "Duplicate fact id: $Id"}
    if([string]$Fact.state -notin $AllowedStates){throw "Unsupported fact state for ${Id}: $($Fact.state)"}
    $Facts[$Id]=$Fact
}
function Get-FactState([string]$Id){if($Facts.ContainsKey($Id)){return [string]$Facts[$Id].state};return 'Missing'}
$Candidates=foreach($Technique in @($Catalog.techniques)){
    $Required=@($Technique.required|ForEach-Object{[pscustomobject]@{Id=[string]$_;State=(Get-FactState ([string]$_))}})
    $Blocking=@($Technique.blocking|ForEach-Object{[pscustomobject]@{Id=[string]$_;State=(Get-FactState ([string]$_))}})
    $Supporting=@($Technique.supporting|ForEach-Object{[pscustomobject]@{Id=[string]$_;State=(Get-FactState ([string]$_))}})
    $ActiveBlocks=@($Blocking|Where-Object State -eq 'Confirmed')
    $Unsatisfied=@($Required|Where-Object State -eq 'Not observed')
    $Unknown=@($Required|Where-Object{$_.State -in @('Missing','Inconclusive')})
    $NotApplicable=@($Required|Where-Object State -eq 'Not applicable')
    $Satisfied=@($Required|Where-Object State -eq 'Confirmed')
    $Disposition=if($NotApplicable.Count -gt 0){'Not applicable'}elseif($ActiveBlocks.Count -gt 0 -or $Unsatisfied.Count -gt 0){'Blocked'}elseif($Unknown.Count -gt 0){'Incomplete evidence'}else{'Prerequisites satisfied'}
    [pscustomobject][ordered]@{
        Technique=[string]$Technique.id;Title=[string]$Technique.title;Category=[string]$Technique.category
        RuntimeDependent=[bool]$Technique.runtimeDependent;Disposition=$Disposition
        RequiredCount=$Required.Count;SatisfiedRequiredCount=$Satisfied.Count
        MissingOrInconclusiveRequired=@($Unknown);NotObservedRequired=@($Unsatisfied);NotApplicableRequired=@($NotApplicable)
        ConfirmedBlockingEvidence=@($ActiveBlocks);SupportingEvidence=@($Supporting)
        SafeFollowUp=[string]$Technique.safeFollowUp
        Limitations=@('This record is a prerequisite correlation, not a vulnerability or exploitability declaration.','Effective permissions, reachability, mapping behavior, and runtime controls must be supported by deterministic evidence where applicable.')
    }
}
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$JsonPath=Join-Path $OutputDirectory 'adcs-technique-candidates.json'
$CsvPath=Join-Path $OutputDirectory 'adcs-technique-candidate-summary.csv'
$Candidates|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $JsonPath -Encoding UTF8
$Candidates|Select-Object Technique,Title,Category,RuntimeDependent,Disposition,RequiredCount,SatisfiedRequiredCount,@{N='UnknownRequiredCount';E={@($_.MissingOrInconclusiveRequired).Count}},@{N='NotObservedRequiredCount';E={@($_.NotObservedRequired).Count}},@{N='BlockingEvidenceCount';E={@($_.ConfirmedBlockingEvidence).Count}},SafeFollowUp|Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
[pscustomobject][ordered]@{schemaVersion='1.0';engine='ADCSPrerequisiteCorrelation';engineVersion='0.1.1';status='Completed';executionClass='offline_analysis';techniqueCount=@($Candidates).Count;prerequisitesSatisfiedCount=@($Candidates|Where-Object Disposition -eq 'Prerequisites satisfied').Count;blockedCount=@($Candidates|Where-Object Disposition -eq 'Blocked').Count;incompleteEvidenceCount=@($Candidates|Where-Object Disposition -eq 'Incomplete evidence').Count;notApplicableCount=@($Candidates|Where-Object Disposition -eq 'Not applicable').Count;evidence=@($JsonPath,$CsvPath)}
