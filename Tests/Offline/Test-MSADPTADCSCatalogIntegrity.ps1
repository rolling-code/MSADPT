[CmdletBinding()]
param([string]$RepositoryRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Failures=New-Object 'System.Collections.Generic.List[object]'
function Fail([string]$Gate,[string]$Detail){$Failures.Add([pscustomobject]@{Gate=$Gate;Detail=$Detail})}
$CatalogPath=Join-Path $RepositoryRoot 'Catalogs\ADCS\adcs-technique-prerequisites-v1.0.0.json'
$FactBuilderPath=Join-Path $RepositoryRoot 'Analysis\ADCS\Convert-MSADPTADCSEvidenceToFacts.ps1'
$Catalog=Get-Content -LiteralPath $CatalogPath -Raw|ConvertFrom-Json -ErrorAction Stop
if([string]$Catalog.schemaVersion -ne '1.0.0'){Fail 'SchemaVersion' ([string]$Catalog.schemaVersion)}
$Ids=@($Catalog.techniques|ForEach-Object{[string]$_.id}|Sort-Object)
$Expected=@(1..16|ForEach-Object{'ESC'+$_}|Sort-Object)
if(($Ids -join ',') -ne ($Expected -join ',')){Fail 'TechniqueIds' ($Ids -join ',')}
if(@($Catalog.techniques).Count -ne 16){Fail 'TechniqueCount' ([string]@($Catalog.techniques).Count)}
$Allowed=@('Prerequisites satisfied','Blocked','Incomplete evidence','Not applicable')
foreach($Disposition in @($Catalog.allowedCandidateDispositions)){if([string]$Disposition -notin $Allowed){Fail 'Disposition' ([string]$Disposition)}}
foreach($Conclusion in @('Vulnerable','Exploitable','Critical','Domain compromise')){if($Conclusion -notin @($Catalog.prohibitedConclusions)){Fail 'ProhibitedConclusion' $Conclusion}}
$FactText=Get-Content -LiteralPath $FactBuilderPath -Raw
$ReferencedFacts=@($Catalog.techniques|ForEach-Object{@($_.required)+@($_.blocking)+@($_.supporting)}|Sort-Object -Unique)
$Missing=@($ReferencedFacts|Where-Object{$FactText -notmatch [regex]::Escape([string]$_)})
# Missing references remain evidence for integration work, but only a completely empty mapping blocks foundation readiness.
if($ReferencedFacts.Count -gt 0 -and $Missing.Count -eq $ReferencedFacts.Count){Fail 'FactMapping' 'No catalog fact identifier was found in the current fact builder.'}
$Rows=[object[]]$Failures.ToArray()
[pscustomobject]@{Status=if($Rows.Count-eq0){'Passed'}else{'Failed'};TechniqueCount=@($Catalog.techniques).Count;ReferencedFactCount=$ReferencedFacts.Count;MissingFactReferenceCount=$Missing.Count;MissingFactReferences=$Missing;FailureCount=$Rows.Count;Failures=$Rows;NetworkActivity='None'}