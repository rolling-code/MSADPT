[CmdletBinding()]
param([string]$RepositoryRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Failures=New-Object 'System.Collections.Generic.List[object]'
function Fail([string]$Gate,[string]$Detail){$Failures.Add([pscustomobject]@{Gate=$Gate;Detail=$Detail})}
$Helper=Join-Path $RepositoryRoot 'Common\MSADPT.Evidence.psm1'
Import-Module $Helper -Force -ErrorAction Stop
$Root=Join-Path ([IO.Path]::GetTempPath()) ('msadpt-adcs-foundation-'+[guid]::NewGuid().ToString('N'))
try{
 New-Item -ItemType Directory -Path $Root -Force|Out-Null
 $EmptyPath=Join-Path $Root 'empty.json'
 Write-MSADPTJsonEvidence -Path $EmptyPath -Value @()
 if((Get-Content -LiteralPath $EmptyPath -Raw).Trim() -ne '[]'){Fail 'EmptyArray' (Get-Content -LiteralPath $EmptyPath -Raw)}
 $ObjectPath=Join-Path $Root 'object.json'
 Write-MSADPTJsonEvidence -Path $ObjectPath -Value ([pscustomobject]@{Status='Completed'})
 $ManifestPath=New-MSADPTEvidenceManifest -EvidenceDirectory $Root -ModuleId 'SyntheticADCS' -ModuleVersion '0.1.0'
 if(-not(Test-MSADPTEvidenceManifest -ManifestPath $ManifestPath)){Fail 'ManifestValidation' $ManifestPath}
 Add-Content -LiteralPath $ObjectPath -Value 'tamper'
 if(Test-MSADPTEvidenceManifest -ManifestPath $ManifestPath){Fail 'ManifestTamperDetection' 'Tampering was not detected.'}
}finally{Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue}
$Rows=[object[]]$Failures.ToArray()
[pscustomobject]@{Status=if($Rows.Count-eq0){'Passed'}else{'Failed'};FailureCount=$Rows.Count;Failures=$Rows;NetworkActivity='None';ActiveDirectoryQueries='None'}