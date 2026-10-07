[CmdletBinding()]param([string]$RepositoryRoot=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$gate=Join-Path $RepositoryRoot 'Tests\Offline\Test-MSADPTADHealthCollectionEvidence-v1.4.0.ps1'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('MSADPT-ADHealthGate-'+[guid]::NewGuid().ToString('N'));$raw=Join-Path $temp 'Raw';$htmlRoot=Join-Path $temp 'OfflineAssessment\Assessment';New-Item -ItemType Directory -Path $raw,$htmlRoot -Force|Out-Null
try{
 $targets=@('DC01.example.test','DC02.example.test');$records=New-Object 'System.Collections.Generic.List[object]'
 foreach($t in $targets){$s=$t-replace'[^A-Za-z0-9._-]','_';foreach($pair in @(@('dcdiag.exe',"DCDiag-$s.txt"),@('repadmin.exe',"Repadmin-ShowRepl-$s.txt"),@('repadmin.exe',"Repadmin-Queue-$s.txt"),@('nltest.exe',"Nltest-Query-$s.txt"),@('nltest.exe',"Nltest-DSGetSite-$s.txt"),@('w32tm.exe',"W32tm-Status-$s.txt"))){$p=Join-Path $raw $pair[1];Set-Content -LiteralPath $p -Value 'synthetic';$records.Add([pscustomobject]@{Target=$t;Utility=$pair[0];OutputPath=$p;SHA256=(Get-FileHash $p -Algorithm SHA256).Hash})}}
 $rp=Join-Path $raw 'Repadmin-ReplSummary.txt';Set-Content $rp 'synthetic';$records.Add([pscustomobject]@{Target='Domain';Utility='repadmin.exe';OutputPath=$rp;SHA256=(Get-FileHash $rp -Algorithm SHA256).Hash})
 @($targets|ForEach-Object{[pscustomobject]@{Target=$_}})|Export-Csv (Join-Path $temp 'ExpectedTargets.csv') -NoTypeInformation
 @($records.ToArray())|ConvertTo-Json -Depth 5|Set-Content (Join-Path $temp 'ADHealth-Collection-Manifest.json')
 @{Status='Completed'}|ConvertTo-Json|Set-Content (Join-Path $temp 'ADHealth-Collection-Summary.json');Set-Content (Join-Path $htmlRoot 'MSADPT-AD-Health.html') '<html></html>'
 $r=& $gate -CollectionRoot $temp;if($r.Status-ne'Passed'){throw 'Gate did not pass synthetic complete evidence'}
 [pscustomobject]@{Status='Passed';TestVersion='1.4.0';CompleteEvidenceAccepted=$true;HashValidationPassed=$true;ReportContractPassed=$true;NetworkActivity='None';ActiveDirectoryQueries='None';RemoteChanges='None'}
}finally{Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
