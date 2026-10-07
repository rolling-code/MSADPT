<#
.SYNOPSIS
Collects read-only native Active Directory health evidence with explicit target and protocol disclosure.
.NOTES
Version: 1.3.0
Supports Windows PowerShell 5.1 and PowerShell 7 on Windows.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$OutputRoot,
 [string]$DomainControllerInventoryPath,
 [string[]]$DomainController=@(),
 [ValidateRange(10,3600)][int]$CommandTimeoutSeconds=180,
 [switch]$PlanOnly,
 [switch]$SkipEventLogs,
 [switch]$SkipOfflineAssessment
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Version='1.3.0'
function Show{param([string]$State,[string]$Message,[ConsoleColor]$Color='Gray');Write-Host ('[{0,-12}] {1}'-f$State,$Message)-ForegroundColor $Color}
function Safe([string]$Value){($Value-replace'[^A-Za-z0-9._-]','_')}
function Get-Targets{
 $list=New-Object 'System.Collections.Generic.List[string]'
 foreach($dc in @($DomainController)){if(-not[string]::IsNullOrWhiteSpace($dc)){$list.Add($dc.Trim())}}
 if($DomainControllerInventoryPath){
  if(-not(Test-Path -LiteralPath $DomainControllerInventoryPath -PathType Leaf)){throw "InventoryMissing: $DomainControllerInventoryPath"}
  foreach($row in @(Import-Csv -LiteralPath $DomainControllerInventoryPath)){
   $value=$null
   foreach($name in @('Target','HostName','Hostname','DNSHostName','DnsHostName','DomainController','Name','Server')){if($row.PSObject.Properties[$name] -and -not[string]::IsNullOrWhiteSpace([string]$row.$name)){$value=[string]$row.$name;break}}
   if($value){$list.Add($value.Trim())}
  }
 }
 @($list.ToArray()|Sort-Object -Unique)
}
$targets=@(Get-Targets);if(-not$targets.Count){throw 'NoDomainControllersResolved: supply -DomainControllerInventoryPath or -DomainController.'}
$OutputRoot=[IO.Path]::GetFullPath($OutputRoot);$raw=Join-Path $OutputRoot 'Raw';New-Item -ItemType Directory -Path $raw -Force|Out-Null
$plan=New-Object 'System.Collections.Generic.List[object]'
foreach($dc in $targets){
 $s=Safe $dc
 $plan.Add([pscustomobject]@{Target=$dc;Utility='dcdiag.exe';Operation='Connectivity Advertising Services MachineAccount';Execution='Local utility targeting remote DC';Protocols='DNS, LDAP, Kerberos, RPC, SMB as required by DCDiag';Ports='53 TCP/UDP; 88 TCP/UDP; 135 TCP; 389 TCP/UDP; 445 TCP; dynamic RPC';OutputFile="DCDiag-$s.txt"})
 $plan.Add([pscustomobject]@{Target=$dc;Utility='repadmin.exe';Operation='/showrepl';Execution='Local utility targeting remote DC';Protocols='RPC, LDAP';Ports='135 TCP; 389 TCP; dynamic RPC';OutputFile="Repadmin-ShowRepl-$s.txt"})
 $plan.Add([pscustomobject]@{Target=$dc;Utility='repadmin.exe';Operation='/queue';Execution='Local utility targeting remote DC';Protocols='RPC';Ports='135 TCP; dynamic RPC';OutputFile="Repadmin-Queue-$s.txt"})
 $plan.Add([pscustomobject]@{Target=$dc;Utility='nltest.exe';Operation='/server /query';Execution='Local utility targeting remote DC';Protocols='Netlogon RPC, SMB';Ports='135 TCP; 445 TCP; dynamic RPC';OutputFile="Nltest-Query-$s.txt"})
 $plan.Add([pscustomobject]@{Target=$dc;Utility='nltest.exe';Operation='/server /dsgetsite';Execution='Local utility targeting remote DC';Protocols='Netlogon RPC, SMB';Ports='135 TCP; 445 TCP; dynamic RPC';OutputFile="Nltest-DSGetSite-$s.txt"})
 $plan.Add([pscustomobject]@{Target=$dc;Utility='w32tm.exe';Operation='/query /status';Execution='Local utility targeting remote DC';Protocols='Windows Time, RPC';Ports='123 UDP; 135 TCP; dynamic RPC';OutputFile="W32tm-Status-$s.txt"})
 if(-not$SkipEventLogs){$plan.Add([pscustomobject]@{Target=$dc;Utility='Get-WinEvent';Operation='Directory Service and DFS Replication recent warning/error events';Execution='Remote event-log read';Protocols='Windows Event Log RPC';Ports='135 TCP; dynamic RPC';OutputFile="EventLog-DirectoryService-$s.json"})}
}
$plan.Add([pscustomobject]@{Target='Domain';Utility='repadmin.exe';Operation='/replsummary';Execution='Local utility; domain-wide summary';Protocols='RPC, LDAP';Ports='135 TCP; 389 TCP; dynamic RPC';OutputFile='Repadmin-ReplSummary.txt'})
$planPath=Join-Path $OutputRoot 'ADHealth-Collection-Plan.csv';@($plan.ToArray())|Export-Csv -LiteralPath $planPath -NoTypeInformation -Encoding UTF8
Show TARGETS ("Domain controllers ({0}): {1}"-f$targets.Count,($targets-join', ')) Cyan
Show NETWORK 'Planned protocols/ports are disclosed below for SOC coordination. No write operations are included.' Yellow
$plan|Format-Table Target,Utility,Operation,Protocols,Ports,OutputFile -Wrap|Out-Host
if($PlanOnly){Show PLANONLY "Plan exported: $planPath" Green;return [pscustomobject]@{Status='Planned';CollectorVersion=$Version;TargetCount=$targets.Count;CommandCount=$plan.Count;PlanPath=$planPath;NetworkActivity='None';ActiveDirectoryQueries='None';RemoteChanges='None'}}
if($PSVersionTable.Platform -and $PSVersionTable.Platform-ne'Win32NT'){throw 'WindowsRequired: native AD health utilities require Windows.'}
$results=New-Object 'System.Collections.Generic.List[object]'
function Run-Native{
 param([string]$Target,[string]$Utility,[string[]]$Arguments,[string]$OutputFile,[string]$Operation)
 $path=Join-Path $raw $OutputFile;$stderr="$path.stderr.txt";$started=(Get-Date).ToUniversalTime();$status='Completed';$exit=$null;$timedOut=$false
 $cmd=Get-Command $Utility -ErrorAction SilentlyContinue
 if(-not$cmd){$status='ToolUnavailable';[IO.File]::WriteAllText($path,"Tool unavailable: $Utility",(New-Object Text.UTF8Encoding($false)))}else{
  Show RUN "$Utility $($Arguments-join' ') -> $OutputFile" DarkCyan
  $p=Start-Process -FilePath $cmd.Source -ArgumentList $Arguments -NoNewWindow -PassThru -RedirectStandardOutput $path -RedirectStandardError $stderr
  if(-not$p.WaitForExit($CommandTimeoutSeconds*1000)){try{$p.Kill()}catch{};$timedOut=$true;$status='TimedOut'}else{$exit=$p.ExitCode;if($exit-ne0){$status='Failed'}}
 }
 $finished=(Get-Date).ToUniversalTime();$hash=if(Test-Path -LiteralPath $path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}else{$null}
 $results.Add([pscustomobject]@{Target=$Target;Utility=$Utility;Operation=$Operation;Status=$status;ExitCode=$exit;TimedOut=$timedOut;StartedUtc=$started.ToString('o');CompletedUtc=$finished.ToString('o');DurationMilliseconds=[math]::Round(($finished-$started).TotalMilliseconds);OutputPath=$path;SHA256=$hash;StandardErrorPath=if(Test-Path $stderr){$stderr}else{$null}})
}
foreach($dc in $targets){$s=Safe $dc
 Run-Native $dc 'dcdiag.exe' @('/s:'+$dc,'/test:Connectivity','/test:Advertising','/test:Services','/test:MachineAccount','/v') "DCDiag-$s.txt" 'Selected read-only DCDiag tests'
 Run-Native $dc 'repadmin.exe' @('/showrepl',$dc,'/verbose') "Repadmin-ShowRepl-$s.txt" '/showrepl'
 Run-Native $dc 'repadmin.exe' @('/queue',$dc) "Repadmin-Queue-$s.txt" '/queue'
 Run-Native $dc 'nltest.exe' @('/server:'+$dc,'/query') "Nltest-Query-$s.txt" '/query'
 Run-Native $dc 'nltest.exe' @('/server:'+$dc,'/dsgetsite') "Nltest-DSGetSite-$s.txt" '/dsgetsite'
 Run-Native $dc 'w32tm.exe' @('/query','/computer:'+$dc,'/status','/verbose') "W32tm-Status-$s.txt" '/query /status'
 if(-not$SkipEventLogs){
  $ep=Join-Path $raw "EventLog-DirectoryService-$s.json";$started=(Get-Date).ToUniversalTime();$status='Completed';$items=@();$lim=@()
  try{foreach($log in @('Directory Service','DFS Replication')){try{$items+=@(Get-WinEvent -ComputerName $dc -FilterHashtable @{LogName=$log;Level=1,2,3;StartTime=(Get-Date).AddDays(-7)} -ErrorAction Stop|Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,LogName,MachineName,Message)}catch{$lim+=@("${log}: $($_.Exception.Message)")}};@{QuerySucceeded=($lim.Count-eq0);Target=$dc;WindowDays=7;Events=$items;Limitations=$lim}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ep -Encoding UTF8;if($lim.Count){$status='Partial'}}catch{$status='Failed';@{QuerySucceeded=$false;Target=$dc;Events=@();Limitations=@($_.Exception.Message)}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $ep -Encoding UTF8}
  $finished=(Get-Date).ToUniversalTime();$results.Add([pscustomobject]@{Target=$dc;Utility='Get-WinEvent';Operation='Directory Service and DFS Replication';Status=$status;ExitCode=$null;TimedOut=$false;StartedUtc=$started.ToString('o');CompletedUtc=$finished.ToString('o');DurationMilliseconds=[math]::Round(($finished-$started).TotalMilliseconds);OutputPath=$ep;SHA256=(Get-FileHash -LiteralPath $ep -Algorithm SHA256).Hash;StandardErrorPath=$null})
 }
}
Run-Native 'Domain' 'repadmin.exe' @('/replsummary') 'Repadmin-ReplSummary.txt' '/replsummary'
$manifestPath=Join-Path $OutputRoot 'ADHealth-Collection-Manifest.json';@($results.ToArray())|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $manifestPath -Encoding UTF8
$targetsPath=Join-Path $OutputRoot 'ExpectedTargets.csv';@($targets|ForEach-Object{[pscustomobject]@{Target=$_}})|Export-Csv -LiteralPath $targetsPath -NoTypeInformation -Encoding UTF8
$assessment=$null;if(-not$SkipOfflineAssessment){$prep=Join-Path $PSScriptRoot 'Prepare-MSADPTADHealthEvidence-v1.2.0.ps1';if(Test-Path -LiteralPath $prep){$assessment=& $prep -SourceEvidenceRoot $raw -OutputRoot (Join-Path $OutputRoot 'OfflineAssessment') -ExpectedTargetPath $targetsPath}else{Show WARN 'Preparation module v1.2.0 not found; collection retained for later offline analysis.' Yellow}}
$summary=[pscustomobject]@{Status='Completed';CollectorVersion=$Version;TargetCount=$targets.Count;ResultCount=$results.Count;CompletedCount=@($results|Where-Object Status -eq'Completed').Count;PartialCount=@($results|Where-Object Status -eq'Partial').Count;FailedCount=@($results|Where-Object Status -eq'Failed').Count;TimedOutCount=@($results|Where-Object Status -eq'TimedOut').Count;ToolUnavailableCount=@($results|Where-Object Status -eq'ToolUnavailable').Count;PlanPath=$planPath;ManifestPath=$manifestPath;ExpectedTargetsPath=$targetsPath;RawEvidenceRoot=$raw;OfflineAssessmentStatus=if($assessment){$assessment.Status}else{'NotRun'};RemoteChanges='None';GitChanges='None'}
$summary|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $OutputRoot 'ADHealth-Collection-Summary.json') -Encoding UTF8;Show PASSED "Collection completed. Raw evidence: $raw" Green;$summary
