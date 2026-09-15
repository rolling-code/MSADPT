<#
.SYNOPSIS
Imports confirmed-open TCP/445 targets from operator-generated Nmap XML.
.DESCRIPTION
Uses XPath over local Nmap XML. Only host records explicitly marked up with TCP/445 explicitly marked
open are eligible. Missing optional metadata remains null. MSADPT does not execute Nmap.
.NOTES
Version: 1.0.5
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$NmapXmlPath,
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputDirectory
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function Get-AttributeValue{
 param([System.Xml.XmlNode]$Node,[string]$Name)
 if($null-eq$Node-or$null-eq$Node.Attributes){return $null}
 $Attribute=$Node.Attributes[$Name]
 if($null-eq$Attribute){return $null}
 return [string]$Attribute.Value
}
if(-not(Test-Path -LiteralPath $NmapXmlPath -PathType Leaf)){throw "NmapXmlMissing: $NmapXmlPath"}
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
try{[xml]$Xml=Get-Content -LiteralPath $NmapXmlPath -Raw -ErrorAction Stop}catch{throw "NmapXmlParseFailure: $($_.Exception.Message)"}
$RootNode=$Xml.SelectSingleNode('/nmaprun')
if($null-eq$RootNode){throw 'NmapXmlSchemaUnsupported: /nmaprun is missing.'}
$HostNodes=@($Xml.SelectNodes('/nmaprun/host'))
$Rows=New-Object 'Collections.Generic.List[object]'
$Targets=New-Object 'Collections.Generic.List[string]'
foreach($HostNode in $HostNodes){
 $StatusNode=$HostNode.SelectSingleNode('./status')
 $HostState=Get-AttributeValue $StatusNode 'state'
 if([string]::IsNullOrWhiteSpace($HostState)){$HostState='Missing'}
 $AddressRows=@()
 foreach($AddressNode in @($HostNode.SelectNodes('./address'))){
  $AddressRows+=[pscustomobject][ordered]@{Address=Get-AttributeValue $AddressNode 'addr';Type=Get-AttributeValue $AddressNode 'addrtype'}
 }
 $HostnameRows=@()
 foreach($HostnameNode in @($HostNode.SelectNodes('./hostnames/hostname'))){
  $HostnameValue=Get-AttributeValue $HostnameNode 'name'
  if(-not[string]::IsNullOrWhiteSpace($HostnameValue)){$HostnameRows+=$HostnameValue}
 }
 $PortNode=$HostNode.SelectSingleNode('./ports/port[@protocol="tcp" and @portid="445"]')
 $StateNode=if($null-ne$PortNode){$PortNode.SelectSingleNode('./state')}else{$null}
 $PortState=Get-AttributeValue $StateNode 'state'
 if([string]::IsNullOrWhiteSpace($PortState)){$PortState='Missing'}
 $PortReason=Get-AttributeValue $StateNode 'reason'
 $Eligible=$HostState-eq'up'-and$PortState-eq'open'
 $SelectedTarget=@($HostnameRows|Select-Object -First 1)
 if($SelectedTarget.Count-eq0){$SelectedTarget=@($AddressRows|Where-Object{$_.Type-eq'ipv4'}|Select-Object -ExpandProperty Address -First 1)}
 if($SelectedTarget.Count-eq0){$SelectedTarget=@($AddressRows|Select-Object -ExpandProperty Address -First 1)}
 $Preferred=if($SelectedTarget.Count){[string]$SelectedTarget[0]}else{$null}
 $Rows.Add([pscustomobject][ordered]@{HostState=$HostState;Port=445;Protocol='tcp';PortState=$PortState;Eligible=$Eligible;SelectedTarget=$Preferred;Hostnames=@($HostnameRows);Addresses=@($AddressRows);Reason=$PortReason})
 if($Eligible-and-not[string]::IsNullOrWhiteSpace($Preferred)){$Targets.Add($Preferred)}
}
$UniqueTargets=@($Targets|Sort-Object -Unique)
$EvidencePath=Join-Path $OutputDirectory 'nmap-smb-target-evidence.json'
$TargetsPath=Join-Path $OutputDirectory 'nmap-smb-open-targets.txt'
$SummaryPath=Join-Path $OutputDirectory 'nmap-smb-import-summary.json'
$Rows.ToArray()|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $EvidencePath -Encoding UTF8
if($UniqueTargets.Count){$UniqueTargets|Set-Content -LiteralPath $TargetsPath -Encoding UTF8}else{[IO.File]::WriteAllText($TargetsPath,'',(New-Object Text.UTF8Encoding($false)))}
$FinishedNode=$Xml.SelectSingleNode('/nmaprun/runstats/finished')
$Summary=[pscustomobject][ordered]@{
 SchemaVersion='1.0';ImporterVersion='1.0.6';Status='Completed'
 SourcePath=[IO.Path]::GetFullPath($NmapXmlPath);SourceSha256=(Get-FileHash -LiteralPath $NmapXmlPath -Algorithm SHA256).Hash
 NmapArguments=Get-AttributeValue $RootNode 'args';ScanStart=Get-AttributeValue $RootNode 'startstr';ScanFinished=Get-AttributeValue $FinishedNode 'timestr'
 HostRecordCount=$Rows.Count;ConfirmedOpenTcp445TargetCount=$UniqueTargets.Count;RejectedHostRecordCount=@($Rows|Where-Object{-not$_.Eligible}).Count
 Targets=@($UniqueTargets);SelectionRule='host state=up AND protocol=tcp AND portid=445 AND port state=open'
 EvidencePath=$EvidencePath;TargetsPath=$TargetsPath;NetworkActivity='None';NmapExecution='None'
}
$Summary|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $SummaryPath -Encoding UTF8
$Summary