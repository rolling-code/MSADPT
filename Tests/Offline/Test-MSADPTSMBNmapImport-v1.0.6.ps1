[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$RepositoryRoot)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Importer=Join-Path $RepositoryRoot 'Modules\SMB\Import-MSADPTNmapSMBTargets.ps1'
$Tokens=$null;$ParseErrors=$null;[void][Management.Automation.Language.Parser]::ParseFile($Importer,[ref]$Tokens,[ref]$ParseErrors);if(@($ParseErrors).Count){throw "ImporterParserFailure: $(@($ParseErrors|ForEach-Object{$_.Message})-join'; ')"}
$Temp=Join-Path ([IO.Path]::GetTempPath()) ('MSADPT-NmapXPath-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory $Temp|Out-Null
try{
$Fixture=@"
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -n -Pn -p 445 --open --reason" start="1789495200" startstr="Tue Sep 15 14:00:00 2026">
<host><status state="up" reason="user-set"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><extraports state="closed" count="0"/><port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds"/></port></ports><times srtt="1000"/></host>
<host><status state="up" reason="user-set"/><address addr="192.0.2.11" addrtype="ipv4"/><hostnames><hostname name="fileserver.example.test" type="PTR"/></hostnames><ports><port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/></port></ports></host>
<host><status state="up"/><address addr="192.0.2.12" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="filtered" reason="no-response"/></port></ports></host>
<host><status state="up"/><address addr="192.0.2.13" addrtype="ipv4"/></host>
<runstats><finished time="1789495202" timestr="Tue Sep 15 14:00:02 2026"/><hosts up="4" down="0" total="4"/></runstats>
</nmaprun>
"@
$FixturePath=Join-Path $Temp 'realistic.xml';[IO.File]::WriteAllText($FixturePath,$Fixture,(New-Object Text.UTF8Encoding($false)))
$Result=&$Importer -NmapXmlPath $FixturePath -OutputDirectory (Join-Path $Temp 'output')
if($Result.HostRecordCount-ne4){throw "HostCountMismatch: $($Result.HostRecordCount)"}
if($Result.ConfirmedOpenTcp445TargetCount-ne2){throw "OpenCountMismatch: $($Result.ConfirmedOpenTcp445TargetCount)"}
if($Result.RejectedHostRecordCount-ne2){throw "RejectedCountMismatch: $($Result.RejectedHostRecordCount)"}
if('192.0.2.10'-notin@($Result.Targets)){throw 'AddressFallbackMissing'}
if('fileserver.example.test'-notin@($Result.Targets)){throw 'HostnameSelectionMissing'}
[pscustomobject][ordered]@{Status='Passed';HostRecords=4;ConfirmedOpenImported=2;Rejected=2;AddressFallbackValidated=$true;HostnameSelectionValidated=$true;NetworkActivity='None'}
}finally{Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue}