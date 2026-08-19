<#
.SYNOPSIS
Creates deterministic raw-output parser fixtures for ADCS CA-runtime interpretation.
.NOTES
Version: 1.0.0
All data is synthetic. No network or system query is performed.
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null

function New-Query {
    param([string]$Name,[string]$Status,[Nullable[int]]$ExitCode,[string]$Output,[string]$ErrorText)
    [pscustomobject][ordered]@{
        Name=$Name
        Result=[pscustomobject][ordered]@{
            CaConfiguration='ca01.example.test\EXAMPLE-CA';Arguments=@('-config','ca01.example.test\EXAMPLE-CA','-getreg','synthetic')
            Status=$Status;ExitCode=$ExitCode;StandardOutput=$Output;StandardError=$ErrorText
            StartedUtc='2026-08-13T20:00:00Z';CompletedUtc='2026-08-13T20:00:01Z'
        }
    }
}

$Cases=[ordered]@{
    HexKnownFlag=@(New-Query 'EditFlags' 'Completed' 0 'policy\EditFlags REG_DWORD = 0x00040000' '')
    DecimalValue=@(New-Query 'InterfaceFlags' 'Completed' 0 'CA\InterfaceFlags REG_DWORD = 512' '')
    FrenchNumeric=@(New-Query 'EditFlags' 'Completed' 0 'Valeur du registre : 0x00040000' '')
    AccessDenied=@(New-Query 'EnrollmentAgentRights' 'Failed' 5 '' 'Access is denied.')
    FrenchAccessDenied=@(New-Query 'OfficerRights' 'Failed' 5 '' 'Acces refuse')
    ValueNotFound=@(New-Query 'OfficerRights' 'Failed' 2 '' 'The system cannot find the registry value.')
    FrenchValueNotFound=@(New-Query 'OfficerRights' 'Failed' 2 '' 'Valeur introuvable')
    RpcUnavailable=@(New-Query 'Ping' 'Failed' 1722 '' 'The RPC server is unavailable.')
    Timeout=@(New-Query 'Ping' 'TimedOut' $null '' 'Command timeout')
    EmptyOutput=@(New-Query 'EditFlags' 'Completed' 0 '' '')
    UnknownText=@(New-Query 'EditFlags' 'Completed' 0 'Unstructured output without a value' '')
    NonZeroPartial=@(New-Query 'EditFlags' 'Failed' 1 'Partial output 0x00040000' 'Synthetic failure')
}

$Index=New-Object 'System.Collections.Generic.List[object]'
foreach($Case in $Cases.GetEnumerator()){
    $Path=Join-Path $OutputDirectory ($Case.Key+'.json')
    @([pscustomobject][ordered]@{
        Name='EXAMPLE-CA';DisplayName='EXAMPLE-CA';DnsHostName='ca01.example.test';CaConfiguration='ca01.example.test\EXAMPLE-CA'
        DistinguishedName='CN=EXAMPLE-CA,CN=Enrollment Services,CN=Configuration,DC=example,DC=test';Flags='10';PublishedTemplates=@()
        DirectorySecurity=[pscustomobject]@{Status='Collected';Owner='EXAMPLE\Enterprise Admins';AccessEntries=@();Error=$null}
        PortEvidence=@();CertutilQueries=@($Case.Value)
    })|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $Path -Encoding UTF8
    $Index.Add([pscustomobject]@{Case=$Case.Key;EvidencePath=$Path})
}
$IndexPath=Join-Path $OutputDirectory 'parser-fixture-index.json'
$Index.ToArray()|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $IndexPath -Encoding UTF8
[pscustomobject]@{Status='Completed';CaseCount=$Index.Count;IndexPath=$IndexPath;OutputDirectory=$OutputDirectory}
