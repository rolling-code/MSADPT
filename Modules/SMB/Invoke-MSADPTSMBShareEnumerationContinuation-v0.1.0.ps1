<#
.SYNOPSIS
Continues SMB share enumeration only for hosts already proven reachable in prior MSADPT evidence.

.DESCRIPTION
Consumes reachable-host-share-status.json from MSADPT SMB evidence diagnostics and reuses completed
computer discovery, TCP/445 reachability, and Nmap signing evidence. Calls NetShareEnum with an explicit
UInt32 maximum buffer value. It does not rediscover targets, probe TCP, run Nmap, list share roots, traverse
metadata, read file contents, perform write tests, capture credentials, relay authentication, or execute code.

.NOTES
Version: 0.1.0
Package identity: MSADPT-SMB-SHARE-ENUMERATION-CONTINUATION
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$DiagnosticsDirectory,

    [string]$OutputDirectory,
    [ValidateRange(1,5000)][int]$MaximumTargets = 500,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$PackageIdentity='MSADPT-SMB-SHARE-ENUMERATION-CONTINUATION'
$PackageVersion='0.1.0'
$OperationalErrors=New-Object 'System.Collections.Generic.List[object]'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray)
    if($Quiet){return}
    $Text='[{0,-12}] {1}' -f $Status,$Message
    if($NoColor){Write-Host $Text}else{Write-Host $Text -ForegroundColor $Color}
}
function Require-File {
    param([string]$Path,[string]$Label)
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "RequiredFileMissing [$Label]: $Path"}
    if((Get-Item -LiteralPath $Path).Length -eq 0){throw "RequiredFileEmpty [$Label]: $Path"}
}
function Write-JsonArray {
    param([object[]]$Rows,[string]$Path,[int]$Depth=14)
    $Array=[object[]]@($Rows)
    if(@($Array).Count -eq 0){
        [IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))
    }else{
        $Array|ConvertTo-Json -Depth $Depth|Set-Content -LiteralPath $Path -Encoding UTF8
    }
    $RoundTrip=[object[]]@(Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop)
    if(@($RoundTrip).Count -ne @($Array).Count){throw "JsonArrayRoundTripMismatch: $Path"}
}
function Write-JsonDocument {
    param([object]$Document,[string]$Path,[int]$Depth=14)
    $Document|ConvertTo-Json -Depth $Depth|Set-Content -LiteralPath $Path -Encoding UTF8
    $null=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop
}
function Convert-HtmlText { param([object]$Value) return [Net.WebUtility]::HtmlEncode([string]$Value) }
function Get-ShareClass {
    param([string]$Name,[uint32]$Type)
    if($Name -in @('ADMIN$','C$','IPC$','PRINT$')){return 'Administrative'}
    if($Name -in @('SYSVOL','NETLOGON')){return 'DirectoryServices'}
    if(($Type -band [uint32]0x80000000) -ne 0){return 'Special'}
    if(($Type -band 3) -eq 1){return 'Printer'}
    return 'BusinessOrApplication'
}

if(-not('MSADPT.ContinuationNativeShare' -as [type])){
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace MSADPT {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CONTINUATION_SHARE_INFO_1 {
        public string shi1_netname;
        public uint shi1_type;
        public string shi1_remark;
    }
    public static class ContinuationNativeShare {
        [DllImport("Netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern uint NetShareEnum(string servername, int level, out IntPtr bufptr,
            uint prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);
        [DllImport("Netapi32.dll", SetLastError=true)]
        public static extern uint NetApiBufferFree(IntPtr buffer);
    }
}
'@
}

function Get-RemoteSharesCorrected {
    param([string]$Target)
    $Buffer=[IntPtr]::Zero
    $EntriesRead=0
    $TotalEntries=0
    $ResumeHandle=0
    $Rows=New-Object 'System.Collections.Generic.List[object]'
    try{
        do{
            [uint32]$PreferredMaximumLength=[uint32]::MaxValue
            [uint32]$Status=[MSADPT.ContinuationNativeShare]::NetShareEnum(
                "\\$Target",1,[ref]$Buffer,$PreferredMaximumLength,
                [ref]$EntriesRead,[ref]$TotalEntries,[ref]$ResumeHandle
            )
            if($Status -notin @([uint32]0,[uint32]234)){
                $Message=(New-Object ComponentModel.Win32Exception([int]$Status)).Message
                throw "NetShareEnum failed with Win32 status $Status ($Message)"
            }
            $Size=[Runtime.InteropServices.Marshal]::SizeOf([type][MSADPT.CONTINUATION_SHARE_INFO_1])
            for($Index=0;$Index -lt $EntriesRead;$Index++){
                $Pointer=[IntPtr]($Buffer.ToInt64()+($Index*$Size))
                $Info=[Runtime.InteropServices.Marshal]::PtrToStructure($Pointer,[type][MSADPT.CONTINUATION_SHARE_INFO_1])
                $Rows.Add([pscustomobject][ordered]@{
                    Target=$Target
                    ShareName=[string]$Info.shi1_netname
                    UncPath="\\$Target\$([string]$Info.shi1_netname)"
                    ShareType=[uint32]$Info.shi1_type
                    ShareClass=Get-ShareClass -Name ([string]$Info.shi1_netname) -Type ([uint32]$Info.shi1_type)
                    Remark=[string]$Info.shi1_remark
                    RootListingTested=$false
                    MetadataTraversal=$false
                    ContentRead=$false
                    WriteTestPerformed=$false
                })
            }
            if($Buffer -ne [IntPtr]::Zero){
                [void][MSADPT.ContinuationNativeShare]::NetApiBufferFree($Buffer)
                $Buffer=[IntPtr]::Zero
            }
        }while($Status -eq [uint32]234)
        return [object[]]$Rows.ToArray()
    }finally{
        if($Buffer -ne [IntPtr]::Zero){[void][MSADPT.ContinuationNativeShare]::NetApiBufferFree($Buffer)}
    }
}

try{
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'Continuation reuses prior discovery, TCP/445, and Nmap evidence.' DarkGray
    if(-not(Test-Path -LiteralPath $DiagnosticsDirectory -PathType Container)){throw "DiagnosticsDirectoryMissing: $DiagnosticsDirectory"}
    $ReachablePath=Join-Path $DiagnosticsDirectory 'reachable-host-share-status.json'
    Require-File $ReachablePath 'Reachable-host status'
    $Targets=[object[]]@(Get-Content -LiteralPath $ReachablePath -Raw|ConvertFrom-Json -ErrorAction Stop|Select-Object -First $MaximumTargets)
    if(@($Targets).Count -eq 0){throw 'No previously reachable hosts were found.'}
    if([string]::IsNullOrWhiteSpace($OutputDirectory)){$OutputDirectory=Join-Path $DiagnosticsDirectory 'ShareEnumerationContinuation-v0.1.0'}
    if(Test-Path -LiteralPath $OutputDirectory -PathType Container){if(@(Get-ChildItem -LiteralPath $OutputDirectory -Force).Count -gt 0){throw "OutputDirectoryNotEmpty: $OutputDirectory"}}
    New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null

    Write-Step 'NETWORK' 'Planned live network operations follow.' Magenta
    Write-Step 'SCOPE' "Targets=$(@($Targets).Count); Protocol=SMB; Port=TCP/445; Operation=NetShareEnum only." DarkCyan
    foreach($TargetRecord in $Targets){Write-Step 'TARGET' "$($TargetRecord.Target) TCP/445 SMB share enumeration; TCP probe=False; Nmap=False; listing=False; content=False; write=False" DarkCyan}
    Write-Step 'CHANGES' 'Remote file changes=None; credential capture=None; relay=None; remote execution=None.' DarkCyan

    $ShareList=New-Object 'System.Collections.Generic.List[object]'
    $TargetResultList=New-Object 'System.Collections.Generic.List[object]'
    $Position=0
    foreach($TargetRecord in $Targets){
        $Position++
        $TargetName=[string]$TargetRecord.Target
        Write-Step 'ENUMERATE' "$Position/$(@($Targets).Count) $TargetName" Yellow
        try{
            $Shares=[object[]]@(Get-RemoteSharesCorrected -Target $TargetName)
            foreach($Share in $Shares){$ShareList.Add($Share)}
            $TargetResultList.Add([pscustomobject][ordered]@{
                Target=$TargetName;Status='Completed';ShareCount=@($Shares).Count
                TargetRole=[string]$TargetRecord.TargetRole;SigningState=[string]$TargetRecord.SigningState
                SmbV1Detected=[bool]$TargetRecord.SmbV1Detected;Error=$null
            })
        }catch{
            $OperationalErrors.Add([pscustomobject]@{Stage='CorrectedShareEnumeration';Target=$TargetName;Protocol='SMB';Port=445;Error=$_.Exception.Message})
            $TargetResultList.Add([pscustomobject][ordered]@{
                Target=$TargetName;Status='Failed';ShareCount=0
                TargetRole=[string]$TargetRecord.TargetRole;SigningState=[string]$TargetRecord.SigningState
                SmbV1Detected=[bool]$TargetRecord.SmbV1Detected;Error=$_.Exception.Message
            })
        }
    }

    $ShareRows=[object[]]$ShareList.ToArray()
    $TargetResults=[object[]]$TargetResultList.ToArray()
    $ErrorRows=[object[]]$OperationalErrors.ToArray()
    $SuccessfulTargets=[int]@($TargetResults|Where-Object{$_.Status -eq 'Completed'}).Count
    $FailedTargets=[int]@($TargetResults|Where-Object{$_.Status -eq 'Failed'}).Count
    $TotalShares=[int]@($ShareRows).Count
    $AdministrativeShares=[int]@($ShareRows|Where-Object{$_.ShareClass -in @('Administrative','Special')}).Count
    $DirectoryServicesShares=[int]@($ShareRows|Where-Object{$_.ShareClass -eq 'DirectoryServices'}).Count
    $BusinessShares=[int]@($ShareRows|Where-Object{$_.ShareClass -eq 'BusinessOrApplication'}).Count
    $PrinterShares=[int]@($ShareRows|Where-Object{$_.ShareClass -eq 'Printer'}).Count

    $SharesJson=Join-Path $OutputDirectory 'smb-share-inventory-continuation.json'
    $SharesCsv=Join-Path $OutputDirectory 'smb-share-inventory-continuation.csv'
    $TargetsJson=Join-Path $OutputDirectory 'smb-share-enumeration-target-results.json'
    $TargetsCsv=Join-Path $OutputDirectory 'smb-share-enumeration-target-results.csv'
    $ErrorsJson=Join-Path $OutputDirectory 'operational-errors.json'
    Write-JsonArray $ShareRows $SharesJson;$ShareRows|Export-Csv -LiteralPath $SharesCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $TargetResults $TargetsJson;$TargetResults|Export-Csv -LiteralPath $TargetsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $ErrorRows $ErrorsJson

    $Summary=[pscustomobject][ordered]@{
        SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Status=if($FailedTargets -gt 0){'CompletedWithErrors'}else{'Completed'}
        GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        SourceDiagnosticsDirectory=$DiagnosticsDirectory
        Counts=[pscustomobject]@{Targets=@($Targets).Count;SuccessfulTargets=$SuccessfulTargets;FailedTargets=$FailedTargets;Shares=$TotalShares;AdministrativeOrSpecialShares=$AdministrativeShares;DirectoryServicesShares=$DirectoryServicesShares;BusinessOrApplicationShares=$BusinessShares;PrinterShares=$PrinterShares}
        ReusedEvidence=[pscustomobject]@{TargetDiscovery=$true;TcpReachability=$true;SigningEvidence=$true;NmapEvidence=$true}
        InterpretationBoundary=@('Share enumeration is an inventory action, not a vulnerability finding.','No share root was listed and no file content was read.','Nonadministrative shares require separate access and exposure validation.','Signing optional remains a relay prerequisite only.')
        Safety=[pscustomobject]@{RepeatedDiscovery='None';RepeatedTcpProbe='None';RepeatedNmap='None';RootListing='None';MetadataTraversal='None';ContentReads='None';RemoteFileChanges='None';RelayAttempts='None';RemoteExecution='None'}
    }
    $SummaryPath=Join-Path $OutputDirectory 'smb-share-enumeration-continuation-summary.json';Write-JsonDocument $Summary $SummaryPath

    $BusinessHtml=($ShareRows|Where-Object{$_.ShareClass -notin @('Administrative','Special')}|ForEach-Object{
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (Convert-HtmlText $_.Target),(Convert-HtmlText $_.ShareName),(Convert-HtmlText $_.ShareClass),(Convert-HtmlText $_.Remark)
    })-join"`n"
    $ReportPath=Join-Path $OutputDirectory 'MSADPT-SMB-Share-Enumeration-Continuation.html'
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT SMB Share Enumeration Continuation</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left}th{background:#eaf2f8}</style></head><body><h1>MSADPT SMB Share Enumeration Continuation</h1><div class="card"><b>Targets reused:</b> $(@($Targets).Count)<br><b>Successful:</b> $SuccessfulTargets<br><b>Failed:</b> $FailedTargets<br><b>Total shares:</b> $TotalShares<br><b>Business/application:</b> $BusinessShares<br><b>Directory services:</b> $DirectoryServicesShares<br><b>Discovery repeated:</b> No<br><b>TCP probes repeated:</b> No<br><b>Nmap repeated:</b> No<br><b>Root listing:</b> None<br><b>Content read:</b> None<br><b>Remote changes:</b> None</div><h2>Nonadministrative Shares</h2><table><tr><th>Target</th><th>Share</th><th>Class</th><th>Remark</th></tr>$BusinessHtml</table><h2>Evidence</h2><ul><li><a href="smb-share-inventory-continuation.csv">Share inventory</a></li><li><a href="smb-share-enumeration-target-results.csv">Target results</a></li><li><a href="operational-errors.json">Operational errors</a></li><li><a href="smb-share-enumeration-continuation-summary.json">Summary</a></li></ul></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File|Where-Object{$_.Name -ne 'evidence-manifest.json'}|Sort-Object Name)
    $ManifestRows=[object[]]@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json';Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=@($ManifestRows).Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "Continuation complete: targets=$(@($Targets).Count), successful=$SuccessfulTargets, failed=$FailedTargets, shares=$TotalShares, business=$BusinessShares, directory-services=$DirectoryServicesShares." Green
    [pscustomobject][ordered]@{
        Status=if($FailedTargets -gt 0){'PassedWithErrors'}else{'Passed'}
        PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        TargetCount=@($Targets).Count;SuccessfulTargetCount=$SuccessfulTargets;FailedTargetCount=$FailedTargets
        ShareCount=$TotalShares;AdministrativeOrSpecialShareCount=$AdministrativeShares
        DirectoryServicesShareCount=$DirectoryServicesShares;BusinessOrApplicationShareCount=$BusinessShares;PrinterShareCount=$PrinterShares
        OutputDirectory=$OutputDirectory;HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath
        RepeatedTargetDiscovery='No';RepeatedTcpProbe='No';RepeatedNmap='No';RootListing='None';ContentReads='None';RemoteFileChanges='None';RelayAttempts='None';RemoteExecution='None'
    }
}catch{
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
