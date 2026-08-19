<#
.SYNOPSIS
Runs the MSADPT read-only SMB share and pivot-surface assessment in one command.

.DESCRIPTION
Discovers enabled Windows computers from Active Directory or accepts an explicit target list. Before
network activity, displays every target, port, protocol, authentication context, and planned operation.
Tests TCP/445, optionally collects SMB signing evidence with Nmap, enumerates shares with NetShareEnum,
validates root listing access, and performs bounded metadata-only discovery for selected file patterns.

The baseline does not open file contents, copy files, modify remote files, execute programs, capture
credentials, poison name resolution, relay authentication, or perform remote command execution.

.NOTES
Version: 0.1.1
Package identity: MSADPT-SMB-SHARE-PIVOT-ASSESSMENT
Execution class: authorized_read_only_live_validation
#>
[CmdletBinding()]
param(
    [ValidateSet('Servers','AllWindows','DomainControllers')]
    [string]$TargetMode = 'Servers',

    [string[]]$ComputerName,
    [string]$TargetListPath,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$OutputDirectory,

    [ValidateRange(1,5000)]
    [int]$MaximumTargets = 500,

    [ValidateRange(1,10)]
    [int]$TcpTimeoutSeconds = 3,

    [ValidateRange(0,8)]
    [int]$MaximumShareDepth = 2,

    [ValidateRange(1,10000)]
    [int]$MaximumEntriesPerShare = 500,

    [ValidateRange(1,120)]
    [int]$ShareOperationTimeoutSeconds = 15,

    [switch]$SkipNmap,
    [switch]$SkipFileMetadata,
    [switch]$IncludeAdministrativeShareMetadata,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$PackageIdentity = 'MSADPT-SMB-SHARE-PIVOT-ASSESSMENT'
$PackageVersion = '0.1.1'
$OperationalErrors = New-Object 'System.Collections.Generic.List[object]'

$InterestingPatterns = @(
    '*.ps1','*.psm1','*.psd1','*.bat','*.cmd','*.vbs','*.xml','*.config','*.ini',
    '*.kdbx','*.rdp','*.ppk','*.pem','*.pfx','*.p12','*.key','*.ovpn','*.sql','*.bak',
    'unattend*.xml','web.config','appsettings*.json','Groups.xml','Services.xml',
    'ScheduledTasks.xml','Registry.xml','Drives.xml','Printers.xml','DataSources.xml'
)

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray)
    if ($Quiet) { return }
    $Text = '[{0,-12}] {1}' -f $Status,$Message
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}

function Add-OperationalError {
    param([string]$Stage,[string]$Target,[string]$Protocol,[object]$Port,[string]$ErrorText)
    $OperationalErrors.Add([pscustomobject][ordered]@{
        Stage=$Stage;Target=$Target;Protocol=$Protocol;Port=$Port
        Status='Failed';Error=$ErrorText
    })
}

function Require-File {
    param([string]$Path,[string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "RequiredFileMissing [$Label]: $Path" }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) { throw "RequiredFileEmpty [$Label]: $Path" }
}

function Write-JsonArray {
    param([object[]]$Rows,[string]$Path,[int]$Depth=16)
    $Array = [object[]]@($Rows)
    if (@($Array).Count -eq 0) {
        [IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))
    } else {
        $Array | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    $Check = [object[]]@(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
    if (@($Check).Count -ne @($Array).Count) { throw "JsonArrayRoundTripMismatch: $Path" }
}

function Write-JsonDocument {
    param([object]$Document,[string]$Path,[int]$Depth=16)
    $Document | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}

function Convert-HtmlText {
    param([object]$Value)
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

function Test-Tcp445 {
    param([string]$Target,[int]$TimeoutSeconds)
    $Started = Get-Date
    $Client = New-Object Net.Sockets.TcpClient
    try {
        $Task = $Client.ConnectAsync($Target,445)
        if (-not $Task.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            return [pscustomobject]@{Target=$Target;Port=445;Protocol='SMB';Status='TimedOut';Connected=$false;ElapsedMs=[int]((Get-Date)-$Started).TotalMilliseconds;Error=$null}
        }
        return [pscustomobject]@{Target=$Target;Port=445;Protocol='SMB';Status='Completed';Connected=[bool]$Client.Connected;ElapsedMs=[int]((Get-Date)-$Started).TotalMilliseconds;Error=$null}
    } catch {
        return [pscustomobject]@{Target=$Target;Port=445;Protocol='SMB';Status='Failed';Connected=$false;ElapsedMs=[int]((Get-Date)-$Started).TotalMilliseconds;Error=$_.Exception.Message}
    } finally {
        $Client.Dispose()
    }
}

function Get-ShareClass {
    param([string]$Name,[int]$Type)
    if ($Name -in @('ADMIN$','C$','IPC$','PRINT$')) { return 'Administrative' }
    if ($Name -in @('SYSVOL','NETLOGON')) { return 'DirectoryServices' }
    if (($Type -band 0x80000000) -ne 0) { return 'Special' }
    if (($Type -band 3) -eq 1) { return 'Printer' }
    return 'BusinessOrApplication'
}

function Test-InterestingFileName {
    param([string]$Name)
    foreach ($Pattern in $InterestingPatterns) {
        if ($Name -like $Pattern) { return $true }
    }
    return $false
}

function Get-BoundedShareMetadata {
    param(
        [string]$Target,
        [string]$ShareName,
        [int]$MaximumDepth,
        [int]$MaximumEntries,
        [int]$TimeoutSeconds
    )

    $Rows = New-Object 'System.Collections.Generic.List[object]'
    $Root = "\\$Target\$ShareName"
    $Queue = New-Object 'System.Collections.Generic.Queue[object]'
    $Queue.Enqueue([pscustomobject]@{Path=$Root;RelativePath='';Depth=0})
    $Started = Get-Date
    $Truncated = $false

    while ($Queue.Count -gt 0) {
        if (((Get-Date)-$Started).TotalSeconds -ge $TimeoutSeconds) { $Truncated=$true;break }
        if ($Rows.Count -ge $MaximumEntries) { $Truncated=$true;break }
        $Node = $Queue.Dequeue()
        try {
            $Items = @(Get-ChildItem -LiteralPath $Node.Path -Force -ErrorAction Stop)
            foreach ($Item in $Items) {
                if ($Rows.Count -ge $MaximumEntries) { $Truncated=$true;break }
                $Relative = if ([string]::IsNullOrWhiteSpace($Node.RelativePath)) { $Item.Name } else { Join-Path $Node.RelativePath $Item.Name }
                $Interesting = if ($Item.PSIsContainer) { $false } else { Test-InterestingFileName $Item.Name }
                $Rows.Add([pscustomobject][ordered]@{
                    Target=$Target;Share=$ShareName;RelativePath=$Relative
                    EntryType=if($Item.PSIsContainer){'Directory'}else{'File'}
                    Extension=if($Item.PSIsContainer){$null}else{[string]$Item.Extension}
                    Size=if($Item.PSIsContainer){$null}else{[int64]$Item.Length}
                    LastWriteTimeUtc=if($null-ne$Item.LastWriteTimeUtc){$Item.LastWriteTimeUtc.ToString('o')}else{$null}
                    Depth=[int]$Node.Depth;InterestingName=[bool]$Interesting
                    ContentRead=$false
                })
                if ($Item.PSIsContainer -and [int]$Node.Depth -lt $MaximumDepth) {
                    $Queue.Enqueue([pscustomobject]@{Path=$Item.FullName;RelativePath=$Relative;Depth=([int]$Node.Depth+1)})
                }
            }
        } catch {
            Add-OperationalError 'ShareMetadata' "$Target\$ShareName\$($Node.RelativePath)" 'SMB' 445 $_.Exception.Message
        }
    }

    return [pscustomobject]@{Rows=[object[]]$Rows.ToArray();Truncated=$Truncated;ElapsedMs=[int]((Get-Date)-$Started).TotalMilliseconds}
}

if (-not ('MSADPT.NativeShare' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace MSADPT {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct SHARE_INFO_1 {
        public string shi1_netname;
        public uint shi1_type;
        public string shi1_remark;
    }
    public static class NativeShare {
        [DllImport("Netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern uint NetShareEnum(string servername, int level, out IntPtr bufptr, uint prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);
        [DllImport("Netapi32.dll", SetLastError=true)]
        public static extern uint NetApiBufferFree(IntPtr Buffer);
    }
}
'@
}

function Get-RemoteShares {
    param([string]$Target)
    $Buffer=[IntPtr]::Zero;$Read=0;$Total=0;$Resume=0
    $Results=New-Object 'System.Collections.Generic.List[object]'
    try {
        do {
            $Status=[MSADPT.NativeShare]::NetShareEnum("\\$Target",1,[ref]$Buffer,0xFFFFFFFF,[ref]$Read,[ref]$Total,[ref]$Resume)
            if ($Status -notin @(0,234)) { throw "NetShareEnum failed with Win32 status $Status" }
            $Size=[Runtime.InteropServices.Marshal]::SizeOf([type][MSADPT.SHARE_INFO_1])
            for($i=0;$i-lt$Read;$i++){
                $Pointer=[IntPtr]($Buffer.ToInt64()+($i*$Size))
                $Info=[Runtime.InteropServices.Marshal]::PtrToStructure($Pointer,[type][MSADPT.SHARE_INFO_1])
                $Results.Add([pscustomobject]@{Name=$Info.shi1_netname;Type=[int64]$Info.shi1_type;Remark=$Info.shi1_remark})
            }
            if($Buffer-ne[IntPtr]::Zero){[void][MSADPT.NativeShare]::NetApiBufferFree($Buffer);$Buffer=[IntPtr]::Zero}
        } while ($Status-eq234)
        return [object[]]$Results.ToArray()
    } finally {
        if($Buffer-ne[IntPtr]::Zero){[void][MSADPT.NativeShare]::NetApiBufferFree($Buffer)}
    }
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Import-Module ActiveDirectory -ErrorAction Stop

    $Discovery=@{ErrorAction='Stop'}
    if($null-ne$Credential){$Discovery.Credential=$Credential}
    $Domain=Get-ADDomain @Discovery

    $TargetRows=New-Object 'System.Collections.Generic.List[object]'
    if($null-ne$ComputerName -and @($ComputerName).Count-gt0){
        foreach ($Name in $ComputerName){if(-not[string]::IsNullOrWhiteSpace($Name)){$TargetRows.Add([pscustomobject]@{HostName=$Name.Trim();OperatingSystem=$null;Source='Explicit'})}}
    } elseif(-not[string]::IsNullOrWhiteSpace($TargetListPath)){
        Require-File $TargetListPath 'Target list'
        foreach ($Name in @(Get-Content -LiteralPath $TargetListPath|Where-Object{-not[string]::IsNullOrWhiteSpace($_)})){ $TargetRows.Add([pscustomobject]@{HostName=$Name.Trim();OperatingSystem=$null;Source='TargetList'}) }
    } else {
        if([string]::IsNullOrWhiteSpace($Server)){ $Server=(Get-ADDomainController -Discover -Writable @Discovery).HostName }
        Write-Step 'DISCOVER' "$Server LDAP/ADWS: enabled Windows computers for TargetMode=$TargetMode" Yellow
        $Properties=@('DNSHostName','OperatingSystem','OperatingSystemVersion','LastLogonDate','Enabled')
        $Computers=@(Get-ADComputer -Filter 'Enabled -eq $true' -Properties $Properties -Server $Server -ErrorAction Stop)
        foreach ($Computer in $Computers){
            $Os=[string]$Computer.OperatingSystem
            if($Os -notmatch '(?i)Windows'){continue}
            if($TargetMode-eq'Servers' -and $Os -notmatch '(?i)Server'){continue}
            if($TargetMode-eq'DomainControllers' -and [string]$Computer.DistinguishedName -notmatch '(?i)OU=Domain Controllers'){continue}
            $HostName=[string]$Computer.DNSHostName;if([string]::IsNullOrWhiteSpace($HostName)){$HostName=[string]$Computer.Name}
            $TargetRows.Add([pscustomobject]@{HostName=$HostName;OperatingSystem=$Os;OperatingSystemVersion=[string]$Computer.OperatingSystemVersion;LastLogonDate=$Computer.LastLogonDate;Source='ActiveDirectory'})
        }
    }

    $Targets=[object[]]@($TargetRows.ToArray()|Sort-Object HostName -Unique|Select-Object -First $MaximumTargets)
    if(@($Targets).Count-eq0){throw'No SMB targets were selected.'}

    if([string]::IsNullOrWhiteSpace($OutputDirectory)){
        $OutputDirectory=Join-Path (Get-Location) ('MSADPT-SMB-Share-Pivot-{0}-{1}'-f([string]$Domain.DNSRoot-replace'[^A-Za-z0-9.-]','_'),(Get-Date -Format'yyyyMMdd-HHmmss'))
    }
    if(Test-Path $OutputDirectory -PathType Container){if(@(Get-ChildItem $OutputDirectory -Force).Count-gt0){throw"OutputDirectoryNotEmpty: $OutputDirectory"}}
    New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null

    Write-Step 'NETWORK' 'Planned live network operations follow.' Magenta
    Write-Step 'SCOPE' "Targets=$(@($Targets).Count); Protocol=SMB; Port=TCP/445; Authentication=current Windows identity or supplied credential for AD discovery only." DarkCyan
    foreach ($Target in $Targets){Write-Step 'TARGET' "$($Target.HostName) TCP/445 SMB: reachability, signing evidence, share enumeration, bounded root listing and metadata." DarkCyan}
    Write-Step 'CHANGES' 'Remote file changes=None; content reads=None; credential capture=None; relay=None; remote execution=None.' DarkCyan

    $TcpRows=New-Object 'System.Collections.Generic.List[object]'
    $SigningRows=New-Object 'System.Collections.Generic.List[object]'
    $ShareRows=New-Object 'System.Collections.Generic.List[object]'
    $MetadataRows=New-Object 'System.Collections.Generic.List[object]'
    $Nmap=$null
    if(-not$SkipNmap){$Nmap=(Get-Command nmap.exe -ErrorAction SilentlyContinue|Select-Object -First 1);if($null-eq$Nmap){$Nmap=(Get-Command nmap -ErrorAction SilentlyContinue|Select-Object -First 1)}}

    $TargetIndex=0
    foreach ($TargetRecord in $Targets){
        $TargetIndex++;$Target=[string]$TargetRecord.HostName
        Write-Step 'PROGRESS' "Target $TargetIndex/$(@($Targets).Count): $Target" Cyan
        $Tcp=Test-Tcp445 $Target $TcpTimeoutSeconds;$TcpRows.Add($Tcp)
        if(-not$Tcp.Connected){if($Tcp.Status-eq'Failed'){Add-OperationalError 'Tcp445' $Target 'SMB' 445 $Tcp.Error};continue}

        if($null-ne$Nmap){
            $SafeTarget=$Target-replace'[^A-Za-z0-9_.-]','_';$Prefix=Join-Path $OutputDirectory "nmap-smb-$SafeTarget"
            Write-Step 'NMAP' "$Target TCP/445 scripts smb-protocols,smb2-security-mode,smb2-time" Magenta
            try{
                $Lines=@(& $Nmap.Source -Pn -sT -p 445 --script 'smb-protocols,smb2-security-mode,smb2-time' -oA $Prefix $Target 2>&1|ForEach-Object{[string]$_});$Exit=$LASTEXITCODE
                $Text=$Lines-join"`n";$Signing='Inconclusive'
                if($Text-match'(?i)message signing enabled and required'){$Signing='Required'}elseif($Text-match'(?i)message signing enabled but not required|enabled and not required'){$Signing='EnabledNotRequired'}elseif($Text-match'(?i)message signing disabled'){$Signing='Disabled'}
                $SmbV1=($Text-match'(?i)NT LM 0\.12.*dangerous|SMBv1')
                $SigningRows.Add([pscustomobject]@{Target=$Target;Status=if($Exit-eq0){'Completed'}else{'Failed'};ExitCode=$Exit;SigningState=$Signing;SmbV1Detected=$SmbV1;OutputPrefix=$Prefix;RawConsole=$Text})
                if($Exit-ne0){Add-OperationalError 'NmapSMB' $Target 'SMB' 445 $Text}
            }catch{Add-OperationalError 'NmapSMB' $Target 'SMB' 445 $_.Exception.Message;$SigningRows.Add([pscustomobject]@{Target=$Target;Status='Failed';ExitCode=$null;SigningState='Inconclusive';SmbV1Detected=$false;OutputPrefix=$Prefix;RawConsole=$_.Exception.Message})}
        }

        Write-Step 'SHARES' "$Target TCP/445 NetShareEnum with current Windows identity" Yellow
        try{$Shares=[object[]]@(Get-RemoteShares $Target)}catch{Add-OperationalError 'ShareEnumeration' $Target 'SMB' 445 $_.Exception.Message;continue}
        foreach ($Share in $Shares){
            $Class=Get-ShareClass $Share.Name ([int]$Share.Type);$Unc="\\$Target\$($Share.Name)";$ListAccessible=$false;$ListError=$null
            try{$null=@(Get-ChildItem -LiteralPath $Unc -Force -ErrorAction Stop|Select-Object -First 1);$ListAccessible=$true}catch{$ListError=$_.Exception.Message}
            $ShareRows.Add([pscustomobject][ordered]@{Target=$Target;ShareName=[string]$Share.Name;UncPath=$Unc;ShareType=[int64]$Share.Type;ShareClass=$Class;Remark=[string]$Share.Remark;RootListAccessible=$ListAccessible;RootListError=$ListError;WriteTestPerformed=$false;ContentRead=$false})
            if(-not$ListAccessible){continue}
            if($SkipFileMetadata){continue}
            if($Class-eq'Administrative' -and -not$IncludeAdministrativeShareMetadata){continue}
            Write-Step 'METADATA' "$Target\$($Share.Name): depth=$MaximumShareDepth maxEntries=$MaximumEntriesPerShare timeout=${ShareOperationTimeoutSeconds}s contentRead=False" DarkCyan
            $Result=Get-BoundedShareMetadata $Target $Share.Name $MaximumShareDepth $MaximumEntriesPerShare $ShareOperationTimeoutSeconds
            foreach ($Row in [object[]]$Result.Rows){$MetadataRows.Add($Row)}
        }
    }

    $TargetsJson=Join-Path $OutputDirectory 'smb-targets.json';$TargetsCsv=Join-Path $OutputDirectory 'smb-targets.csv'
    $TcpJson=Join-Path $OutputDirectory 'smb-tcp-reachability.json';$TcpCsv=Join-Path $OutputDirectory 'smb-tcp-reachability.csv'
    $SigningJson=Join-Path $OutputDirectory 'smb-signing-observations.json';$SigningCsv=Join-Path $OutputDirectory 'smb-signing-observations.csv'
    $SharesJson=Join-Path $OutputDirectory 'smb-share-inventory.json';$SharesCsv=Join-Path $OutputDirectory 'smb-share-inventory.csv'
    $MetadataJson=Join-Path $OutputDirectory 'smb-file-metadata.json';$MetadataCsv=Join-Path $OutputDirectory 'smb-file-metadata.csv'
    $ErrorsJson=Join-Path $OutputDirectory 'operational-errors.json'
    Write-JsonArray $Targets $TargetsJson;$Targets|Export-Csv $TargetsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $TcpRows.ToArray() $TcpJson;$TcpRows|Export-Csv $TcpCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $SigningRows.ToArray() $SigningJson;$SigningRows|Export-Csv $SigningCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $ShareRows.ToArray() $SharesJson;$ShareRows|Export-Csv $SharesCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $MetadataRows.ToArray() $MetadataJson;$MetadataRows|Export-Csv $MetadataCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $OperationalErrors.ToArray() $ErrorsJson

    $Reachable=@($TcpRows|Where-Object{$_.Connected}).Count;$AccessibleShares=@($ShareRows|Where-Object{$_.RootListAccessible}).Count;$Interesting=@($MetadataRows|Where-Object{$_.InterestingName}).Count;$OptionalSigning=@($SigningRows|Where-Object{$_.SigningState-in@('EnabledNotRequired','Disabled')}).Count
    $Summary=[pscustomobject][ordered]@{SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;Status=if($OperationalErrors.Count-gt0){'CompletedWithErrors'}else{'Completed'};GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o');Domain=[string]$Domain.DNSRoot;TargetMode=$TargetMode;Counts=[pscustomobject]@{Targets=@($Targets).Count;Tcp445Reachable=$Reachable;SigningOptionalOrDisabled=$OptionalSigning;Shares=$ShareRows.Count;RootListAccessibleShares=$AccessibleShares;MetadataEntries=$MetadataRows.Count;InterestingFileNameLeads=$Interesting;OperationalErrors=$OperationalErrors.Count};InterpretationBoundary=@('Share existence and access are inventory facts, not vulnerabilities.','Interesting filenames are leads; file contents were not read.','Signing optional or disabled is a relay prerequisite, not proof of relay impact.','No write access test or remote execution occurred.');Safety=[pscustomobject]@{RemoteFileChanges='None';ContentReads='None';CredentialCapture='None';RelayAttempts='None';RemoteExecution='None';OllamaActivity='None'}}
    $SummaryPath=Join-Path $OutputDirectory 'smb-share-pivot-summary.json';Write-JsonDocument $Summary $SummaryPath

    $AccessibleHtml=($ShareRows|Where-Object{$_.RootListAccessible}|Select-Object -First 150|ForEach-Object{"<tr><td>$(Convert-HtmlText $_.Target)</td><td>$(Convert-HtmlText $_.ShareName)</td><td>$(Convert-HtmlText $_.ShareClass)</td><td>True</td><td>False</td></tr>"})-join"`n"
    $LeadHtml=($MetadataRows|Where-Object{$_.InterestingName}|Select-Object -First 150|ForEach-Object{"<tr><td>$(Convert-HtmlText $_.Target)</td><td>$(Convert-HtmlText $_.Share)</td><td>$(Convert-HtmlText $_.RelativePath)</td><td>$(Convert-HtmlText $_.Size)</td><td>False</td></tr>"})-join"`n"
    $ReportPath=Join-Path $OutputDirectory 'MSADPT-SMB-Share-Pivot-Report.html'
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT SMB Share and Pivot Assessment</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body><h1>MSADPT SMB Share and Pivot Surface Assessment</h1><div class="card"><b>Status:</b> $(Convert-HtmlText $Summary.Status)<br><b>Domain:</b> $(Convert-HtmlText $Summary.Domain)<br><b>Targets:</b> $(@($Targets).Count)<br><b>TCP/445 reachable:</b> $Reachable<br><b>Accessible shares:</b> $AccessibleShares<br><b>Interesting filename leads:</b> $Interesting<br><b>Remote file changes:</b> None<br><b>File contents read:</b> None</div><h2>Accessible Shares</h2><table><tr><th>Target</th><th>Share</th><th>Class</th><th>Root listing</th><th>Write tested</th></tr>$AccessibleHtml</table><h2>Metadata Leads</h2><table><tr><th>Target</th><th>Share</th><th>Relative path</th><th>Size</th><th>Content read</th></tr>$LeadHtml</table><h2>Evidence</h2><ul><li><a href="smb-targets.csv">Targets</a></li><li><a href="smb-tcp-reachability.csv">TCP reachability</a></li><li><a href="smb-signing-observations.csv">Signing evidence</a></li><li><a href="smb-share-inventory.csv">Share inventory</a></li><li><a href="smb-file-metadata.csv">File metadata</a></li><li><a href="operational-errors.json">Operational errors</a></li><li><a href="smb-share-pivot-summary.json">Structured summary</a></li></ul><p class="note">Results are leads, not vulnerabilities. Sensitive content, write access, execution paths, relay behavior and lateral movement require separate bounded validation.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))
    $Files = @(
        Get-ChildItem -LiteralPath $OutputDirectory -File |
            Where-Object { $_.Name -ne 'evidence-manifest.json' } |
            Sort-Object Name
    )
    $ManifestRows = [object[]]@(
        foreach ($File in $Files) {
            [pscustomobject]@{
                Name = $File.Name
                Size = [int64]$File.Length
                SHA256 = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
            }
        }
    )
    $ManifestPath = Join-Path $OutputDirectory 'evidence-manifest.json'
    Write-JsonDocument -Document ([pscustomobject]@{
        SchemaVersion = '1.0'
        Status = 'Completed'
        FileCount = @($ManifestRows).Count
        Files = $ManifestRows
    }) -Path $ManifestPath
    Write-Step 'DONE' "SMB assessment complete: targets=$(@($Targets).Count), reachable=$Reachable, shares=$($ShareRows.Count), accessible=$AccessibleShares, leads=$Interesting, errors=$($OperationalErrors.Count)." Green
    [pscustomobject][ordered]@{Status=if($OperationalErrors.Count-gt0){'PassedWithErrors'}else{'Passed'};PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;Domain=[string]$Domain.DNSRoot;TargetMode=$TargetMode;TargetCount=@($Targets).Count;Tcp445ReachableCount=$Reachable;SigningOptionalOrDisabledCount=$OptionalSigning;ShareCount=$ShareRows.Count;AccessibleShareCount=$AccessibleShares;MetadataEntryCount=$MetadataRows.Count;InterestingFileNameLeadCount=$Interesting;OperationalErrorCount=$OperationalErrors.Count;OutputDirectory=$OutputDirectory;HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath;RemoteFileChanges='None';ContentReads='None';RelayAttempts='None';RemoteExecution='None';OllamaActivity='None'}
}catch{Write-Step 'FAIL' $_.Exception.Message Red;throw}
