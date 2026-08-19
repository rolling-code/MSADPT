<#
.SYNOPSIS
Validates the corrected SMB share-enumeration method against a minimal evidence-selected target set.

.DESCRIPTION
Consumes minimal-validation-targets.json from MSADPT SMB evidence diagnostics. Reuses prior TCP/445
and Nmap evidence and calls NetShareEnum with [uint32]::MaxValue. It performs share enumeration only.
No target discovery, TCP probing, Nmap, root listing, metadata traversal, content read, write test,
credential capture, relay, or remote execution occurs.

.NOTES
Version: 0.1.0
Package identity: MSADPT-SMB-SHARE-ENUMERATION-VALIDATION
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$DiagnosticsDirectory,

    [string]$OutputDirectory,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-SMB-SHARE-ENUMERATION-VALIDATION'
$PackageVersion = '0.1.0'
$Errors = New-Object 'System.Collections.Generic.List[object]'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray)
    if ($Quiet) { return }
    $Text = '[{0,-12}] {1}' -f $Status,$Message
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}
function Require-File {
    param([string]$Path,[string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "RequiredFileMissing [$Label]: $Path" }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) { throw "RequiredFileEmpty [$Label]: $Path" }
}
function Write-JsonArray {
    param([object[]]$Rows,[string]$Path,[int]$Depth=12)
    $Array=[object[]]@($Rows)
    if (@($Array).Count -eq 0) {
        [IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))
    } else {
        $Array | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    $Check=[object[]]@(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
    if (@($Check).Count -ne @($Array).Count) { throw "JsonArrayRoundTripMismatch: $Path" }
}
function Write-JsonDocument {
    param([object]$Document,[string]$Path,[int]$Depth=12)
    $Document | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    $null=Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}
function Convert-HtmlText { param([object]$Value) return [Net.WebUtility]::HtmlEncode([string]$Value) }
function Get-ShareClass {
    param([string]$Name,[uint32]$Type)
    if ($Name -in @('ADMIN$','C$','IPC$','PRINT$')) { return 'Administrative' }
    if ($Name -in @('SYSVOL','NETLOGON')) { return 'DirectoryServices' }
    if (($Type -band [uint32]0x80000000) -ne 0) { return 'Special' }
    if (($Type -band 3) -eq 1) { return 'Printer' }
    return 'BusinessOrApplication'
}

if (-not ('MSADPT.ValidationNativeShare' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace MSADPT {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct VALIDATION_SHARE_INFO_1 {
        public string shi1_netname;
        public uint shi1_type;
        public string shi1_remark;
    }
    public static class ValidationNativeShare {
        [DllImport("Netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern uint NetShareEnum(string servername, int level, out IntPtr bufptr,
            uint prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);
        [DllImport("Netapi32.dll", SetLastError=true)]
        public static extern uint NetApiBufferFree(IntPtr buffer);
    }
}
'@
}

function Get-CorrectedRemoteShares {
    param([string]$Target)
    $Buffer=[IntPtr]::Zero
    $EntriesRead=0
    $TotalEntries=0
    $ResumeHandle=0
    $Rows=New-Object 'System.Collections.Generic.List[object]'
    try {
        do {
            # Critical correction: explicit UInt32, not PowerShell's signed 0xFFFFFFFF (-1).
            [uint32]$PreferredMaximumLength=[uint32]::MaxValue
            [uint32]$Status=[MSADPT.ValidationNativeShare]::NetShareEnum(
                "\\$Target",1,[ref]$Buffer,$PreferredMaximumLength,
                [ref]$EntriesRead,[ref]$TotalEntries,[ref]$ResumeHandle
            )
            if ($Status -notin @([uint32]0,[uint32]234)) {
                $Message=(New-Object ComponentModel.Win32Exception([int]$Status)).Message
                throw "NetShareEnum failed with Win32 status $Status ($Message)"
            }
            $StructureSize=[Runtime.InteropServices.Marshal]::SizeOf([type][MSADPT.VALIDATION_SHARE_INFO_1])
            for ($Index=0; $Index -lt $EntriesRead; $Index++) {
                $Pointer=[IntPtr]($Buffer.ToInt64()+($Index*$StructureSize))
                $Info=[Runtime.InteropServices.Marshal]::PtrToStructure($Pointer,[type][MSADPT.VALIDATION_SHARE_INFO_1])
                $Rows.Add([pscustomobject][ordered]@{
                    Target=$Target
                    ShareName=[string]$Info.shi1_netname
                    ShareType=[uint32]$Info.shi1_type
                    ShareClass=Get-ShareClass -Name ([string]$Info.shi1_netname) -Type ([uint32]$Info.shi1_type)
                    Remark=[string]$Info.shi1_remark
                    RootListingTested=$false
                    ContentRead=$false
                    WriteTestPerformed=$false
                })
            }
            if ($Buffer -ne [IntPtr]::Zero) {
                [void][MSADPT.ValidationNativeShare]::NetApiBufferFree($Buffer)
                $Buffer=[IntPtr]::Zero
            }
        } while ($Status -eq [uint32]234)
        return [object[]]$Rows.ToArray()
    } finally {
        if ($Buffer -ne [IntPtr]::Zero) { [void][MSADPT.ValidationNativeShare]::NetApiBufferFree($Buffer) }
    }
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'Minimal corrected-method validation only. Prior TCP and Nmap evidence will be reused.' DarkGray
    if (-not (Test-Path -LiteralPath $DiagnosticsDirectory -PathType Container)) { throw "DiagnosticsDirectoryMissing: $DiagnosticsDirectory" }
    $TargetsPath=Join-Path $DiagnosticsDirectory 'minimal-validation-targets.json'
    Require-File $TargetsPath 'Minimal validation targets'
    $Targets=[object[]]@(Get-Content -LiteralPath $TargetsPath -Raw | ConvertFrom-Json -ErrorAction Stop)
    if (@($Targets).Count -eq 0) { throw 'No minimal validation targets were selected.' }
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory=Join-Path $DiagnosticsDirectory 'ShareEnumerationValidation-v0.1.0' }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) { throw "OutputDirectoryNotEmpty: $OutputDirectory" }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    Write-Step 'NETWORK' 'Planned live network operations follow.' Magenta
    foreach ($TargetRecord in $Targets) {
        Write-Step 'TARGET' "$($TargetRecord.Target) TCP/445 SMB NetShareEnum only; TCP probe=False; Nmap=False; root listing=False; content read=False; write=False" DarkCyan
    }
    Write-Step 'CHANGES' 'Remote file changes=None; credential capture=None; relay=None; remote execution=None.' DarkCyan

    $ResultList=New-Object 'System.Collections.Generic.List[object]'
    $TargetResultList=New-Object 'System.Collections.Generic.List[object]'
    $Position=0
    foreach ($TargetRecord in $Targets) {
        $Position++
        $TargetName=[string]$TargetRecord.Target
        Write-Step 'ENUMERATE' "$Position/$(@($Targets).Count) $TargetName TCP/445 SMB NetShareEnum prefmaxlen=UInt32.MaxValue" Yellow
        try {
            $Shares=[object[]]@(Get-CorrectedRemoteShares -Target $TargetName)
            foreach ($Share in $Shares) { $ResultList.Add($Share) }
            $TargetResultList.Add([pscustomobject][ordered]@{
                Target=$TargetName;Status='Completed';ShareCount=@($Shares).Count
                SigningState=[string]$TargetRecord.SigningState
                PriorEnumerationErrorCategory=[string]$TargetRecord.PriorEnumerationErrorCategory
                Error=$null
            })
        } catch {
            $Errors.Add([pscustomobject]@{Stage='CorrectedShareEnumeration';Target=$TargetName;Protocol='SMB';Port=445;Error=$_.Exception.Message})
            $TargetResultList.Add([pscustomobject][ordered]@{
                Target=$TargetName;Status='Failed';ShareCount=0
                SigningState=[string]$TargetRecord.SigningState
                PriorEnumerationErrorCategory=[string]$TargetRecord.PriorEnumerationErrorCategory
                Error=$_.Exception.Message
            })
        }
    }

    $ShareRows=[object[]]$ResultList.ToArray()
    $TargetResults=[object[]]$TargetResultList.ToArray()
    $ErrorRows=[object[]]$Errors.ToArray()
    $SuccessfulTargets=[int]@($TargetResults | Where-Object { $_.Status -eq 'Completed' }).Count
    $FailedTargets=[int]@($TargetResults | Where-Object { $_.Status -eq 'Failed' }).Count
    $TotalShares=[int]@($ShareRows).Count
    $NonAdministrative=[int]@($ShareRows | Where-Object { $_.ShareClass -notin @('Administrative','Special') }).Count
    $MethodDisposition=if($SuccessfulTargets -gt 0){'CorrectedMethodValidated'}else{'CorrectedMethodNotValidated'}

    $SharesJson=Join-Path $OutputDirectory 'validated-share-inventory.json'
    $SharesCsv=Join-Path $OutputDirectory 'validated-share-inventory.csv'
    $TargetsJson=Join-Path $OutputDirectory 'share-enumeration-target-results.json'
    $TargetsCsv=Join-Path $OutputDirectory 'share-enumeration-target-results.csv'
    $ErrorsJson=Join-Path $OutputDirectory 'operational-errors.json'
    Write-JsonArray $ShareRows $SharesJson
    $ShareRows | Export-Csv -LiteralPath $SharesCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $TargetResults $TargetsJson
    $TargetResults | Export-Csv -LiteralPath $TargetsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $ErrorRows $ErrorsJson

    $Summary=[pscustomobject][ordered]@{
        SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Status=if($FailedTargets -gt 0){'CompletedWithErrors'}else{'Completed'}
        GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        SourceDiagnosticsDirectory=$DiagnosticsDirectory
        MethodDisposition=$MethodDisposition
        Counts=[pscustomobject]@{Targets=@($Targets).Count;SuccessfulTargets=$SuccessfulTargets;FailedTargets=$FailedTargets;Shares=$TotalShares;NonAdministrativeShares=$NonAdministrative}
        ReusedEvidence=[pscustomobject]@{TargetSelection=$true;TcpReachability=$true;SigningEvidence=$true;NmapEvidence=$true}
        Safety=[pscustomobject]@{TcpProbe='None';Nmap='None';RootListing='None';ContentReads='None';RemoteFileChanges='None';RelayAttempts='None';RemoteExecution='None'}
    }
    $SummaryPath=Join-Path $OutputDirectory 'share-enumeration-validation-summary.json'
    Write-JsonDocument $Summary $SummaryPath

    $ShareHtml=($ShareRows | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (Convert-HtmlText $_.Target),(Convert-HtmlText $_.ShareName),(Convert-HtmlText $_.ShareClass),(Convert-HtmlText $_.Remark)
    }) -join "`n"
    $ReportPath=Join-Path $OutputDirectory 'MSADPT-SMB-Share-Enumeration-Validation.html'
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT SMB Share Enumeration Validation</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}</style></head><body><h1>MSADPT SMB Share Enumeration Method Validation</h1><div class="card"><b>Disposition:</b> $(Convert-HtmlText $MethodDisposition)<br><b>Targets:</b> $(@($Targets).Count)<br><b>Successful:</b> $SuccessfulTargets<br><b>Failed:</b> $FailedTargets<br><b>Shares:</b> $TotalShares<br><b>Nonadministrative shares:</b> $NonAdministrative<br><b>TCP probes repeated:</b> No<br><b>Nmap repeated:</b> No<br><b>Content read:</b> No<br><b>Remote changes:</b> None</div><h2>Enumerated Shares</h2><table><tr><th>Target</th><th>Share</th><th>Class</th><th>Remark</th></tr>$ShareHtml</table><h2>Evidence</h2><ul><li><a href="validated-share-inventory.csv">Share inventory</a></li><li><a href="share-enumeration-target-results.csv">Target results</a></li><li><a href="operational-errors.json">Operational errors</a></li><li><a href="share-enumeration-validation-summary.json">Summary</a></li></ul></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File | Where-Object { $_.Name -ne 'evidence-manifest.json' } | Sort-Object Name)
    $ManifestRows=[object[]]@(foreach ($File in $Files) {[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json'
    Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=@($ManifestRows).Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "Method validation complete: targets=$(@($Targets).Count), successful=$SuccessfulTargets, failed=$FailedTargets, shares=$TotalShares, disposition=$MethodDisposition." Green
    [pscustomobject][ordered]@{
        Status=if($FailedTargets -gt 0){'PassedWithErrors'}else{'Passed'}
        PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        MethodDisposition=$MethodDisposition;TargetCount=@($Targets).Count
        SuccessfulTargetCount=$SuccessfulTargets;FailedTargetCount=$FailedTargets
        ShareCount=$TotalShares;NonAdministrativeShareCount=$NonAdministrative
        OutputDirectory=$OutputDirectory;HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath
        RepeatedTargetDiscovery='No';RepeatedTcpProbe='No';RepeatedNmap='No'
        RootListing='None';ContentReads='None';RemoteFileChanges='None';RelayAttempts='None';RemoteExecution='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
