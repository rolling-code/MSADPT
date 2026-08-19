<#
.SYNOPSIS
Classifies SMB continuation failures locally and validates bounded metadata on evidence-selected SYSVOL and NETLOGON shares.

.DESCRIPTION
Consumes the completed SMB share-enumeration continuation evidence. It locally classifies target-specific
enumeration failures, selects only SYSVOL and NETLOGON share records, displays every target and UNC path,
and performs bounded metadata-only traversal. File contents are never opened or copied. No remote file is
created, modified, or deleted. Completed target discovery, TCP/445, Nmap, and share-enumeration work is reused.

.NOTES
Version: 0.1.0
Package identity: MSADPT-SMB-DIRECTORY-SERVICES-FOLLOW-UP
Execution class: authorized_bounded_read_only_live_validation
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ContinuationDirectory,

    [string]$OutputDirectory,

    [ValidateRange(0,6)]
    [int]$MaximumDepth = 3,

    [ValidateRange(1,10000)]
    [int]$MaximumEntriesPerShare = 2000,

    [ValidateRange(5,300)]
    [int]$MaximumSecondsPerShare = 45,

    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$PackageIdentity='MSADPT-SMB-DIRECTORY-SERVICES-FOLLOW-UP'
$PackageVersion='0.1.0'
$OperationalErrors=New-Object 'System.Collections.Generic.List[object]'

$InterestingPatterns=@(
    '*.ps1','*.psm1','*.psd1','*.bat','*.cmd','*.vbs','*.js','*.wsf',
    '*.xml','*.config','*.ini','*.json','*.yml','*.yaml','*.txt','*.bak','*.old','*.orig','*.save',
    '*.kdbx','*.rdp','*.ppk','*.pem','*.pfx','*.p12','*.key','*.ovpn','*.sql',
    'unattend*.xml','web.config','appsettings*.json','Groups.xml','Services.xml',
    'ScheduledTasks.xml','Registry.xml','Drives.xml','Printers.xml','DataSources.xml',
    'Preferences.xml','scripts.ini','psscripts.ini'
)

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
function Read-JsonArray {
    param([string]$Path,[string]$Label)
    Require-File $Path $Label
    return (Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop)
}
function Write-JsonArray {
    param([object[]]$Rows,[string]$Path,[int]$Depth=16)
    $Array=[object[]]@($Rows)
    if(@($Array).Count -eq 0){
        [IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))
    }else{
        $Array|ConvertTo-Json -Depth $Depth|Set-Content -LiteralPath $Path -Encoding UTF8
    }
    $Check=[object[]]@(Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop)
    if(@($Check).Count -ne @($Array).Count){throw "JsonArrayRoundTripMismatch: $Path"}
}
function Write-JsonDocument {
    param([object]$Document,[string]$Path,[int]$Depth=16)
    $Document|ConvertTo-Json -Depth $Depth|Set-Content -LiteralPath $Path -Encoding UTF8
    $null=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop
}
function Convert-HtmlText { param([object]$Value) return [Net.WebUtility]::HtmlEncode([string]$Value) }
function Add-OperationalError {
    param([string]$Stage,[string]$Target,[string]$Share,[string]$RelativePath,[string]$ErrorText)
    $OperationalErrors.Add([pscustomobject][ordered]@{
        Stage=$Stage;Target=$Target;Share=$Share;RelativePath=$RelativePath
        Protocol='SMB';Port=445;Error=$ErrorText
    })
}
function Test-InterestingName {
    param([string]$Name)
    foreach($Pattern in $InterestingPatterns){if($Name -like $Pattern){return $true}}
    return $false
}
function Get-FailureCategory {
    param([string]$ErrorText)
    if($ErrorText -match '(?i)status\s*5\b|access is denied|access denied'){return 'AccessDenied'}
    if($ErrorText -match '(?i)status\s*53\b|network path was not found'){return 'NetworkPathNotFound'}
    if($ErrorText -match '(?i)status\s*64\b|specified network name is no longer available'){return 'NetworkNameUnavailable'}
    if($ErrorText -match '(?i)status\s*67\b|network name cannot be found'){return 'NetworkNameNotFound'}
    if($ErrorText -match '(?i)status\s*121\b|semaphore timeout'){return 'Timeout'}
    if($ErrorText -match '(?i)status\s*1722\b|RPC server is unavailable'){return 'RpcUnavailable'}
    if($ErrorText -match '(?i)status\s*2114\b|server service is not started'){return 'ServerServiceUnavailable'}
    if($ErrorText -match '(?i)logon failure|status\s*1326\b'){return 'AuthenticationFailure'}
    return 'Other'
}
function Get-BoundedMetadata {
    param(
        [string]$Target,
        [string]$ShareName,
        [string]$UncPath,
        [int]$DepthLimit,
        [int]$EntryLimit,
        [int]$SecondsLimit
    )

    $Rows=New-Object 'System.Collections.Generic.List[object]'
    $Queue=New-Object 'System.Collections.Generic.Queue[object]'
    $Queue.Enqueue([pscustomobject]@{Path=$UncPath;RelativePath='';Depth=0})
    $Started=Get-Date
    $Truncated=$false
    $RootListAccessible=$false
    $RootListAttempted=$false

    while($Queue.Count -gt 0){
        if(((Get-Date)-$Started).TotalSeconds -ge $SecondsLimit){$Truncated=$true;break}
        if($Rows.Count -ge $EntryLimit){$Truncated=$true;break}

        $Node=$Queue.Dequeue()
        try{
            $RootListAttempted=$true
            $Items=@(Get-ChildItem -LiteralPath $Node.Path -Force -ErrorAction Stop)
            if([int]$Node.Depth -eq 0){$RootListAccessible=$true}

            foreach($Item in $Items){
                if($Rows.Count -ge $EntryLimit){$Truncated=$true;break}
                if(((Get-Date)-$Started).TotalSeconds -ge $SecondsLimit){$Truncated=$true;break}

                $Relative=if([string]::IsNullOrWhiteSpace([string]$Node.RelativePath)){$Item.Name}else{Join-Path ([string]$Node.RelativePath) $Item.Name}
                $Interesting=if($Item.PSIsContainer){$false}else{Test-InterestingName -Name $Item.Name}

                $Rows.Add([pscustomobject][ordered]@{
                    Target=$Target;Share=$ShareName;UncPath=$UncPath;RelativePath=$Relative
                    EntryType=if($Item.PSIsContainer){'Directory'}else{'File'}
                    Extension=if($Item.PSIsContainer){$null}else{[string]$Item.Extension}
                    Size=if($Item.PSIsContainer){$null}else{[int64]$Item.Length}
                    LastWriteTimeUtc=if($null-ne$Item.LastWriteTimeUtc){$Item.LastWriteTimeUtc.ToString('o')}else{$null}
                    Depth=[int]$Node.Depth;InterestingName=[bool]$Interesting
                    ContentRead=$false;HashCalculated=$false;RemoteChange=$false
                })

                if($Item.PSIsContainer -and [int]$Node.Depth -lt $DepthLimit){
                    $Queue.Enqueue([pscustomobject]@{Path=$Item.FullName;RelativePath=$Relative;Depth=([int]$Node.Depth+1)})
                }
            }
        }catch{
            Add-OperationalError -Stage 'DirectoryServicesMetadata' -Target $Target -Share $ShareName -RelativePath ([string]$Node.RelativePath) -ErrorText $_.Exception.Message
        }
    }

    return [pscustomobject][ordered]@{
        Rows=[object[]]$Rows.ToArray()
        RootListAttempted=$RootListAttempted
        RootListAccessible=$RootListAccessible
        Truncated=$Truncated
        ElapsedMs=[int]((Get-Date)-$Started).TotalMilliseconds
    }
}

try{
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'Local failure classification plus evidence-selected SYSVOL/NETLOGON metadata validation.' DarkGray

    if(-not(Test-Path -LiteralPath $ContinuationDirectory -PathType Container)){throw "ContinuationDirectoryMissing: $ContinuationDirectory"}

    $SharesPath=Join-Path $ContinuationDirectory 'smb-share-inventory-continuation.json'
    $TargetResultsPath=Join-Path $ContinuationDirectory 'smb-share-enumeration-target-results.json'
    $ErrorsPath=Join-Path $ContinuationDirectory 'operational-errors.json'
    Require-File $SharesPath 'Continuation share inventory'
    Require-File $TargetResultsPath 'Continuation target results'
    Require-File $ErrorsPath 'Continuation operational errors'

    if([string]::IsNullOrWhiteSpace($OutputDirectory)){$OutputDirectory=Join-Path $ContinuationDirectory 'DirectoryServicesFollowUp-v0.1.0'}
    if(Test-Path -LiteralPath $OutputDirectory -PathType Container){if(@(Get-ChildItem -LiteralPath $OutputDirectory -Force).Count -gt 0){throw "OutputDirectoryNotEmpty: $OutputDirectory"}}
    New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null

    Write-Step 'LOAD' 'Loading continuation evidence. No network activity yet.' Yellow
    $AllShares=[object[]]@(Read-JsonArray $SharesPath 'Continuation share inventory')
    $TargetResults=[object[]]@(Read-JsonArray $TargetResultsPath 'Continuation target results')
    $PriorErrors=[object[]]@(Read-JsonArray $ErrorsPath 'Continuation operational errors')

    $FailedTargets=[object[]]@($TargetResults|Where-Object{$_.Status -eq 'Failed'})
    $DirectoryShares=[object[]]@($AllShares|Where-Object{$_.ShareClass -eq 'DirectoryServices' -and $_.ShareName -in @('SYSVOL','NETLOGON')}|Sort-Object Target,ShareName -Unique)

    $FailureRows=[object[]]@(
        foreach($Failure in $FailedTargets){
            [pscustomobject][ordered]@{
                Target=[string]$Failure.Target
                SigningState=[string]$Failure.SigningState
                SmbV1Detected=[bool]$Failure.SmbV1Detected
                Error=[string]$Failure.Error
                Category=Get-FailureCategory -ErrorText ([string]$Failure.Error)
                RetryRecommended=$false
            }
        }
    )
    $FailureDistribution=[object[]]@($FailureRows|Group-Object Category|Sort-Object Count -Descending|ForEach-Object{[pscustomobject]@{Category=[string]$_.Name;Count=[int]$_.Count}})

    Write-Step 'LOCAL' "Classified $(@($FailureRows).Count) failed targets locally. Automatic retry=False." DarkCyan
    Write-Step 'NETWORK' 'Planned live network operations follow.' Magenta
    Write-Step 'SCOPE' "Evidence-selected shares=$(@($DirectoryShares).Count); Protocol=SMB; Port=TCP/445; depth=$MaximumDepth; maxEntries=$MaximumEntriesPerShare; timeout=${MaximumSecondsPerShare}s." DarkCyan
    foreach($ShareRecord in $DirectoryShares){
        Write-Step 'TARGET' "$($ShareRecord.Target) TCP/445 $($ShareRecord.UncPath): root listing and bounded metadata only; content=False; hash=False; write=False" DarkCyan
    }
    Write-Step 'CHANGES' 'Remote file changes=None; content reads=None; credential capture=None; relay=None; remote execution=None.' DarkCyan

    $MetadataList=New-Object 'System.Collections.Generic.List[object]'
    $ShareResultList=New-Object 'System.Collections.Generic.List[object]'
    $Position=0
    foreach($ShareRecord in $DirectoryShares){
        $Position++
        $TargetName=[string]$ShareRecord.Target
        $ShareName=[string]$ShareRecord.ShareName
        $UncPath=[string]$ShareRecord.UncPath
        Write-Step 'METADATA' "$Position/$(@($DirectoryShares).Count) $UncPath" Yellow
        $Result=Get-BoundedMetadata -Target $TargetName -ShareName $ShareName -UncPath $UncPath -DepthLimit $MaximumDepth -EntryLimit $MaximumEntriesPerShare -SecondsLimit $MaximumSecondsPerShare
        foreach($Row in [object[]]$Result.Rows){$MetadataList.Add($Row)}
        $ShareResultList.Add([pscustomobject][ordered]@{
            Target=$TargetName;Share=$ShareName;UncPath=$UncPath
            RootListAttempted=[bool]$Result.RootListAttempted
            RootListAccessible=[bool]$Result.RootListAccessible
            MetadataEntryCount=@([object[]]$Result.Rows).Count
            InterestingNameLeadCount=@([object[]]$Result.Rows|Where-Object{$_.InterestingName}).Count
            Truncated=[bool]$Result.Truncated;ElapsedMs=[int]$Result.ElapsedMs
            ContentRead=$false;RemoteChange=$false
        })
    }

    $MetadataRows=[object[]]$MetadataList.ToArray()
    $ShareResults=[object[]]$ShareResultList.ToArray()
    $ErrorRows=[object[]]$OperationalErrors.ToArray()
    $MetadataCount=[int]@($MetadataRows).Count
    $InterestingRows=[object[]]@($MetadataRows|Where-Object{$_.InterestingName})
    $InterestingCount=[int]@($InterestingRows).Count
    $AccessibleShareCount=[int]@($ShareResults|Where-Object{$_.RootListAccessible}).Count
    $TruncatedShareCount=[int]@($ShareResults|Where-Object{$_.Truncated}).Count

    $FailureJson=Join-Path $OutputDirectory 'failed-target-classification.json'
    $FailureCsv=Join-Path $OutputDirectory 'failed-target-classification.csv'
    $FailureDistJson=Join-Path $OutputDirectory 'failure-distribution.json'
    $FailureDistCsv=Join-Path $OutputDirectory 'failure-distribution.csv'
    $SelectedJson=Join-Path $OutputDirectory 'selected-directory-services-shares.json'
    $SelectedCsv=Join-Path $OutputDirectory 'selected-directory-services-shares.csv'
    $ResultsJson=Join-Path $OutputDirectory 'directory-services-share-results.json'
    $ResultsCsv=Join-Path $OutputDirectory 'directory-services-share-results.csv'
    $MetadataJson=Join-Path $OutputDirectory 'directory-services-file-metadata.json'
    $MetadataCsv=Join-Path $OutputDirectory 'directory-services-file-metadata.csv'
    $LeadsJson=Join-Path $OutputDirectory 'directory-services-interesting-name-leads.json'
    $LeadsCsv=Join-Path $OutputDirectory 'directory-services-interesting-name-leads.csv'
    $ErrorsJson=Join-Path $OutputDirectory 'operational-errors.json'

    Write-JsonArray $FailureRows $FailureJson;$FailureRows|Export-Csv -LiteralPath $FailureCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $FailureDistribution $FailureDistJson;$FailureDistribution|Export-Csv -LiteralPath $FailureDistCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $DirectoryShares $SelectedJson;$DirectoryShares|Export-Csv -LiteralPath $SelectedCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $ShareResults $ResultsJson;$ShareResults|Export-Csv -LiteralPath $ResultsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $MetadataRows $MetadataJson;$MetadataRows|Export-Csv -LiteralPath $MetadataCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $InterestingRows $LeadsJson;$InterestingRows|Export-Csv -LiteralPath $LeadsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $ErrorRows $ErrorsJson

    $Disposition=if($InterestingCount -gt 0){'MetadataLeadsDetected'}elseif($AccessibleShareCount -gt 0){'AccessibleNoInterestingNameLeadDetected'}else{'DirectoryServicesShareAccessInconclusive'}
    $Summary=[pscustomobject][ordered]@{
        SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion
        Status=if(@($ErrorRows).Count -gt 0){'CompletedWithErrors'}else{'Completed'}
        GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        SourceContinuationDirectory=$ContinuationDirectory;Disposition=$Disposition
        Counts=[pscustomobject]@{PriorFailedTargets=@($FailureRows).Count;SelectedDirectoryServicesShares=@($DirectoryShares).Count;RootListAccessibleShares=$AccessibleShareCount;MetadataEntries=$MetadataCount;InterestingNameLeads=$InterestingCount;TruncatedShares=$TruncatedShareCount;OperationalErrors=@($ErrorRows).Count}
        ReusedEvidence=[pscustomobject]@{TargetDiscovery=$true;TcpReachability=$true;Nmap=$true;ShareEnumeration=$true}
        InterpretationBoundary=@('SYSVOL and NETLOGON existence and normal read access are expected domain behavior.','Interesting filenames are leads only; file contents were not read.','Failed continuation targets were classified locally and not retried.','A finding requires actual sensitive content or a demonstrable unsafe downstream operation.')
        Safety=[pscustomobject]@{RepeatedDiscovery='None';RepeatedTcpProbe='None';RepeatedNmap='None';RepeatedShareEnumeration='None';ContentReads='None';Hashes='None';RemoteFileChanges='None';RelayAttempts='None';RemoteExecution='None';OllamaActivity='None'}
    }
    $SummaryPath=Join-Path $OutputDirectory 'smb-directory-services-follow-up-summary.json';Write-JsonDocument $Summary $SummaryPath

    $FailureHtml=($FailureDistribution|ForEach-Object{'<tr><td>{0}</td><td>{1}</td></tr>' -f (Convert-HtmlText $_.Category),(Convert-HtmlText $_.Count)})-join"`n"
    $ShareHtml=($ShareResults|ForEach-Object{'<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (Convert-HtmlText $_.Target),(Convert-HtmlText $_.Share),(Convert-HtmlText $_.RootListAccessible),(Convert-HtmlText $_.MetadataEntryCount),(Convert-HtmlText $_.InterestingNameLeadCount)})-join"`n"
    $LeadHtml=($InterestingRows|Select-Object -First 250|ForEach-Object{'<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>False</td></tr>' -f (Convert-HtmlText $_.Target),(Convert-HtmlText $_.Share),(Convert-HtmlText $_.RelativePath),(Convert-HtmlText $_.Size)})-join"`n"
    $ReportPath=Join-Path $OutputDirectory 'MSADPT-SMB-Directory-Services-Follow-Up.html'
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT SMB Directory Services Follow-Up</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body><h1>MSADPT SMB Directory Services Follow-Up</h1><div class="card"><b>Disposition:</b> $(Convert-HtmlText $Disposition)<br><b>Failed targets classified locally:</b> $(@($FailureRows).Count)<br><b>Selected SYSVOL/NETLOGON shares:</b> $(@($DirectoryShares).Count)<br><b>Accessible roots:</b> $AccessibleShareCount<br><b>Metadata entries:</b> $MetadataCount<br><b>Interesting filename leads:</b> $InterestingCount<br><b>Content read:</b> None<br><b>Remote changes:</b> None</div><h2>Failure Distribution</h2><table><tr><th>Category</th><th>Count</th></tr>$FailureHtml</table><h2>Directory Services Shares</h2><table><tr><th>Target</th><th>Share</th><th>Accessible</th><th>Entries</th><th>Leads</th></tr>$ShareHtml</table><h2>Interesting Filename Leads</h2><table><tr><th>Target</th><th>Share</th><th>Relative path</th><th>Size</th><th>Content read</th></tr>$LeadHtml</table><h2>Evidence</h2><ul><li><a href="failed-target-classification.csv">Failed-target classification</a></li><li><a href="selected-directory-services-shares.csv">Selected shares</a></li><li><a href="directory-services-share-results.csv">Share results</a></li><li><a href="directory-services-file-metadata.csv">Metadata</a></li><li><a href="directory-services-interesting-name-leads.csv">Filename leads</a></li><li><a href="operational-errors.json">Operational errors</a></li><li><a href="smb-directory-services-follow-up-summary.json">Summary</a></li></ul><p class="note">No file contents were read. Filename matches are validation leads, not vulnerabilities.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File|Where-Object{$_.Name -ne 'evidence-manifest.json'}|Sort-Object Name)
    $ManifestRows=[object[]]@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json';Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=@($ManifestRows).Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "Follow-up complete: failures=$(@($FailureRows).Count), shares=$(@($DirectoryShares).Count), accessible=$AccessibleShareCount, metadata=$MetadataCount, leads=$InterestingCount, disposition=$Disposition." Green
    [pscustomobject][ordered]@{
        Status=if(@($ErrorRows).Count -gt 0){'PassedWithErrors'}else{'Passed'}
        PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;Disposition=$Disposition
        FailedTargetCount=@($FailureRows).Count;SelectedDirectoryServicesShareCount=@($DirectoryShares).Count
        AccessibleShareCount=$AccessibleShareCount;MetadataEntryCount=$MetadataCount
        InterestingNameLeadCount=$InterestingCount;TruncatedShareCount=$TruncatedShareCount
        OperationalErrorCount=@($ErrorRows).Count;OutputDirectory=$OutputDirectory
        HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath
        RepeatedTargetDiscovery='No';RepeatedTcpProbe='No';RepeatedNmap='No';RepeatedShareEnumeration='No'
        ContentReads='None';Hashes='None';RemoteFileChanges='None';RelayAttempts='None';RemoteExecution='None';OllamaActivity='None'
    }
}catch{
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
