<#
.SYNOPSIS
Performs bounded, redacted static analysis of ranked P2 SYSVOL and NETLOGON artifacts.

.DESCRIPTION
Consumes p2-content-validation-queue.json. Reads only the ranked P2 queue, up to the configured maximum.
Each file is read from one evidence-selected DC, with alternate-source failover only after a genuine
remote read failure. Content is analyzed in memory and is never executed or saved in full.

The analyzer identifies structural indicators for credentials, certificate imports, remote management,
service and scheduled-task operations, encoded PowerShell, download or staging activity, domain join,
mapped drives, administrative shares, software deployment, security exclusions, and hard-coded network
or identity references. Potential values are represented only as <REDACTED>.

No script is executed. No remote file is created, modified, renamed, or deleted. No credential is used.

.NOTES
Version: 0.1.1
Package identity: MSADPT-SMB-DIRECTORY-SERVICES-P2-CONTENT-VALIDATION
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$P2RankingDirectory,

    [string]$OutputDirectory,

    [ValidateRange(1,25)]
    [int]$MaximumFiles = 15,

    [ValidateRange(4096,1048576)]
    [int]$MaximumBytesPerFile = 1048576,

    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$PackageIdentity='MSADPT-SMB-DIRECTORY-SERVICES-P2-CONTENT-VALIDATION'
$PackageVersion='0.1.1'
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
    param([object[]]$Rows,[string]$Path,[int]$Depth=18)
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
    param([object]$Document,[string]$Path,[int]$Depth=18)
    $Document|ConvertTo-Json -Depth $Depth|Set-Content -LiteralPath $Path -Encoding UTF8
    $null=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop
}
function Convert-HtmlText { param([object]$Value) return [Net.WebUtility]::HtmlEncode([string]$Value) }
function Add-OperationalError {
    param([string]$QueueId,[string]$Stage,[string]$Target,[string]$UncPath,[string]$ErrorText)
    $OperationalErrors.Add([pscustomobject][ordered]@{QueueId=$QueueId;Stage=$Stage;Target=$Target;UncPath=$UncPath;Protocol='SMB';Port=445;Error=$ErrorText})
}
function Get-UncPath {
    param([string]$Target,[string]$Share,[string]$RelativePath)
    return "\\$Target\$Share\$($RelativePath.Replace('/','\').TrimStart('\'))"
}
function Read-BoundedFile {
    param([string]$Path,[int]$MaximumBytes)
    $Stream=$null
    try{
        $Stream=New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $Length=[int64]$Stream.Length
        $BytesToRead=[int][Math]::Min($Length,[int64]$MaximumBytes)
        $Buffer=New-Object byte[] $BytesToRead
        $Total=0
        while($Total -lt $BytesToRead){
            $Read=$Stream.Read($Buffer,$Total,$BytesToRead-$Total)
            if($Read -le 0){break}
            $Total+=$Read
        }
        if($Total -lt $Buffer.Length){
            $Trimmed=New-Object byte[] $Total
            [Array]::Copy($Buffer,$Trimmed,$Total)
            $Buffer=$Trimmed
        }
        return [pscustomobject][ordered]@{Bytes=$Buffer;BytesRead=$Total;OriginalLength=$Length;Truncated=($Length -gt $Total)}
    }finally{if($null-ne$Stream){$Stream.Dispose()}}
}
function Convert-BytesToText {
    param([byte[]]$Bytes)
    if($null-eq$Bytes -or $Bytes.Length -eq 0){return ''}
    $Text=(New-Object Text.UTF8Encoding($false,$false)).GetString($Bytes)
    if($Text -match "`0"){try{$Text=[Text.Encoding]::Unicode.GetString($Bytes)}catch{}}
    return $Text
}
function Get-Definitions {
    return [object[]]@(
        [pscustomobject]@{Class='PotentialPlaintextSecretAssignment';Pattern='(?im)^\s*\$?[A-Za-z0-9_.-]*(password|passwd|pwd|secret|token|apikey|api_key|accesskey)[A-Za-z0-9_.-]*\s*=\s*[^\s$][^\r\n]*';Weight=100;Sensitive=$true}
        [pscustomobject]@{Class='CredentialParameter';Pattern='(?i)(-credential\b|-username\b|-password\b|-clientsecret\b|-accesstoken\b)';Weight=55;Sensitive=$true}
        [pscustomobject]@{Class='PSCredentialConstruction';Pattern='(?i)(System\.Management\.Automation\.PSCredential|New-Object\s+.*PSCredential|\[PSCredential\])';Weight=45;Sensitive=$true}
        [pscustomobject]@{Class='SecureStringConversion';Pattern='(?i)(ConvertTo-SecureString|SecureStringToBSTR|PtrToStringAuto)';Weight=45;Sensitive=$true}
        [pscustomobject]@{Class='CertificateImport';Pattern='(?i)(Import-PfxCertificate|X509Certificate2|X509Certificate2Collection|certutil(?:\.exe)?\s+.*-importpfx|Import-Pfx)';Weight=50;Sensitive=$true}
        [pscustomobject]@{Class='MappedDriveCredential';Pattern='(?i)(New-PSDrive|net\s+use)\b[^\r\n]*(credential|user:|password|persistent)';Weight=55;Sensitive=$true}
        [pscustomobject]@{Class='PowerShellRemoting';Pattern='(?i)(Invoke-Command|Enter-PSSession|New-PSSession|Test-WSMan|winrs(?:\.exe)?)';Weight=35;Sensitive=$false}
        [pscustomobject]@{Class='PsExecOrAdminShare';Pattern='(?i)(psexec|\\\\[^\\\s]+\\(?:admin\$|c\$|ipc\$))';Weight=45;Sensitive=$false}
        [pscustomobject]@{Class='ScheduledTaskOperation';Pattern='(?i)(schtasks(?:\.exe)?|Register-ScheduledTask|New-ScheduledTask|ScheduledTask)';Weight=35;Sensitive=$false}
        [pscustomobject]@{Class='ServiceOperation';Pattern='(?i)(New-Service|Set-Service|sc(?:\.exe)?\s+(?:create|config|start)|Win32_Service)';Weight=35;Sensitive=$false}
        [pscustomobject]@{Class='EncodedPowerShell';Pattern='(?i)(powershell(?:\.exe)?[^\r\n]*(?:-enc|-encodedcommand)|FromBase64String)';Weight=60;Sensitive=$false}
        [pscustomobject]@{Class='DownloadOrStaging';Pattern='(?i)(Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|DownloadFile|DownloadString|curl(?:\.exe)?|wget(?:\.exe)?)';Weight=35;Sensitive=$false}
        [pscustomobject]@{Class='DomainJoinOperation';Pattern='(?i)(Add-Computer|JoinDomainOrWorkgroup|netdom(?:\.exe)?\s+join|djoin(?:\.exe)?)';Weight=40;Sensitive=$true}
        [pscustomobject]@{Class='SoftwareDeployment';Pattern='(?i)(msiexec(?:\.exe)?|Start-Process[^\r\n]*\.msi|Install-Package|choco(?:\.exe)?\s+install|winget(?:\.exe)?\s+install)';Weight=25;Sensitive=$false}
        [pscustomobject]@{Class='SecurityControlModification';Pattern='(?i)(Add-MpPreference|Set-MpPreference|DisableRealtimeMonitoring|ExclusionPath|ExclusionProcess|netsh\s+advfirewall)';Weight=50;Sensitive=$false}
        [pscustomobject]@{Class='HardCodedUncOrHostReference';Pattern='(?i)(\\\\[A-Za-z0-9_.-]+\\|https?://[A-Za-z0-9_.:-]+)';Weight=10;Sensitive=$false}
        [pscustomobject]@{Class='AccountOrServiceIdentityReference';Pattern='(?i)(runas|serviceaccount|username|userprincipalname|domain\\[A-Za-z0-9_.-]+)';Weight=15;Sensitive=$true}
        [pscustomobject]@{Class='CyberArkContext';Pattern='(?i)(CyberArk|PSM|PVWA|CPM|CCP|AIMWebService)';Weight=30;Sensitive=$false}
    )
}
function Analyze-Text {
    param([string]$Text,[string]$Extension)
    $DetectionList=New-Object 'System.Collections.Generic.List[object]'
    $Score=0
    foreach($Definition in (Get-Definitions)){
        $Matches=[regex]::Matches($Text,[string]$Definition.Pattern)
        if($Matches.Count -gt 0){
            $Score += ([int]$Definition.Weight * [Math]::Min($Matches.Count,5))
            $DetectionList.Add([pscustomobject][ordered]@{DetectionClass=[string]$Definition.Class;MatchCount=[int]$Matches.Count;PotentiallySensitive=[bool]$Definition.Sensitive;Value='<REDACTED>';Weight=[int]$Definition.Weight})
        }
    }
    $ParseState='NotApplicable'
    $ParseErrorCount=0
    if($Extension -in @('.ps1','.psm1','.psd1')){
        $ParseState='PowerShellParserUnavailable'
        try{
            $Tokens=$null;$ParseErrors=$null
            $null=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$Tokens,[ref]$ParseErrors)
            $ParseErrorCount=@($ParseErrors).Count
            $ParseState=if($ParseErrorCount -eq 0){'Parsed'}else{'ParsedWithErrors'}
        }catch{$ParseState='PowerShellParserFailed'}
    }
    return [pscustomobject][ordered]@{Detections=[object[]]$DetectionList.ToArray();AnalysisScore=$Score;ParseState=$ParseState;ParseErrorCount=$ParseErrorCount}
}

try{
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'P2-only bounded static analysis. P3 excluded. Scripts are never executed.' DarkGray
    if(-not(Test-Path -LiteralPath $P2RankingDirectory -PathType Container)){throw "P2RankingDirectoryMissing: $P2RankingDirectory"}
    $QueuePath=Join-Path $P2RankingDirectory 'p2-content-validation-queue.json'
    Require-File $QueuePath 'P2 content-validation queue'
    if([string]::IsNullOrWhiteSpace($OutputDirectory)){$OutputDirectory=Join-Path $P2RankingDirectory 'P2ContentValidation-v0.1.1'}
    if(Test-Path -LiteralPath $OutputDirectory -PathType Container){if(@(Get-ChildItem -LiteralPath $OutputDirectory -Force).Count -gt 0){throw "OutputDirectoryNotEmpty: $OutputDirectory"}}
    New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null

    $Queue=[object[]]@(Get-Content -LiteralPath $QueuePath -Raw|ConvertFrom-Json -ErrorAction Stop|Select-Object -First $MaximumFiles)
    if(@($Queue).Count -eq 0){throw 'The P2 validation queue is empty.'}

    Write-Step 'NETWORK' 'Planned live network operations follow.' Magenta
    Write-Step 'SCOPE' "Files=$(@($Queue).Count); Protocol=SMB; Port=TCP/445; maxBytes=$MaximumBytesPerFile; P2 only; P3=0." DarkCyan
    foreach($Item in $Queue){
        $PreferredUnc=Get-UncPath -Target ([string]$Item.PreferredTarget) -Share ([string]$Item.Share) -RelativePath ([string]$Item.RelativePath)
        Write-Step 'TARGET' "$($Item.PreferredTarget) TCP/445 ${PreferredUnc}: read-only static analysis; execute=False; values=REDACTED; saveContent=False; write=False" DarkCyan
    }
    Write-Step 'CHANGES' 'Script execution=None; remote file changes=None; credential use=None; relay=None; remote execution=None.' DarkCyan

    $ResultList=New-Object 'System.Collections.Generic.List[object]'
    $DetectionList=New-Object 'System.Collections.Generic.List[object]'
    $Position=0
    foreach($Item in $Queue){
        $Position++
        $Sources=[object[]]@($Item.PreferredTarget)+[object[]]@($Item.SourceTargets|Where-Object{$_ -ne $Item.PreferredTarget}|Sort-Object -Unique)
        $ReadSucceeded=$false;$ReadResult=$null;$SelectedTarget=$null;$SelectedUnc=$null;$Attempts=0;$FinalError=$null
        foreach($TargetName in $Sources){
            if($ReadSucceeded){break}
            $Attempts++
            $UncPath=Get-UncPath -Target ([string]$TargetName) -Share ([string]$Item.Share) -RelativePath ([string]$Item.RelativePath)
            Write-Step 'READ' "$Position/$(@($Queue).Count) attempt=$Attempts target=$TargetName path=$UncPath" Yellow
            try{$ReadResult=Read-BoundedFile -Path $UncPath -MaximumBytes $MaximumBytesPerFile;$SelectedTarget=[string]$TargetName;$SelectedUnc=$UncPath;$ReadSucceeded=$true}
            catch{$FinalError=$_.Exception.Message;Add-OperationalError -QueueId ([string]$Item.QueueId) -Stage 'BoundedContentRead' -Target ([string]$TargetName) -UncPath $UncPath -ErrorText $FinalError}
        }
        if(-not$ReadSucceeded){
            $ResultList.Add([pscustomobject][ordered]@{QueueId=[string]$Item.QueueId;Rank=[int]$Item.Rank;RankingScore=[int]$Item.Score;Category=[string]$Item.Category;Share=[string]$Item.Share;RelativePath=[string]$Item.RelativePath;Target=$null;UncPath=$null;Attempts=$Attempts;RemoteReadSucceeded=$false;LocalAnalysisSucceeded=$false;BytesRead=0;OriginalLength=$null;Truncated=$false;PowerShellParseState=$null;PowerShellParseErrorCount=0;DetectionClassCount=0;SensitiveDetectionClassCount=0;DetectedClasses=@();AnalysisScore=0;Disposition='FileUnavailable';CompleteContentSaved=$false;ScriptExecuted=$false;RemoteChange=$false;Error=$FinalError})
            continue
        }
        try{
            $Extension=[IO.Path]::GetExtension([string]$Item.RelativePath).ToLowerInvariant()
            $Text=Convert-BytesToText -Bytes ([byte[]]$ReadResult.Bytes)
            $Analysis=Analyze-Text -Text $Text -Extension $Extension
            $Detections=[object[]]@($Analysis.Detections)
            $SensitiveDetections=[object[]]@($Detections|Where-Object{$_.PotentiallySensitive})
            $DetectedClasses=[object[]]@($Detections|ForEach-Object{[string]$_.DetectionClass}|Sort-Object -Unique)
            foreach($Detection in $Detections){$DetectionList.Add([pscustomobject][ordered]@{QueueId=[string]$Item.QueueId;Target=$SelectedTarget;Share=[string]$Item.Share;RelativePath=[string]$Item.RelativePath;DetectionClass=[string]$Detection.DetectionClass;MatchCount=[int]$Detection.MatchCount;PotentiallySensitive=[bool]$Detection.PotentiallySensitive;Value='<REDACTED>';Weight=[int]$Detection.Weight})}
            $Disposition='NoHighValuePatternDetected'
            if(@($SensitiveDetections).Count -gt 0){$Disposition='PotentialSensitiveConfigurationPatternDetected'}
            elseif(@($Detections).Count -gt 0){$Disposition='OperationalOrDeploymentPatternDetected'}
            elseif([bool]$ReadResult.Truncated){$Disposition='ContentTruncatedNoPatternDetectedInReadWindow'}
            $ResultList.Add([pscustomobject][ordered]@{QueueId=[string]$Item.QueueId;Rank=[int]$Item.Rank;RankingScore=[int]$Item.Score;Category=[string]$Item.Category;Share=[string]$Item.Share;RelativePath=[string]$Item.RelativePath;Target=$SelectedTarget;UncPath=$SelectedUnc;Attempts=$Attempts;RemoteReadSucceeded=$true;LocalAnalysisSucceeded=$true;BytesRead=[int]$ReadResult.BytesRead;OriginalLength=[int64]$ReadResult.OriginalLength;Truncated=[bool]$ReadResult.Truncated;PowerShellParseState=[string]$Analysis.ParseState;PowerShellParseErrorCount=[int]$Analysis.ParseErrorCount;DetectionClassCount=@($Detections).Count;SensitiveDetectionClassCount=@($SensitiveDetections).Count;DetectedClasses=$DetectedClasses;AnalysisScore=[int]$Analysis.AnalysisScore;Disposition=$Disposition;CompleteContentSaved=$false;ScriptExecuted=$false;RemoteChange=$false;Error=$null})
        }catch{
            $FinalError=$_.Exception.Message;Add-OperationalError -QueueId ([string]$Item.QueueId) -Stage 'LocalStaticAnalysis' -Target $SelectedTarget -UncPath $SelectedUnc -ErrorText $FinalError
            $ResultList.Add([pscustomobject][ordered]@{QueueId=[string]$Item.QueueId;Rank=[int]$Item.Rank;RankingScore=[int]$Item.Score;Category=[string]$Item.Category;Share=[string]$Item.Share;RelativePath=[string]$Item.RelativePath;Target=$SelectedTarget;UncPath=$SelectedUnc;Attempts=$Attempts;RemoteReadSucceeded=$true;LocalAnalysisSucceeded=$false;BytesRead=[int]$ReadResult.BytesRead;OriginalLength=[int64]$ReadResult.OriginalLength;Truncated=[bool]$ReadResult.Truncated;PowerShellParseState=$null;PowerShellParseErrorCount=0;DetectionClassCount=0;SensitiveDetectionClassCount=0;DetectedClasses=@();AnalysisScore=0;Disposition='LocalAnalysisFailed';CompleteContentSaved=$false;ScriptExecuted=$false;RemoteChange=$false;Error=$FinalError})
        }finally{if($null-ne$ReadResult -and $null-ne$ReadResult.Bytes){[Array]::Clear($ReadResult.Bytes,0,$ReadResult.Bytes.Length)}}
    }

    $Results=[object[]]$ResultList.ToArray();$Detections=[object[]]$DetectionList.ToArray();$Errors=[object[]]$OperationalErrors.ToArray()
    $RemoteReads=[int]@($Results|Where-Object{$_.RemoteReadSucceeded}).Count
    $Validated=[int]@($Results|Where-Object{$_.LocalAnalysisSucceeded}).Count
    $SensitiveFiles=[int]@($Results|Where-Object{$_.Disposition -eq 'PotentialSensitiveConfigurationPatternDetected'}).Count
    $OperationalFiles=[int]@($Results|Where-Object{$_.Disposition -eq 'OperationalOrDeploymentPatternDetected'}).Count
    $Unavailable=[int]@($Results|Where-Object{$_.Disposition -eq 'FileUnavailable'}).Count
    $AnalysisFailed=[int]@($Results|Where-Object{$_.Disposition -eq 'LocalAnalysisFailed'}).Count
    $Overall='NoHighValueP2PatternDetected'
    if($SensitiveFiles -gt 0){$Overall='PotentialSensitiveP2PatternsDetected'}elseif($OperationalFiles -gt 0){$Overall='OperationalP2PatternsDetected'}elseif($Validated -eq 0){$Overall='P2ValidationInconclusive'}

    $ResultsJson=Join-Path $OutputDirectory 'p2-content-validation-results.json';$ResultsCsv=Join-Path $OutputDirectory 'p2-content-validation-results.csv'
    $DetectionsJson=Join-Path $OutputDirectory 'p2-redacted-detections.json';$DetectionsCsv=Join-Path $OutputDirectory 'p2-redacted-detections.csv'
    $ErrorsJson=Join-Path $OutputDirectory 'operational-errors.json'
    Write-JsonArray $Results $ResultsJson;$Results|Export-Csv -LiteralPath $ResultsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $Detections $DetectionsJson;$Detections|Export-Csv -LiteralPath $DetectionsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray $Errors $ErrorsJson

    $Summary=[pscustomobject][ordered]@{SchemaVersion='1.0';PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;Status=if(@($Errors).Count-gt0){'CompletedWithErrors'}else{'Completed'};GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o');SourceP2RankingDirectory=$P2RankingDirectory;OverallDisposition=$Overall;Counts=[pscustomobject]@{FilesSelected=@($Queue).Count;RemoteReadSuccesses=$RemoteReads;FilesValidated=$Validated;PotentialSensitivePatternFiles=$SensitiveFiles;OperationalPatternFiles=$OperationalFiles;UnavailableFiles=$Unavailable;LocalAnalysisFailures=$AnalysisFailed;DetectionRows=@($Detections).Count;P3Included=0;OperationalErrors=@($Errors).Count};InterpretationBoundary=@('Static pattern detection is a lead and does not prove a valid credential or exploitable execution path.','Potential values are never emitted.','Scripts were never executed.','P3 artifacts were excluded.','A vulnerability requires current applicability and reproduced impact.');Safety=[pscustomobject]@{MaximumBytesPerFile=$MaximumBytesPerFile;P3Included=0;ScriptExecution='None';SecretOutput='None';CompleteContentSaved=$false;RemoteFileChanges='None';CredentialUse='None';RelayAttempts='None';RemoteExecution='None';OllamaActivity='None'}}
    $SummaryPath=Join-Path $OutputDirectory 'p2-content-validation-summary.json';Write-JsonDocument $Summary $SummaryPath

    $RowsHtml=($Results|ForEach-Object{'<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>'-f(Convert-HtmlText $_.Rank),(Convert-HtmlText $_.RelativePath),(Convert-HtmlText $_.BytesRead),(Convert-HtmlText $_.DetectedClasses),(Convert-HtmlText $_.AnalysisScore),(Convert-HtmlText $_.Disposition)})-join"`n"
    $ReportPath=Join-Path $OutputDirectory 'MSADPT-SMB-P2-Content-Validation.html'
    $Html=@"
<!doctype html><html><head><meta charset="utf-8"><title>MSADPT SMB P2 Content Validation</title><style>body{font-family:Segoe UI,Arial;margin:32px;color:#17202a}h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}th{background:#eaf2f8}.note{color:#5d6d7e}</style></head><body><h1>MSADPT SMB P2 Redacted Static Analysis</h1><div class="card"><b>Disposition:</b> $(Convert-HtmlText $Overall)<br><b>Files selected:</b> $(@($Queue).Count)<br><b>Remote reads:</b> $RemoteReads<br><b>Validated:</b> $Validated<br><b>Potential-sensitive-pattern files:</b> $SensitiveFiles<br><b>Operational-pattern files:</b> $OperationalFiles<br><b>P3 included:</b> 0<br><b>Scripts executed:</b> None<br><b>Complete contents saved:</b> No<br><b>Remote changes:</b> None</div><h2>Results</h2><table><tr><th>Rank</th><th>Relative path</th><th>Bytes</th><th>Detection classes</th><th>Analysis score</th><th>Disposition</th></tr>$RowsHtml</table><h2>Evidence</h2><ul><li><a href="p2-content-validation-results.csv">Results</a></li><li><a href="p2-redacted-detections.csv">Redacted detections</a></li><li><a href="operational-errors.json">Operational errors</a></li><li><a href="p2-content-validation-summary.json">Summary</a></li></ul><p class="note">Values are redacted. Static detections are leads until current applicability and impact are reproduced.</p></body></html>
"@
    [IO.File]::WriteAllText($ReportPath,$Html,(New-Object Text.UTF8Encoding($false)))
    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File|Where-Object{$_.Name-ne'evidence-manifest.json'}|Sort-Object Name)
    $ManifestRows=[object[]]@(foreach($File in $Files){[pscustomobject]@{Name=$File.Name;Size=[int64]$File.Length;SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash}})
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json';Write-JsonDocument ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';FileCount=@($ManifestRows).Count;Files=$ManifestRows}) $ManifestPath

    Write-Step 'DONE' "P2 validation complete: selected=$(@($Queue).Count), remote-read=$RemoteReads, validated=$Validated, sensitive=$SensitiveFiles, operational=$OperationalFiles, unavailable=$Unavailable, analysis-failed=$AnalysisFailed, P3=0, disposition=$Overall." Green
    [pscustomobject][ordered]@{Status=if(@($Errors).Count-gt0){'PassedWithErrors'}else{'Passed'};PackageIdentity=$PackageIdentity;PackageVersion=$PackageVersion;OverallDisposition=$Overall;SelectedFileCount=@($Queue).Count;RemoteReadSuccessCount=$RemoteReads;ValidatedFileCount=$Validated;PotentialSensitivePatternFileCount=$SensitiveFiles;OperationalPatternFileCount=$OperationalFiles;UnavailableFileCount=$Unavailable;LocalAnalysisFailureCount=$AnalysisFailed;RedactedDetectionCount=@($Detections).Count;P3IncludedCount=0;OperationalErrorCount=@($Errors).Count;OutputDirectory=$OutputDirectory;HtmlReportPath=$ReportPath;SummaryPath=$SummaryPath;ManifestPath=$ManifestPath;MaximumBytesPerFile=$MaximumBytesPerFile;ScriptExecution='None';SecretOutput='None';CompleteContentSaved='No';RemoteFileChanges='None';CredentialUse='None';RelayAttempts='None';RemoteExecution='None';OllamaActivity='None'}
}catch{Write-Step 'FAIL' $_.Exception.Message Red;throw}
