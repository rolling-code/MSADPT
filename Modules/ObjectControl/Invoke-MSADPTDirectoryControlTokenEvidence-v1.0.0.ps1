<#
.SYNOPSIS
Collects read-only token evidence for MSADPT Directory Control trustees.
.DESCRIPTION
Reads trustee SIDs from Directory Control candidate evidence, resolves each directory principal,
traverses direct and nested group membership with cycle protection, includes SIDHistory and the
primary group when available, records incomplete resolution, and exports evidence for the offline
effective-access evaluator. No directory object is modified.
.NOTES
Version: 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$CandidateEvidencePath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
    [string]$Server,
    [PSCredential]$Credential,
    [ValidateRange(1,64)][int]$MaximumDepth = 16,
    [switch]$NoColor
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ModuleId = 'Invoke-MSADPTDirectoryControlTokenEvidence'
$ModuleVersion = '1.0.0'
function Show {
    param([string]$State,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray)
    $Text='[{0,-12}] {1}' -f $State,$Message
    if($NoColor){Write-Host $Text}else{Write-Host $Text -ForegroundColor $Color}
}
function Get-SafeProperty {
    param([object]$Object,[string]$Name,[object]$Default=$null)
    if($null -eq $Object){return $Default}
    $Property=$Object.PSObject.Properties[$Name]
    if($null -eq $Property -or $null -eq $Property.Value){return $Default}
    return $Property.Value
}
function ConvertTo-SidText {
    param([object]$Value)
    if($null -eq $Value){return $null}
    if($Value -is [Security.Principal.SecurityIdentifier]){return $Value.Value.ToUpperInvariant()}
    $Text=[string]$Value
    if($Text -match '^S-1-'){return $Text.ToUpperInvariant()}
    return $null
}
function Write-JsonDocument {
    param([object]$Value,[string]$Path)
    $Value|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $Path -Encoding UTF8
    $null=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop
}
function Write-JsonArray {
    param([object[]]$Value,[string]$Path)
    $Array=[object[]]@($Value)
    if($Array.Count -eq 0){[IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))}
    else{$Array|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $Path -Encoding UTF8}
    $null=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop
}
if(-not(Test-Path -LiteralPath $CandidateEvidencePath -PathType Leaf)){throw "CandidateEvidenceMissing: $CandidateEvidencePath"}
if($null -eq (Get-Module -ListAvailable -Name ActiveDirectory|Select-Object -First 1)){throw 'ActiveDirectoryModuleUnavailable'}
Import-Module ActiveDirectory -ErrorAction Stop
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$CommonParameters=@{Properties=@('objectSid','sIDHistory','memberOf','primaryGroupID','distinguishedName','samAccountName','objectClass','userAccountControl');ErrorAction='Stop'}
if(-not[string]::IsNullOrWhiteSpace($Server)){$CommonParameters.Server=$Server}
if($null -ne $Credential){$CommonParameters.Credential=$Credential}
$Target='Current domain through ActiveDirectory module'
if(-not[string]::IsNullOrWhiteSpace($Server)){$Target=$Server}
Show -State 'START' -Message "$ModuleId v$ModuleVersion" -Color Cyan
Show -State 'NETWORK' -Message "Target=$Target; protocol=ADWS/LDAP; ports=environment-defined; operation=read-only trustee and nested-group resolution." -Color Magenta
Show -State 'SAFETY' -Message 'Directory changes=None; authentication attempts=None; impact reproduction=None; secrets=None.' -Color Yellow
$InputRows=@(Import-Csv -LiteralPath $CandidateEvidencePath)
$PrincipalSids=New-Object 'Collections.Generic.HashSet[string]'
foreach($Row in $InputRows){
    foreach($PropertyName in @('TrusteeSid','PrincipalSid')){
        $Sid=ConvertTo-SidText (Get-SafeProperty $Row $PropertyName)
        if($null -ne $Sid){$null=$PrincipalSids.Add($Sid)}
    }
}
Show -State 'SCOPE' -Message "Unique trustee SIDs=$($PrincipalSids.Count); maximum depth=$MaximumDepth." -Color DarkCyan
$TokenRows=New-Object 'Collections.Generic.List[object]'
$PrincipalRows=New-Object 'Collections.Generic.List[object]'
$Errors=New-Object 'Collections.Generic.List[object]'
function Get-DirectoryObject {
    param([string]$Identity)
    $Parameters=$CommonParameters.Clone()
    $Parameters.Identity=$Identity
    return Get-ADObject @Parameters
}
$Domain=$null
try{
    $DomainParameters=@{ErrorAction='Stop'}
    if(-not[string]::IsNullOrWhiteSpace($Server)){$DomainParameters.Server=$Server}
    if($null -ne $Credential){$DomainParameters.Credential=$Credential}
    $Domain=Get-ADDomain @DomainParameters
}
catch{
    $Errors.Add([pscustomobject]@{PrincipalSid='';Stage='DomainContext';Identity='';Error=$_.Exception.Message})
}
foreach($PrincipalSid in @($PrincipalSids|Sort-Object)){
    $Complete=$true
    $ResolutionState='Resolved'
    $Principal=$null
    try{$Principal=Get-DirectoryObject $PrincipalSid}
    catch{
        $Complete=$false
        $ResolutionState='Unresolved'
        $Errors.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Stage='ResolvePrincipal';Identity=$PrincipalSid;Error=$_.Exception.Message})
    }
    $Display=$PrincipalSid
    if($null -ne $Principal){
        if(-not[string]::IsNullOrWhiteSpace([string]$Principal.SamAccountName)){$Display=[string]$Principal.SamAccountName}
        else{$Display=[string]$Principal.DistinguishedName}
    }
    $Token=New-Object 'Collections.Generic.HashSet[string]'
    $null=$Token.Add($PrincipalSid)
    $Queue=New-Object 'Collections.Generic.Queue[object]'
    $Visited=New-Object 'Collections.Generic.HashSet[string]'
    $PrincipalTokenRows=New-Object 'Collections.Generic.List[object]'
    $PrincipalTokenRows.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Principal=$Display;TokenSid=$PrincipalSid;TokenPrincipal=$Display;Source='Self';Depth=0;Complete=$false;ResolutionState=$ResolutionState})
    if($null -ne $Principal){
        foreach($HistoryValue in @($Principal.sIDHistory)){
            $HistorySid=ConvertTo-SidText $HistoryValue
            if($null -ne $HistorySid -and $Token.Add($HistorySid)){
                $PrincipalTokenRows.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Principal=$Display;TokenSid=$HistorySid;TokenPrincipal=$HistorySid;Source='SIDHistory';Depth=0;Complete=$false;ResolutionState='SidOnly'})
            }
        }
        foreach($GroupDn in @($Principal.memberOf)){
            if(-not[string]::IsNullOrWhiteSpace([string]$GroupDn)){$Queue.Enqueue([pscustomobject]@{Identity=[string]$GroupDn;Depth=1;Source='DirectGroup'})}
        }
        if($null -ne $Domain -and $null -ne $Principal.primaryGroupID){
            try{
                $PrimarySid="$([string]$Domain.DomainSID.Value)-$([int]$Principal.primaryGroupID)"
                $Queue.Enqueue([pscustomobject]@{Identity=$PrimarySid;Depth=1;Source='PrimaryGroup'})
            }
            catch{
                $Complete=$false
                $Errors.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Stage='PrimaryGroup';Identity=$Display;Error=$_.Exception.Message})
            }
        }
        elseif($null -eq $Domain){$Complete=$false}
    }
    while($Queue.Count -gt 0){
        $Item=$Queue.Dequeue()
        if([int]$Item.Depth -gt $MaximumDepth){$Complete=$false;continue}
        $Identity=[string]$Item.Identity
        if(-not $Visited.Add($Identity.ToLowerInvariant())){continue}
        try{
            $Group=Get-DirectoryObject $Identity
            $GroupSid=ConvertTo-SidText $Group.objectSid
            if($null -eq $GroupSid){$Complete=$false;continue}
            if($Token.Add($GroupSid)){
                $GroupDisplay=[string]$Group.DistinguishedName
                if(-not[string]::IsNullOrWhiteSpace([string]$Group.SamAccountName)){$GroupDisplay=[string]$Group.SamAccountName}
                $PrincipalTokenRows.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Principal=$Display;TokenSid=$GroupSid;TokenPrincipal=$GroupDisplay;Source=[string]$Item.Source;Depth=[int]$Item.Depth;Complete=$false;ResolutionState='Resolved'})
            }
            foreach($ParentDn in @($Group.memberOf)){
                if(-not[string]::IsNullOrWhiteSpace([string]$ParentDn)){$Queue.Enqueue([pscustomobject]@{Identity=[string]$ParentDn;Depth=([int]$Item.Depth+1);Source='NestedGroup'})}
            }
        }
        catch{
            $Complete=$false
            $Errors.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Stage='ResolveGroup';Identity=$Identity;Error=$_.Exception.Message})
        }
    }
    foreach($TokenRow in $PrincipalTokenRows){$TokenRow.Complete=$Complete;$TokenRows.Add($TokenRow)}
    $PrincipalRows.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Principal=$Display;ResolutionState=$ResolutionState;TokenSidCount=$Token.Count;TraversalComplete=$Complete;MaximumDepth=$MaximumDepth})
    $Color=[ConsoleColor]::Green
    if(-not $Complete){$Color=[ConsoleColor]::Yellow}
    Show -State 'PRINCIPAL' -Message "$Display; token SIDs=$($Token.Count); complete=$Complete" -Color $Color
}
$TokenPath=Join-Path $OutputDirectory 'directory-control-token-evidence.csv'
$PrincipalsPath=Join-Path $OutputDirectory 'directory-control-token-principals.json'
$ErrorsPath=Join-Path $OutputDirectory 'directory-control-token-operational-errors.json'
$SummaryPath=Join-Path $OutputDirectory 'directory-control-token-summary.json'
$TokenRows.ToArray()|Export-Csv -LiteralPath $TokenPath -NoTypeInformation -Encoding UTF8
Write-JsonArray -Value $PrincipalRows.ToArray() -Path $PrincipalsPath
Write-JsonArray -Value $Errors.ToArray() -Path $ErrorsPath
$CompleteCount=@($PrincipalRows|Where-Object{$_.TraversalComplete}).Count
$Disposition='Inconclusive'
if($PrincipalRows.Count -eq 0){$Disposition='NotDetected'}elseif($CompleteCount -eq $PrincipalRows.Count){$Disposition='Collected'}
$Summary=[pscustomobject][ordered]@{SchemaVersion='1.0';ModuleId=$ModuleId;ModuleVersion=$ModuleVersion;Status='Completed';Disposition=$Disposition;GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o');PrincipalCount=$PrincipalRows.Count;CompletePrincipalCount=$CompleteCount;IncompletePrincipalCount=($PrincipalRows.Count-$CompleteCount);TokenRowCount=$TokenRows.Count;OperationalErrorCount=$Errors.Count;CandidateEvidencePath=[IO.Path]::GetFullPath($CandidateEvidencePath);Safety=[pscustomobject]@{NetworkActivity='ReadOnlyADQueries';DirectoryChanges='None';ImpactReproduction='None';RemoteChanges='None'}}
Write-JsonDocument -Value $Summary -Path $SummaryPath
$Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File|Where-Object{$_.Name -ne 'evidence-manifest.json'}|Sort-Object Name|ForEach-Object{[pscustomobject]@{Name=$_.Name;Size=$_.Length;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
Write-JsonDocument -Value ([pscustomobject]@{SchemaVersion='1.0';Status='Completed';ModuleId=$ModuleId;ModuleVersion=$ModuleVersion;FileCount=$Files.Count;Files=$Files}) -Path (Join-Path $OutputDirectory 'evidence-manifest.json')
Show -State 'DONE' -Message "Principals=$($PrincipalRows.Count); complete=$CompleteCount; token rows=$($TokenRows.Count); errors=$($Errors.Count)." -Color Green
[pscustomobject][ordered]@{Status='Passed';ModuleId=$ModuleId;ModuleVersion=$ModuleVersion;PrincipalCount=$PrincipalRows.Count;CompletePrincipalCount=$CompleteCount;TokenEvidencePath=$TokenPath;SummaryPath=$SummaryPath;NetworkActivity='ReadOnlyADQueries';RemoteChanges='None'}
