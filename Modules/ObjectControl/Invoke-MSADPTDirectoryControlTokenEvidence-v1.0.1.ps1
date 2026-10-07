<#
.SYNOPSIS
Collects read-only, SID-safe token evidence for MSADPT Directory Control trustees.
.DESCRIPTION
Resolves candidate trustee SIDs using object-class-specific Active Directory cmdlets and a SID-filter
fallback, traverses direct and nested group memberships with cycle protection, includes SIDHistory
and primary-group context, and records per-principal completeness. No directory object is modified.
.NOTES
Version: 1.0.2
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$CandidateEvidencePath,
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
 [string]$Server,
 [PSCredential]$Credential,
 [ValidateRange(1,64)][int]$MaximumDepth=16,
 [switch]$NoColor
)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$ModuleId='Invoke-MSADPTDirectoryControlTokenEvidence';$ModuleVersion='1.0.2'
function Show([string]$State,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray){$Text='[{0,-12}] {1}'-f$State,$Message;if($NoColor){Write-Host $Text}else{Write-Host $Text -ForegroundColor $Color}}
function Field([object]$Object,[string]$Name,[object]$Default=$null){if($null -eq $Object){return $Default};$p=$Object.PSObject.Properties[$Name];if($null -eq $p -or $null -eq $p.Value){return $Default};return $p.Value}
function Sid([object]$Value){if($null -eq $Value){return $null};if($Value -is [Security.Principal.SecurityIdentifier]){return $Value.Value.ToUpperInvariant()};$s=[string]$Value;if($s -match '^S-1-'){return $s.ToUpperInvariant()};return $null}
function Json([object]$Value,[string]$Path){$Value|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $Path -Encoding UTF8;$null=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop}
function JsonArray([object[]]$Value,[string]$Path){$a=[object[]]@($Value);if($a.Count -eq 0){[IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))}else{$a|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $Path -Encoding UTF8};$null=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop}
if(-not(Test-Path -LiteralPath $CandidateEvidencePath -PathType Leaf)){throw "CandidateEvidenceMissing: $CandidateEvidencePath"}
if($null -eq (Get-Module -ListAvailable ActiveDirectory|Select-Object -First 1)){throw 'ActiveDirectoryModuleUnavailable'};Import-Module ActiveDirectory -ErrorAction Stop
$Common=@{ErrorAction='Stop'};if($Server){$Common.Server=$Server};if($Credential){$Common.Credential=$Credential}
$Properties=@('objectSid','sIDHistory','memberOf','primaryGroupID','distinguishedName','samAccountName','objectClass','userAccountControl','enabled')
function Resolve-SidObject([string]$Identity){
 if($Identity -notmatch '^S-1-(?:\d+-)+\d+$'){throw "InvalidSid: $Identity"}
 foreach($Command in @('Get-ADUser','Get-ADGroup','Get-ADComputer')){
  try{$p=$Common.Clone();$p.Identity=$Identity;$p.Properties=$Properties;return & $Command @p}catch{}
 }
 try{$p=$Common.Clone();$p.Filter="objectSid -eq '$Identity'";$p.Properties=$Properties;$objects=@(Get-ADObject @p);if($objects.Count -eq 1){return $objects[0]};if($objects.Count -gt 1){throw "SidResolutionAmbiguous: $Identity"}}catch{if($_.Exception.Message -like 'SidResolutionAmbiguous*'){throw}}
 throw "SidResolutionNotFound: $Identity"
}
function Resolve-DirectoryObject([string]$Identity){
 if($Identity -match '^S-1-'){return Resolve-SidObject $Identity}
 $p=$Common.Clone();$p.Identity=$Identity;$p.Properties=$Properties;return Get-ADObject @p
}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory);New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$Target=if($Server){$Server}else{'current domain'};Show START "$ModuleId v$ModuleVersion" Cyan;Show NETWORK "Target=$Target; protocol=ADWS/LDAP; operations=SID-safe principal lookup, SIDHistory, primary group, direct and nested memberships; changes=None." Magenta;Show SAFETY 'Read-only AD queries. Directory changes=None; impact reproduction=None; secrets=None.' Yellow
$Domain=$null;$GlobalErrors=New-Object 'Collections.Generic.List[object]';try{$Domain=Get-ADDomain @Common}catch{$GlobalErrors.Add([pscustomobject]@{PrincipalSid='';Stage='DomainContext';Identity='';Error=$_.Exception.Message})}
$PrincipalSids=New-Object 'Collections.Generic.HashSet[string]';foreach($row in @(Import-Csv $CandidateEvidencePath)){foreach($n in @('TrusteeSid','PrincipalSid')){$x=Sid (Field $row $n);if($x){$null=$PrincipalSids.Add($x)}}};Show SCOPE "Unique trustee SIDs=$($PrincipalSids.Count); maximum depth=$MaximumDepth." DarkCyan
$TokenRows=New-Object 'Collections.Generic.List[object]';$PrincipalRows=New-Object 'Collections.Generic.List[object]';$Errors=New-Object 'Collections.Generic.List[object]';foreach($g in $GlobalErrors){$Errors.Add($g)}
foreach($PrincipalSid in @($PrincipalSids|Sort-Object)){
 $Complete=$true;$Principal=$null;$Resolution='Resolved';try{$Principal=Resolve-SidObject $PrincipalSid}catch{$Complete=$false;$Resolution='Unresolved';$Errors.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Stage='ResolvePrincipal';Identity=$PrincipalSid;Error=$_.Exception.Message})}
 $Display=$PrincipalSid;if($Principal){$Display=if($Principal.SamAccountName){[string]$Principal.SamAccountName}else{[string]$Principal.DistinguishedName}}
 $Token=New-Object 'Collections.Generic.HashSet[string]';$null=$Token.Add($PrincipalSid);$Rows=New-Object 'Collections.Generic.List[object]';$Rows.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Principal=$Display;TokenSid=$PrincipalSid;TokenPrincipal=$Display;Source='Self';Depth=0;Complete=$false;ResolutionState=$Resolution})
 $Queue=New-Object 'Collections.Generic.Queue[object]';$Visited=New-Object 'Collections.Generic.HashSet[string]'
 if($Principal){
  foreach($h in @($Principal.sIDHistory)){$hs=Sid $h;if($hs -and $Token.Add($hs)){$Rows.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Principal=$Display;TokenSid=$hs;TokenPrincipal=$hs;Source='SIDHistory';Depth=0;Complete=$false;ResolutionState='SidOnly'})}}
  foreach($dn in @($Principal.memberOf)){if($dn){$Queue.Enqueue([pscustomobject]@{Identity=[string]$dn;Depth=1;Source='DirectGroup'})}}
  if($Domain -and $null -ne $Principal.primaryGroupID){$Queue.Enqueue([pscustomobject]@{Identity="$($Domain.DomainSID.Value)-$([int]$Principal.primaryGroupID)";Depth=1;Source='PrimaryGroup'})}elseif(-not$Domain){$Complete=$false}
 }
 while($Queue.Count){$item=$Queue.Dequeue();if($item.Depth -gt $MaximumDepth){$Complete=$false;continue};$id=[string]$item.Identity;if(-not$Visited.Add($id.ToLowerInvariant())){continue};try{$Group=Resolve-DirectoryObject $id;$gs=Sid $Group.objectSid;if(-not$gs){throw "ResolvedObjectMissingSid: $id"};if($Token.Add($gs)){$gd=if($Group.SamAccountName){[string]$Group.SamAccountName}else{[string]$Group.DistinguishedName};$Rows.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Principal=$Display;TokenSid=$gs;TokenPrincipal=$gd;Source=[string]$item.Source;Depth=[int]$item.Depth;Complete=$false;ResolutionState='Resolved'})};foreach($parent in @($Group.memberOf)){if($parent){$Queue.Enqueue([pscustomobject]@{Identity=[string]$parent;Depth=($item.Depth+1);Source='NestedGroup'})}}}catch{$Complete=$false;$Errors.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Stage='ResolveGroup';Identity=$id;Error=$_.Exception.Message})}}
 foreach($Row in $Rows){$Row.Complete=$Complete;$TokenRows.Add($Row)};$PrincipalRows.Add([pscustomobject]@{PrincipalSid=$PrincipalSid;Principal=$Display;ObjectClass=if($Principal){[string]$Principal.ObjectClass}else{''};ResolutionState=$Resolution;TokenSidCount=$Token.Count;TraversalComplete=$Complete;MaximumDepth=$MaximumDepth});Show PRINCIPAL "$Display; token SIDs=$($Token.Count); complete=$Complete" $(if($Complete){'Green'}else{'Yellow'})
}
$TokenPath = Join-Path $OutputDirectory 'directory-control-token-evidence.csv'
$PrincipalPath = Join-Path $OutputDirectory 'directory-control-token-principals.json'
$OperationalErrorPath = Join-Path $OutputDirectory 'directory-control-token-operational-errors.json'
$SummaryPath = Join-Path $OutputDirectory 'directory-control-token-summary.json'
$ManifestPath = Join-Path $OutputDirectory 'evidence-manifest.json'

$TokenRows.ToArray() |
    Export-Csv -LiteralPath $TokenPath -NoTypeInformation -Encoding UTF8

JsonArray $PrincipalRows.ToArray() $PrincipalPath
JsonArray $Errors.ToArray() $OperationalErrorPath

$ResolvedPrincipalCount = @(
    $PrincipalRows |
        Where-Object -Property ResolutionState -EQ 'Resolved'
).Count

$UnresolvedPrincipalCount = @(
    $PrincipalRows |
        Where-Object -Property ResolutionState -EQ 'Unresolved'
).Count

$CompletePrincipalCount = @(
    $PrincipalRows |
        Where-Object -Property TraversalComplete -EQ $true
).Count

$IncompletePrincipalCount = $PrincipalRows.Count - $CompletePrincipalCount

$Disposition = 'Inconclusive'
if ($PrincipalRows.Count -eq 0) {
    $Disposition = 'NotDetected'
}
elseif ($CompletePrincipalCount -eq $PrincipalRows.Count) {
    $Disposition = 'Collected'
}

$Summary = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    ModuleId = $ModuleId
    ModuleVersion = $ModuleVersion
    Status = 'Completed'
    Disposition = $Disposition
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    PrincipalCount = $PrincipalRows.Count
    ResolvedPrincipalCount = $ResolvedPrincipalCount
    UnresolvedPrincipalCount = $UnresolvedPrincipalCount
    CompletePrincipalCount = $CompletePrincipalCount
    IncompletePrincipalCount = $IncompletePrincipalCount
    TokenRowCount = $TokenRows.Count
    OperationalErrorCount = $Errors.Count
    CandidateEvidencePath = [IO.Path]::GetFullPath($CandidateEvidencePath)
    Safety = [pscustomobject][ordered]@{
        NetworkActivity = 'ReadOnlyADQueries'
        DirectoryChanges = 'None'
        RemoteChanges = 'None'
    }
}

Json $Summary $SummaryPath

$ManifestFiles = @(
    Get-ChildItem -LiteralPath $OutputDirectory -File |
        Where-Object -Property Name -NE 'evidence-manifest.json' |
        Sort-Object -Property Name |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name = $_.Name
                Size = $_.Length
                SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        }
)

$Manifest = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    Status = 'Completed'
    ModuleId = $ModuleId
    ModuleVersion = $ModuleVersion
    FileCount = $ManifestFiles.Count
    Files = $ManifestFiles
}

Json $Manifest $ManifestPath

Show DONE "Principals=$($PrincipalRows.Count); resolved=$ResolvedPrincipalCount; complete=$CompletePrincipalCount; errors=$($Errors.Count)." Green

[pscustomobject][ordered]@{
    Status = 'Passed'
    ModuleId = $ModuleId
    ModuleVersion = $ModuleVersion
    PrincipalCount = $PrincipalRows.Count
    ResolvedPrincipalCount = $ResolvedPrincipalCount
    UnresolvedPrincipalCount = $UnresolvedPrincipalCount
    CompletePrincipalCount = $CompletePrincipalCount
    IncompletePrincipalCount = $IncompletePrincipalCount
    OperationalErrorCount = $Errors.Count
    TokenEvidencePath = $TokenPath
    NetworkActivity = 'ReadOnlyADQueries'
    RemoteChanges = 'None'
}
