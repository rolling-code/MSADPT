<#
.SYNOPSIS
Validates flattened MSADPT ADCS prerequisite evidence offline.
.NOTES
Version: 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ResolvedEvidencePath,
    [Parameter()][string]$SummaryCsvPath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not(Test-Path -LiteralPath $ResolvedEvidencePath -PathType Leaf)){throw "Evidence not found: $ResolvedEvidencePath"}
$Raw=Get-Content -LiteralPath $ResolvedEvidencePath -Raw
$Evidence=@($Raw|ConvertFrom-Json -ErrorAction Stop)
$Issues=New-Object 'System.Collections.Generic.List[object]'
$AllowedMemberProperties=@('Name','SamAccountName','ObjectClass','DistinguishedName','Sid')
$AllowedControlProperties=@('IdentityReference','AccessControlType','ActiveDirectoryRights','ObjectType','IsInherited','Classification','IsPrivilegedOrSystem','Reason')
foreach($Identity in $Evidence){
    foreach($CollectionName in @('DirectMembers','RecursiveMembers')){
        foreach($Member in @($Identity.$CollectionName)){
            $Properties=@($Member.PSObject.Properties.Name)
            $Unexpected=@($Properties|Where-Object{$_ -notin $AllowedMemberProperties})
            if($Unexpected.Count -gt 0){$Issues.Add([pscustomobject]@{Identity=$Identity.IdentityReference;Area=$CollectionName;Issue='UnexpectedMemberProperty';Detail=($Unexpected -join ';')})}
            if($null-ne$Member.Sid -and $Member.Sid -isnot [string]){$Issues.Add([pscustomobject]@{Identity=$Identity.IdentityReference;Area=$CollectionName;Issue='NonScalarSid';Detail=[string]$Member.Sid.GetType().FullName})}
        }
    }
    foreach($Ace in @($Identity.ControlEntries)){
        $Properties=@($Ace.PSObject.Properties.Name)
        $Unexpected=@($Properties|Where-Object{$_ -notin $AllowedControlProperties})
        if($Unexpected.Count -gt 0){$Issues.Add([pscustomobject]@{Identity=$Identity.IdentityReference;Area='ControlEntries';Issue='UnexpectedControlProperty';Detail=($Unexpected -join ';')})}
        if($Ace.Classification -notin @('BroadObjectControl','OwnerOrDaclControl','MembershipControl','BroadPropertyControl','DenyControl')){$Issues.Add([pscustomobject]@{Identity=$Identity.IdentityReference;Area='ControlEntries';Issue='UnexpectedClassification';Detail=[string]$Ace.Classification})}
    }
}
if($SummaryCsvPath){
    if(-not(Test-Path -LiteralPath $SummaryCsvPath -PathType Leaf)){throw "Summary not found: $SummaryCsvPath"}
    $Summary=@(Import-Csv -LiteralPath $SummaryCsvPath)
    if($Summary.Count -ne $Evidence.Count){$Issues.Add([pscustomobject]@{Identity='*';Area='Summary';Issue='RowCountMismatch';Detail="JSON=$($Evidence.Count);CSV=$($Summary.Count)"})}
}
$RoundTrip=$Evidence|ConvertTo-Json -Depth 8|ConvertFrom-Json
if(@($RoundTrip).Count -ne $Evidence.Count){$Issues.Add([pscustomobject]@{Identity='*';Area='Serialization';Issue='RoundTripCountMismatch';Detail='Evidence count changed after JSON round trip.'})}
if($Issues.Count -gt 0){$Issues|Format-Table -AutoSize;throw "$($Issues.Count) evidence serialization issue(s) detected."}
[pscustomobject]@{Status='Passed';IdentityCount=$Evidence.Count;IssueCount=0;ResolvedEvidencePath=$ResolvedEvidencePath;SummaryCsvPath=$SummaryCsvPath}
