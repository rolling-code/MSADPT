<#
.SYNOPSIS
Offline deterministic tests for MSADPT ADCS ACL permission evaluation.
.NOTES
Version: 1.0.0
No Active Directory connection or collector execution is performed.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$CollectorPath = (Join-Path $PSScriptRoot 'Invoke-MSADPTADCSConfigurationCollection.ps1')
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $CollectorPath -PathType Leaf)) { throw "Collector not found: $CollectorPath" }
$Tokens=$null;$Errors=$null
$Ast=[System.Management.Automation.Language.Parser]::ParseFile($CollectorPath,[ref]$Tokens,[ref]$Errors)
if($Errors.Count -gt 0){throw "Collector parse failed: $($Errors.Message -join '; ')"}
$Names=@('Test-MSADPTRightsMask','Get-MSADPTTemplateAccessEntry')
foreach($Name in $Names){
    $FunctionAst=$Ast.Find({param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $Name},$true)
    if($null -eq $FunctionAst){throw "Required function not found: $Name"}
    Invoke-Expression $FunctionAst.Extent.Text
}
$script:PermissionEvaluationVersion='1.1.0'
$script:EnrollExtendedRightGuid=[guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$script:AutoEnrollExtendedRightGuid=[guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
$script:EmptyGuid=[guid]::Empty
function New-TestRule {
 param([System.DirectoryServices.ActiveDirectoryRights]$Rights,[guid]$ObjectType=[guid]::Empty,[string]$Type='Allow')
 [pscustomobject]@{
  IdentityReference=[pscustomobject]@{Value='TEST\\Principal'}
  AccessControlType=$Type
  ActiveDirectoryRights=$Rights
  ObjectType=$ObjectType
  InheritedObjectType=[guid]::Empty
  IsInherited=$false
  InheritanceType='None'
 }
}
$Cases=@(
 @{Name='GenericRead';Rights=[System.DirectoryServices.ActiveDirectoryRights]::GenericRead;GA=$false;GW=$false;WP=$false;WD=$false;WO=$false;Enroll=$false;Auto=$false;AllExt=$false},
 @{Name='GenericWrite';Rights=[System.DirectoryServices.ActiveDirectoryRights]::GenericWrite;GA=$false;GW=$true;WP=$true;WD=$false;WO=$false;Enroll=$false;Auto=$false;AllExt=$false},
 @{Name='GenericAll';Rights=[System.DirectoryServices.ActiveDirectoryRights]::GenericAll;GA=$true;GW=$true;WP=$true;WD=$true;WO=$true;Enroll=$false;Auto=$false;AllExt=$false},
 @{Name='WriteProperty';Rights=[System.DirectoryServices.ActiveDirectoryRights]::WriteProperty;GA=$false;GW=$false;WP=$true;WD=$false;WO=$false;Enroll=$false;Auto=$false;AllExt=$false},
 @{Name='WriteDacl';Rights=[System.DirectoryServices.ActiveDirectoryRights]::WriteDacl;GA=$false;GW=$false;WP=$false;WD=$true;WO=$false;Enroll=$false;Auto=$false;AllExt=$false},
 @{Name='WriteOwner';Rights=[System.DirectoryServices.ActiveDirectoryRights]::WriteOwner;GA=$false;GW=$false;WP=$false;WD=$false;WO=$true;Enroll=$false;Auto=$false;AllExt=$false},
 @{Name='Enroll';Rights=[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight;Object=$script:EnrollExtendedRightGuid;GA=$false;GW=$false;WP=$false;WD=$false;WO=$false;Enroll=$true;Auto=$false;AllExt=$false},
 @{Name='AutoEnroll';Rights=[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight;Object=$script:AutoEnrollExtendedRightGuid;GA=$false;GW=$false;WP=$false;WD=$false;WO=$false;Enroll=$false;Auto=$true;AllExt=$false},
 @{Name='AllExtendedRights';Rights=[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight;Object=[guid]::Empty;GA=$false;GW=$false;WP=$false;WD=$false;WO=$false;Enroll=$true;Auto=$true;AllExt=$true},
 @{Name='DeniedGenericAll';Rights=[System.DirectoryServices.ActiveDirectoryRights]::GenericAll;Type='Deny';GA=$false;GW=$false;WP=$false;WD=$false;WO=$false;Enroll=$false;Auto=$false;AllExt=$false}
)
$Results=foreach($Case in $Cases){
 $Object=if($Case.ContainsKey('Object')){$Case.Object}else{[guid]::Empty}
 $Type=if($Case.ContainsKey('Type')){$Case.Type}else{'Allow'}
 $Actual=Get-MSADPTTemplateAccessEntry (New-TestRule -Rights $Case.Rights -ObjectType $Object -Type $Type)
 $Checks=@(
  $Actual.AllowsGenericAll -eq $Case.GA,
  $Actual.AllowsGenericWrite -eq $Case.GW,
  $Actual.AllowsWriteProperty -eq $Case.WP,
  $Actual.AllowsWriteDacl -eq $Case.WD,
  $Actual.AllowsWriteOwner -eq $Case.WO,
  $Actual.AllowsEnroll -eq $Case.Enroll,
  $Actual.AllowsAutoEnroll -eq $Case.Auto,
  $Actual.AllowsAllExtendedRights -eq $Case.AllExt
 )
 [pscustomobject]@{Test=$Case.Name;Passed=($Checks -notcontains $false);Actual=$Actual}
}
$Results|Select-Object Test,Passed|Format-Table -AutoSize
$Failed=@($Results|Where-Object{-not $_.Passed})
if($Failed.Count -gt 0){$Failed|ForEach-Object{$_.Actual|Format-List *};throw "$($Failed.Count) ADCS permission evaluation test(s) failed."}
[pscustomobject]@{Status='Passed';TestCount=$Results.Count;PermissionEvaluationVersion=$script:PermissionEvaluationVersion;CollectorPath=$CollectorPath}
