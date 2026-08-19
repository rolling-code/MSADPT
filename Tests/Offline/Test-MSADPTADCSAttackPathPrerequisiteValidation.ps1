<#
.SYNOPSIS
Runs offline structural and serialization tests for ADCSAttackPathPrerequisiteValidation v0.1.4.
.NOTES
Version: 1.0.4
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ModulePath,
    [Parameter(Mandatory=$true)][string]$ManifestPath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
foreach($Path in @($ModulePath,$ManifestPath)){if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "Required file not found: $Path"}}
$Tokens=$null;$Errors=$null
$Ast=[System.Management.Automation.Language.Parser]::ParseFile($ModulePath,[ref]$Tokens,[ref]$Errors)
if($Errors.Count -gt 0){throw "Module parse failed: $($Errors.Message -join '; ')"}
$Manifest=Get-Content -LiteralPath $ManifestPath -Raw|ConvertFrom-Json
$Source=Get-Content -LiteralPath $ModulePath -Raw
$Functions=@($Ast.FindAll({param($Node)$Node -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true).Name)
$Commands=@($Ast.FindAll({param($Node)$Node -is [System.Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
$Checks=[ordered]@{
    ModuleVersion=([string]$Manifest.moduleVersion -eq '0.1.4')
    ManifestVersion=([string]$Manifest.manifestVersion -eq '1.0.4')
    ReadOnly=([string]$Manifest.executionClass -eq 'read_only')
    HasFlatMemberConverter=($Functions -contains 'ConvertTo-MSADPTFlatMember')
    HasClassifiedControlAce=($Functions -contains 'ConvertTo-MSADPTClassifiedControlAce')
    HasRelevantControlEvidence=($Functions -contains 'Get-MSADPTObjectControlEvidence')
    HasPortableSidLookup=($Functions -contains 'ConvertTo-MSADPTLdapSidFilterValue')
    UsesBoundedJsonDepth=($Source -match 'ConvertTo-Json -Depth 8')
    DoesNotUseDepth30=($Source -notmatch 'ConvertTo-Json -Depth 30')
    FlattensSidValue=($Source -match 'Sid = \$SidText')
    ClassifiesMembershipControl=($Source -match "'MembershipControl'")
    ClassifiesOwnerOrDacl=($Source -match "'OwnerOrDaclControl'")
    ExcludesPropertySpecificFromRelevant=($Source -match "Classification -in @\('BroadObjectControl','OwnerOrDaclControl','MembershipControl','BroadPropertyControl','DenyControl'\)")
    BlocksEnrollment=(@($Manifest.doesNotPerform)-contains 'certificateEnrollment')
    BlocksStateChange=(@($Manifest.doesNotPerform)-contains 'stateChange')
    NoInvokeExpression=($Commands -notcontains 'Invoke-Expression')
    NoADWrites=(@($Commands|Where-Object{$_ -match '^(Set|Add|Remove|New|Move|Rename)-AD'}).Count -eq 0)
    NoCertificateRequests=(@($Commands|Where-Object{$_ -match '^(certreq|Get-Certificate)$'}).Count -eq 0)
}
$Results=foreach($Check in $Checks.GetEnumerator()){[pscustomobject]@{Test=$Check.Key;Passed=[bool]$Check.Value}}
$Results|Format-Table -AutoSize
$Failed=@($Results|Where-Object{-not $_.Passed})
if($Failed.Count -gt 0){throw "$($Failed.Count) offline validation test(s) failed."}
[pscustomobject]@{Status='Passed';TestCount=$Results.Count;ModuleVersion=[string]$Manifest.moduleVersion;ManifestVersion=[string]$Manifest.manifestVersion;ModulePath=$ModulePath;ManifestPath=$ManifestPath}
