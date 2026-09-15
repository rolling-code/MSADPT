[CmdletBinding()]param([string]$RepositoryRoot=(Resolve-Path(Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$dns=Join-Path $RepositoryRoot 'Modules\ADDnsSecurity\Invoke-MSADPTADDnsSecurity.ps1'
$kerb=Join-Path $RepositoryRoot 'Modules\Kerberos\Invoke-MSADPTKerberosSPNBaselineCollection-v0.1.2.ps1'
foreach($path in @($dns,$kerb)){if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "RequiredFileMissing: $path"};$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors);if(@($errors).Count-gt0){throw "$path`: $(@($errors|ForEach-Object{$_.Message})-join'; ')"}}
$dnsText=[IO.File]::ReadAllText($dns)
foreach($marker in @("`$attrs['defaultNamingContext']",'GetValues([string])','Write-Output -NoEnumerate','DefaultNamingContextInvalid','CleanupVerified','NoSuchObject')){if(-not$dnsText.Contains($marker)){throw "DnsContractMissing: $marker"}}
$kerbText=[IO.File]::ReadAllText($kerb)
foreach($marker in @('Get-ADRootDSE','read-only RootDSE validation','defaultNamingContext')){if(-not$kerbText.Contains($marker)){throw "KerberosContractMissing: $marker"}}
if($kerbText.Contains('Identity = $Server')){throw 'BrittleKerberosIdentityValidationStillPresent'}
[pscustomobject]@{Status='Passed';DnsRootDseTypedExtraction=$true;DnsAttributeNoEnumeration=$true;KerberosRootDseServerValidation=$true;ParserErrorCount=0}
