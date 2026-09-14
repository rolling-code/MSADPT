<#
.SYNOPSIS
Collects static Kerberos encryption posture for service-relevant Active Directory accounts.
.DESCRIPTION
MSADPT Kerberos Account Encryption Posture v0.1.0 runs from a domain-joined Windows host using read-only
Active Directory queries. It inventories enabled accounts with SPNs, managed service accounts, krbtgt accounts,
and accounts explicitly configured for DES. It separates configured encryption capability from observed Kerberos
usage. It does not request tickets, read Security logs, reset passwords, modify accounts, or change domain policy.
.NOTES
Version: 0.1.4
Compatible with Windows PowerShell 5.1 and PowerShell 7 when the ActiveDirectory module is available.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$EngagementDirectory,
    [string]$Server,
    [PSCredential]$Credential,
    [ValidateRange(100,500000)][int]$MaximumAccounts=100000,
    [switch]$IncludeDisabled,
    [switch]$NoColor
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$ModuleVersion = '0.1.4'
function Show([string]$State,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray){$text='[{0,-12}] {1}'-f$State,$Message;if($NoColor){Write-Host $text}else{Write-Host $text -ForegroundColor $Color}}
function Write-Json([string]$Path,[object]$Value){$json=ConvertTo-Json -InputObject $Value -Depth 12 -WarningAction Stop;if([string]::IsNullOrWhiteSpace($json)){$json='[]'};Set-Content -LiteralPath $Path -Value $json -Encoding UTF8;$null=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -ErrorAction Stop}
function Get-AdParams() { $p = @{ Server = $Server; ErrorAction = 'Stop' }; if ($null -ne $Credential) { $p.Credential = $Credential }; return $p }
function Test-UacFlag([long]$Uac, [long]$Flag) { return (($Uac -band $Flag) -eq $Flag) }
function Get-EncryptionClassification([object]$Value, [bool]$DesOnly) {
    if ($DesOnly) { return 'DESConfigured' }
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return 'EncryptionTypesNotConfigured'
    }

    $numericValue = [int64]$Value
    $rc4Enabled = (($numericValue -band 4) -eq 4)
    $aes128Enabled = (($numericValue -band 8) -eq 8)
    $aes256Enabled = (($numericValue -band 16) -eq 16)
    $aesEnabled = $aes128Enabled -or $aes256Enabled

    if ($rc4Enabled -and $aesEnabled) { return 'ExplicitAESAndRC4Enabled' }
    if ($rc4Enabled) { return 'ExplicitRC4Enabled' }
    if ($aesEnabled) { return 'ExplicitAESOnly' }
    return 'ExplicitOtherOrUnknown'
}

function Get-Readiness([string]$Classification, [datetime]$PasswordLastSet, [string]$ObjectClass) {
    if ($Classification -eq 'ExplicitAESOnly') { return 'AESReady' }
    if ($Classification -eq 'ExplicitAESAndRC4Enabled') { return 'AESCapabilityProbable' }
    if ($Classification -eq 'ExplicitRC4Enabled' -or $Classification -eq 'DESConfigured') {
        return 'LegacyEncryptionConfigured'
    }
    if ($ObjectClass -in @('msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount')) {
        return 'AESCapabilityProbable'
    }
    if ($Classification -eq 'EncryptionTypesNotConfigured') {
        return 'AESReadinessRequiresValidation'
    }
    return 'StaticPostureInconclusive'
}

$EngagementDirectory = [IO.Path]::GetFullPath($EngagementDirectory)
if (-not (Test-Path $EngagementDirectory -PathType Container)) { throw "EngagementDirectoryMissing: $EngagementDirectory" }
Import-Module ActiveDirectory -ErrorAction Stop
if ([string]::IsNullOrWhiteSpace($Server)) {$Server=(Get-ADDomainController -Discover -Writable).HostName}
$OutputDirectory=Join-Path $EngagementDirectory 'evidence\KerberosAccountEncryptionPosture';New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
Show 'START' "MSADPT Kerberos Account Encryption Posture v$ModuleVersion" Cyan
Show 'TARGET' "Server=$Server" Yellow
Show 'PROTOCOL' 'ADWS/LDAP through ActiveDirectory module.' Yellow
Show 'BOUNDARY' 'Read-only AD query. Ticket requests=None; password operations=None; directory changes=None.' Green
$filter='(|(servicePrincipalName=*)(sAMAccountName=krbtgt)(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount)(userAccountControl:1.2.840.113556.1.4.803:=2097152))'
$properties = @('sAMAccountName','servicePrincipalName','msDS-SupportedEncryptionTypes','pwdLastSet','whenCreated','userAccountControl','adminCount','memberOf','objectClass','distinguishedName')
$p=Get-AdParams
Show 'QUERY' 'Enumerating service-relevant accounts and explicit DES configurations.' DarkCyan
$objects=@(Get-ADObject -LDAPFilter $filter -Properties $properties @p|Select-Object -First $MaximumAccounts)
$truncated=$objects.Count -ge $MaximumAccounts
$rows=New-Object 'System.Collections.Generic.List[object]';$index=0
foreach ($o in $objects) {
    $index++;if (($index % 250) -eq 0) {Show 'PROGRESS' "$index/$($objects.Count) accounts normalized" DarkGray}
    $uac = [int64]$o.userAccountControl; $enabled = -not (Test-UacFlag $uac 2); if (-not $IncludeDisabled -and -not $enabled) { continue }
    $etype=$o.'msDS-SupportedEncryptionTypes';$desOnly=Test-UacFlag $uac 2097152;$classification=Get-EncryptionClassification $etype $desOnly
    $pwd = $null; if ($null -ne $o.pwdLastSet -and [int64]$o.pwdLastSet -gt 0) { $pwd = [datetime]::FromFileTimeUtc([int64]$o.pwdLastSet) }
    $spns = @($o.servicePrincipalName); $cls = [string]$o.ObjectClass; $managed = $cls -in @('msDS-GroupManagedServiceAccount','msDS-ManagedServiceAccount')
    $rows.Add([pscustomobject][ordered]@{
        SchemaVersion='1.0';SamAccountName=[string]$o.sAMAccountName;DistinguishedName=[string]$o.DistinguishedName;ObjectClass=$cls
        Enabled=$enabled;ServicePrincipalNames=$spns;ServicePrincipalNameCount=$spns.Count;ManagedServiceAccount=$managed
        SupportedEncryptionTypesRaw=if($null -ne $etype){[int64]$etype}else{$null};EncryptionClassification=$classification
        RC4ExplicitlyEnabled=if($null -ne $etype){(([int64]$etype -band 4) -eq 4)}else{$null};AES128ExplicitlyEnabled=if($null -ne $etype){(([int64]$etype -band 8) -eq 8)}else{$null};AES256ExplicitlyEnabled=if($null -ne $etype){(([int64]$etype-band16) -eq 16)}else{$null}
        DESOnlyAccount=$desOnly;PasswordLastSetUtc=if($null -ne $pwd){$pwd.ToUniversalTime().ToString('o')}else{$null};WhenCreatedUtc=if($null -ne $o.whenCreated){([datetime]$o.whenCreated).ToUniversalTime().ToString('o')}else{$null}
        PasswordNeverExpires=(Test-UacFlag $uac 65536);AdminCount=[int]$o.adminCount;PotentiallyProtected=([int]$o.adminCount -eq 1)
        TrustedForDelegation=(Test-UacFlag $uac 524288);TrustedToAuthForDelegation=(Test-UacFlag $uac 16777216);AccountNotDelegated=(Test-UacFlag $uac 1048576)
        ReadinessState=Get-Readiness $classification $pwd $cls;ObservedKerberosUsage='NotEvaluated';Disposition=if($classification -in @('ExplicitRC4Enabled','DESConfigured')){'LegacyEncryptionConfigured'}elseif ($classification -eq 'ExplicitAESAndRC4Enabled'){'RC4CapableButNotObserved'}elseif ($classification -eq 'ExplicitAESOnly'){'AESConfigured'}else{'RequiresValidation'}
        Limitations='Static AD configuration does not prove ticket encryption actually used. Missing msDS-SupportedEncryptionTypes is not equivalent to RC4-only or AES absence.'
    })
}
$data=[object[]]$rows.ToArray()
$summary=@($data|Group-Object EncryptionClassification|ForEach-Object{[pscustomobject]@{Classification=$_.Name;AccountCount=$_.Count;EnabledAccountCount=@($_.Group|Where-Object{$_.Enabled}).Count;SPNAccountCount=@($_.Group|Where-Object{$_.ServicePrincipalNameCount -gt 0}).Count}}|Sort-Object Classification)
$candidates=@($data|Where-Object{$_.Disposition -in @('LegacyEncryptionConfigured','RC4CapableButNotObserved','RequiresValidation')})
$DataPath=Join-Path $OutputDirectory 'kerberos-account-encryption-posture.json';$CsvPath=Join-Path $OutputDirectory 'kerberos-account-encryption-posture.csv';$SummaryPath=Join-Path $OutputDirectory 'kerberos-account-encryption-summary.json';$CandidatePath=Join-Path $OutputDirectory 'kerberos-encryption-review-candidates.csv';$ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json'
Write-Json $DataPath $data;$data|Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8;Write-Json $SummaryPath $summary;$candidates|Select-Object SamAccountName,ObjectClass,Enabled,ServicePrincipalNameCount,EncryptionClassification,ReadinessState,Disposition,PasswordLastSetUtc,PotentiallyProtected|Export-Csv -LiteralPath $CandidatePath -NoTypeInformation -Encoding UTF8
$files=@($DataPath,$CsvPath,$SummaryPath,$CandidatePath)|ForEach-Object{[pscustomobject]@{Name=(Split-Path -Leaf $_);Size=(Get-Item $_).Length;SHA256=(Get-FileHash $_ -Algorithm SHA256).Hash}}
$manifest=[pscustomobject][ordered]@{SchemaVersion='1.0';Status='Completed';ModuleId='KerberosAccountEncryptionPosture';ModuleVersion=$ModuleVersion;GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o');Server=$Server;AccountCount=$data.Count;QueryResultLimit=$MaximumAccounts;ResultLimitReached=$truncated;ExplicitRC4OnlyCount=@($data|Where-Object{$_.EncryptionClassification -eq 'ExplicitRC4Enabled'}).Count;AESAndRC4Count=@($data|Where-Object{$_.EncryptionClassification -eq 'ExplicitAESAndRC4Enabled'}).Count;AESOnlyCount=@($data|Where-Object{$_.EncryptionClassification -eq 'ExplicitAESOnly'}).Count;DESConfiguredCount=@($data|Where-Object{$_.EncryptionClassification -eq 'DESConfigured'}).Count;NotConfiguredCount=@($data|Where-Object{$_.EncryptionClassification -eq 'EncryptionTypesNotConfigured'}).Count;ReviewCandidateCount=$candidates.Count;ObservedKerberosUsage='NotEvaluated';Disposition=if(@($data|Where-Object{$_.EncryptionClassification -in @('ExplicitRC4Enabled','DESConfigured')}).Count-gt0){'LegacyEncryptionConfigured'}elseif($candidates.Count -gt 0){'ReviewRequired'}else{'NoStaticLegacyConfigurationDetected'};Limitations='Static posture does not prove observed RC4 use or confirm AES key material. Event 4768/4769 correlation remains required when KDC telemetry becomes available.';RemoteChanges='None';TicketRequests='None';PasswordOperations='None';Files=$files}
Write-Json $ManifestPath $manifest
Show 'DONE' "accounts=$($data.Count); rc4-only=$($manifest.ExplicitRC4OnlyCount); aes+rc4=$($manifest.AESAndRC4Count); aes-only=$($manifest.AESOnlyCount); DES=$($manifest.DESConfiguredCount); unconfigured=$($manifest.NotConfiguredCount); disposition=$($manifest.Disposition)" Green
[pscustomobject][ordered]@{Status='Completed';Version=$ModuleVersion;Server=$Server;AccountCount=$data.Count;ExplicitRC4OnlyCount=$manifest.ExplicitRC4OnlyCount;AESAndRC4Count=$manifest.AESAndRC4Count;AESOnlyCount=$manifest.AESOnlyCount;DESConfiguredCount=$manifest.DESConfiguredCount;NotConfiguredCount=$manifest.NotConfiguredCount;ReviewCandidateCount=$manifest.ReviewCandidateCount;Disposition=$manifest.Disposition;EvidenceDirectory=$OutputDirectory;ManifestPath=$ManifestPath;RemoteChanges='None';TicketRequests='None';PasswordOperations='None'}
