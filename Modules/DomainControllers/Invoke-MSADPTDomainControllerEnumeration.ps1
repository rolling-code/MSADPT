[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$EngagementPath,[Parameter()][PSCredential]$Credential)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$state = Get-Content -LiteralPath (Join-Path $EngagementPath 'state\engagement-state.json') -Raw | ConvertFrom-Json
$server = [string]$state.BootstrapServer
if ([string]::IsNullOrWhiteSpace($server)) { throw 'BootstrapServer is missing from engagement state.' }
Import-Module ActiveDirectory -ErrorAction Stop
$params = @{ Filter='*'; Server=$server; ErrorAction='Stop' }
if ($null -ne $Credential) { $params.Credential=$Credential }
$dcs = @(Get-ADDomainController @params)
$rows = foreach ($dc in $dcs) {
    $computerParams = @{ Identity=$dc.ComputerObjectDN; Server=$server; Properties=@('operatingSystemVersion','whenCreated','pwdLastSet','servicePrincipalName','userAccountControl'); ErrorAction='Stop' }
    if ($null -ne $Credential) { $computerParams.Credential=$Credential }
    $computer = Get-ADComputer @computerParams
    [pscustomobject][ordered]@{
        Name=$dc.Name; HostName=$dc.HostName; Site=$dc.Site; IPv4Address=$dc.IPv4Address; IsGlobalCatalog=$dc.IsGlobalCatalog
        IsReadOnly=$dc.IsReadOnly; OperatingSystem=$dc.OperatingSystem; OperatingSystemVersion=$computer.OperatingSystemVersion
        WhenCreated=$computer.whenCreated; PasswordLastSetUtc=if($computer.pwdLastSet){[DateTime]::FromFileTimeUtc([Int64]$computer.pwdLastSet).ToString('o')}else{$null}
        UserAccountControl=$computer.userAccountControl; ServicePrincipalNameCount=@($computer.servicePrincipalName).Count
    }
}
$outDir=Join-Path $EngagementPath 'evidence\DomainControllerEnumeration'; New-Item -ItemType Directory -Path $outDir -Force|Out-Null
$rows|Export-Csv -LiteralPath (Join-Path $outDir 'domain-controller-details.csv') -NoTypeInformation -Encoding UTF8
$rows|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $outDir 'domain-controller-details.json') -Encoding UTF8
[pscustomobject]@{schemaVersion='1.0';module='DomainControllerEnumeration';status='Completed';executionClass='read_only';targetCount=$rows.Count;evidence=@('evidence/DomainControllerEnumeration/domain-controller-details.csv','evidence/DomainControllerEnumeration/domain-controller-details.json');limitations=@('Directory metadata only; no remote command execution, service probing, or credential testing performed.');completedUtc=(Get-Date).ToUniversalTime().ToString('o')}
