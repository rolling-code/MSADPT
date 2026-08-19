<#
.SYNOPSIS
Collects read-only AD CS certification-authority runtime and service-surface evidence for MSADPT.
.DESCRIPTION
Discovers enterprise certification authorities from Active Directory, records CA publication and directory
security evidence, performs bounded TCP reachability checks, and invokes read-only certutil queries against
explicit CA configurations. Raw command output is preserved because certutil output can vary by Windows
version and locale. Query failures are recorded per CA and do not terminate the remaining collection.

This collector does not submit certificate requests, authenticate with certificates, modify the registry,
change CA configuration, restart services, alter templates, or change Active Directory.
.NOTES
Version: 0.1.1
Execution class: read_only
Compatible with Windows PowerShell 5.1 and PowerShell 7 when the ActiveDirectory module is available.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EngagementPath,

    [Parameter()]
    [PSCredential]$Credential,

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$TcpTimeoutSeconds = 3,

    [Parameter()]
    [ValidateRange(5, 120)]
    [int]$CommandTimeoutSeconds = 30
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ModuleVersion = '0.1.1'
$EvidenceSchemaVersion = '1.0.0'

function ConvertTo-MSADPTFlatAce {
    param($AccessRule)
    [pscustomobject][ordered]@{
        IdentityReference = [string]$AccessRule.IdentityReference.Value
        AccessControlType = [string]$AccessRule.AccessControlType
        ActiveDirectoryRights = [string]$AccessRule.ActiveDirectoryRights
        ObjectType = ([guid]$AccessRule.ObjectType).ToString()
        InheritedObjectType = ([guid]$AccessRule.InheritedObjectType).ToString()
        IsInherited = [bool]$AccessRule.IsInherited
        InheritanceType = [string]$AccessRule.InheritanceType
    }
}

function Get-MSADPTDirectorySecurityEvidence {
    param([string]$DistinguishedName)
    try {
        $Acl = Get-Acl -LiteralPath ('AD:\' + $DistinguishedName) -ErrorAction Stop
        [pscustomobject][ordered]@{
            Status = 'Collected'
            Owner = [string]$Acl.Owner
            AccessEntries = @($Acl.Access | ForEach-Object { ConvertTo-MSADPTFlatAce $_ })
            Error = $null
        }
    }
    catch {
        [pscustomobject][ordered]@{
            Status = 'Failed'
            Owner = $null
            AccessEntries = @()
            Error = $_.Exception.Message
        }
    }
}

function Test-MSADPTTcpPort {
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$TimeoutSeconds
    )

    $Client = New-Object System.Net.Sockets.TcpClient
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $AsyncResult = $Client.BeginConnect($ComputerName, $Port, $null, $null)
        $ConnectedWithinTimeout = $AsyncResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
        if (-not $ConnectedWithinTimeout) {
            return [pscustomobject][ordered]@{
                ComputerName = $ComputerName; Port = $Port; Reachable = $false
                DurationMilliseconds = $Stopwatch.ElapsedMilliseconds; Error = 'Timeout'
            }
        }
        $Client.EndConnect($AsyncResult)
        return [pscustomobject][ordered]@{
            ComputerName = $ComputerName; Port = $Port; Reachable = [bool]$Client.Connected
            DurationMilliseconds = $Stopwatch.ElapsedMilliseconds; Error = $null
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            ComputerName = $ComputerName; Port = $Port; Reachable = $false
            DurationMilliseconds = $Stopwatch.ElapsedMilliseconds; Error = $_.Exception.Message
        }
    }
    finally {
        $Stopwatch.Stop()
        $Client.Dispose()
    }
}

function Invoke-MSADPTReadOnlyProcess {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [int]$TimeoutSeconds
    )

    $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $FilePath
    $StartInfo.UseShellExecute = $false
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $StartInfo.CreateNoWindow = $true
    $QuotedArguments = @(
        foreach ($Argument in $ArgumentList) {
            $Text = [string]$Argument
            if ($Text -match '[\s"]') {
                '"' + $Text.Replace('\', '\\').Replace('"', '\"') + '"'
            }
            else {
                $Text
            }
        }
    )
    $StartInfo.Arguments = ($QuotedArguments -join ' ')

    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $StartInfo
    $StartedUtc = (Get-Date).ToUniversalTime()
    try {
        [void]$Process.Start()
        $StandardOutputTask = $Process.StandardOutput.ReadToEndAsync()
        $StandardErrorTask = $Process.StandardError.ReadToEndAsync()
        $Completed = $Process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $Completed) {
            try { $Process.Kill() } catch {}
            return [pscustomobject][ordered]@{
                Status = 'TimedOut'; ExitCode = $null; StandardOutput = $StandardOutputTask.Result
                StandardError = $StandardErrorTask.Result; StartedUtc = $StartedUtc.ToString('o')
                CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
            }
        }
        return [pscustomobject][ordered]@{
            Status = if ($Process.ExitCode -eq 0) { 'Completed' } else { 'Failed' }
            ExitCode = [int]$Process.ExitCode; StandardOutput = $StandardOutputTask.Result
            StandardError = $StandardErrorTask.Result; StartedUtc = $StartedUtc.ToString('o')
            CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Status = 'FailedToStart'; ExitCode = $null; StandardOutput = $null
            StandardError = $_.Exception.Message; StartedUtc = $StartedUtc.ToString('o')
            CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
        }
    }
    finally {
        $Process.Dispose()
    }
}

function Invoke-MSADPTCertutilQuery {
    param(
        [string]$CaConfiguration,
        [string[]]$QueryArguments,
        [int]$TimeoutSeconds
    )

    $Arguments = @('-config', $CaConfiguration) + $QueryArguments
    $Result = Invoke-MSADPTReadOnlyProcess -FilePath 'certutil.exe' -ArgumentList $Arguments -TimeoutSeconds $TimeoutSeconds
    [pscustomobject][ordered]@{
        CaConfiguration = $CaConfiguration
        Arguments = @($Arguments)
        Status = $Result.Status
        ExitCode = $Result.ExitCode
        StandardOutput = [string]$Result.StandardOutput
        StandardError = [string]$Result.StandardError
        StartedUtc = $Result.StartedUtc
        CompletedUtc = $Result.CompletedUtc
    }
}

$StatePath = Join-Path $EngagementPath 'state\engagement-state.json'
if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
    throw "Engagement state not found: $StatePath"
}

$State = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
$BootstrapServer = [string]$State.BootstrapServer
if ([string]::IsNullOrWhiteSpace($BootstrapServer)) {
    throw 'BootstrapServer is missing from engagement state.'
}

Import-Module ActiveDirectory -ErrorAction Stop
$CommonAdParameters = @{ Server = $BootstrapServer; ErrorAction = 'Stop' }
if ($null -ne $Credential) { $CommonAdParameters.Credential = $Credential }

$RootDse = Get-ADRootDSE @CommonAdParameters
$ConfigurationNamingContext = [string]$RootDse.ConfigurationNamingContext
$EnrollmentServicesBase = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,{0}' -f $ConfigurationNamingContext
$PublicKeyServicesBase = 'CN=Public Key Services,CN=Services,{0}' -f $ConfigurationNamingContext

$CaParameters = @{
    SearchBase = $EnrollmentServicesBase
    LDAPFilter = '(objectClass=pKIEnrollmentService)'
    Properties = @('displayName','dNSHostName','certificateTemplates','cACertificate','flags')
    Server = $BootstrapServer
    ErrorAction = 'Stop'
}
if ($null -ne $Credential) { $CaParameters.Credential = $Credential }

$EnterpriseCaObjects = @(Get-ADObject @CaParameters)
$ServiceConnectionPoints = @()
$ServiceConnectionPointError = $null
try {
    $ServiceConnectionPoints = @(
        Get-ADObject @CommonAdParameters -SearchBase $PublicKeyServicesBase -LDAPFilter '(objectClass=serviceConnectionPoint)' -Properties @('serviceBindingInformation','keywords','displayName') |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = [string]$_.Name
                    DisplayName = [string]$_.DisplayName
                    DistinguishedName = [string]$_.DistinguishedName
                    ServiceBindingInformation = @($_.serviceBindingInformation | ForEach-Object { [string]$_ })
                    Keywords = @($_.keywords | ForEach-Object { [string]$_ })
                }
            }
    )
}
catch {
    $ServiceConnectionPointError = $_.Exception.Message
}

$CaResults = New-Object 'System.Collections.Generic.List[object]'
foreach ($CaObject in $EnterpriseCaObjects) {
    $CaName = [string]$CaObject.Name
    $DnsHostName = [string]$CaObject.dNSHostName
    $CaConfiguration = '{0}\{1}' -f $DnsHostName, $CaName
    $DirectorySecurity = Get-MSADPTDirectorySecurityEvidence -DistinguishedName $CaObject.DistinguishedName

    $PortEvidence = @(
        foreach ($Port in @(80,135,443,445,5985,5986)) {
            Test-MSADPTTcpPort -ComputerName $DnsHostName -Port $Port -TimeoutSeconds $TcpTimeoutSeconds
        }
    )

    $CertutilQueries = @(
        [pscustomobject]@{ Name='Ping'; Result=(Invoke-MSADPTCertutilQuery -CaConfiguration $CaConfiguration -QueryArguments @('-ping') -TimeoutSeconds $CommandTimeoutSeconds) }
        [pscustomobject]@{ Name='EditFlags'; Result=(Invoke-MSADPTCertutilQuery -CaConfiguration $CaConfiguration -QueryArguments @('-getreg','policy\EditFlags') -TimeoutSeconds $CommandTimeoutSeconds) }
        [pscustomobject]@{ Name='InterfaceFlags'; Result=(Invoke-MSADPTCertutilQuery -CaConfiguration $CaConfiguration -QueryArguments @('-getreg','CA\InterfaceFlags') -TimeoutSeconds $CommandTimeoutSeconds) }
        [pscustomobject]@{ Name='RequestDisposition'; Result=(Invoke-MSADPTCertutilQuery -CaConfiguration $CaConfiguration -QueryArguments @('-getreg','CA\RequestDisposition') -TimeoutSeconds $CommandTimeoutSeconds) }
        [pscustomobject]@{ Name='RoleSeparationEnabled'; Result=(Invoke-MSADPTCertutilQuery -CaConfiguration $CaConfiguration -QueryArguments @('-getreg','CA\RoleSeparationEnabled') -TimeoutSeconds $CommandTimeoutSeconds) }
        [pscustomobject]@{ Name='EnrollmentAgentRights'; Result=(Invoke-MSADPTCertutilQuery -CaConfiguration $CaConfiguration -QueryArguments @('-getreg','CA\EnrollmentAgentRights') -TimeoutSeconds $CommandTimeoutSeconds) }
        [pscustomobject]@{ Name='OfficerRights'; Result=(Invoke-MSADPTCertutilQuery -CaConfiguration $CaConfiguration -QueryArguments @('-getreg','CA\OfficerRights') -TimeoutSeconds $CommandTimeoutSeconds) }
    )

    $CaResults.Add([pscustomobject][ordered]@{
        Name = $CaName
        DisplayName = [string]$CaObject.DisplayName
        DnsHostName = $DnsHostName
        CaConfiguration = $CaConfiguration
        DistinguishedName = [string]$CaObject.DistinguishedName
        Flags = [string]$CaObject.flags
        PublishedTemplates = @($CaObject.certificateTemplates | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        DirectorySecurity = $DirectorySecurity
        PortEvidence = $PortEvidence
        CertutilQueries = $CertutilQueries
    })
}

$OutputDirectory = Join-Path $EngagementPath 'evidence\ADCSCARuntimeConfigurationCollection'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$RuntimeEvidencePath = Join-Path $OutputDirectory 'ca-runtime-evidence.json'
$RuntimeSummaryPath = Join-Path $OutputDirectory 'ca-runtime-summary.csv'
$ServiceEvidencePath = Join-Path $OutputDirectory 'adcs-service-connection-points.json'

$CaResults.ToArray() | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $RuntimeEvidencePath -Encoding UTF8
$ServiceConnectionPoints | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ServiceEvidencePath -Encoding UTF8
$CaResults.ToArray() |
    Select-Object Name, DisplayName, DnsHostName, CaConfiguration,
        @{Name='PublishedTemplateCount';Expression={ @($_.PublishedTemplates).Count }},
        @{Name='DirectorySecurityStatus';Expression={ $_.DirectorySecurity.Status }},
        @{Name='ReachablePortCount';Expression={ @($_.PortEvidence | Where-Object Reachable).Count }},
        @{Name='CompletedCertutilQueryCount';Expression={ @($_.CertutilQueries | Where-Object { $_.Result.Status -eq 'Completed' }).Count }},
        @{Name='FailedCertutilQueryCount';Expression={ @($_.CertutilQueries | Where-Object { $_.Result.Status -ne 'Completed' }).Count }} |
    Export-Csv -LiteralPath $RuntimeSummaryPath -NoTypeInformation -Encoding UTF8

[pscustomobject][ordered]@{
    schemaVersion = '1.0'
    module = 'ADCSCARuntimeConfigurationCollection'
    moduleVersion = $ModuleVersion
    evidenceSchemaVersion = $EvidenceSchemaVersion
    status = 'Completed'
    executionClass = 'read_only'
    enterpriseCaCount = $CaResults.Count
    serviceConnectionPointCount = $ServiceConnectionPoints.Count
    serviceConnectionPointError = if ($ServiceConnectionPointError) { $ServiceConnectionPointError } else { $null }
    targetCount = $CaResults.Count
    evidence = @(
        'evidence/ADCSCARuntimeConfigurationCollection/ca-runtime-evidence.json',
        'evidence/ADCSCARuntimeConfigurationCollection/ca-runtime-summary.csv',
        'evidence/ADCSCARuntimeConfigurationCollection/adcs-service-connection-points.json'
    )
    limitations = @(
        'certutil output is preserved as raw text because format and localization can vary across Windows versions.',
        'TCP reachability does not prove that an enrollment interface is enabled, authenticated, or exploitable.',
        'A failed certutil query may reflect permissions, RPC/firewall behavior, service availability, or an unsupported registry value.',
        'No certificate request, authentication attempt, registry modification, CA configuration change, service restart, or Active Directory modification is performed.'
    )
    completedUtc = (Get-Date).ToUniversalTime().ToString('o')
}
