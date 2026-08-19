<#
.SYNOPSIS
    Read-only controller functions for MSADPT Milestone 1.
.VERSION
    0.2.0
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-MSADPTStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $Color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'WARNING' { 'Yellow' }
        'ERROR'   { 'Red' }
        default   { 'Gray' }
    }

    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $Color
}

function Test-MSADPTAdministrator {
    [CmdletBinding()]
    param()

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Export-MSADPTJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [int]$Depth = 20
    )

    $InputObject | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
}

function New-MSADPTCoverageRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$Limitation
    )

    [pscustomobject][ordered]@{
        Module       = $Module
        Status       = $Status
        Evidence     = $Evidence
        Limitation   = $Limitation
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Get-MSADPTCredentialLabel {
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCredential]$Credential
    )

    if ($null -ne $Credential) {
        return [string]$Credential.UserName
    }

    return [Security.Principal.WindowsIdentity]::GetCurrent().Name
}

function Invoke-MSADPTAssessment {
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [string]$DomainFQDN,

        [Parameter()]
        [string]$AdServer,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EngagementName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputRoot,

        [Parameter()]
        [switch]$SkipAdminCheck
    )

    $Started = Get-Date
    $SafeEngagementName = $EngagementName -replace '[^A-Za-z0-9._-]', '-'
    $RunId = '{0}-{1}' -f $SafeEngagementName, $Started.ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $EngagementPath = Join-Path -Path $OutputRoot -ChildPath $RunId
    $EvidencePath = Join-Path -Path $EngagementPath -ChildPath 'evidence'
    $ReportsPath = Join-Path -Path $EngagementPath -ChildPath 'reports'
    $StatePath = Join-Path -Path $EngagementPath -ChildPath 'state'

    foreach ($Path in @($EngagementPath, $EvidencePath, $ReportsPath, $StatePath)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    $TranscriptPath = Join-Path -Path $EngagementPath -ChildPath 'console-transcript.txt'
    $TranscriptStarted = $false
    try {
        Start-Transcript -Path $TranscriptPath -Force | Out-Null
        $TranscriptStarted = $true
    }
    catch {
        Write-MSADPTStatus ("Transcript could not be started: {0}" -f $_.Exception.Message) 'WARNING'
    }

    $Coverage = New-Object 'System.Collections.Generic.List[object]'
    $Errors = New-Object 'System.Collections.Generic.List[string]'

    try {
        Write-MSADPTStatus 'MSADPT Milestone 1 engagement started.' 'SUCCESS'
        Write-MSADPTStatus "Run ID: $RunId"
        Write-MSADPTStatus 'Mode: read-only assessment'

        if ($null -ne $Credential) {
            Write-MSADPTStatus ("Authentication: explicit credential for {0}." -f $Credential.UserName)
        }
        else {
            Write-MSADPTStatus ("Authentication: current Windows identity {0}." -f ([Security.Principal.WindowsIdentity]::GetCurrent().Name))
        }

        if (-not $SkipAdminCheck) {
            if (Test-MSADPTAdministrator) {
                Write-MSADPTStatus 'PowerShell is running with local administrator privileges.' 'SUCCESS'
            }
            else {
                Write-MSADPTStatus 'PowerShell is not elevated. Milestone 1 can continue, but later modules may require elevation.' 'WARNING'
            }
        }

        Write-MSADPTStatus 'Checking the ActiveDirectory module.'
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw 'The ActiveDirectory PowerShell module is not installed. Install RSAT Active Directory tools before running MSADPT.'
        }

        Import-Module ActiveDirectory -ErrorAction Stop
        $Coverage.Add((New-MSADPTCoverageRow -Module 'Prerequisites' -Status 'Assessed' -Evidence 'ActiveDirectory module imported.' -Limitation 'No additional optional tools assessed in Milestone 1.'))

        if ([string]::IsNullOrWhiteSpace($AdServer)) {
            Write-MSADPTStatus 'No AD server supplied. Attempting domain-controller discovery.'

            # Get-ADDomainController -Discover does not accept -Credential. Discovery uses
            # the current Windows/domain context. Explicit credentials are applied to all
            # subsequent authoritative AD queries after a bootstrap server is selected.
            $DiscoveryParameters = @{
                Discover      = $true
                ForceDiscover = $true
                Service       = 'ADWS'
                ErrorAction   = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($DomainFQDN)) {
                $DiscoveryParameters.DomainName = $DomainFQDN
            }

            $DiscoveredServer = Get-ADDomainController @DiscoveryParameters
            $AdServer = [string]$DiscoveredServer.HostName

            if ([string]::IsNullOrWhiteSpace($AdServer)) {
                throw 'Domain-controller discovery completed without returning a usable host name.'
            }
        }

        Write-MSADPTStatus "Testing AD connectivity through $AdServer."

        $CommonAdParameters = @{
            Server      = $AdServer
            ErrorAction = 'Stop'
        }
        if ($null -ne $Credential) {
            $CommonAdParameters.Credential = $Credential
        }

        $RootDse = Get-ADRootDSE @CommonAdParameters
        $Domain = Get-ADDomain @CommonAdParameters
        $Forest = Get-ADForest @CommonAdParameters

        if ([string]::IsNullOrWhiteSpace($DomainFQDN)) {
            $DomainFQDN = [string]$Domain.DNSRoot
        }

        $Coverage.Add((New-MSADPTCoverageRow -Module 'ADConnectivity' -Status 'Assessed' -Evidence "Connected to $AdServer for $DomainFQDN." -Limitation 'Connectivity was validated only through the selected bootstrap server.'))

        Write-MSADPTStatus 'Collecting local environment evidence.'
        $DsRegText = $null
        try {
            $DsRegText = (& dsregcmd.exe /status 2>&1 | Out-String)
        }
        catch {
            $Errors.Add("Local environment dsregcmd collection: $($_.Exception.Message)")
        }

        $IsAzureAdJoined = $false
        if ($DsRegText -match 'AzureAdJoined\s*:\s*YES') {
            $IsAzureAdJoined = $true
        }

        $Environment = [pscustomobject][ordered]@{
            TimestampUtc              = (Get-Date).ToUniversalTime().ToString('o')
            ComputerName              = $env:COMPUTERNAME
            ExecutingUser             = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            DirectoryQueryIdentity    = Get-MSADPTCredentialLabel -Credential $Credential
            ExplicitCredentialSupplied = ($null -ne $Credential)
            IsAdministrator           = Test-MSADPTAdministrator
            PowerShellVersion         = $PSVersionTable.PSVersion.ToString()
            DomainFQDN                = $DomainFQDN
            DomainNetBIOSName         = $Domain.NetBIOSName
            ForestName                = $Forest.Name
            BootstrapServer           = $AdServer
            DefaultNamingContext      = $RootDse.DefaultNamingContext
            ConfigurationNamingContext = $RootDse.ConfigurationNamingContext
            IsAzureAdJoined           = $IsAzureAdJoined
            AssessmentMode            = 'ReadOnly'
        }

        $Environment | Export-Csv -LiteralPath (Join-Path $EvidencePath 'environment.csv') -NoTypeInformation -Encoding UTF8
        Export-MSADPTJson -InputObject $Environment -Path (Join-Path $EvidencePath 'environment.json')

        Write-MSADPTStatus 'Discovering domain controllers.'
        $DomainControllerParameters = @{
            Filter      = '*'
            Server      = $AdServer
            ErrorAction = 'Stop'
        }
        if ($null -ne $Credential) {
            $DomainControllerParameters.Credential = $Credential
        }

        $DomainControllers = @(
            Get-ADDomainController @DomainControllerParameters |
                Select-Object Name, HostName, IPv4Address, IPv6Address, Site, IsGlobalCatalog, IsReadOnly, OperatingSystem, Domain, Forest
        )

        $DomainControllers | Export-Csv -LiteralPath (Join-Path $EvidencePath 'domain-controllers.csv') -NoTypeInformation -Encoding UTF8
        Export-MSADPTJson -InputObject $DomainControllers -Path (Join-Path $EvidencePath 'domain-controllers.json')
        $Coverage.Add((New-MSADPTCoverageRow -Module 'DomainControllerDiscovery' -Status 'Assessed' -Evidence ("Discovered {0} domain controller(s)." -f $DomainControllers.Count) -Limitation 'Detailed per-DC control validation is scheduled for a later module.'))

        Write-MSADPTStatus 'Discovering enterprise certification authorities.'
        $EnrollmentBase = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,{0}' -f $RootDse.ConfigurationNamingContext
        $CertificationAuthorities = @()

        try {
            $AdObjectParameters = @{
                SearchBase  = $EnrollmentBase
                LDAPFilter  = '(objectClass=pKIEnrollmentService)'
                Properties  = @('dNSHostName', 'certificateTemplates', 'displayName')
                Server      = $AdServer
                ErrorAction = 'Stop'
            }
            if ($null -ne $Credential) {
                $AdObjectParameters.Credential = $Credential
            }

            $CertificationAuthorities = @(
                Get-ADObject @AdObjectParameters |
                    Select-Object Name, DisplayName, dNSHostName, DistinguishedName,
                        @{Name = 'PublishedTemplateCount'; Expression = { @($_.certificateTemplates).Count }}
            )

            $Coverage.Add((New-MSADPTCoverageRow -Module 'ADCSDiscovery' -Status 'Assessed' -Evidence ("Discovered {0} enterprise CA object(s)." -f $CertificationAuthorities.Count) -Limitation 'Milestone 1 discovers CA objects but does not yet evaluate ESC conditions.'))
        }
        catch {
            $Errors.Add("ADCS discovery: $($_.Exception.Message)")
            $Coverage.Add((New-MSADPTCoverageRow -Module 'ADCSDiscovery' -Status 'Failed' -Evidence 'No authoritative AD CS discovery result was produced.' -Limitation $_.Exception.Message))
        }

        $CertificationAuthorities | Export-Csv -LiteralPath (Join-Path $EvidencePath 'enterprise-cas.csv') -NoTypeInformation -Encoding UTF8
        Export-MSADPTJson -InputObject $CertificationAuthorities -Path (Join-Path $EvidencePath 'enterprise-cas.json')

        $NextModule = if ($DomainControllers.Count -gt 0) { 'DomainControllerEnumeration' } else { 'Stop' }
        $Reason = if ($DomainControllers.Count -gt 0) {
            'Domain controllers were discovered. Detailed read-only per-DC enumeration is the next deterministic assessment stage.'
        }
        else {
            'No domain controllers were discovered, so the assessment cannot continue automatically.'
        }

        $Decision = [pscustomobject][ordered]@{
            DecisionSource            = 'DeterministicPolicy'
            RecommendedModule          = $NextModule
            Reason                     = $Reason
            RequiresHumanApproval      = $false
            Allowed                    = ($NextModule -ne 'Stop')
            SecurityCopilotIntegration = 'NotConfiguredInMilestone1'
            TimestampUtc               = (Get-Date).ToUniversalTime().ToString('o')
        }

        Export-MSADPTJson -InputObject $Decision -Path (Join-Path $StatePath 'next-decision.json')
        $Coverage.ToArray() | Export-Csv -LiteralPath (Join-Path $ReportsPath 'coverage.csv') -NoTypeInformation -Encoding UTF8
        Export-MSADPTJson -InputObject $Coverage.ToArray() -Path (Join-Path $ReportsPath 'coverage.json')

        $State = [pscustomobject][ordered]@{
            SchemaVersion                = '1.0'
            ControllerVersion            = '0.2.0'
            RunId                        = $RunId
            EngagementName               = $EngagementName
            AssessmentMode               = 'ReadOnly'
            StartedUtc                   = $Started.ToUniversalTime().ToString('o')
            CompletedUtc                 = (Get-Date).ToUniversalTime().ToString('o')
            Status                       = if ($Errors.Count -eq 0) { 'Completed' } else { 'CompletedWithLimitations' }
            DomainFQDN                   = $DomainFQDN
            BootstrapServer              = $AdServer
            DirectoryQueryIdentity       = Get-MSADPTCredentialLabel -Credential $Credential
            ExplicitCredentialSupplied   = ($null -ne $Credential)
            DomainControllerCount        = $DomainControllers.Count
            CertificationAuthorityCount  = $CertificationAuthorities.Count
            NextDecision                 = $Decision
            Errors                       = $Errors.ToArray()
        }

        Export-MSADPTJson -InputObject $State -Path (Join-Path $StatePath 'engagement-state.json')

        Write-MSADPTStatus ("Discovered {0} domain controller(s)." -f $DomainControllers.Count) 'SUCCESS'
        Write-MSADPTStatus ("Discovered {0} enterprise CA object(s)." -f $CertificationAuthorities.Count) 'SUCCESS'
        Write-MSADPTStatus ("Next recommended module: {0}" -f $Decision.RecommendedModule)
        Write-MSADPTStatus $Decision.Reason
        Write-MSADPTStatus "Engagement evidence: $EngagementPath" 'SUCCESS'

        return $State
    }
    catch {
        $FailureMessage = $_.Exception.Message
        $Errors.Add($FailureMessage)
        $Coverage.Add((New-MSADPTCoverageRow -Module 'Controller' -Status 'Failed' -Evidence 'The controller did not complete.' -Limitation $FailureMessage))
        $Coverage.ToArray() | Export-Csv -LiteralPath (Join-Path $ReportsPath 'coverage.csv') -NoTypeInformation -Encoding UTF8
        Export-MSADPTJson -InputObject $Coverage.ToArray() -Path (Join-Path $ReportsPath 'coverage.json')

        $FailureState = [pscustomobject][ordered]@{
            SchemaVersion              = '1.0'
            ControllerVersion          = '0.2.0'
            RunId                      = $RunId
            EngagementName             = $EngagementName
            AssessmentMode             = 'ReadOnly'
            Status                     = 'Failed'
            StartedUtc                 = $Started.ToUniversalTime().ToString('o')
            CompletedUtc               = (Get-Date).ToUniversalTime().ToString('o')
            DomainFQDN                 = $DomainFQDN
            BootstrapServer            = $AdServer
            DirectoryQueryIdentity     = Get-MSADPTCredentialLabel -Credential $Credential
            ExplicitCredentialSupplied = ($null -ne $Credential)
            Errors                     = $Errors.ToArray()
        }

        Export-MSADPTJson -InputObject $FailureState -Path (Join-Path $StatePath 'engagement-state.json')
        Write-MSADPTStatus $FailureMessage 'ERROR'
        throw
    }
    finally {
        if ($TranscriptStarted) {
            try { Stop-Transcript | Out-Null } catch { }
        }
    }
}

Export-ModuleMember -Function Invoke-MSADPTAssessment
