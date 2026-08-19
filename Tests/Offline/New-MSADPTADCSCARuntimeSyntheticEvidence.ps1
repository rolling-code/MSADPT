<#
.SYNOPSIS
Creates deterministic synthetic evidence for offline ADCS CA-runtime testing.
.NOTES
Version: 1.0.1
No network, Active Directory, certification authority, TCP, certutil, or registry operation is performed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function New-SyntheticPortEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][int[]]$ReachablePorts
    )

    foreach ($Port in @(80, 135, 443, 445, 5985, 5986)) {
        $Reachable = $ReachablePorts -contains $Port
        [pscustomobject][ordered]@{
            ComputerName = $ComputerName
            Port = $Port
            Reachable = $Reachable
            DurationMilliseconds = if ($Reachable) { 12 } else { 3000 }
            Error = if ($Reachable) { $null } else { 'Timeout' }
        }
    }
}

function New-SyntheticQuery {
    param(
        [Parameter(Mandatory = $true)][string]$CaConfiguration,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter()][string]$Status = 'Completed',
        [Parameter()][AllowNull()][Nullable[int]]$ExitCode = 0,
        [Parameter()][AllowEmptyString()][string]$Output = 'Synthetic read-only output',
        [Parameter()][AllowNull()][string]$ErrorText = $null
    )

    $QueryArguments = switch ($Name) {
        'Ping' { @('-ping') }
        'EditFlags' { @('-getreg', 'policy\EditFlags') }
        'InterfaceFlags' { @('-getreg', 'CA\InterfaceFlags') }
        'RequestDisposition' { @('-getreg', 'CA\RequestDisposition') }
        'RoleSeparationEnabled' { @('-getreg', 'CA\RoleSeparationEnabled') }
        'EnrollmentAgentRights' { @('-getreg', 'CA\EnrollmentAgentRights') }
        'OfficerRights' { @('-getreg', 'CA\OfficerRights') }
        default { @('-getreg', 'CA\UnknownValue') }
    }

    [pscustomobject][ordered]@{
        Name = $Name
        Result = [pscustomobject][ordered]@{
            CaConfiguration = $CaConfiguration
            Arguments = @('-config', $CaConfiguration) + $QueryArguments
            Status = $Status
            ExitCode = $ExitCode
            StandardOutput = $Output
            StandardError = $ErrorText
            StartedUtc = '2026-08-13T20:00:00.0000000Z'
            CompletedUtc = '2026-08-13T20:00:01.0000000Z'
        }
    }
}

function New-SyntheticCa {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$DnsHostName,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][int[]]$ReachablePorts,
        [Parameter(Mandatory = $true)][hashtable]$QueryOverrides
    )

    $Configuration = '{0}\{1}' -f $DnsHostName, $Name
    $QueryNames = @(
        'Ping',
        'EditFlags',
        'InterfaceFlags',
        'RequestDisposition',
        'RoleSeparationEnabled',
        'EnrollmentAgentRights',
        'OfficerRights'
    )

    $Queries = foreach ($QueryName in $QueryNames) {
        if ($QueryOverrides.ContainsKey($QueryName)) {
            $Override = $QueryOverrides[$QueryName]
            New-SyntheticQuery `
                -CaConfiguration $Configuration `
                -Name $QueryName `
                -Status ([string]$Override.Status) `
                -ExitCode $Override.ExitCode `
                -Output ([string]$Override.Output) `
                -ErrorText ([string]$Override.Error)
        }
        else {
            New-SyntheticQuery -CaConfiguration $Configuration -Name $QueryName
        }
    }

    [pscustomobject][ordered]@{
        Name = $Name
        DisplayName = $Name
        DnsHostName = $DnsHostName
        CaConfiguration = $Configuration
        DistinguishedName = "CN=$Name,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test"
        Flags = '10'
        PublishedTemplates = @('User', 'Machine', 'WebServer')
        DirectorySecurity = [pscustomobject][ordered]@{
            Status = 'Collected'
            Owner = 'EXAMPLE\Enterprise Admins'
            AccessEntries = @(
                [pscustomobject][ordered]@{
                    IdentityReference = 'EXAMPLE\Enterprise Admins'
                    AccessControlType = 'Allow'
                    ActiveDirectoryRights = 'GenericAll'
                    ObjectType = '00000000-0000-0000-0000-000000000000'
                    InheritedObjectType = '00000000-0000-0000-0000-000000000000'
                    IsInherited = $false
                    InheritanceType = 'None'
                }
            )
            Error = $null
        }
        PortEvidence = @(
            New-SyntheticPortEvidence `
                -ComputerName $DnsHostName `
                -ReachablePorts $ReachablePorts
        )
        CertutilQueries = @($Queries)
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$Scenarios = [ordered]@{}

$Scenarios.SuccessSingleCa = @(
    New-SyntheticCa `
        -Name 'EXAMPLE-CA' `
        -DnsHostName 'ca01.example.test' `
        -ReachablePorts @(80, 135, 443, 445) `
        -QueryOverrides @{}
)

$Scenarios.PartialAccess = @(
    New-SyntheticCa `
        -Name 'EXAMPLE-CA' `
        -DnsHostName 'ca01.example.test' `
        -ReachablePorts @(135, 445) `
        -QueryOverrides @{
            EnrollmentAgentRights = @{
                Status = 'Failed'
                ExitCode = 5
                Output = ''
                Error = 'Access is denied.'
            }
            OfficerRights = @{
                Status = 'Failed'
                ExitCode = 2
                Output = ''
                Error = 'The system cannot find the registry value.'
            }
        }
)

$Scenarios.Timeout = @(
    New-SyntheticCa `
        -Name 'EXAMPLE-CA' `
        -DnsHostName 'ca01.example.test' `
        -ReachablePorts @() `
        -QueryOverrides @{
            Ping = @{
                Status = 'TimedOut'
                ExitCode = $null
                Output = ''
                Error = 'Command timeout'
            }
        }
)

# Do not place commas between PowerShell command invocations in this array.
# A comma after the first invocation can be bound to the final hashtable parameter.
$MultipleCaItems = New-Object 'System.Collections.Generic.List[object]'
$MultipleCaItems.Add(
    (New-SyntheticCa `
        -Name 'EXAMPLE-ROOT-CA' `
        -DnsHostName 'ca01.example.test' `
        -ReachablePorts @(135, 445) `
        -QueryOverrides @{})
)
$MultipleCaItems.Add(
    (New-SyntheticCa `
        -Name 'EXAMPLE-ISSUING-CA' `
        -DnsHostName 'ca02.example.test' `
        -ReachablePorts @(80, 135, 443, 445) `
        -QueryOverrides @{
            RoleSeparationEnabled = @{
                Status = 'Failed'
                ExitCode = 2
                Output = 'Valeur introuvable'
                Error = 'Sortie localisee synthetique'
            }
        })
)
$Scenarios.MultipleCa = @($MultipleCaItems.ToArray())

$Index = New-Object 'System.Collections.Generic.List[object]'

foreach ($Scenario in $Scenarios.GetEnumerator()) {
    $ScenarioDirectory = Join-Path $OutputDirectory $Scenario.Key
    New-Item -ItemType Directory -Path $ScenarioDirectory -Force | Out-Null

    $JsonPath = Join-Path $ScenarioDirectory 'ca-runtime-evidence.json'
    $SummaryPath = Join-Path $ScenarioDirectory 'ca-runtime-summary.csv'
    $ServiceConnectionPointPath = Join-Path $ScenarioDirectory 'adcs-service-connection-points.json'

    $Scenario.Value |
        ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath $JsonPath -Encoding UTF8

    $Scenario.Value |
        Select-Object `
            Name,
            DisplayName,
            DnsHostName,
            CaConfiguration,
            @{Name = 'PublishedTemplateCount'; Expression = { @($_.PublishedTemplates).Count }},
            @{Name = 'DirectorySecurityStatus'; Expression = { $_.DirectorySecurity.Status }},
            @{Name = 'ReachablePortCount'; Expression = { @($_.PortEvidence | Where-Object Reachable).Count }},
            @{Name = 'CompletedCertutilQueryCount'; Expression = { @($_.CertutilQueries | Where-Object { $_.Result.Status -eq 'Completed' }).Count }},
            @{Name = 'FailedCertutilQueryCount'; Expression = { @($_.CertutilQueries | Where-Object { $_.Result.Status -ne 'Completed' }).Count }} |
        Export-Csv -LiteralPath $SummaryPath -NoTypeInformation -Encoding UTF8

    @(
        [pscustomobject][ordered]@{
            Name = 'Synthetic Enrollment Service'
            DisplayName = 'Synthetic Enrollment Service'
            DistinguishedName = 'CN=Synthetic,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test'
            ServiceBindingInformation = @('https://ca01.example.test/certsrv/')
            Keywords = @('synthetic', 'offline')
        }
    ) |
        ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $ServiceConnectionPointPath -Encoding UTF8

    $Index.Add(
        [pscustomobject][ordered]@{
            Scenario = $Scenario.Key
            CaCount = @($Scenario.Value).Count
            EvidencePath = $JsonPath
            SummaryPath = $SummaryPath
            ServiceConnectionPointPath = $ServiceConnectionPointPath
        }
    )
}

$IndexPath = Join-Path $OutputDirectory 'synthetic-fixture-index.json'
$Index.ToArray() |
    ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $IndexPath -Encoding UTF8

[pscustomobject]@{
    Status = 'Completed'
    GeneratorVersion = '1.0.1'
    ScenarioCount = $Index.Count
    OutputDirectory = $OutputDirectory
    IndexPath = $IndexPath
}
