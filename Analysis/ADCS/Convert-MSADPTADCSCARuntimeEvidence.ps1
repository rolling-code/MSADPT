<#
.SYNOPSIS
Converts validated ADCS CA-runtime evidence into normalized, cautious observations.
.DESCRIPTION
Parses previously collected or synthetic CA-runtime evidence offline. Numeric registry values are extracted
only from locale-independent hexadecimal or decimal tokens. Command failures, timeouts, missing values,
localized text without a numeric token, and unknown formats remain explicit and inconclusive.

This script does not contact Active Directory, resolve DNS, open sockets, invoke certutil, read the registry,
or modify an MSADPT engagement.
.NOTES
Version: 0.1.0
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EvidencePath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ParserVersion = '0.1.0'
$ObservationSchemaVersion = '1.0.0'

function Get-MSADPTQueryDisposition {
    param($QueryResult)

    $Status = [string]$QueryResult.Status
    $ExitCode = $QueryResult.ExitCode
    $StdOut = [string]$QueryResult.StandardOutput
    $StdErr = [string]$QueryResult.StandardError
    $Combined = ($StdOut + "`n" + $StdErr).Trim()

    if ($Status -eq 'TimedOut') {
        return [pscustomobject]@{ EvidenceStatus='Query failed'; ParseStatus='TimedOut'; Detail='The command exceeded its configured timeout.' }
    }
    if ($Status -eq 'FailedToStart') {
        return [pscustomobject]@{ EvidenceStatus='Query failed'; ParseStatus='FailedToStart'; Detail=$StdErr }
    }
    if ($Combined -match '(?i)access\s+is\s+denied|acc[eè]s\s+refus[eé]|zugriff\s+verweigert') {
        return [pscustomobject]@{ EvidenceStatus='Query failed'; ParseStatus='AccessDenied'; Detail=$Combined }
    }
    if ($Combined -match '(?i)cannot\s+find|not\s+found|introuvable|nicht\s+gefunden|does\s+not\s+exist') {
        return [pscustomobject]@{ EvidenceStatus='Not observed'; ParseStatus='ValueNotFound'; Detail=$Combined }
    }
    if ($Combined -match '(?i)rpc\s+server\s+is\s+unavailable|serveur\s+rpc\s+.*indisponible|rpc-server\s+.*nicht\s+verf') {
        return [pscustomobject]@{ EvidenceStatus='Query failed'; ParseStatus='RpcUnavailable'; Detail=$Combined }
    }
    if ($Status -eq 'Failed' -or ($null -ne $ExitCode -and [int]$ExitCode -ne 0)) {
        return [pscustomobject]@{ EvidenceStatus='Query failed'; ParseStatus='NonZeroExitCode'; Detail=$Combined }
    }
    if ([string]::IsNullOrWhiteSpace($Combined)) {
        return [pscustomobject]@{ EvidenceStatus='Inconclusive'; ParseStatus='EmptyOutput'; Detail='The query completed without parseable output.' }
    }
    return [pscustomobject]@{ EvidenceStatus='Observed'; ParseStatus='CommandCompleted'; Detail=$Combined }
}

function ConvertFrom-MSADPTNumericToken {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return [pscustomobject]@{ Found=$false; Format=$null; Token=$null; Value=$null }
    }

    $HexMatches = [regex]::Matches($Text, '(?i)(?<![0-9A-F])0x[0-9A-F]{1,16}(?![0-9A-F])')
    if ($HexMatches.Count -gt 0) {
        $Token = $HexMatches[$HexMatches.Count - 1].Value
        try {
            $Value = [Convert]::ToUInt64($Token.Substring(2), 16)
            return [pscustomobject]@{ Found=$true; Format='Hexadecimal'; Token=$Token; Value=[uint64]$Value }
        }
        catch {
            return [pscustomobject]@{ Found=$false; Format='HexadecimalOverflow'; Token=$Token; Value=$null }
        }
    }

    $DecimalMatches = [regex]::Matches($Text, '(?<![0-9A-Za-z])[-+]?[0-9]{1,20}(?![0-9A-Za-z])')
    if ($DecimalMatches.Count -gt 0) {
        $Token = $DecimalMatches[$DecimalMatches.Count - 1].Value
        $Parsed = [uint64]0
        if ([uint64]::TryParse($Token.TrimStart('+'), [ref]$Parsed)) {
            return [pscustomobject]@{ Found=$true; Format='Decimal'; Token=$Token; Value=$Parsed }
        }
    }

    return [pscustomobject]@{ Found=$false; Format=$null; Token=$null; Value=$null }
}

function ConvertTo-MSADPTFlagObservation {
    param(
        [string]$CaConfiguration,
        [string]$QueryName,
        $QueryResult,
        [hashtable]$KnownFlags
    )

    $Disposition = Get-MSADPTQueryDisposition -QueryResult $QueryResult
    $Numeric = ConvertFrom-MSADPTNumericToken -Text ([string]$QueryResult.StandardOutput)
    $DispositionName = $Disposition.EvidenceStatus
    $ParseStatus = $Disposition.ParseStatus
    $ParsedValue = $null
    $Flags = @()

    if ($Disposition.EvidenceStatus -eq 'Observed') {
        if ($Numeric.Found) {
            $ParsedValue = [uint64]$Numeric.Value
            foreach ($Flag in $KnownFlags.GetEnumerator() | Sort-Object Value) {
                $Mask = [uint64]$Flag.Value
                if ($Mask -ne 0 -and (($ParsedValue -band $Mask) -eq $Mask)) {
                    $Flags += [string]$Flag.Key
                }
            }
            $ParseStatus = 'NumericValueParsed'
        }
        else {
            $DispositionName = 'Unsupported format'
            $ParseStatus = 'NumericValueNotFound'
        }
    }

    [pscustomobject][ordered]@{
        ObservationId = ('CA-RUNTIME-{0}-{1}' -f (($CaConfiguration -replace '[^A-Za-z0-9]','_').Trim('_')), $QueryName)
        CertificationAuthority = $CaConfiguration
        EvidenceArea = 'CaRuntimeRegistry'
        Setting = $QueryName
        RawValue = [string]$QueryResult.StandardOutput
        ParsedValue = $ParsedValue
        NumericFormat = $Numeric.Format
        NumericToken = $Numeric.Token
        EnabledKnownFlags = @($Flags)
        QueryStatus = [string]$QueryResult.Status
        ExitCode = $QueryResult.ExitCode
        EvidenceStatus = $DispositionName
        ParseStatus = $ParseStatus
        SecurityRelevance = 'Requires correlation with templates, permissions, mapping behavior, and reachability before any attack-path conclusion.'
        Prerequisites = @('Validated source evidence','Successful locale-independent parsing or explicit query-failure classification')
        Limitations = @($Disposition.Detail)
        Disposition = $DispositionName
        RecommendedValidation = if ($DispositionName -eq 'Observed') {'Correlate the parsed value with the technique prerequisite catalog.'} elseif ($DispositionName -eq 'Not observed') {'Confirm whether the value is absent, unsupported, or inherited from a default.'} else {'Resolve the query or format limitation before drawing a security conclusion.'}
        SourceEvidence = [string]$QueryName
    }
}

function ConvertTo-MSADPTPingObservation {
    param([string]$CaConfiguration, $QueryResult)
    $Disposition = Get-MSADPTQueryDisposition -QueryResult $QueryResult
    [pscustomobject][ordered]@{
        ObservationId = ('CA-RUNTIME-{0}-Ping' -f (($CaConfiguration -replace '[^A-Za-z0-9]','_').Trim('_')))
        CertificationAuthority = $CaConfiguration
        EvidenceArea = 'CaRpcReachability'
        Setting = 'Ping'
        RawValue = [string]$QueryResult.StandardOutput
        ParsedValue = $null
        NumericFormat = $null
        NumericToken = $null
        EnabledKnownFlags = @()
        QueryStatus = [string]$QueryResult.Status
        ExitCode = $QueryResult.ExitCode
        EvidenceStatus = $Disposition.EvidenceStatus
        ParseStatus = $Disposition.ParseStatus
        SecurityRelevance = 'RPC reachability alone does not prove enrollment authorization, relay exposure, or exploitability.'
        Prerequisites = @('Validated source evidence')
        Limitations = @($Disposition.Detail)
        Disposition = $Disposition.EvidenceStatus
        RecommendedValidation = if ($Disposition.EvidenceStatus -eq 'Observed') {'Correlate RPC reachability with interface flags, authentication controls, and template permissions.'} else {'Resolve connectivity or query limitations before drawing a conclusion.'}
        SourceEvidence = 'Ping'
    }
}

$KnownFlagsBySetting = @{
    EditFlags = [ordered]@{
        EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
        EDITF_DISABLEEXTENSIONLIST = 0x00000080
        EDITF_REQUESTEXTENSIONLIST = 0x00000020
        EDITF_ENABLERENEWONBEHALFOF = 0x00010000
    }
    InterfaceFlags = [ordered]@{
        IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200
        IF_NOREMOTEICERTREQUEST = 0x00000080
        IF_NOREMOTEICERTADMIN = 0x00000040
    }
    RequestDisposition = [ordered]@{
        REQDISP_PENDINGFIRST = 0x00000100
    }
    RoleSeparationEnabled = [ordered]@{}
    EnrollmentAgentRights = [ordered]@{}
    OfficerRights = [ordered]@{}
}

if (-not (Test-Path -LiteralPath $EvidencePath -PathType Leaf)) {
    throw "Evidence file not found: $EvidencePath"
}

try {
    $CaEvidence = @(Get-Content -LiteralPath $EvidencePath -Raw | ConvertFrom-Json -ErrorAction Stop)
}
catch {
    throw "EvidenceJsonParseFailure: $($_.Exception.Message)"
}

$Observations = New-Object 'System.Collections.Generic.List[object]'
foreach ($Ca in $CaEvidence) {
    $CaConfiguration = [string]$Ca.CaConfiguration
    foreach ($Query in @($Ca.CertutilQueries)) {
        $QueryName = [string]$Query.Name
        if ($QueryName -eq 'Ping') {
            $Observations.Add((ConvertTo-MSADPTPingObservation -CaConfiguration $CaConfiguration -QueryResult $Query.Result))
            continue
        }
        if ($KnownFlagsBySetting.ContainsKey($QueryName)) {
            $Observations.Add((ConvertTo-MSADPTFlagObservation -CaConfiguration $CaConfiguration -QueryName $QueryName -QueryResult $Query.Result -KnownFlags $KnownFlagsBySetting[$QueryName]))
        }
        else {
            $Disposition = Get-MSADPTQueryDisposition -QueryResult $Query.Result
            $Observations.Add([pscustomobject][ordered]@{
                ObservationId=('CA-RUNTIME-{0}-{1}' -f (($CaConfiguration -replace '[^A-Za-z0-9]','_').Trim('_')),$QueryName)
                CertificationAuthority=$CaConfiguration;EvidenceArea='CaRuntimeUnknownQuery';Setting=$QueryName
                RawValue=[string]$Query.Result.StandardOutput;ParsedValue=$null;NumericFormat=$null;NumericToken=$null
                EnabledKnownFlags=@();QueryStatus=[string]$Query.Result.Status;ExitCode=$Query.Result.ExitCode
                EvidenceStatus='Unsupported format';ParseStatus='UnsupportedQuery';SecurityRelevance='Unknown query type.'
                Prerequisites=@('Validated source evidence');Limitations=@($Disposition.Detail);Disposition='Unsupported format'
                RecommendedValidation='Add an explicit parser and tests before interpreting this query.';SourceEvidence=$QueryName
            })
        }
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$ObservationPath = Join-Path $OutputDirectory 'ca-runtime-observations.json'
$SummaryPath = Join-Path $OutputDirectory 'ca-runtime-observation-summary.csv'

$Observations.ToArray() | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ObservationPath -Encoding UTF8
$Observations.ToArray() |
    Select-Object ObservationId,CertificationAuthority,EvidenceArea,Setting,ParsedValue,NumericFormat,NumericToken,
        @{Name='EnabledKnownFlags';Expression={@($_.EnabledKnownFlags) -join ';'}},QueryStatus,ExitCode,EvidenceStatus,ParseStatus,Disposition,RecommendedValidation,SourceEvidence |
    Export-Csv -LiteralPath $SummaryPath -NoTypeInformation -Encoding UTF8

[pscustomobject][ordered]@{
    schemaVersion='1.0';parser='ADCSCARuntimeEvidence';parserVersion=$ParserVersion;observationSchemaVersion=$ObservationSchemaVersion
    status='Completed';executionClass='offline_analysis';caCount=$CaEvidence.Count;observationCount=$Observations.Count
    observedCount=@($Observations|Where-Object EvidenceStatus -eq 'Observed').Count
    notObservedCount=@($Observations|Where-Object EvidenceStatus -eq 'Not observed').Count
    queryFailedCount=@($Observations|Where-Object EvidenceStatus -eq 'Query failed').Count
    inconclusiveCount=@($Observations|Where-Object EvidenceStatus -eq 'Inconclusive').Count
    unsupportedFormatCount=@($Observations|Where-Object EvidenceStatus -eq 'Unsupported format').Count
    evidence=@($ObservationPath,$SummaryPath)
    limitations=@('Numeric parsing uses locale-independent decimal or hexadecimal tokens only.','Observed flags are not vulnerability declarations.','Unknown or localized text without a numeric token remains Unsupported format.','Attack-path conclusions require correlation with templates, permissions, mapping behavior, and reachability.')
    completedUtc=(Get-Date).ToUniversalTime().ToString('o')
}
