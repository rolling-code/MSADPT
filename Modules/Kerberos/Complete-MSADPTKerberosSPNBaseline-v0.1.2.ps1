<#
.SYNOPSIS
Completes an interrupted MSADPT Kerberos/SPN baseline without repeating Active Directory collection.
.DESCRIPTION
Consumes the object and SPN evidence successfully produced by baseline collector v0.1.1. Rebuilds
empty-safe duplicate-SPN evidence, the neutral validation-candidate inventory, the baseline summary,
and the evidence manifest. This completion step is entirely local and performs no AD queries, ticket
requests, service authentication, password collection, or directory changes.
.NOTES
Version: 0.1.2
Package identity: MSADPT-KERBEROS-SPN-BASELINE-COMPLETION
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-KERBEROS-SPN-BASELINE-COMPLETION'
$PackageVersion = '0.1.2'

function Write-Step {
    param(
        [string]$Status,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    if ($Quiet) { return }
    $Text = '[{0,-8}] {1}' -f $Status,$Message
    if ($NoColor) { Write-Host $Text }
    else { Write-Host $Text -ForegroundColor $Color }
}

function Require-File {
    param([string]$Path,[string]$Label)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "RequiredFileMissing [$Label]: $Path"
    }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) {
        throw "RequiredFileEmpty [$Label]: $Path"
    }
}

function Write-JsonArrayFile {
    param(
        [object[]]$Rows,
        [string]$Path,
        [int]$Depth = 12
    )

    $Array = @($Rows)
    if ($Array.Count -eq 0) {
        [IO.File]::WriteAllText(
            $Path,
            "[]`r`n",
            (New-Object Text.UTF8Encoding($false))
        )
    }
    else {
        $Array |
            ConvertTo-Json -Depth $Depth |
            Set-Content -LiteralPath $Path -Encoding UTF8
    }

    $RoundTrip = @(
        Get-Content -LiteralPath $Path -Raw |
            ConvertFrom-Json -ErrorAction Stop
    )
    if ($RoundTrip.Count -ne $Array.Count) {
        throw "JsonArrayRoundTripMismatch [$Path]: expected $($Array.Count), found $($RoundTrip.Count)"
    }
}

function Write-JsonDocument {
    param(
        [object]$Document,
        [string]$Path,
        [int]$Depth = 12
    )

    $Document |
        ConvertTo-Json -Depth $Depth |
        Set-Content -LiteralPath $Path -Encoding UTF8

    $null = Get-Content -LiteralPath $Path -Raw |
        ConvertFrom-Json -ErrorAction Stop
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan
    Write-Step 'INFO' 'Local completion only. Existing AD evidence will not be recollected.' DarkGray

    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
        throw "OutputDirectoryMissing: $OutputDirectory"
    }

    $ObjectsJson = Join-Path $OutputDirectory 'kerberos-directory-objects.json'
    $ObjectsCsv = Join-Path $OutputDirectory 'kerberos-directory-objects.csv'
    $SpnsJson = Join-Path $OutputDirectory 'spn-inventory.json'
    $SpnsCsv = Join-Path $OutputDirectory 'spn-inventory.csv'
    $DuplicatesJson = Join-Path $OutputDirectory 'duplicate-spns.json'
    $DuplicatesCsv = Join-Path $OutputDirectory 'duplicate-spns.csv'
    $CandidatesJson = Join-Path $OutputDirectory 'kerberos-validation-candidates.json'
    $CandidatesCsv = Join-Path $OutputDirectory 'kerberos-validation-candidates.csv'
    $SummaryPath = Join-Path $OutputDirectory 'kerberos-spn-baseline-summary.json'
    $ManifestPath = Join-Path $OutputDirectory 'evidence-manifest.json'

    foreach ($Required in @(
        @{Path=$ObjectsJson;Label='Directory object JSON'},
        @{Path=$ObjectsCsv;Label='Directory object CSV'},
        @{Path=$SpnsJson;Label='SPN inventory JSON'},
        @{Path=$SpnsCsv;Label='SPN inventory CSV'}
    )) {
        Require-File -Path $Required.Path -Label $Required.Label
    }

    $ObjectRows = @(
        Get-Content -LiteralPath $ObjectsJson -Raw |
            ConvertFrom-Json -ErrorAction Stop
    )
    $SpnRows = @(
        Get-Content -LiteralPath $SpnsJson -Raw |
            ConvertFrom-Json -ErrorAction Stop
    )

    if ($ObjectRows.Count -eq 0) { throw 'Preserved directory-object evidence is empty.' }
    if ($SpnRows.Count -eq 0) { throw 'Preserved SPN evidence is empty.' }

    $RequiredObjectProperties = @(
        'ObjectType','SamAccountName','TrustedForDelegation',
        'TrustedToAuthForDelegation','AllowedToDelegateTo','RbcdConfigured'
    )
    foreach ($PropertyName in $RequiredObjectProperties) {
        if ($null -eq $ObjectRows[0].PSObject.Properties[$PropertyName]) {
            throw "ObjectEvidenceSchemaMismatch: missing $PropertyName"
        }
    }

    $RequiredSpnProperties = @(
        'Spn','NormalizedSpn','OwnerType','OwnerSamAccountName'
    )
    foreach ($PropertyName in $RequiredSpnProperties) {
        if ($null -eq $SpnRows[0].PSObject.Properties[$PropertyName]) {
            throw "SpnEvidenceSchemaMismatch: missing $PropertyName"
        }
    }

    Write-Step 'OK' "Loaded preserved evidence: objects=$($ObjectRows.Count), SPNs=$($SpnRows.Count)." Green

    $DuplicateGroups = @(
        $SpnRows |
            Group-Object NormalizedSpn |
            Where-Object { $_.Count -gt 1 }
    )

    $DuplicateRows = @(
        foreach ($Group in $DuplicateGroups) {
            foreach ($Row in @($Group.Group)) {
                [pscustomobject][ordered]@{
                    NormalizedSpn = [string]$Group.Name
                    DuplicateCount = [int]$Group.Count
                    Spn = [string]$Row.Spn
                    OwnerType = [string]$Row.OwnerType
                    OwnerSamAccountName = [string]$Row.OwnerSamAccountName
                    OwnerDistinguishedName = [string]$Row.OwnerDistinguishedName
                }
            }
        }
    )

    Write-JsonArrayFile -Rows $DuplicateRows -Path $DuplicatesJson
    if ($DuplicateRows.Count -eq 0) {
        'NormalizedSpn,DuplicateCount,Spn,OwnerType,OwnerSamAccountName,OwnerDistinguishedName' |
            Set-Content -LiteralPath $DuplicatesCsv -Encoding UTF8
    }
    else {
        $DuplicateRows |
            Export-Csv -LiteralPath $DuplicatesCsv -NoTypeInformation -Encoding UTF8
    }
    Write-Step 'OK' "Duplicate-SPN evidence completed: groups=$($DuplicateGroups.Count), rows=$($DuplicateRows.Count)." Green

    $CandidateRows = New-Object 'System.Collections.Generic.List[object]'

    foreach ($Row in $ObjectRows) {
        if ([bool]$Row.DoesNotRequirePreAuth) {
            $CandidateRows.Add([pscustomobject][ordered]@{
                CandidateType='ASREP';ObjectType=$Row.ObjectType;SamAccountName=$Row.SamAccountName
                Priority='P1';Reason='Kerberos pre-authentication disabled'
                EvidenceState='Confirmed configuration'
            })
        }

        if ([bool]$Row.TrustedForDelegation) {
            $Priority = if ([string]$Row.ObjectType -eq 'User') { 'P1' } else { 'P2' }
            $CandidateRows.Add([pscustomobject][ordered]@{
                CandidateType='UnconstrainedDelegation';ObjectType=$Row.ObjectType
                SamAccountName=$Row.SamAccountName;Priority=$Priority
                Reason='TRUSTED_FOR_DELEGATION enabled';EvidenceState='Confirmed configuration'
            })
        }

        if ([bool]$Row.TrustedToAuthForDelegation -or @($Row.AllowedToDelegateTo).Count -gt 0) {
            $CandidateRows.Add([pscustomobject][ordered]@{
                CandidateType='ConstrainedDelegation';ObjectType=$Row.ObjectType
                SamAccountName=$Row.SamAccountName;Priority='P2'
                Reason='Protocol transition or delegation targets configured'
                EvidenceState='Confirmed configuration'
            })
        }

        if ([bool]$Row.RbcdConfigured) {
            $CandidateRows.Add([pscustomobject][ordered]@{
                CandidateType='RBCD';ObjectType=$Row.ObjectType
                SamAccountName=$Row.SamAccountName;Priority='P2'
                Reason='RBCD security descriptor present';EvidenceState='Trustee resolution pending'
            })
        }
    }

    foreach ($Row in @($SpnRows | Where-Object { [string]$_.OwnerType -eq 'User' })) {
        $Priority = 'P3'
        if ($Row.OwnerAdminCount -eq 1) {
            $Priority = 'P1'
        }
        elseif (
            [bool]$Row.DesExplicit -or
            [bool]$Row.Rc4Explicit -or
            [bool]$Row.EncryptionTypesUnspecified
        ) {
            $Priority = 'P2'
        }

        $CandidateRows.Add([pscustomobject][ordered]@{
            CandidateType='Kerberoast';ObjectType='User'
            SamAccountName=$Row.OwnerSamAccountName;Priority=$Priority
            Reason=('User-owned SPN: {0}' -f $Row.Spn)
            EvidenceState='Ticket-request validation pending'
        })
    }

    foreach ($Group in $DuplicateGroups) {
        $Owners = @($Group.Group.OwnerSamAccountName | Sort-Object -Unique) -join ','
        $CandidateRows.Add([pscustomobject][ordered]@{
            CandidateType='DuplicateSPN';ObjectType='Multiple';SamAccountName=$Owners
            Priority='P2';Reason=('Duplicate SPN: {0}' -f $Group.Name)
            EvidenceState='Confirmed duplicate registration'
        })
    }

    Write-JsonArrayFile -Rows $CandidateRows.ToArray() -Path $CandidatesJson
    if ($CandidateRows.Count -eq 0) {
        'CandidateType,ObjectType,SamAccountName,Priority,Reason,EvidenceState' |
            Set-Content -LiteralPath $CandidatesCsv -Encoding UTF8
    }
    else {
        $CandidateRows |
            Export-Csv -LiteralPath $CandidatesCsv -NoTypeInformation -Encoding UTF8
    }
    Write-Step 'OK' "Validation candidate inventory completed: $($CandidateRows.Count) row(s)." Green

    $UserObjects = @($ObjectRows | Where-Object { [string]$_.ObjectType -eq 'User' })
    $ComputerObjects = @($ObjectRows | Where-Object { [string]$_.ObjectType -eq 'Computer' })
    $UserSpns = @($SpnRows | Where-Object { [string]$_.OwnerType -eq 'User' })

    $Summary = [pscustomobject][ordered]@{
        SchemaVersion='1.0'
        PackageIdentity='MSADPT-KERBEROS-SPN-BASELINE-COLLECTION'
        PackageVersion='0.1.2'
        CompletionPackageIdentity=$PackageIdentity
        Status='Completed'
        GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        Counts=[pscustomobject][ordered]@{
            UserObjects=$UserObjects.Count
            ComputerObjects=$ComputerObjects.Count
            SpnRecords=$SpnRows.Count
            UserSpnRecords=$UserSpns.Count
            DuplicateSpnGroups=$DuplicateGroups.Count
            AsRepCandidates=@($CandidateRows | Where-Object { $_.CandidateType -eq 'ASREP' }).Count
            UnconstrainedDelegationCandidates=@($CandidateRows | Where-Object { $_.CandidateType -eq 'UnconstrainedDelegation' }).Count
            ConstrainedDelegationCandidates=@($CandidateRows | Where-Object { $_.CandidateType -eq 'ConstrainedDelegation' }).Count
            RbcdCandidates=@($CandidateRows | Where-Object { $_.CandidateType -eq 'RBCD' }).Count
            KerberoastCandidates=@($CandidateRows | Where-Object { $_.CandidateType -eq 'Kerberoast' }).Count
            ValidationCandidates=$CandidateRows.Count
        }
        Outputs=[pscustomobject][ordered]@{
            ObjectsJson=$ObjectsJson;ObjectsCsv=$ObjectsCsv
            SpnsJson=$SpnsJson;SpnsCsv=$SpnsCsv
            DuplicatesJson=$DuplicatesJson;DuplicatesCsv=$DuplicatesCsv
            CandidatesJson=$CandidatesJson;CandidatesCsv=$CandidatesCsv
        }
        Limitations=@(
            'SPN presence is not proof of crackable password material.',
            'Encryption types set to zero may use domain defaults and are not automatically RC4-only.',
            'Delegation configuration requires privilege, reachability, and ticket-flow validation.',
            'RBCD security descriptors require trustee resolution before impact assessment.'
        )
        Safety=[pscustomobject][ordered]@{
            NetworkActivity='None during completion'
            ActiveDirectoryQueries='None during completion'
            DirectoryChanges='None'
            TicketRequests='None'
            TicketExtraction='None'
            PasswordMaterial='None'
            OllamaActivity='None'
        }
    }

    Write-JsonDocument -Document $Summary -Path $SummaryPath

    $EvidenceFiles = @(
        Get-ChildItem -LiteralPath $OutputDirectory -File |
            Where-Object { $_.Name -ne 'evidence-manifest.json' } |
            Sort-Object Name
    )
    $ManifestRows = @(
        foreach ($File in $EvidenceFiles) {
            [pscustomobject][ordered]@{
                Name=$File.Name
                Path=$File.FullName
                Size=[int64]$File.Length
                SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
                LastWriteTimeUtc=$File.LastWriteTimeUtc.ToUniversalTime().ToString('o')
            }
        }
    )
    $Manifest = [pscustomobject][ordered]@{
        SchemaVersion='1.0';Status='Completed';GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        CompletionPackageIdentity=$PackageIdentity;CompletionPackageVersion=$PackageVersion
        FileCount=$ManifestRows.Count;Files=$ManifestRows
    }
    Write-JsonDocument -Document $Manifest -Path $ManifestPath

    Write-Step 'DONE' (
        'Baseline completed locally: SPNs={0}, user SPNs={1}, duplicates={2}, candidates={3}.' -f
        $SpnRows.Count,$UserSpns.Count,$DuplicateGroups.Count,$CandidateRows.Count
    ) Green

    [pscustomobject][ordered]@{
        Status='Passed'
        PackageIdentity=$PackageIdentity
        PackageVersion=$PackageVersion
        UserObjectCount=$UserObjects.Count
        ComputerObjectCount=$ComputerObjects.Count
        SpnRecordCount=$SpnRows.Count
        UserSpnRecordCount=$UserSpns.Count
        DuplicateSpnGroupCount=$DuplicateGroups.Count
        AsRepCandidateCount=$Summary.Counts.AsRepCandidates
        UnconstrainedDelegationCandidateCount=$Summary.Counts.UnconstrainedDelegationCandidates
        ConstrainedDelegationCandidateCount=$Summary.Counts.ConstrainedDelegationCandidates
        RbcdCandidateCount=$Summary.Counts.RbcdCandidates
        KerberoastCandidateCount=$Summary.Counts.KerberoastCandidates
        ValidationCandidateCount=$Summary.Counts.ValidationCandidates
        OutputDirectory=$OutputDirectory
        SummaryPath=$SummaryPath
        ManifestPath=$ManifestPath
        NetworkActivity='None'
        ActiveDirectoryQueries='None'
        DirectoryChanges='None'
        TicketRequests='None'
        PasswordMaterial='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
