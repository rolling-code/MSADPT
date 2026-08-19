<#
.SYNOPSIS
Performs controlled Kerberos service-ticket request validation for enabled user-owned SPNs.
.DESCRIPTION
Consumes an MSADPT SPN inventory, selects one canonical valid SPN per enabled user account, excludes
krbtgt and malformed URI-style registrations, requests one TGS per selected account using native
klist.exe, captures pre/post ticket-cache evidence and raw command output, and creates structured JSON,
CSV, summary, and SHA-256 manifest evidence.

A successful TGS request proves ticket requestability only. It does not prove password recovery,
credential compromise, service authentication, privilege escalation, or vulnerability.
.NOTES
Version: 0.1.0
Package identity: MSADPT-KERBEROAST-TICKET-VALIDATION
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SpnInventoryPath,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [string[]]$IncludeAccount,
    [string[]]$ExcludeAccount = @('krbtgt'),
    [ValidateRange(1,100)][int]$MaximumAccounts = 20,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PackageIdentity = 'MSADPT-KERBEROAST-TICKET-VALIDATION'
$PackageVersion = '0.1.0'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray)
    if ($Quiet) { return }
    $Text='[{0,-8}] {1}' -f $Status,$Message
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}

function Write-JsonArrayFile {
    param([object[]]$Rows,[string]$Path,[int]$Depth=12)
    $Array=@($Rows)
    if ($Array.Count -eq 0) {
        [IO.File]::WriteAllText($Path,"[]`r`n",(New-Object Text.UTF8Encoding($false)))
    }
    else {
        $Array | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    $RoundTrip=@(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
    if ($RoundTrip.Count -ne $Array.Count) {
        throw "JsonArrayRoundTripMismatch [$Path]: expected $($Array.Count), found $($RoundTrip.Count)"
    }
}

function Write-JsonDocument {
    param([object]$Document,[string]$Path,[int]$Depth=12)
    $Document | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    $null=Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
}

function Invoke-KlistCapture {
    param([string[]]$Arguments,[string]$OutputPath)
    $Lines=@(& klist.exe @Arguments 2>&1 | ForEach-Object { [string]$_ })
    $ExitCode=$LASTEXITCODE
    $Lines | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    return [pscustomobject]@{ExitCode=$ExitCode;Lines=$Lines;OutputPath=$OutputPath}
}

try {
    Write-Step 'START' "$PackageIdentity v$PackageVersion" Cyan

    if (-not (Test-Path -LiteralPath $SpnInventoryPath -PathType Leaf)) {
        throw "SpnInventoryMissing: $SpnInventoryPath"
    }
    if ($null -eq (Get-Command klist.exe -ErrorAction SilentlyContinue)) {
        throw 'klist.exe was not found.'
    }
    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $Spns=@(Get-Content -LiteralPath $SpnInventoryPath -Raw | ConvertFrom-Json -ErrorAction Stop)
    if ($Spns.Count -eq 0) { throw 'SPN inventory is empty.' }

    $EligibleRows=@(
        $Spns |
        Where-Object {
            [string]$_.OwnerType -eq 'User' -and
            [bool]$_.OwnerEnabled -and
            [string]$_.OwnerSamAccountName -notin $ExcludeAccount -and
            [string]$_.ParseStatus -eq 'Parsed' -and
            [string]$_.Spn -notmatch '^[A-Za-z]+://' -and
            [string]$_.Spn -match '^[^/]+/[^/]+'
        }
    )
    if ($null -ne $IncludeAccount -and $IncludeAccount.Count -gt 0) {
        $EligibleRows=@($EligibleRows | Where-Object { [string]$_.OwnerSamAccountName -in $IncludeAccount })
    }

    $Selections=@(
        $EligibleRows |
        Group-Object OwnerSamAccountName |
        ForEach-Object {
            $Rows=@($_.Group)
            $Preferred=@(
                $Rows |
                Sort-Object `
                    @{Expression={if([string]$_.Host -match '\.') {0}else{1}}},
                    @{Expression={if($null-ne$_.Port){0}else{1}}},
                    Spn
            )[0]
            [pscustomobject][ordered]@{
                SamAccountName=[string]$_.Name
                Spn=[string]$Preferred.Spn
                ServiceClass=[string]$Preferred.ServiceClass
                Host=[string]$Preferred.Host
                Port=$Preferred.Port
                AdminCount=$Preferred.OwnerAdminCount
                PasswordLastSetUtc=$Preferred.OwnerPasswordLastSetUtc
                Rc4Explicit=[bool]$Preferred.Rc4Explicit
                AesExplicit=[bool]$Preferred.AesExplicit
                DesExplicit=[bool]$Preferred.DesExplicit
                EncryptionTypesUnspecified=[bool]$Preferred.EncryptionTypesUnspecified
                CandidateSpnCount=$Rows.Count
            }
        } |
        Sort-Object SamAccountName |
        Select-Object -First $MaximumAccounts
    )

    if ($Selections.Count -eq 0) {
        throw 'No enabled, valid, user-owned SPN was eligible for controlled ticket validation.'
    }

    Write-Step 'OK' "Selected $($Selections.Count) distinct enabled account(s) for one TGS request each." Green
    foreach ($Selection in $Selections) {
        Write-Step 'TARGET' "$($Selection.SamAccountName): $($Selection.Spn)" DarkCyan
    }

    $BeforePath=Join-Path $OutputDirectory 'klist-before.txt'
    $Before=Invoke-KlistCapture -Arguments @() -OutputPath $BeforePath

    $Results=New-Object 'System.Collections.Generic.List[object]'
    $Index=0
    foreach ($Selection in $Selections) {
        $Index++
        $SafeName=([string]$Selection.SamAccountName -replace '[^A-Za-z0-9_.-]','_')
        $RawPath=Join-Path $OutputDirectory ('tgs-{0:D2}-{1}.txt' -f $Index,$SafeName)
        Write-Step 'REQUEST' "[$Index/$($Selections.Count)] Requesting TGS for $($Selection.Spn)" Yellow
        $Started=(Get-Date).ToUniversalTime()
        $Capture=Invoke-KlistCapture -Arguments @('get',[string]$Selection.Spn) -OutputPath $RawPath
        $Completed=(Get-Date).ToUniversalTime()
        $Combined=$Capture.Lines -join "`n"
        $Success=($Capture.ExitCode -eq 0 -and $Combined -match '(?i)ticket|cached|success')
        $EncryptionType=$null
        foreach ($Line in $Capture.Lines) {
            if ($Line -match '(?i)(KerbTicket Encryption Type|Ticket Encryption Type|Encryption type)\s*:\s*(.+)$') {
                $EncryptionType=$Matches[2].Trim()
                break
            }
        }
        $Results.Add([pscustomobject][ordered]@{
            SamAccountName=$Selection.SamAccountName
            Spn=$Selection.Spn
            ServiceClass=$Selection.ServiceClass
            Host=$Selection.Host
            Port=$Selection.Port
            AdminCount=$Selection.AdminCount
            PasswordLastSetUtc=$Selection.PasswordLastSetUtc
            Rc4Explicit=$Selection.Rc4Explicit
            AesExplicit=$Selection.AesExplicit
            DesExplicit=$Selection.DesExplicit
            EncryptionTypesUnspecified=$Selection.EncryptionTypesUnspecified
            StartedUtc=$Started.ToString('o')
            CompletedUtc=$Completed.ToString('o')
            ExitCode=$Capture.ExitCode
            RequestSucceeded=$Success
            ObservedEncryptionType=$EncryptionType
            RawOutputPath=$RawPath
            RawOutputSha256=(Get-FileHash -LiteralPath $RawPath -Algorithm SHA256).Hash
            EvidenceState=if($Success){'TGS request reproduced'}else{'TGS request not reproduced'}
        })
    }

    $AfterPath=Join-Path $OutputDirectory 'klist-after.txt'
    $After=Invoke-KlistCapture -Arguments @() -OutputPath $AfterPath

    $ResultsJson=Join-Path $OutputDirectory 'kerberoast-ticket-validation.json'
    $ResultsCsv=Join-Path $OutputDirectory 'kerberoast-ticket-validation.csv'
    Write-JsonArrayFile -Rows $Results.ToArray() -Path $ResultsJson
    $Results | Export-Csv -LiteralPath $ResultsCsv -NoTypeInformation -Encoding UTF8

    $SummaryPath=Join-Path $OutputDirectory 'kerberoast-ticket-validation-summary.json'
    $Summary=[pscustomobject][ordered]@{
        SchemaVersion='1.0'
        PackageIdentity=$PackageIdentity
        PackageVersion=$PackageVersion
        Status='Completed'
        GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        SourceSpnInventoryPath=$SpnInventoryPath
        SourceSpnInventorySha256=(Get-FileHash -LiteralPath $SpnInventoryPath -Algorithm SHA256).Hash
        Counts=[pscustomobject][ordered]@{
            EligibleSpnRows=$EligibleRows.Count
            SelectedAccounts=$Selections.Count
            SuccessfulTgsRequests=@($Results | Where-Object { [bool]$_.RequestSucceeded }).Count
            FailedTgsRequests=@($Results | Where-Object { -not [bool]$_.RequestSucceeded }).Count
        }
        Interpretation=@(
            'A successful TGS request proves service-ticket requestability only.',
            'Successful ticket request does not prove password recovery or credential compromise.',
            'Offline password-strength validation requires a separately approved validator and preserved artifacts.',
            'Disabled accounts, krbtgt, malformed URI-style SPNs, computer-owned SPNs, and duplicate per-account requests are excluded.'
        )
        Outputs=[pscustomobject][ordered]@{
            KlistBefore=$BeforePath
            KlistAfter=$AfterPath
            ResultsJson=$ResultsJson
            ResultsCsv=$ResultsCsv
        }
        Safety=[pscustomobject][ordered]@{
            ActiveDirectoryQueries='None'
            DirectoryChanges='None'
            TicketRequests='One TGS per selected account'
            TicketExtraction='None'
            PasswordMaterial='None'
            PasswordCracking='None'
            ServiceAuthentication='None'
            OllamaActivity='None'
        }
    }
    Write-JsonDocument -Document $Summary -Path $SummaryPath

    $Files=@(Get-ChildItem -LiteralPath $OutputDirectory -File | Sort-Object Name)
    $ManifestRows=@(
        foreach($File in $Files){
            [pscustomobject][ordered]@{
                Name=$File.Name
                Size=[int64]$File.Length
                SHA256=(Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
            }
        }
    )
    $ManifestPath=Join-Path $OutputDirectory 'evidence-manifest.json'
    Write-JsonDocument -Document ([pscustomobject][ordered]@{
        SchemaVersion='1.0';Status='Completed';FileCount=$ManifestRows.Count;Files=$ManifestRows
    }) -Path $ManifestPath

    Write-Step 'DONE' (
        'Controlled TGS validation complete: selected={0}, succeeded={1}, failed={2}.' -f
        $Selections.Count,$Summary.Counts.SuccessfulTgsRequests,$Summary.Counts.FailedTgsRequests
    ) Green

    [pscustomobject][ordered]@{
        Status='Passed'
        PackageIdentity=$PackageIdentity
        PackageVersion=$PackageVersion
        EligibleSpnRowCount=$EligibleRows.Count
        SelectedAccountCount=$Selections.Count
        SuccessfulTgsRequestCount=$Summary.Counts.SuccessfulTgsRequests
        FailedTgsRequestCount=$Summary.Counts.FailedTgsRequests
        SelectedAccounts=@($Selections.SamAccountName)
        SelectedSpns=@($Selections.Spn)
        OutputDirectory=$OutputDirectory
        SummaryPath=$SummaryPath
        ManifestPath=$ManifestPath
        ActiveDirectoryQueries='None'
        DirectoryChanges='None'
        TicketRequests='One TGS per selected account'
        TicketExtraction='None'
        PasswordMaterial='None'
    }
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
