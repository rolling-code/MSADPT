<#
.SYNOPSIS
Runs the candidate-specific ESC2 and ESC15 builder against preserved real MSADPT evidence.
.DESCRIPTION
Discovers the latest candidate-specific route inventory, certificate-template configuration, and identity
context evidence under the local MSADPT tree. It validates input structure, invokes the validated offline
builder, verifies output uniqueness and counts, and writes a concise real-evidence summary and next-LAN
plan. It performs no AD, CA, LDAP, DNS, TCP, SMB, Kerberos, certificate, authentication, Ollama, or ledger
operation.
.NOTES
Version: 1.0.1
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [string]$MSADPTRoot = 'C:\Temp\MSADPT-Example\Downloads\PowerShell-Scripts\On-Prem Active Directory\MSADPT',
    [string]$CandidateFactsPath,
    [string]$TemplateConfigurationPath,
    [string]$IdentityContextPath,
    [string]$OutputDirectory,
    [switch]$Force,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$RunnerVersion = '1.0.1'
$ExpectedBuilderVersion = '0.1.2'

function Write-Step {
    param([string]$Status,[string]$Message,[ConsoleColor]$Color)
    if (-not $Quiet) {
        Write-Host ('[{0,-5}] {1}' -f $Status,$Message) -ForegroundColor $Color
    }
}

function Get-NewestFile {
    param([string]$Root,[string]$Filter,[string[]]$PreferredPathPatterns)
    $Files = @(
        Get-ChildItem -LiteralPath $Root -Filter $Filter -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                [string]$_.FullName -notmatch '\\.backup-' -and
                [string]$_.FullName -notmatch '\\Fixtures?\\' -and
                [string]$_.FullName -notmatch '\\Synthetic\\' -and
                [string]$_.FullName -notmatch '\\ESC2ESC15RealEvidenceRunner-Test\\' -and
                [string]$_.FullName -notmatch '\\Tests\\Offline\\Generated\\[^\\]+-Test\\'
            }
    )
    if ($Files.Count -eq 0) { return $null }
    foreach ($Pattern in $PreferredPathPatterns) {
        $Preferred = @($Files | Where-Object { [string]$_.FullName -match $Pattern } | Sort-Object LastWriteTimeUtc -Descending)
        if ($Preferred.Count -gt 0) { return $Preferred[0] }
    }
    return @($Files | Sort-Object LastWriteTimeUtc -Descending)[0]
}

function Assert-JsonArray {
    param([string]$Path,[string]$Label)
    try {
        $Rows = @(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        throw "${Label}JsonParseFailure: $($_.Exception.Message)"
    }
    if ($Rows.Count -eq 0) { throw "${Label}Empty: $Path" }
    return $Rows
}

try {
    Write-Step 'START' 'Starting real-evidence ESC2 and ESC15 offline analysis.' Cyan
    Write-Step 'INFO' "MSADPT root: $MSADPTRoot" DarkGray
    if (-not (Test-Path -LiteralPath $MSADPTRoot -PathType Container)) {
        throw "MSADPTRootNotFound: $MSADPTRoot"
    }

    $BuilderPath = Join-Path $MSADPTRoot 'Analysis\ADCS\Convert-MSADPTADCSEvidenceToESC2ESC15CandidateFacts.ps1'
    $ConsoleModulePath = Join-Path $MSADPTRoot 'Common\MSADPT.Console.psm1'
    foreach ($RequiredPath in @($BuilderPath,$ConsoleModulePath)) {
        Write-Step 'CHECK' "Verifying required component: $RequiredPath" Yellow
        if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
            throw "RequiredComponentMissing: $RequiredPath"
        }
        Write-Step 'OK' "Found: $RequiredPath" Green
    }

    if ([string]::IsNullOrWhiteSpace($CandidateFactsPath)) {
        Write-Step 'STEP' 'Discovering candidate-specific ESC1/ESC4 route evidence.' Yellow
        $StandardCandidatePath = Join-Path $MSADPTRoot 'Tests\Offline\Generated\ADCSCandidateSpecificFacts\adcs-candidate-specific-facts.json'
        if (Test-Path -LiteralPath $StandardCandidatePath -PathType Leaf) {
            $CandidateFactsPath = $StandardCandidatePath
            Write-Step 'OK' 'Selected the standard real candidate-facts path.' Green
        }
        else {
            $Found = Get-NewestFile -Root $MSADPTRoot -Filter 'adcs-candidate-specific-facts.json' -PreferredPathPatterns @('Tests\\Offline\\Generated\\ADCSCandidateSpecificFacts')
            if ($null -eq $Found) { throw 'CandidateFactsNotFound: adcs-candidate-specific-facts.json was not found.' }
            $CandidateFactsPath = $Found.FullName
        }
    }
    if ([string]::IsNullOrWhiteSpace($TemplateConfigurationPath)) {
        Write-Step 'STEP' 'Discovering certificate-template configuration evidence under the real Engagements root.' Yellow
        $EngagementsRoot = Join-Path $MSADPTRoot 'Engagements'
        if (-not (Test-Path -LiteralPath $EngagementsRoot -PathType Container)) {
            throw "EngagementsRootNotFound: $EngagementsRoot"
        }
        $Found = Get-NewestFile -Root $EngagementsRoot -Filter 'certificate-template-configuration.json' -PreferredPathPatterns @('evidence\\ADCSConfigurationCollection')
        if ($null -eq $Found) { throw 'TemplateConfigurationNotFound: certificate-template-configuration.json was not found under the real Engagements root.' }
        $TemplateConfigurationPath = $Found.FullName
    }
    if ([string]::IsNullOrWhiteSpace($IdentityContextPath)) {
        Write-Step 'STEP' 'Discovering identity-context evidence.' Yellow
        $StandardIdentityPath = Join-Path $MSADPTRoot 'Tests\Offline\Generated\ADIdentityContext\ad-identity-context.json'
        if (Test-Path -LiteralPath $StandardIdentityPath -PathType Leaf) {
            $IdentityContextPath = $StandardIdentityPath
            Write-Step 'OK' 'Selected the standard real identity-context path.' Green
        }
        else {
            $Found = Get-NewestFile -Root $MSADPTRoot -Filter 'ad-identity-context.json' -PreferredPathPatterns @('Tests\\Offline\\Generated\\ADIdentityContext')
            if ($null -eq $Found) { throw 'IdentityContextNotFound: ad-identity-context.json was not found.' }
            $IdentityContextPath = $Found.FullName
        }
    }
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = Join-Path $MSADPTRoot 'Tests\Offline\Generated\ADCSCandidateESC2ESC15-RealEvidence'
    }

    foreach ($Input in @(
        [pscustomobject]@{Label='Candidate facts';Path=$CandidateFactsPath},
        [pscustomobject]@{Label='Template configuration';Path=$TemplateConfigurationPath},
        [pscustomobject]@{Label='Identity context';Path=$IdentityContextPath}
    )) {
        Write-Step 'CHECK' "$($Input.Label): $($Input.Path)" Yellow
        if (-not (Test-Path -LiteralPath $Input.Path -PathType Leaf)) {
            throw "InputMissing [$($Input.Label)]: $($Input.Path)"
        }
        Write-Step 'OK' "$($Input.Label) found" Green
    }

    $CandidateRows = @(Assert-JsonArray -Path $CandidateFactsPath -Label 'CandidateFacts')
    $TemplateRows = @(Assert-JsonArray -Path $TemplateConfigurationPath -Label 'TemplateConfiguration')
    $IdentityRows = @(Assert-JsonArray -Path $IdentityContextPath -Label 'IdentityContext')
    $Esc1Routes = @($CandidateRows | Where-Object { [string]$_.technique -eq 'ESC1' })
    if ($Esc1Routes.Count -eq 0) { throw 'Esc1RouteInventoryEmpty: No ESC1 routes exist in candidate facts.' }
    Write-Step 'OK' "Validated inputs: $($Esc1Routes.Count) ESC1 source routes, $($TemplateRows.Count) templates, $($IdentityRows.Count) identities" Green

    if ((Test-Path -LiteralPath $OutputDirectory -PathType Container) -and -not $Force) {
        $ExistingResult = Join-Path $OutputDirectory 'adcs-esc2-esc15-candidates.json'
        if (Test-Path -LiteralPath $ExistingResult -PathType Leaf) {
            Write-Step 'INFO' 'Existing output will be replaced because this runner always creates a point-in-time offline result.' DarkYellow
        }
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    Write-Step 'STEP' 'Invoking candidate-specific ESC2 and ESC15 builder v0.1.2.' Yellow
    $BuilderOutput = @(
        & $BuilderPath `
            -CandidateFactsPath $CandidateFactsPath `
            -TemplateConfigurationPath $TemplateConfigurationPath `
            -IdentityContextPath $IdentityContextPath `
            -OutputDirectory $OutputDirectory `
            -ConsoleModulePath $ConsoleModulePath
    )
    $Terminal = @(
        $BuilderOutput | Where-Object {
            $null -ne $_ -and
            $null -ne $_.PSObject.Properties['builderVersion'] -and
            $null -ne $_.PSObject.Properties['status'] -and
            [string]$_.builderVersion -eq $ExpectedBuilderVersion -and
            [string]$_.status -eq 'Completed'
        }
    ) | Select-Object -Last 1
    if ($null -eq $Terminal) {
        throw "BuilderTerminalResultMissing: Expected builder $ExpectedBuilderVersion Completed result."
    }

    $ResultPath = Join-Path $OutputDirectory 'adcs-esc2-esc15-candidates.json'
    $SummaryCsvPath = Join-Path $OutputDirectory 'adcs-esc2-esc15-candidate-summary.csv'
    $Rows = @(Assert-JsonArray -Path $ResultPath -Label 'Esc2Esc15Candidates')
    $ExpectedCandidateCount = $Esc1Routes.Count * 2
    if ($Rows.Count -ne $ExpectedCandidateCount) {
        throw "CandidateCountMismatch: expected $ExpectedCandidateCount, found $($Rows.Count)."
    }
    $DuplicateIds = @($Rows | Group-Object candidateId | Where-Object { $_.Count -gt 1 })
    if ($DuplicateIds.Count -gt 0) {
        throw "DuplicateCandidateIds: $($DuplicateIds.Count) duplicate candidate ID group(s) detected."
    }
    $Esc2Rows = @($Rows | Where-Object { [string]$_.technique -eq 'ESC2' })
    $Esc15Rows = @($Rows | Where-Object { [string]$_.technique -eq 'ESC15' })
    if ($Esc2Rows.Count -ne $Esc1Routes.Count -or $Esc15Rows.Count -ne $Esc1Routes.Count) {
        throw "TechniqueCountMismatch: ESC2=$($Esc2Rows.Count), ESC15=$($Esc15Rows.Count), source routes=$($Esc1Routes.Count)."
    }

    $VersionOneRoutes = @($Esc15Rows | Where-Object {
        @($_.facts | Where-Object { [string]$_.id -eq 'affectedVersionOneTemplate' -and [string]$_.state -eq 'Confirmed' }).Count -eq 1
    })
    $Esc2CapabilityRoutes = @($Esc2Rows | Where-Object {
        @($_.facts | Where-Object { [string]$_.id -eq 'anyPurposeOrNoEkuRestriction' -and [string]$_.state -eq 'Confirmed' }).Count -eq 1
    })
    $RuntimeGapIds = @('applicationPolicyRequestHandling','relevantPatchState','policyModuleRestriction')
    $Esc15WithExpectedRuntimeGaps = @($Esc15Rows | Where-Object {
        @($_.facts | Where-Object { [string]$_.id -in $RuntimeGapIds -and [string]$_.state -eq 'Inconclusive' }).Count -eq 3
    })
    if ($Esc15WithExpectedRuntimeGaps.Count -ne $Esc15Rows.Count) {
        throw 'UnexpectedEsc15RuntimeState: One or more ESC15 candidates did not preserve all three offline runtime gaps.'
    }

    $RealSummaryPath = Join-Path $OutputDirectory 'adcs-esc2-esc15-real-evidence-summary.json'
    $NextLanPlanPath = Join-Path $OutputDirectory 'adcs-esc2-esc15-next-lan-plan.json'
    $Summary = [pscustomobject][ordered]@{
        schemaVersion='1.0';runner='ADCSESC2ESC15RealEvidence';runnerVersion=$RunnerVersion
        status='Completed';executionClass='offline_analysis';sourceScope='preserved_real_evidence';sourceEsc1RouteCount=$Esc1Routes.Count
        totalCandidateCount=$Rows.Count;esc2Count=$Esc2Rows.Count;esc15Count=$Esc15Rows.Count
        esc2CapabilityRouteCount=$Esc2CapabilityRoutes.Count;versionOneEsc15RouteCount=$VersionOneRoutes.Count
        prerequisitesSatisfiedCount=@($Rows | Where-Object { [string]$_.disposition -eq 'Prerequisites satisfied' }).Count
        blockedCount=@($Rows | Where-Object { [string]$_.disposition -eq 'Blocked' }).Count
        incompleteEvidenceCount=@($Rows | Where-Object { [string]$_.disposition -eq 'Incomplete evidence' }).Count
        inputEvidence=[pscustomobject]@{candidateFacts=$CandidateFactsPath;templateConfiguration=$TemplateConfigurationPath;identityContext=$IdentityContextPath}
        outputEvidence=@($ResultPath,$SummaryCsvPath,$NextLanPlanPath)
        limitations=@('No ESC15 runtime, patch, or policy-module evidence was collected while offline.','Candidate records are prerequisites, not vulnerability or exploitability declarations.')
    }
    $Summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $RealSummaryPath -Encoding UTF8

    $NextLanPlan = [pscustomobject][ordered]@{
        schemaVersion='1.0';generatedUtc=(Get-Date).ToUniversalTime().ToString('o')
        requiredEvidence=@(
            [pscustomobject]@{factId='applicationPolicyRequestHandling';scope='Certification authority';purpose='Determine whether requested Application Policies are accepted, stripped, or restricted.'},
            [pscustomobject]@{factId='relevantPatchState';scope='CA host and relevant domain controllers';purpose='Establish affected-version and enforcement state without inferring from operating-system family.'},
            [pscustomobject]@{factId='policyModuleRestriction';scope='Certification authority';purpose='Determine whether the active policy module restricts Application Policies or requester-controlled identity.'}
        )
        targetedVersionOneTemplates=@($VersionOneRoutes | Select-Object -ExpandProperty template -Unique | Sort-Object)
        esc2CapabilityTemplates=@($Esc2CapabilityRoutes | Select-Object -ExpandProperty template -Unique | Sort-Object)
        prohibitedAutomaticActions=@('Certificate request','Certificate authentication','Template modification','CA setting change','Credential or hash replay')
    }
    $NextLanPlan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $NextLanPlanPath -Encoding UTF8

    Write-Step 'OK' "Validated $($Rows.Count) unique candidates: ESC2=$($Esc2Rows.Count), ESC15=$($Esc15Rows.Count)" Green
    Write-Step 'OK' "Version 1 ESC15 routes: $($VersionOneRoutes.Count); ESC2 capability routes: $($Esc2CapabilityRoutes.Count)" Green
    Write-Step 'DONE' 'Real-evidence ESC2 and ESC15 offline analysis completed.' Green
    Write-Output $Summary
}
catch {
    Write-Step 'FAIL' $_.Exception.Message Red
    throw
}
