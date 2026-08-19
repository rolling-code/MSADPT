<#
.SYNOPSIS
Builds candidate-specific ADCS prerequisite facts from preserved evidence.
.DESCRIPTION
Creates one evidence record per technique, template, principal, and publishing CA combination.
This prevents facts from unrelated templates or principals from being combined into an apparent attack path.
The script reads saved JSON and CSV evidence only. It performs no AD, CA, LDAP, network, registry,
certificate, authentication, or state-changing operation.
.NOTES
Version: 0.2.3
Execution class: offline_analysis
Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$TemplateConfigurationPath,
    [Parameter(Mandatory=$true)][string]$TemplateAccessPath,
    [Parameter()][string]$IdentityPrerequisitePath,
    [Parameter()][string]$CaRuntimeObservationPath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter()][string]$ConsoleModulePath,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$BuilderVersion = '0.2.3'
$AllowedStates = @('Confirmed','Not observed','Inconclusive','Not applicable')

foreach ($Path in @($TemplateConfigurationPath,$TemplateAccessPath)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required evidence not found: $Path"
    }
}

if (-not [string]::IsNullOrWhiteSpace($ConsoleModulePath)) {
    Import-Module $ConsoleModulePath -Force -ErrorAction Stop
}

function Test-MSADPTTrue {
    param($Value)
    if ($Value -is [bool]) { return [bool]$Value }
    return ([string]$Value -eq 'True')
}

function Write-MSADPTCandidateEvent {
    param(
        [ValidateSet('Info','Action','Success','Warning','Error','Muted')][string]$Kind,
        [string]$Message,
        [string]$Target,
        [string]$Code,
        [hashtable]$Data
    )
    if (Get-Command Write-MSADPTConsoleEvent -ErrorAction SilentlyContinue) {
        return Write-MSADPTConsoleEvent -Kind $Kind -Message $Message -Target $Target -Code $Code -Data $Data
    }
    $Event = [pscustomobject][ordered]@{
        TimestampUtc=(Get-Date).ToUniversalTime().ToString('o');Kind=$Kind;Code=$Code;Message=$Message;Target=$Target
        Data=if($null-ne$Data){[pscustomobject]$Data}else{$null}
    }
    if (-not $Quiet) {
        $Color = switch($Kind){'Info'{'Cyan'}'Action'{'Yellow'}'Success'{'Green'}'Warning'{'DarkYellow'}'Error'{'Red'}default{'DarkGray'}}
        Write-Host ('[{0}] {1}: {2}' -f $Kind.ToUpperInvariant(),$Target,$Message) -ForegroundColor $Color
    }
    Write-Output $Event
}

function New-MSADPTFact {
    param([string]$Id,[string]$State,[string]$Rationale,[string[]]$Sources,[string[]]$Limitations)
    if ($State -notin $AllowedStates) { throw "Unsupported fact state for ${Id}: $State" }
    [pscustomobject][ordered]@{
        id=$Id;state=$State;rationale=$Rationale;sourceEvidence=@($Sources);limitations=@($Limitations)
        derivation='deterministic';builderVersion=$BuilderVersion
    }
}

function Get-MSADPTIdentityRecord {
    param([string]$IdentityReference,$IdentityRecords)
    # PowerShell unwraps single-item pipeline output. The caller must still wrap this result in @().
    return ($IdentityRecords | Where-Object { [string]$_.IdentityReference -eq $IdentityReference } | Select-Object -First 1)
}

function Get-MSADPTEnrollmentState {
    param($AccessRows,$IdentityRecord)
    $Rows = @($AccessRows)
    $AllowEnrollmentRows = @(
        $Rows |
            Where-Object {
                [string]$_.AccessControlType -eq 'Allow' -and
                (Test-MSADPTTrue $_.AllowsEnroll)
            }
    )
    if ($AllowEnrollmentRows.Count -eq 0) {
        return [pscustomobject]@{State='Not observed';Rationale='No allow enrollment ACE was observed for this template and principal.'}
    }

    $Identity = [string]$AllowEnrollmentRows[0].IdentityReference
    if ($Identity -match '(?i)\\(Domain Users|Domain Computers|Authenticated Users|Everyone)$|^S-1-1-0$|^S-1-5-11$') {
        return [pscustomobject]@{State='Confirmed';Rationale='A broadly scoped principal has one or more direct allow enrollment ACEs.'}
    }
    if ($null -eq $IdentityRecord) {
        return [pscustomobject]@{State='Inconclusive';Rationale='Enrollment is allowed, but identity-resolution evidence is unavailable.'}
    }
    if ([string]$IdentityRecord.ResolutionStatus -eq 'Resolved') {
        if ([string]$IdentityRecord.ObjectClass -eq 'group') {
            return [pscustomobject]@{State='Inconclusive';Rationale='The enrollment group resolved, but effective low-privilege membership and deny ACE evaluation remain required.'}
        }
        if ([string]$IdentityRecord.ObjectClass -in @('user','computer') -and [bool]$IdentityRecord.Enabled) {
            return [pscustomobject]@{State='Inconclusive';Rationale='The principal is enabled and has enrollment, but its privilege level and effective deny conditions remain unresolved.'}
        }
        return [pscustomobject]@{State='Not observed';Rationale='The resolved principal is not currently enabled or usable according to supplied evidence.'}
    }
    if ([string]$IdentityRecord.ResolutionStatus -eq 'NotFound') {
        return [pscustomobject]@{State='Not observed';Rationale='The enrollment principal was not found in the supplied directory evidence.'}
    }
    return [pscustomobject]@{State='Inconclusive';Rationale='The enrollment principal could not be conclusively classified.'}
}

function Get-MSADPTTemplateControlState {
    param($AccessRows,$IdentityRecord)
    $Rows = @($AccessRows)
    $BroadRows = @(
        $Rows |
            Where-Object {
                [string]$_.AccessControlType -eq 'Allow' -and
                (
                    (Test-MSADPTTrue $_.AllowsGenericAll) -or
                    (Test-MSADPTTrue $_.AllowsGenericWrite) -or
                    (Test-MSADPTTrue $_.AllowsWriteDacl) -or
                    (Test-MSADPTTrue $_.AllowsWriteOwner)
                )
            }
    )
    if ($BroadRows.Count -eq 0) {
        return [pscustomobject]@{State='Not observed';Rationale='No broad allow template-control right was observed for this template and principal.'}
    }

    $Identity = [string]$BroadRows[0].IdentityReference
    if ($Identity -match '(?i)\\(Domain Admins|Enterprise Admins|Administrators)$') {
        return [pscustomobject]@{State='Not observed';Rationale='Only a routine privileged administrative identity is represented by this route.'}
    }
    if ($null -eq $IdentityRecord) {
        return [pscustomobject]@{State='Inconclusive';Rationale='Broad template control is present, but the controlling identity has not been resolved.'}
    }
    if ([string]$IdentityRecord.ResolutionStatus -ne 'Resolved') {
        return [pscustomobject]@{State='Not observed';Rationale='The controlling identity was not resolved as a current directory object.'}
    }
    if ([string]$IdentityRecord.ObjectClass -eq 'group' -and @($IdentityRecord.RecursiveMembers).Count -eq 0) {
        return [pscustomobject]@{State='Not observed';Rationale='The controlling group is currently empty in the supplied evidence.'}
    }
    return [pscustomobject]@{State='Inconclusive';Rationale='Broad template control is present, but effective privilege, deny, inheritance, and nested control remain unresolved.'}
}

$Events = New-Object 'System.Collections.Generic.List[object]'
$Events.Add((Write-MSADPTCandidateEvent -Kind Info -Code 'CandidateFactBuilderStarted' -Message 'Loading preserved ADCS evidence.' -Target 'Candidate fact builder' -Data @{BuilderVersion=$BuilderVersion}))

$Templates = @(Get-Content -LiteralPath $TemplateConfigurationPath -Raw | ConvertFrom-Json -ErrorAction Stop)
$AccessRows = @(Import-Csv -LiteralPath $TemplateAccessPath)
$IdentityRecords = @()
if (-not [string]::IsNullOrWhiteSpace($IdentityPrerequisitePath) -and (Test-Path -LiteralPath $IdentityPrerequisitePath -PathType Leaf)) {
    $IdentityRecords = @(Get-Content -LiteralPath $IdentityPrerequisitePath -Raw | ConvertFrom-Json -ErrorAction Stop)
}
$RuntimeObservations = @()
if (-not [string]::IsNullOrWhiteSpace($CaRuntimeObservationPath) -and (Test-Path -LiteralPath $CaRuntimeObservationPath -PathType Leaf)) {
    $RuntimeObservations = @(Get-Content -LiteralPath $CaRuntimeObservationPath -Raw | ConvertFrom-Json -ErrorAction Stop)
}

$PublishedTemplates = @($Templates | Where-Object { Test-MSADPTTrue $_.PublishedByDiscoveredCA })
$CandidateRecords = New-Object 'System.Collections.Generic.List[object]'
$CandidateGroups = @(
    $AccessRows |
        Where-Object { Test-MSADPTTrue $_.PublishedByDiscoveredCA } |
        Group-Object TemplateName,IdentityReference
)
$Total = [math]::Max(1,$CandidateGroups.Count)
$Current = 0

foreach ($CandidateGroup in $CandidateGroups) {
    $Current++
    $CandidateAccessRows = @($CandidateGroup.Group)
    if ($CandidateAccessRows.Count -eq 0) { continue }
    $AccessRow = $CandidateAccessRows[0]
    $Template = @($PublishedTemplates | Where-Object { [string]$_.Name -eq [string]$AccessRow.TemplateName } | Select-Object -First 1)
    if ($Template.Count -eq 0) { continue }
    $Template = $Template[0]
    $Principal = [string]$AccessRow.IdentityReference
    $IdentityRecordArray = @(Get-MSADPTIdentityRecord -IdentityReference $Principal -IdentityRecords $IdentityRecords)
    $IdentityRecord = if ($IdentityRecordArray.Count -gt 0) { $IdentityRecordArray[0] } else { $null }
    $PublishingCas = @($Template.PublishingCAs | ForEach-Object { [string]$_ })
    if ($PublishingCas.Count -eq 0) { $PublishingCas = @('Unknown enterprise CA') }

    if (-not $Quiet) {
        $Percent = [math]::Round(($Current / $Total) * 100,0)
        $Events.Add((Write-MSADPTCandidateEvent -Kind Action -Code 'EvaluateTemplatePrincipal' -Message ("[{0}/{1} {2}%] Evaluating template and principal evidence." -f $Current,$Total,$Percent) -Target ("{0} / {1}" -f $Template.Name,$Principal) -Data $null))
    }

    foreach ($Ca in $PublishingCas) {
        # Do not separate PowerShell command invocations with commas inside @().
        # A comma can be parsed as part of the final command argument, causing later facts to disappear.
        $CommonFactList = New-Object 'System.Collections.Generic.List[object]'
        $CommonFactList.Add((New-MSADPTFact 'enterpriseCaPresent' 'Confirmed' 'The template is published by a discovered enterprise CA.' @($TemplateConfigurationPath) @()))
        $CommonFactList.Add((New-MSADPTFact 'templatePresent' 'Confirmed' 'The certificate template is present in the directory evidence.' @($TemplateConfigurationPath) @()))
        $CommonFactList.Add((New-MSADPTFact 'templatePublished' 'Confirmed' ("The template is published by {0}." -f $Ca) @($TemplateConfigurationPath) @()))
        $PrincipalResolutionState = if ($null -ne $IdentityRecord -and [string]$IdentityRecord.ResolutionStatus -eq 'Resolved') {
            'Confirmed'
        }
        elseif ($null -ne $IdentityRecord -and [string]$IdentityRecord.ResolutionStatus -eq 'NotFound') {
            'Not observed'
        }
        else {
            'Inconclusive'
        }
        $PrincipalResolutionRationale = if ($null -ne $IdentityRecord) {
            "Identity resolution status: $($IdentityRecord.ResolutionStatus)."
        }
        else {
            'No identity record was supplied.'
        }
        $CommonFactList.Add((New-MSADPTFact 'principalResolved' $PrincipalResolutionState $PrincipalResolutionRationale @($IdentityPrerequisitePath) @()))
        $CommonFacts = @($CommonFactList.ToArray())

        $Enrollment = Get-MSADPTEnrollmentState -AccessRows $CandidateAccessRows -IdentityRecord $IdentityRecord
        $TemplateControl = Get-MSADPTTemplateControlState -AccessRows $CandidateAccessRows -IdentityRecord $IdentityRecord

        $Esc1FactList = New-Object 'System.Collections.Generic.List[object]'
        foreach ($CommonFact in $CommonFacts) {
            $Esc1FactList.Add($CommonFact)
        }
        $Esc1FactList.Add((New-MSADPTFact 'effectiveLowPrivilegeEnrollment' $Enrollment.State $Enrollment.Rationale @($TemplateAccessPath,$IdentityPrerequisitePath) @('Effective deny ACE and complete nested-membership evaluation remain required.')))
        $Esc1FactList.Add((New-MSADPTFact 'enrolleeSuppliesIdentity' $(if((Test-MSADPTTrue $Template.EnrolleeSuppliesSubject) -or (Test-MSADPTTrue $Template.EnrolleeSuppliesSubjectAltName)){'Confirmed'}else{'Not observed'}) 'Derived from certificate name flags.' @($TemplateConfigurationPath) @()))
        $Esc1FactList.Add((New-MSADPTFact 'authenticationCapableEku' $(if((Test-MSADPTTrue $Template.HasAuthenticationCapableEku) -or (Test-MSADPTTrue $Template.NoExtendedKeyUsageRestriction)){'Confirmed'}else{'Not observed'}) 'Derived from template EKU evidence.' @($TemplateConfigurationPath) @()))
        $Esc1FactList.Add((New-MSADPTFact 'managerApprovalDisabled' $(if(Test-MSADPTTrue $Template.ManagerApprovalRequired){'Not observed'}else{'Confirmed'}) 'Derived from template enrollment flags.' @($TemplateConfigurationPath) @()))
        $Esc1FactList.Add((New-MSADPTFact 'authorizedSignaturesNotRequired' $(if(Test-MSADPTTrue $Template.AuthorizedSignaturesRequired){'Not observed'}else{'Confirmed'}) 'Derived from authorized-signature requirements.' @($TemplateConfigurationPath) @()))
        $Esc1Facts = @($Esc1FactList.ToArray())

        $Esc1Required = @('enterpriseCaPresent','templatePublished','effectiveLowPrivilegeEnrollment','enrolleeSuppliesIdentity','authenticationCapableEku','managerApprovalDisabled','authorizedSignaturesNotRequired')
        $Esc1RequiredFacts = @($Esc1Facts | Where-Object { $_.id -in $Esc1Required })
        $Esc1Missing = @($Esc1RequiredFacts | Where-Object { $_.state -eq 'Inconclusive' })
        $Esc1Blocked = @($Esc1RequiredFacts | Where-Object { $_.state -eq 'Not observed' })
        $Esc1Disposition = if($Esc1Blocked.Count -gt 0){'Blocked'}elseif($Esc1Missing.Count -gt 0){'Incomplete evidence'}else{'Prerequisites satisfied'}
        $CandidateRecords.Add([pscustomobject][ordered]@{
            candidateId=('ESC1|{0}|{1}|{2}' -f $Ca,$Template.Name,$Principal);technique='ESC1';certificationAuthority=$Ca
            template=[string]$Template.Name;principal=$Principal;accessRowCount=$CandidateAccessRows.Count;disposition=$Esc1Disposition
            requiredCount=$Esc1Required.Count;satisfiedRequiredCount=@($Esc1RequiredFacts|Where-Object state -eq 'Confirmed').Count
            missingOrInconclusive=@($Esc1Missing|Select-Object id,state,rationale);notObserved=@($Esc1Blocked|Select-Object id,state,rationale)
            facts=@($Esc1Facts);safeFollowUp='Resolve effective enrollment, deny ACEs, nested membership, and current mapping behavior before any certificate-request validation.'
            limitations=@('This is a candidate-specific prerequisite record, not a vulnerability or exploitability declaration.')
        })

        $Esc4FactList = New-Object 'System.Collections.Generic.List[object]'
        foreach ($CommonFact in $CommonFacts) {
            $Esc4FactList.Add($CommonFact)
        }
        $Esc4FactList.Add((New-MSADPTFact 'effectiveNonPrivilegedTemplateControl' $TemplateControl.State $TemplateControl.Rationale @($TemplateAccessPath,$IdentityPrerequisitePath) @('Effective access remains subject to deny ACEs, inheritance, ownership, and nested control.')))
        $Esc4Facts = @($Esc4FactList.ToArray())
        $Esc4Required = @('enterpriseCaPresent','templatePresent','effectiveNonPrivilegedTemplateControl')
        $Esc4RequiredFacts = @($Esc4Facts | Where-Object { $_.id -in $Esc4Required })
        $Esc4Missing = @($Esc4RequiredFacts | Where-Object state -eq 'Inconclusive')
        $Esc4Blocked = @($Esc4RequiredFacts | Where-Object state -eq 'Not observed')
        $Esc4Disposition = if($Esc4Blocked.Count -gt 0){'Blocked'}elseif($Esc4Missing.Count -gt 0){'Incomplete evidence'}else{'Prerequisites satisfied'}
        $CandidateRecords.Add([pscustomobject][ordered]@{
            candidateId=('ESC4|{0}|{1}|{2}' -f $Ca,$Template.Name,$Principal);technique='ESC4';certificationAuthority=$Ca
            template=[string]$Template.Name;principal=$Principal;accessRowCount=$CandidateAccessRows.Count;disposition=$Esc4Disposition
            requiredCount=$Esc4Required.Count;satisfiedRequiredCount=@($Esc4RequiredFacts|Where-Object state -eq 'Confirmed').Count
            missingOrInconclusive=@($Esc4Missing|Select-Object id,state,rationale);notObserved=@($Esc4Blocked|Select-Object id,state,rationale)
            facts=@($Esc4Facts);safeFollowUp='Validate effective template control and whether it can alter a published template into a usable authentication path.'
            limitations=@('This is a candidate-specific prerequisite record, not a vulnerability or exploitability declaration.')
        })
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$JsonPath = Join-Path $OutputDirectory 'adcs-candidate-specific-facts.json'
$CsvPath = Join-Path $OutputDirectory 'adcs-candidate-specific-summary.csv'
$EventPath = Join-Path $OutputDirectory 'adcs-candidate-specific-events.json'

$CandidateRecords.ToArray() | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $JsonPath -Encoding UTF8
$CandidateRecords.ToArray() |
    Select-Object candidateId,technique,certificationAuthority,template,principal,accessRowCount,disposition,requiredCount,satisfiedRequiredCount,
        @{Name='MissingFacts';Expression={@($_.missingOrInconclusive|ForEach-Object{$_.id}) -join ';'}},
        @{Name='NotObservedFacts';Expression={@($_.notObserved|ForEach-Object{$_.id}) -join ';'}},safeFollowUp |
    Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8

$Events.Add((Write-MSADPTCandidateEvent -Kind Success -Code 'CandidateFactBuilderCompleted' -Message ("Generated {0} candidate-specific record(s)." -f $CandidateRecords.Count) -Target 'Candidate fact builder' -Data @{OutputPath=$JsonPath}))
$Events.ToArray() | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $EventPath -Encoding UTF8

[pscustomobject][ordered]@{
    schemaVersion='1.0';builder='ADCSCandidateSpecificFacts';builderVersion=$BuilderVersion;status='Completed';executionClass='offline_analysis'
    templateCount=$PublishedTemplates.Count;candidateRecordCount=$CandidateRecords.Count
    esc1RecordCount=@($CandidateRecords|Where-Object technique -eq 'ESC1').Count
    esc4RecordCount=@($CandidateRecords|Where-Object technique -eq 'ESC4').Count
    prerequisitesSatisfiedCount=@($CandidateRecords|Where-Object disposition -eq 'Prerequisites satisfied').Count
    blockedCount=@($CandidateRecords|Where-Object disposition -eq 'Blocked').Count
    incompleteEvidenceCount=@($CandidateRecords|Where-Object disposition -eq 'Incomplete evidence').Count
    runtimeEvidenceProvided=($RuntimeObservations.Count -gt 0);evidence=@($JsonPath,$CsvPath,$EventPath)
    limitations=@('Version 0.2.0 creates candidate-specific ESC1 and ESC4 records first. Other techniques remain in the aggregate correlator until their per-object evidence contracts are implemented.','No vulnerability or exploitability declaration is produced.')
}
