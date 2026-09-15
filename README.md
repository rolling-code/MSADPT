# MSADPT

MSADPT is an evidence-driven Active Directory security assessment and penetration-testing platform for authorized environments. It combines deterministic collection, explicit network-operation planning, structured evidence, bounded behavioral validation, resumable execution, and consolidated HTML reporting.

MSADPT is designed as a reusable public tool. Environment-specific names, domains, addresses, identities, credentials, and assessment evidence must not be committed to the repository.

## Key Principles

- Treat scanner findings, fingerprints, prerequisite matches, and configuration observations as leads, not proof of exploitability.
- Display targets, ports, protocols, authentication methods, operations, and potential changes before live activity.
- Keep deterministic collectors and validators authoritative.
- Keep local AI reasoning optional and non-authoritative.
- Separate discovery, collection, candidate analysis, behavioral validation, impact reproduction, cleanup, and evidence serialization.
- Preserve incomplete evidence as `Inconclusive` rather than assuming absence.
- Reuse completed, manifest-backed evidence during Resume runs.
- Produce one consolidated HTML report backed by structured local evidence.

## Installation

Clone the repository to a local folder that is not synchronized to cloud storage when unredacted evidence may be produced:

```powershell
git clone https://github.com/rolling-code/MSADPT.git
Set-Location .\MSADPT
```

Run the public-release preflight:

```powershell
.\Tests\Offline\Test-MSADPTPublicRelease.ps1 `
    -RepositoryRoot (Get-Location).Path
```

## Unified Entry Point

MSADPT assessments are started through:

```text
Invoke-MSADPT.ps1
```

Supported modes:

- `Plan`: displays planned activity without executing live modules.
- `Audit`: performs the selected assessment workflow.
- `Analyze`: analyzes existing evidence where supported.
- `Resume`: reuses completed manifest-backed evidence and continues incomplete work.

Supported profiles:

- `Quick`: bounded operational Active Directory assessment.
- `Full`: automatically enables the currently integrated read-only assessment families and optional evidence-backed workflows.

## Quick Profile

Preview the Quick profile:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Plan `
    -Profile Quick
```

Run the Quick profile:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -EngagementDirectory '.\Engagements\MSADPT-Quick-Assessment'
```

Optional Quick-profile capabilities can be selected explicitly:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -IncludePatchState `
    -IncludeKerberosCrypto `
    -IncludeKdcTelemetry `
    -IncludeADCS `
    -IncludeADDns `
    -EngagementDirectory '.\Engagements\MSADPT-Quick-Assessment'
```

## Full Profile

The `Full` profile automatically enables the currently integrated assessment families, including:

- Kerberos and SPN baseline collection
- Kerberos account cryptographic posture
- Optional KDC telemetry collection
- Domain-controller inventory
- Domain-controller patch-state and vulnerability-applicability analysis
- AD CS configuration collection and offline ESC1 through ESC16 prerequisite correlation
- AD-integrated DNS inventory and authorization analysis
- SMB reachability, signing, share enumeration, SYSVOL and NETLOGON classification, and bounded filename metadata analysis

Preview the Full profile without live module execution:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Plan `
    -Profile Full
```

Run the Full profile:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Full `
    -EngagementDirectory '.\Engagements\MSADPT-Full-Assessment'
```

Behavioral validators remain explicitly controlled through:

```text
-EnableBehavioralValidation
```

The Full profile does not claim coverage for an assessment family unless an authoritative first-class orchestration contract is available. Unsupported or incomplete families remain clearly identified in the coverage ledger and final report.

## Nmap-Assisted SMB Targeting

Domain controllers are always included in the Full-profile SMB assessment because SYSVOL, NETLOGON, SMB signing, and relay prerequisites are relevant to Active Directory security.

MSADPT does not automatically probe every Active Directory computer account. Operators can extend SMB coverage by supplying locally generated Nmap XML containing hosts where TCP/445 was explicitly reported open.

MSADPT does not execute Nmap. Generate the discovery evidence separately in an authorized scope.

Example using an approved target list:

```powershell
nmap -sT -n -Pn `
    -p 445 `
    --open `
    --reason `
    -iL '.\MSADPT-Targets.txt' `
    -oA '.\MSADPT-SMB-Discovery'
```

This creates:

```text
MSADPT-SMB-Discovery.xml
MSADPT-SMB-Discovery.nmap
MSADPT-SMB-Discovery.gnmap
```

MSADPT consumes the XML file only.

Run the Full assessment with an explicit Nmap XML path:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Full `
    -SMBNmapXmlPath '.\MSADPT-SMB-Discovery.xml' `
    -EngagementDirectory '.\Engagements\MSADPT-Full-Assessment' `
    -EnableBehavioralValidation
```

If `-SMBNmapXmlPath` is omitted, MSADPT looks for:

```text
MSADPT-SMB-Discovery.xml
```

in the repository root.

If no XML file is supplied or found, MSADPT does not fail. It continues with discovered domain controllers and displays guidance for generating compatible Nmap evidence.

Only Nmap host records meeting all these conditions are imported:

```text
Host state = up
Protocol   = tcp
Port       = 445
Port state = open
```

Filtered, closed, `open|filtered`, missing, and non-TCP results are not treated as confirmed-open SMB targets.

MSADPT:

1. Parses the XML locally using schema-safe XPath queries.
2. Records the source path and SHA-256 hash.
3. Records available Nmap arguments and scan timestamps.
4. Selects only confirmed-open TCP/445 targets.
5. Merges imported targets with discovered domain controllers.
6. Removes duplicate targets.
7. Displays the complete SMB target set before connecting.
8. Writes target-provenance and import evidence into the engagement directory.
9. Prevents the SMB collector from launching Nmap internally.

An open TCP/445 result proves point-in-time network reachability. It does not prove that share enumeration will succeed. Zero returned shares does not prove that shares are absent.

SMB signing being optional or disabled is a relay prerequisite, not proof of relay impact or exploitability.

### SMB Safety Boundaries

The integrated SMB workflow performs bounded:

- TCP/445 reachability validation
- SMB signing posture collection
- Nonadministrative share enumeration
- SYSVOL and NETLOGON classification
- Bounded share-root listing
- Filename and metadata discovery

The first-class workflow does not perform:

- Write-access testing
- Credential capture
- NTLM relay
- Password testing
- Remote execution
- Script execution from shares
- Automatic Nmap execution

### SMB Evidence Layout

```text
<EngagementDirectory>\
└── evidence\
    └── SMBFullAssessment\
        ├── NmapImport\
        │   ├── nmap-smb-import-summary.json
        │   ├── nmap-smb-target-evidence.json
        │   └── nmap-smb-open-targets.txt
        ├── smb-merged-targets.txt
        └── Collector\
            ├── smb-share-pivot-summary.json
            ├── smb-share-inventory.json
            ├── smb-signing-evidence.json
            ├── evidence-manifest.json
            └── MSADPT-SMB-Share-Pivot-Assessment.html
```

## AD-Integrated DNS Security

MSADPT can discover AD-integrated DNS zones, evaluate applicable authorization evidence, and optionally perform one bounded create-read-resolve-delete-verify validation.

Read-only discovery and authorization analysis:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -IncludeADDns `
    -EngagementDirectory '.\Engagements\MSADPT-DNS-Assessment'
```

Behavioral validation with automatic cleanup:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -IncludeADDns `
    -EnableBehavioralValidation `
    -EngagementDirectory '.\Engagements\MSADPT-DNS-Assessment'
```

Before execution, the validator announces:

- Selected domain controller
- TCP port
- LDAP or LDAPS protocol
- Authentication method
- Temporary object operation
- Read-back and resolution validation
- Cleanup and absence verification

A successful controlled DNS write confirms write capability for the tested identity and zone. It does not by itself prove relay, credential capture, privilege escalation, or domain compromise.

MSADPT deletes only its generated test object, verifies its absence, records cleanup separately, and includes the evidence in the consolidated report.

## Kerberos Cryptographic Posture

MSADPT separates static account encryption capability from observed Kerberos behavior.

The workflow can:

- Inventory service-relevant user, computer, and managed service accounts
- Classify explicit AES, RC4, DES, and unconfigured account posture
- Attempt coverage-aware KDC event telemetry
- Preserve inaccessible or incomplete telemetry as `Inconclusive`
- Correlate static account configuration with available behavioral evidence
- Prioritize focused account reviews
- Group broad computer and managed-service-account observations
- Reuse completed evidence during Resume

Static RC4 capability does not prove observed RC4 ticket or session-key use.

Example:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -IncludeKerberosCrypto `
    -IncludeKdcTelemetry `
    -EngagementDirectory '.\Engagements\MSADPT-Kerberos-Assessment'
```

## AD CS Assessment

The integrated AD CS workflow performs read-only directory configuration collection and offline ESC1 through ESC16 prerequisite correlation.

It can collect and analyze:

- Enterprise certification authorities
- Published certificate templates
- Template attributes
- Template access-control evidence
- Neutral prerequisite facts
- Technique-specific candidate dispositions

The automatic workflow does not perform:

- Certificate enrollment
- Certificate authentication
- Private-key access or export
- Template modification
- Certification-authority modification
- Credential relay

An incomplete prerequisite chain remains `Incomplete evidence` or `Inconclusive` rather than being promoted to a confirmed vulnerability.

## Domain-Controller Patch Intelligence

The optional patch-state workflow attempts read-only methods for determining full Windows build information and correlates available evidence with the local vulnerability-applicability catalog.

Method failures are recorded without terminating the overall assessment. A target without a complete four-part build remains:

```text
PatchStateUnknown
```

Patch-state evidence is kept separate from configuration prerequisites and reproduced security impact.

## Resume

Resume mode reuses completed manifest-backed evidence where supported:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Resume `
    -Profile Full `
    -EngagementDirectory '.\Engagements\MSADPT-Full-Assessment'
```

Use `-ForceRerun` only when completed evidence must be replaced intentionally.

## Reporting

The Full-profile consolidated report is written to:

```text
<EngagementDirectory>\reports\MSADPT-Full-Audit.html
```

The Quick-profile consolidated report is written to:

```text
<EngagementDirectory>\reports\MSADPT-Quick-Audit.html
```

Reports link to the local structured evidence used to support their dispositions.

## Dispositions

MSADPT uses evidence-driven dispositions such as:

- `Confirmed`
- `Likely` or `Probable`
- `CandidateDetected`
- `BehaviorallyValidated`
- `Collected`
- `FocusedReviewRequired`
- `Inconclusive`
- `NotDetected`
- `NotApplicable`
- `NotAvailable`
- `Blocked`
- `Failed`

`NotDetected` does not mean `ConfirmedAbsent`.

## Evidence and Safety Model

Modules separate applicable stages where practical:

- Planning
- Discovery
- Network operation
- Acquisition
- Parsing
- Semantic analysis
- Candidate correlation
- Behavioral validation
- Impact reproduction
- Cleanup
- Evidence serialization
- Manifest verification

A compensating control proves only the behavior it directly blocks or observes.

## Optional Local Ollama Integration

Ollama is optional. Deterministic collectors and validators remain authoritative.

A local model may:

- Explain deterministic evidence
- Prioritize already-established candidates
- Suggest bounded follow-up validation

A local model must not:

- Invent findings
- Claim that an unexecuted command ran
- Override deterministic dispositions
- Receive credentials, raw secrets, private keys, or unredacted sensitive evidence

If Ollama is unavailable, MSADPT continues with deterministic collection, analysis, validation, and reporting.

## Repository Layout

```text
MSADPT/
├── Invoke-MSADPT.ps1
├── Analysis/
├── Catalogs/
├── Common/
├── Controller/
├── Integrations/
├── Modules/
├── Policies/
├── Promptbooks/
├── Schemas/
├── Tests/
└── docs/
```

## Runtime Data

Runtime engagement evidence, transcripts, generated outputs, local session state, backups, installation artifacts, Nmap discovery results, migration files, and organization-specific material are intentionally excluded from the public repository.

Common ignored local paths and files include:

```text
Engagements/
Sessions/
Backups/
evidence/
state/
MSADPT-SMB-Discovery.xml
MSADPT-SMB-Discovery.nmap
MSADPT-SMB-Discovery.gnmap
```

## Requirements

Requirements vary by selected module and can include:

- Windows PowerShell 5.1 or PowerShell 7
- ActiveDirectory PowerShell module
- Authorized network access to explicitly disclosed assessment targets
- Appropriate credentials for the selected environment
- Operator-generated Nmap XML for expanded SMB targeting
- Optional local Ollama installation

Nmap is not launched automatically by the integrated Full-profile SMB workflow.

## Public-Release Validation

Before publishing changes, run:

```powershell
.\Tests\Offline\Test-MSADPTPublicRelease.ps1 `
    -RepositoryRoot (Get-Location).Path
```

Public contributions should include:

- Parser validation
- Offline tests
- Sanitized fixtures
- Explicit safety boundaries
- Structured evidence
- Cleanup verification for state-changing validation
- No organization-specific names, domains, addresses, accounts, or assessment results

## Project Status

MSADPT is under active development. Modules in the repository have different maturity and orchestration states. Review the module registry, execution plan, coverage ledger, displayed safety boundaries, and final evidence before drawing conclusions.

## License and Contributions

Use MSADPT only in environments where testing is authorized.

Contributions should preserve the evidence-first model, public-release hygiene, explicit operational disclosure, bounded validation, structured evidence, and cleanup guarantees.
