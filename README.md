# MSADPT

MSADPT v1.9.0 is an evidence-driven Active Directory security assessment and penetration-testing platform for authorized environments. It combines deterministic collection, explicit network-operation planning, structured evidence, bounded behavioral validation, resumable execution, and consolidated HTML reporting.

MSADPT is designed as a reusable public tool. Environment-specific names, domains, addresses, identities, credentials, and assessment evidence must not be committed to the repository.

## Key principles

- Treat scanner results, fingerprints, prerequisite matches, and configuration observations as leads, not proof of exploitability.
- Display targets, ports, protocols, authentication methods, operations, and potential changes before live activity.
- Keep deterministic collectors and validators authoritative.
- Keep local AI reasoning optional and non-authoritative.
- Separate discovery, collection, candidate analysis, behavioral validation, impact reproduction, cleanup, and evidence serialization.
- Preserve incomplete evidence as `Inconclusive` rather than assuming absence.
- Reuse completed manifest-backed evidence during Resume runs.
- Produce one consolidated HTML report backed by structured local evidence.

## Installation

Clone the repository to a local folder that is not synchronized to cloud storage when unredacted evidence may be produced:

```powershell
git clone https://github.com/rolling-code/MSADPT.git
Set-Location '.\MSADPT'
```

Run the public-release preflight:

```powershell
.\Tests\Offline\Test-MSADPTPublicRelease.ps1 `
    -RepositoryRoot (Get-Location).Path
```

## Unified entry point

MSADPT assessments are started through `Invoke-MSADPT.ps1`.

Supported modes:

- `Plan`: displays planned activity without executing live modules.
- `Audit`: performs the selected assessment workflow.
- `Analyze`: analyzes existing evidence where supported.
- `Resume`: reuses completed manifest-backed evidence and continues incomplete work.

Supported profiles:

- `Quick`: bounded operational Active Directory assessment.
- `Full`: enables the currently integrated first-class assessment families.

## Quick profile

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

## Full profile

The `Full` profile enables the currently integrated first-class assessment families, including:

- Kerberos and SPN baseline collection
- Kerberos account cryptographic posture
- Optional KDC telemetry collection
- Domain-controller inventory
- Domain-controller patch-state and vulnerability-applicability analysis
- AD CS configuration collection and offline ESC1 through ESC16 prerequisite correlation
- AD-integrated DNS inventory and authorization analysis
- SMB reachability, signing, share enumeration, SYSVOL and NETLOGON classification, and bounded filename metadata analysis

Preview the Full profile:

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

Behavioral validators remain explicitly controlled through `-EnableBehavioralValidation`.

## Nmap-assisted SMB targeting

Domain controllers are always included in the Full-profile SMB assessment because SYSVOL, NETLOGON, SMB signing, and relay prerequisites are relevant to Active Directory security.

MSADPT does not automatically probe every Active Directory computer account and does not execute Nmap. Operators can extend SMB coverage by supplying locally generated Nmap XML containing hosts where TCP/445 was explicitly reported open.

Example using an approved target list:

```powershell
nmap -sT -n -Pn `
    -p 445 `
    --open `
    --reason `
    -iL '.\MSADPT-Targets.txt' `
    -oA '.\MSADPT-SMB-Discovery'
```

MSADPT consumes the XML file only:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Full `
    -SMBNmapXmlPath '.\MSADPT-SMB-Discovery.xml' `
    -EngagementDirectory '.\Engagements\MSADPT-Full-Assessment' `
    -EnableBehavioralValidation
```

If `-SMBNmapXmlPath` is omitted, MSADPT looks for `MSADPT-SMB-Discovery.xml` in the repository root. If no XML file is supplied or found, the assessment continues against discovered domain controllers and displays compatible Nmap guidance.

Only records meeting all these conditions are imported:

```text
Host state = up
Protocol   = tcp
Port       = 445
Port state = open
```

Filtered, closed, `open|filtered`, missing, and non-TCP results are not treated as confirmed-open SMB targets.

MSADPT parses the XML locally, records source provenance and SHA-256, merges imported targets with domain controllers, removes duplicates, displays the complete target set, and prevents the SMB collector from launching Nmap internally.

An open TCP/445 result proves point-in-time reachability. It does not prove that share enumeration will succeed. Zero returned shares does not prove that shares are absent. SMB signing being optional or disabled is a relay prerequisite, not proof of relay impact.

### SMB safety boundaries

The integrated SMB workflow performs bounded:

- TCP/445 reachability validation
- SMB signing posture collection
- Nonadministrative share enumeration
- SYSVOL and NETLOGON classification
- Bounded share-root listing
- Filename and metadata discovery

It does not perform write-access testing, credential capture, NTLM relay, password testing, remote execution, script execution from shares, or automatic Nmap execution.

## AD-integrated DNS security

MSADPT can discover AD-integrated DNS zones, evaluate applicable authorization evidence, and optionally perform one bounded create-read-resolve-delete-verify validation.

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -IncludeADDns `
    -EnableBehavioralValidation `
    -EngagementDirectory '.\Engagements\MSADPT-DNS-Assessment'
```

A successful controlled DNS write confirms write capability for the tested identity and zone. It does not by itself prove relay, credential capture, privilege escalation, or domain compromise. MSADPT deletes only its generated object, verifies its absence, and records cleanup separately.

## Kerberos cryptographic posture

MSADPT separates static account encryption capability from observed Kerberos behavior. Static RC4 capability does not prove observed RC4 ticket or session-key use.

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -IncludeKerberosCrypto `
    -IncludeKdcTelemetry `
    -EngagementDirectory '.\Engagements\MSADPT-Kerberos-Assessment'
```

## AD CS assessment

The integrated AD CS workflow performs read-only directory configuration collection and offline ESC1 through ESC16 prerequisite correlation. It does not automatically enroll certificates, authenticate with certificates, access or export private keys, modify templates or certification authorities, or relay credentials.

An incomplete prerequisite chain remains `Incomplete evidence` or `Inconclusive` rather than being promoted to a confirmed vulnerability.

## Domain-controller patch intelligence

The optional patch-state workflow uses read-only methods to determine full Windows build information and correlate available evidence with the local vulnerability-applicability catalog. Method failures do not terminate the complete assessment. A target without a complete four-part build remains `PatchStateUnknown`.

## Resume

Resume mode reuses completed manifest-backed evidence where supported:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Resume `
    -Profile Full `
    -EngagementDirectory '.\Engagements\MSADPT-Full-Assessment'
```

Use `-ForceRerun` only when completed evidence must be replaced intentionally.

## Resume result normalization

MSADPT normalizes live SMB terminal results and persisted SMB summaries into one reporting contract. Resume therefore preserves target, reachability, signing, share, metadata, lead, operational-error, and disposition values without repeating completed SMB collection. Reports distinguish the maximum permitted remote change from the actual remote change performed during the current execution.

## Reporting

The consolidated reports are written to:

```text
<EngagementDirectory>\reports\MSADPT-Quick-Audit.html
<EngagementDirectory>\reports\MSADPT-Full-Audit.html
```

Reports provide an at-a-glance posture summary and link to the local structured evidence used to support dispositions.

## Dispositions

MSADPT uses evidence-driven dispositions including:

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

## Optional local Ollama integration

Ollama is optional. Deterministic collectors and validators remain authoritative. A local model may explain deterministic evidence, prioritize already-established candidates, and suggest bounded follow-up validation. It must not invent findings, claim that unexecuted commands ran, override deterministic dispositions, or receive credentials, raw secrets, private keys, or unredacted sensitive evidence.

## Repository layout

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

Runtime engagement evidence, transcripts, generated output, local state, backups, Nmap discovery results, installer artifacts, and organization-specific material are intentionally excluded from the public repository.

## Requirements

Requirements vary by selected module and can include:

- Windows PowerShell 5.1 or PowerShell 7
- ActiveDirectory PowerShell module
- Authorized network access to explicitly disclosed targets
- Appropriate credentials for the selected environment
- Operator-generated Nmap XML for expanded SMB targeting
- Optional local Ollama installation

## Validation

Run the primary offline orchestration regression test:

```powershell
.\Tests\Offline\Test-MSADPTQuickAudit.ps1
```

Run the complete public-release preflight:

```powershell
.\Tests\Offline\Test-MSADPTPublicRelease.ps1 `
    -RepositoryRoot (Get-Location).Path
```

A release is ready for publication only when the public-release gate reports `Status: Passed`, `FailureCount: 0`, and `ReadyForGit: True`.

## Public-release principles

Public contributions should include parser validation, offline tests, sanitized fixtures, explicit safety boundaries, structured evidence, and cleanup verification for state-changing validators. Public files must not contain organization-specific names, domains, addresses, accounts, or assessment results.

## Project status

MSADPT is under active development. Modules in the repository have different maturity and orchestration states. Review the module registry, execution plan, coverage ledger, displayed safety boundaries, and final evidence before drawing conclusions.

## License and contributions

Use MSADPT only in environments where testing is authorized. Contributions should preserve the evidence-first model, public-release hygiene, explicit operational disclosure, bounded validation, structured evidence, and cleanup guarantees.
