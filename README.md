# MSADPT

MSADPT v1.11.0 is an evidence-driven Active Directory security assessment and authorized penetration-testing platform. It combines deterministic collection, explicit network-operation planning, structured evidence, bounded behavioral validation, resumable execution, effective-access analysis, and consolidated HTML reporting.

MSADPT is designed as a reusable public tool. Environment-specific names, domains, addresses, identities, credentials, transcripts, and assessment evidence must not be committed to the repository.

## Key principles

- Treat scanner results, fingerprints, prerequisite matches, and configuration observations as leads, not proof of exploitability.
- Display targets, ports, protocols, authentication methods, operations, and potential changes before live activity.
- Keep deterministic collectors and validators authoritative.
- Separate discovery, collection, candidate analysis, behavioral validation, impact reproduction, cleanup, and evidence serialization.
- Preserve incomplete evidence as `Inconclusive` rather than assuming absence.
- Reuse completed manifest-backed evidence during Resume runs.
- Do not automatically execute modules that are not marked as integrated.
- Produce one consolidated HTML report backed by structured local JSON and CSV evidence.
- Preserve read-only and offline operation by default wherever practical.

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

- `Plan`: Displays planned activity without executing live modules.
- `Audit`: Performs the selected assessment workflow.
- `Analyze`: Processes existing evidence where supported without initiating new live collection.
- `Resume`: Reuses completed manifest-backed evidence and continues incomplete work.

Supported profiles:

- `Quick`: Bounded operational Active Directory assessment.
- `Full`: Enables every currently integrated first-class read-only assessment family.

Important optional switches include:

- `-Server`
- `-Credential`
- `-IncludePatchState`
- `-IncludeKerberosCrypto`
- `-IncludeKdcTelemetry`
- `-IncludeADCS`
- `-IncludeADDns`
- `-IncludeSMB`
- `-IncludeDirectoryControl`
- `-SMBNmapXmlPath`
- `-EnableBehavioralValidation`
- `-ForceRerun`

## Plan mode and operational disclosure

Plan mode performs repository-local planning and does not execute live assessment modules. Before an Audit, MSADPT displays the planned targets, protocol families, authentication context, expected local output, and maximum permitted remote changes.

Preview a scoped assessment:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Plan `
    -Profile Quick `
    -Server 'dc01.example.com' `
    -IncludeKerberosCrypto `
    -IncludeADCS `
    -IncludeADDns `
    -IncludeDirectoryControl
```

Plan output is prospective disclosure. A displayed target or protocol does not mean that a connection was attempted. The returned `LiveModulesExecuted` value identifies whether operational modules ran.

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

Select optional Quick-profile capabilities explicitly:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -Server 'dc01.example.com' `
    -IncludeKerberosCrypto `
    -IncludeKdcTelemetry `
    -IncludeADCS `
    -IncludeADDns `
    -IncludeDirectoryControl `
    -EngagementDirectory '.\Engagements\MSADPT-Quick-Assessment'
```

## Full profile

The Full profile enables the currently integrated first-class assessment families, including:

- Kerberos and SPN baseline collection
- Kerberos account cryptographic posture
- Optional KDC telemetry collection
- Domain-controller inventory
- Domain-controller patch-state and vulnerability-applicability analysis
- AD CS configuration collection and offline ESC1 through ESC16 prerequisite correlation
- AD-integrated DNS inventory and authorization analysis
- SMB reachability, signing, share enumeration, SYSVOL and NETLOGON classification, and bounded filename metadata analysis
- Directory Control collection, candidate reduction, token evidence, schema-class mapping, effective-access evaluation, and HTML evidence reporting

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

## Directory Control and effective access

The integrated Directory Control workflow evaluates high-impact Active Directory objects and security descriptors using SID-first, identity-neutral evidence.

The workflow includes:

- Targeted directory-object and security-descriptor collection
- Trustee and SID normalization
- Identity-neutral candidate reduction
- Current-token SID and group-context evidence
- Schema-class GUID mapping
- Object-class and inherited-object applicability checks
- Explicit and inherited Allow and Deny correlation
- Per-ACE applicability and decision traces
- Token-wide effective-access evaluation
- Manifest-backed selective reprocessing during Resume
- Dedicated effective-access HTML evidence reporting
- Pipeline orchestration with structured stage state

The effective-access evaluator distinguishes configuration evidence from demonstrated access. It preserves unresolved trustees, unsupported applicability conditions, missing evidence, and incomplete processing as explicit diagnostic states rather than silently treating them as absence.

The effective-access pipeline is available through the unified entry point:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -Server 'dc01.example.com' `
    -IncludeDirectoryControl `
    -EngagementDirectory '.\Engagements\MSADPT-Directory-Control'
```

The workflow is read-only. It does not change directory ACLs, group membership, object ownership, schema data, or account configuration.

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
    -EngagementDirectory '.\Engagements\MSADPT-Full-Assessment'
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

An incomplete prerequisite chain remains `IncompleteEvidence` or `Inconclusive` rather than being promoted to a confirmed vulnerability.

## PKCS#12 and PFX analysis

MSADPT supports bounded, generic PKCS#12/PFX metadata analysis for authorized evidence sets.

Safety boundaries include:

- In-memory processing where practical
- SYSVOL and NETLOGON deduplication
- Null or empty-password import attempts only
- Ephemeral handling of imported content
- Certificate metadata collection without private-key export
- No certificate-based authentication
- No persistence of PFX content

The presence of a PFX file is a lead. A successful bounded import confirms only the tested import condition and does not by itself prove privilege escalation or domain compromise.

## Domain-controller patch intelligence

The optional patch-state workflow uses read-only methods to determine full Windows build information and correlate available evidence with the local vulnerability-applicability catalog.

The workflow can use Remote Registry over SMB/RPC with CIM over WSMan as a fallback when selected. MSADPT displays the target systems, ports, protocols, and methods before execution. Method failures do not terminate the complete assessment. A target without a complete four-part build remains `PatchStateUnknown`.

## Resume

Resume mode reuses completed manifest-backed evidence where supported:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Resume `
    -Profile Full `
    -EngagementDirectory '.\Engagements\MSADPT-Full-Assessment'
```

Use `-ForceRerun` only when completed evidence must be replaced intentionally.

Directory Control and effective-access stages support manifest-backed selective reprocessing so that completed collectors can be reused while incomplete downstream analysis is rerun.

## Analyze mode

Analyze mode processes existing evidence without initiating new live collection where supported:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Analyze `
    -Profile Full `
    -EngagementDirectory '.\Engagements\MSADPT-Full-Assessment'
```

Analyze mode requires the necessary manifest-backed evidence. Missing required evidence remains explicit and does not silently trigger live collection.

## Result normalization

MSADPT normalizes live terminal results and persisted summaries into stable reporting contracts. Resume and Analyze therefore preserve target, reachability, configuration, evidence, operational-error, and disposition values without unnecessarily repeating completed collection.

Reports distinguish the maximum permitted remote change from the actual remote change performed during the current execution.

## Reporting

Consolidated reports are written to:

```text
<EngagementDirectory>\reports\MSADPT-Quick-Audit.html
<EngagementDirectory>\reports\MSADPT-Full-Audit.html
```

Dedicated module reports, including Directory Control effective-access evidence, may also be generated inside the engagement directory.

Reports provide an at-a-glance posture summary and link to the local JSON and CSV evidence used to support dispositions. Every integrated, validated capability should be represented in the final consolidated HTML report.

## Dispositions

MSADPT uses evidence-driven dispositions including:

- `Confirmed`
- `Likely` or `Probable`
- `CandidateDetected`
- `BehaviorallyValidated`
- `Collected`
- `FocusedReviewRequired`
- `IncompleteEvidence`
- `Inconclusive`
- `NotDetected`
- `NotApplicable`
- `NotAvailable`
- `Blocked`
- `Failed`

`NotDetected` does not mean `ConfirmedAbsent`.

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
- Local write access to the selected engagement directory

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

Additional offline validation covers:

- Orchestrator syntax and integration markers
- Registry and attack-surface catalog integrity
- Registry-path resolution
- Plan-mode safety
- Directory Control integration contracts
- Effective-access synthetic scenarios
- Per-ACE applicability
- Token-evidence handling
- Schema-class mapping
- Resume and selective reprocessing
- HTML evidence generation

A release is ready for publication only when the applicable public-release and regression gates pass without unresolved failures.

## Public-release principles

Public contributions should include parser validation, offline tests, sanitized fixtures, explicit safety boundaries, structured evidence, and cleanup verification for state-changing validators.

Public files must not contain organization-specific names, domains, addresses, accounts, credentials, secrets, or assessment results.

## Project status

MSADPT is under active development. Modules in the repository have different maturity and orchestration states. The module registry is the source of truth for module metadata, integration state, entry points, supported profiles, safety classification, and execution order.

Review the module registry, execution plan, attack-surface coverage catalog, displayed safety boundaries, stage manifests, and final evidence before drawing conclusions.

## License and contributions

Use MSADPT only in environments where testing is authorized. Contributions should preserve the evidence-first model, public-release hygiene, explicit operational disclosure, bounded validation, structured evidence, resumable execution, and cleanup guarantees.
