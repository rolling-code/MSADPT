# MSADPT

MSADPT is an evidence-driven Active Directory security assessment and penetration-testing platform for authorized environments. It combines deterministic discovery, structured evidence collection, bounded behavioral validation, cleanup verification, resumable execution, and consolidated HTML reporting.

## Installation

Clone the repository to a local folder that is not synchronized to cloud storage when assessments may produce unredacted evidence:

```powershell
git clone https://github.com/rolling-code/MSADPT.git
Set-Location .\MSADPT
```

Run the public-release preflight before an assessment:

```powershell
.\Tests\Offline\Test-MSADPTPublicRelease.ps1
```

Preview the execution plan without running live modules:

```powershell
.\Invoke-MSADPT.ps1 -Mode Plan -Profile Quick
```

Start an assessment through the unified entry point:

```powershell
.\Invoke-MSADPT.ps1 -Mode Audit -Profile Quick
```

Review the displayed targets, ports, protocols, authentication method, planned changes, and cleanup actions before permitting live stages.

## Usage

MSADPT follows a deterministic, evidence-first workflow:

1. Discover the environment and available tools.
2. Display planned network operations before execution.
3. Collect structured evidence using deterministic modules.
4. Correlate candidates and validate pipeline integrity.
5. Run bounded behavioral validators only when explicitly selected and supported by prerequisites.
6. Record behavioral results, cleanup status, and evidence integrity separately.
7. Produce one consolidated HTML report with links to local JSON and CSV evidence.
8. Resume from completed evidence instead of repeating validated stages.

### Common examples

Run the default Quick Audit:

```powershell
.\Invoke-MSADPT.ps1 -Mode Audit -Profile Quick
```

Resume a prior engagement:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Resume `
    -Profile Quick `
    -EngagementDirectory .\Engagements\<engagement-name>
```

Run offline analysis against existing evidence:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Analyze `
    -EngagementDirectory .\Engagements\<engagement-name>
```

Force selected modules to run again rather than reuse completed evidence:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -EngagementDirectory .\Engagements\<engagement-name> `
    -ForceRerun
```

## Quick Audit

Quick Audit performs local preflight checks, announces planned network activity, collects a Kerberos and SPN baseline, inventories domain controllers, updates the coverage ledger, and writes a consolidated report to:

```text
<engagement-directory>\reports\MSADPT-Quick-Audit.html
```

By default, Quick Audit does not request Kerberos tickets, collect password material, authenticate to discovered services, execute remote commands, or modify Active Directory. Optional validators may perform explicitly selected, bounded changes with cleanup verification.

Validate the Quick Audit orchestration contract without contacting Active Directory:

```powershell
.\Tests\Offline\Test-MSADPTQuickAudit.ps1
```

## AD-Integrated DNS Validation

MSADPT can inventory AD-integrated DNS zones, analyze the current identity's effective write path, and identify broadly assigned DNS creation permissions.

When behavioral validation is enabled, MSADPT:

- Creates one uniquely named temporary A record.
- Reads the new `dnsNode` back through LDAP.
- Verifies the record data and attempts DNS resolution validation.
- Deletes only the generated record.
- Confirms that the generated object is absent after cleanup.
- Records authorization, validation, resolution, and cleanup evidence in the engagement directory.

MSADPT does not automatically select or overwrite an existing production record.

Run the controlled validator through Quick Audit:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -IncludeADDns `
    -EnableBehavioralValidation
```

Target a specific writable domain controller when required:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -Server 'dc01.example.com' `
    -IncludeADDns `
    -EnableBehavioralValidation
```

A successful DNS write confirms the tested record-creation capability. It does not by itself prove credential capture, NTLM relay, privilege escalation, or domain compromise.

## Kerberos Cryptographic Posture

The optional Kerberos cryptographic-posture workflow separates static encryption capability from observed Kerberos behavior.

It can:

- Inventory service-relevant user, computer, and managed service accounts.
- Classify explicit AES, RC4, DES, and unconfigured encryption posture.
- Attempt coverage-aware KDC event telemetry when selected.
- Preserve unavailable or incomplete telemetry as inconclusive.
- Correlate static account posture with available behavioral evidence.
- Prioritize focused account reviews without treating every RC4-capable account as a vulnerability.
- Group broad computer and managed service account observations to avoid report flooding.
- Reuse completed evidence during Resume runs.

Run Quick Audit with static Kerberos cryptographic-posture analysis:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -IncludeKerberosCrypto
```

Include available KDC telemetry collection:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -IncludeKerberosCrypto `
    -IncludeKdcTelemetry
```

Static capability does not prove that RC4 tickets or session keys are in use. Missing or inaccessible telemetry is reported as inconclusive rather than as confirmed absence.

## Domain-Controller Patch-State Collection

Quick Audit can optionally collect full Windows build evidence from discovered domain controllers and evaluate the local vulnerability catalog:

```powershell
.\Invoke-MSADPT.ps1 `
    -Mode Audit `
    -Profile Quick `
    -IncludePatchState
```

The collector announces each target and management method before execution. It uses read-only Remote Registry queries with optional CIM fallback. It does not start services, change registry values, install updates, restart systems, or reproduce CVE impact.

Management-protocol failures do not imply vulnerability. Targets without sufficient build evidence remain `PatchStateUnknown`. Patch applicability is reported separately from vulnerable prerequisites and reproduced impact.

## Current Capabilities

The repository includes reusable components for:

- Active Directory and domain-controller discovery
- AD-integrated DNS inventory, authorization analysis, controlled record creation, and cleanup verification
- AD CS collection and ESC1 through ESC16 prerequisite correlation
- AD CS runtime configuration and candidate planning
- Kerberos, SPN, AS-REP, delegation, and controlled TGS validation
- Kerberos cryptographic-posture analysis and optional KDC telemetry correlation
- LDAP signing, channel binding, SMB signing, and relay-prerequisite analysis
- MachineAccountQuota behavioral validation with cleanup verification
- Active Directory ACL collection, semantic correlation, integrity auditing, and transitive path analysis
- SMB reachability, signing, share enumeration, and resumable continuation
- SYSVOL and NETLOGON metadata discovery and replicated-path deduplication
- Bounded, redacted P1 and P2 content analysis without script execution
- In-memory PKCS#12/PFX inspection using null or empty-password imports only, ephemeral key storage, no private-key export, no authentication, and no PFX retention
- Domain-controller patch-state and vulnerability-applicability analysis
- Snapshot comparison, evidence manifests, structured operational errors, and offline regression tests
- Optional local Ollama integration as a non-authoritative reasoning layer

Modules have different maturity and integration levels. Review the module registry, execution plan, and displayed safety boundaries before enabling live functionality.

## Optional Local Ollama Integration

Ollama is optional. Deterministic collectors and validators remain authoritative. A local model may explain evidence, prioritize already-established candidates, and suggest bounded next steps, but it must not invent findings, claim that a command ran, or override deterministic dispositions.

Install Ollama from its official distribution, then configure a local model and endpoint through the applicable MSADPT policy or integration settings. Do not place credentials, raw secrets, private keys, or unredacted evidence in prompts.

Test the local integration with:

```powershell
.\Tests\Offline\Test-MSADPTOllamaIntegration.ps1
```

If Ollama is unavailable, MSADPT continues with deterministic collection, correlation, validation, and reporting.

## Evidence and Safety Model

MSADPT uses these dispositions:

- **Confirmed**
- **Likely or probable**
- **Inconclusive**
- **Not detected**
- **Not applicable**

Scanner matches, fingerprints, prerequisite values, static patterns, and configuration observations are leads. A security impact is confirmed only when the affected component and required conditions are present and the central behavior is reproduced with captured evidence.

Modules report the following stages separately where applicable:

- Planning
- Discovery
- Network operation
- Acquisition
- Parsing
- Semantic analysis
- Behavioral validation
- Impact reproduction
- Cleanup
- Evidence serialization
- Manifest verification

`Not detected` does not mean `confirmed absent`. A compensating control proves only the behavior it directly blocks or observes.

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
├── Schemas/
├── Tests/
└── docs/
```

Runtime engagement evidence, transcripts, generated test output, local session state, backups, installation artifacts, internal migration files, and organization-specific material are intentionally excluded from the public repository.

## Requirements

Requirements depend on the selected modules and may include:

- Windows PowerShell 5.1 or PowerShell 7
- ActiveDirectory PowerShell module for ADWS-based collection
- Network access to explicitly selected assessment targets
- Nmap for Nmap-backed protocol evidence
- Appropriate authorization and credentials for the selected environment
- Optional Ollama installation for local, non-authoritative reasoning

## Public-Release Principles

- Environment-neutral source code, fixtures, and examples
- No organization names, domains, hostnames, identities, network addresses, or assessment evidence
- No persistent private-key or credential material
- No automatic password guessing
- No state-changing validation without explicit activation, bounded scope, planned cleanup, and cleanup verification
- No automatic modification of existing production DNS records
- Resume completed evidence instead of repeating broad collection
- One consolidated report backed by local structured evidence

## Project Status

MSADPT is under active development. Modules present in the repository have different maturity levels. Run the public-release preflight and review the module registry before using live functionality.

## License and Contributions

Use MSADPT only in environments where testing is authorized. Contributions should include parser validation, offline tests, sanitized fixtures, explicit safety boundaries, structured evidence, and cleanup verification where state changes are possible.
