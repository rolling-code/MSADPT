# MSADPT

## Installation

MSADPT is an evidence-driven Active Directory security assessment and penetration-testing platform for authorized environments. Clone the repository to a local folder that is not synchronized to a cloud-storage service when unredacted evidence may be produced.

```powershell
git clone https://github.com/rolling-code/MSADPT.git
Set-Location .\MSADPT
```

Run the release preflight before an assessment:

```powershell
.\Tests\Offline\Test-MSADPTPublicRelease.ps1
```

Start or resume an assessment through the unified entry point:

```powershell
.\Invoke-MSADPT.ps1 -Mode Audit
```

```powershell
.\Invoke-MSADPT.ps1 -Mode Resume -EngagementDirectory .\Engagements\<engagement-name>
```

> The public release candidate is designed for authorized testing. Review the displayed target, port, protocol, authentication, change, and cleanup plan before permitting live stages.

## Usage

MSADPT follows a deterministic, evidence-first workflow:

1. Discover the environment and available tools.
2. Display planned network operations before execution.
3. Collect structured evidence using deterministic modules.
4. Correlate candidates and validate pipeline integrity.
5. Select bounded behavioral validators only when prerequisites justify them.
6. Record cleanup and evidence-manifest status separately.
7. Produce one consolidated HTML report with links to local evidence.
8. Resume from completed evidence instead of rerunning expensive stages.

### Common examples

Run the default authorized audit workflow:

```powershell
.\Invoke-MSADPT.ps1 -Mode Audit
```

Run offline analysis against existing evidence:

```powershell
.\Invoke-MSADPT.ps1 -Mode Analyze -EngagementDirectory .\Engagements\<engagement-name>
```

Preview the planned modules and network activity without executing live stages:

```powershell
.\Invoke-MSADPT.ps1 -Mode Plan
```

## Current capabilities

The project currently includes reusable components for:

- Active Directory and domain-controller discovery
- AD CS collection and ESC1 through ESC16 prerequisite correlation
- AD CS runtime configuration and candidate planning
- Kerberos, SPN, AS-REP, delegation, and controlled TGS validation
- LDAP signing, channel-binding, SMB signing, and relay-prerequisite analysis
- MachineAccountQuota behavioral validation with cleanup verification
- Active Directory ACL collection, semantic correlation, integrity auditing, and transitive path analysis
- SMB reachability, signing, share enumeration, and resumable continuation
- SYSVOL and NETLOGON metadata discovery and replicated-path deduplication
- Bounded, redacted P1 and P2 content analysis without script execution
- In-memory PKCS#12/PFX inspection with null and empty-password imports only, ephemeral key storage, no private-key export, no authentication, and no PFX retention
- Snapshot comparison, evidence manifests, structured operational errors, and offline regression tests
- Optional local Ollama integration as a non-authoritative reasoning layer

## Optional local Ollama integration

Ollama is optional. Deterministic collectors and validators remain authoritative. Ollama may explain evidence, prioritize already-established candidates, and suggest bounded next steps. Ollama must not invent findings, claim that a command ran, or override deterministic dispositions.

Install Ollama from its official distribution, then install a local coding or reasoning model supported by the operator's hardware. Configure the local endpoint and model through the MSADPT policy or integration settings. Do not place credentials, raw secrets, private keys, or unredacted evidence in prompts.

Example connectivity test:

```powershell
.\Tests\Offline\Test-MSADPTOllamaIntegration.ps1
```

If Ollama is unavailable, MSADPT continues with deterministic collection, correlation, and reporting.

## Evidence and safety model

MSADPT distinguishes among:

- Confirmed
- Likely or probable
- Inconclusive
- Not detected
- Not applicable

Scanner matches, fingerprints, prerequisite values, and static patterns are leads. A vulnerability is confirmed only when the affected component and conditions are present and the central security impact is reproduced with captured evidence.

Every module should report these stages separately where applicable:

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

Runtime engagement evidence, transcripts, generated test output, local session state, backups, internal migration files, and organization-specific material are intentionally excluded from the public repository.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7, depending on the selected module
- ActiveDirectory PowerShell module for ADWS-based collection stages
- Network access to explicitly selected assessment targets for live stages
- Nmap for modules that collect Nmap-backed protocol evidence
- Appropriate authorization and credentials for the selected environment
- Optional Ollama installation for local, non-authoritative reasoning

## Public-release principles

- Environment-neutral source code and examples
- No organization names, domains, hostnames, identities, addresses, or evidence
- No persistent private-key or credential material
- No automatic password guessing
- No exploit or write operation without an explicit bounded validator, rollback plan, and cleanup verification
- Resume completed work instead of repeating broad scans
- One consolidated report backed by local structured evidence

## Project status

MSADPT is under active development. Modules that are present in the repository have different maturity levels. Run the release preflight and review the module registry before using live functionality.

## License and contributions

Use MSADPT only in environments where testing is authorized. Contributions should include parser validation, offline tests, sanitized fixtures, explicit safety boundaries, and structured evidence outputs.
## Quick Audit

Run the default bounded read-only assessment from a domain-connected Windows system:

```powershell
.\Invoke-MSADPT.ps1 -Mode Plan -Profile Quick
.\Invoke-MSADPT.ps1 -Mode Audit -Profile Quick
```

Quick Audit performs local preflight, announces the Active Directory query plan, collects a Kerberos/SPN baseline, inventories domain controllers, updates the coverage ledger, and writes `reports\MSADPT-Quick-Audit.html` inside the engagement directory.

Quick Audit does not request Kerberos tickets, collect password material, authenticate to discovered services, execute remote commands, or modify Active Directory.

Resume without repeating completed manifest-backed collection:

```powershell
.\Invoke-MSADPT.ps1 -Mode Resume -Profile Quick -EngagementDirectory .\Engagements\<engagement-name>
```

The other published modules remain available as standalone or experimental components until their parameter, evidence, safety, and resume contracts are integrated and deterministically validated.
Validate the Quick Audit orchestration contract without contacting Active Directory:

```powershell
.\Tests\Offline\Test-MSADPTQuickAudit.ps1
```
### Domain-controller patch-state collection

After Quick Audit produces domain-controller evidence, collect full four-part Windows build evidence and evaluate the local AD vulnerability catalog:

```powershell
.\Modules\VulnerabilityIntelligence\Invoke-MSADPTDomainControllerPatchState-v0.1.0.ps1 `
    -DomainControllerEvidencePath .\Engagements\<name>\evidence\DomainControllerEnumeration\domain-controller-details.json `
    -OutputDirectory .\Engagements\<name>\evidence\DomainControllerPatchState
```

The collector announces every target and management method before execution. It performs read-only Remote Registry queries with optional CIM fallback. It does not start services, change registry values, install updates, restart systems, or reproduce CVE impact.
### Quick Audit with current AD vulnerability intelligence

Run the standard Quick Audit plus optional read-only domain-controller patch-state collection:

```powershell
.\Invoke-MSADPT.ps1 -Mode Plan -Profile Quick -IncludePatchState
.\Invoke-MSADPT.ps1 -Mode Audit -Profile Quick -IncludePatchState
```

Resume reuses manifest-backed Kerberos, domain-controller, and patch-state evidence:

```powershell
.\Invoke-MSADPT.ps1 -Mode Resume -Profile Quick -IncludePatchState -EngagementDirectory .\Engagements\<name>
```

Management-protocol failures do not imply vulnerability and do not invalidate the core Quick Audit. Targets without a full four-part build remain `PatchStateUnknown`. Patch applicability is reported separately from prerequisites and reproduced impact.
