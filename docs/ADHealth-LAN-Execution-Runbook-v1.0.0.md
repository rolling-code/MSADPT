# MSADPT AD Health LAN Execution Runbook

Version: 1.0.0
Collector: Invoke-MSADPTADHealthCollection-v1.3.0.ps1

## Purpose
Perform one focused, read-only native AD Health collection during an authorized LAN session, then validate the resulting evidence before integration claims are made.

## Safety boundary
- Read-only diagnostics and remote event-log reads.
- No directory, DNS, policy, service, registry, or configuration changes.
- No exploitation.
- No Git operations.
- The plan must be reviewed before live execution.

## Source inventory
Use the prior domain-controller inventory when still current:

Engagements\AIM-LAN-20261006-110943\evidence\DomainControllerEnumeration\domain-controller-details.csv

If the inventory is stale or unavailable, generate a current authorized inventory before collection.

## Step 1: Plan only
```powershell
Set-Location 'C:\Users\mcontestabile\Downloads\MSADPT'
$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$OutputRoot = ".\Engagements\AIM-ADHealth-$Timestamp\evidence\ADHealth"
$Inventory = '.\Engagements\AIM-LAN-20261006-110943\evidence\DomainControllerEnumeration\domain-controller-details.csv'

& '.\Modules\ADHealth\Invoke-MSADPTADHealthCollection-v1.3.0.ps1' `
    -DomainControllerInventoryPath $Inventory `
    -OutputRoot $OutputRoot `
    -CommandTimeoutSeconds 180 `
    -PlanOnly
```

Review ADHealth-Collection-Plan.csv and provide the listed targets, protocols, and ports to the SOC before live execution.

## Step 2: Live read-only collection
Reuse the same `$OutputRoot` and `$Inventory` values from Step 1:

```powershell
& '.\Modules\ADHealth\Invoke-MSADPTADHealthCollection-v1.3.0.ps1' `
    -DomainControllerInventoryPath $Inventory `
    -OutputRoot $OutputRoot `
    -CommandTimeoutSeconds 180
```

## Step 3: Offline validation gate
```powershell
& '.\Tests\Offline\Test-MSADPTADHealthCollectionEvidence-v1.4.0.ps1' `
    -CollectionRoot $OutputRoot
```

## Required gate outcomes
- Collection summary and manifest parse successfully.
- Expected-target inventory is present and nonempty.
- Every expected target has a DCDiag file.
- Every expected target has Repadmin ShowRepl, Repadmin Queue, Nltest Query, Nltest DSGetSite, and W32tm Status evidence.
- Domain-wide Repadmin ReplSummary is present.
- Every manifest output that exists matches its recorded SHA-256.
- Empty outputs, timeouts, unavailable tools, nonzero exit codes, partial event-log access, and missing targets remain visible.
- Offline assessment output and HTML report are present.

## Interpretation boundary
A passing gate proves collection completeness and evidence integrity for the declared contract. It does not by itself prove that Active Directory is healthy. Health conclusions must come from parsed evidence and must remain classified as Confirmed, Likely or probable, Inconclusive, Not detected, or Not applicable.
