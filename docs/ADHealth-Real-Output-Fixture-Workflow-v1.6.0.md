# AD Health Real-Output Fixture Workflow

Version: 1.6.0

1. Complete the focused LAN collection and pass the v1.4.0 collection gate.
2. Work from a copy of the collection offline.
3. Build a ReplacementMap containing every real domain, host, site, username, IP address, SID, path fragment, and organization identifier observed during review.
4. Run New-MSADPTADHealthSanitizedFixture-v1.6.0.ps1. The command copies only declared AD Health outputs and never edits source evidence.
5. Inspect every sanitized file and Fixture-Replacement-Map-REVIEW-AND-REMOVE.csv.
6. If identifiers remain, delete the candidate fixture and rebuild with an expanded map. Do not hand-edit evidence into a passing state.
7. Approve only after manual review. Approval removes the sensitive replacement map.
8. Run Invoke-MSADPTADHealthRealFixtureRegression-v1.6.0.ps1.
9. Add parser assertions only for behavior directly demonstrated by approved native evidence.

A sanitized fixture must not be committed until manual review confirms that no AIM-specific identifiers or sensitive operational data remain.
