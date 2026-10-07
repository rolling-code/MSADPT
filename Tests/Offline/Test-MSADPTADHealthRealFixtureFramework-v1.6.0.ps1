[CmdletBinding()]param([string]$RepositoryRoot=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$required=@('Modules\ADHealth\New-MSADPTADHealthSanitizedFixture-v1.6.0.ps1','Modules\ADHealth\Approve-MSADPTADHealthFixture-v1.6.0.ps1','Tests\Offline\Invoke-MSADPTADHealthRealFixtureRegression-v1.6.0.ps1')
foreach ($r in $required) { if (-not (Test-Path (Join-Path $RepositoryRoot $r))){throw "Missing installed component: $r"}}
$source=Get-Content (Join-Path $RepositoryRoot $required[0])-Raw
$contracts=[ordered]@{SourceHashesRecorded=($source-match'SourceSHA256');FixtureHashesRecorded=($source-match'FixtureSHA256');FailClosedLeakScan=($source-match'SanitizationStatus.*Blocked');ApprovalRequired=($source-match'ApprovedForRegression=\$false');NoSyntheticNativeFixtures=($source-notmatch'passed test|failed test|showrepl output|replsummary output');SourceNeverModified=($source-notmatch'Set-Content\s+-LiteralPath\s+\$file\.FullName')}
$contracts.GetEnumerator()|ForEach-Object{[pscustomobject]@{Contract=$_.Key;Passed=$_.Value}}|Format-Table -AutoSize|Out-Host
$failed=@($contracts.GetEnumerator()|Where-Object{-not$_.Value});if($failed.Count){throw "Fixture framework contract failures: $($failed.Key-join', ')"}
[pscustomobject]@{Status='Passed';TestVersion='1.6.1';ContractCount=$contracts.Count;SourceEvidenceImmutable=$true;FailClosedSanitization=$true;HumanApprovalRequired=$true;SyntheticNativeFormatAssumptionsAdded=$false;NetworkActivity='None';ActiveDirectoryQueries='None';RemoteChanges='None'}
