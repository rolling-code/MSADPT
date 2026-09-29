[CmdletBinding()]
param([string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Runner = Join-Path $RepositoryRoot 'Modules\ObjectControl\Invoke-MSADPTDirectoryControlAssessment-v1.0.0.ps1'
if (-not (Test-Path -LiteralPath $Runner -PathType Leaf)) { throw "RunnerMissing: $Runner" }
$TemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('MSADPT-DC-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TemporaryRoot -Force | Out-Null
try {
    $Fixture = @(
        [pscustomobject]@{TargetObjectType='Group';TargetName='Tier0';TargetDistinguishedName='CN=Tier0,DC=example,DC=test';TargetObjectSid='S-1-5-21-1-5000';TargetAdminCount=1;Trustee='EXAMPLE\Operator';TrusteeSid='S-1-5-21-1-1100';TrusteeResolved=$true;TrusteeEnabled=$true;AccessControlType='Allow';ActiveDirectoryRights='GenericAll';ObjectTypeGuid=[guid]::Empty;IsInherited=$false;AceOrder=0}
        [pscustomobject]@{TargetObjectType='Computer';TargetName='Server1';TargetDistinguishedName='CN=Server1,DC=example,DC=test';TargetObjectSid='S-1-5-21-1-2000';TargetAdminCount=0;Trustee='EXAMPLE\Operator';TrusteeSid='S-1-5-21-1-1100';TrusteeResolved=$true;TrusteeEnabled=$true;AccessControlType='Allow';ActiveDirectoryRights='WriteProperty';ObjectTypeGuid='3f78c3e5-f79a-46bd-a0b8-9d18116ddc79';IsInherited=$false;AceOrder=1}
        [pscustomobject]@{TargetObjectType='Computer';TargetName='Server1';TargetDistinguishedName='CN=Server1,DC=example,DC=test';TargetObjectSid='S-1-5-21-1-2000';TargetAdminCount=0;Trustee='EXAMPLE\Operator';TrusteeSid='S-1-5-21-1-1100';TrusteeResolved=$true;TrusteeEnabled=$true;AccessControlType='Deny';ActiveDirectoryRights='WriteProperty';ObjectTypeGuid='3f78c3e5-f79a-46bd-a0b8-9d18116ddc79';IsInherited=$false;AceOrder=2}
        [pscustomobject]@{TargetObjectType='User';TargetName='Svc';TargetDistinguishedName='CN=Svc,DC=example,DC=test';TargetObjectSid='S-1-5-21-1-3000';TargetAdminCount=0;Trustee='S-1-5-21-1-9999';TrusteeSid='S-1-5-21-1-9999';TrusteeResolved=$false;TrusteeEnabled=$null;AccessControlType='Allow';ActiveDirectoryRights='WriteProperty';ObjectTypeGuid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';IsInherited=$true;AceOrder=3}
    )
    $FixturePath = Join-Path $TemporaryRoot 'fixture.json'
    $Fixture | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $FixturePath -Encoding UTF8
    $OutputDirectory = Join-Path $TemporaryRoot 'out'
    $Output = @(& $Runner -OutputDirectory $OutputDirectory -InputAcePath $FixturePath -StartingIdentity 'EXAMPLE\Operator' -NoColor)
    $Result = @($Output | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['PackageIdentity'] }) | Select-Object -Last 1
    if ($null -eq $Result) { throw 'TerminalResultMissing' }
    $Summary = Get-Content -LiteralPath (Join-Path $OutputDirectory 'directory-control-summary.json') -Raw | ConvertFrom-Json -ErrorAction Stop
    foreach ($ControlName in @('SidFirstNormalization','AllowAndDenyPreserved','IdentityNeutralCandidates','CurrentIdentityReachabilitySeparated')) {
        if (-not [bool]$Summary.Controls.$ControlName) { throw "ControlFailed: $ControlName" }
    }
    if ([int]$Summary.Counts.DenyAceRows -ne 1) { throw 'DenyPreservationFailed' }
    if ([int]$Summary.Counts.FocusedReview -lt 2) { throw 'FocusedReviewFailed' }
    if ([string]$Summary.Disposition -ne 'FocusedReviewRequired') { throw 'DispositionFailed' }
    [pscustomobject][ordered]@{Status='Passed';TestVersion='1.0.1';FixtureAceCount=$Fixture.Count;DenyPreserved=$true;SidFirst=$true;FocusedReviewCount=$Summary.Counts.FocusedReview;NetworkActivity='None';RemoteChanges='None'}
} finally {
    Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
