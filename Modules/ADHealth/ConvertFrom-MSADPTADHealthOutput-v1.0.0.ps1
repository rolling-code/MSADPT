<# .SYNOPSIS Normalizes saved AD health command output. .NOTES Version: 1.0.1 #>
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('DCDiag','Repadmin','Nltest','W32tm','EventLog')][string]$Tool,[Parameter(Mandatory)][string]$InputPath,[string]$Target='Unknown',[int]$ExitCode=0,[switch]$TimedOut,[switch]$ToolUnavailable,[string]$ParserVersion='1.0.0')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$raw=if(Test-Path -LiteralPath $InputPath -PathType Leaf){Get-Content -LiteralPath $InputPath -Raw}else{throw "InputEvidenceMissing: $InputPath"}
$lower=$raw.ToLowerInvariant();$facts=New-Object 'System.Collections.Generic.List[string]';$limits=New-Object 'System.Collections.Generic.List[string]'
$execution='Completed';$collection='Complete';$health='Inconclusive'
if($ToolUnavailable){$execution='ToolUnavailable';$collection='Empty';$limits.Add('Required native tool was unavailable.')}
elseif($TimedOut){$execution='TimedOut';$collection='Partial';$limits.Add('Command timed out; output may be incomplete.')}
elseif([string]::IsNullOrWhiteSpace($raw)){$collection='Empty';$limits.Add('Command returned no output.')}
elseif($lower -match 'access is denied|error_access_denied|0x5'){$collection='AccessDenied';$limits.Add('Access was denied; health cannot be inferred from this collection failure.')}
elseif($lower -match 'usage:|syntax:|examples:|repadmin -'){ $execution='InvalidInvocation';$collection='Unrecognized';$limits.Add('Output resembles command help or usage, not health evidence.') }
elseif($lower -match 'could not be found|is not recognized as an internal|command not found'){$execution='ToolUnavailable';$collection='Empty';$limits.Add('Native tool was not found.')}
elseif($ExitCode -ne 0){$collection='Partial';$limits.Add("Command returned exit code $ExitCode; usable observations were preserved.")}

switch($Tool){
'DCDiag'{
  $passed=[regex]::Matches($raw,'(?im)^\s*\.+\s*(?<target>\S+)\s+passed test\s+(?<test>\S+)')
  $failed=[regex]::Matches($raw,'(?im)^\s*\.+\s*(?<target>\S+)\s+failed test\s+(?<test>\S+)')
  foreach($m in $passed){$facts.Add("DCDiagPassed:$($m.Groups['test'].Value)")};foreach($m in $failed){$facts.Add("DCDiagFailed:$($m.Groups['test'].Value)")}
  if($failed.Count -gt 0 -and $collection -eq 'Complete'){$health='ConfirmedUnhealthy'}elseif($passed.Count -gt 0 -and $collection -eq 'Complete'){$health='ConfirmedHealthy'}
  if($lower -match 'warning:'){$facts.Add('DCDiagWarningPresent')}
}
'Repadmin'{
  $failMatches=[regex]::Matches($raw,'(?im)(?:fails?|errors?)\s*[:=]?\s*(?<count>\d+)')
  $success=$lower -match '0\s*(?:fails?|errors?)|successful|last attempt.*successful'
  $failure=$lower -match 'last error|result\s+\d+|failed|operational error'
  if($success){$facts.Add('ReplicationSuccessObserved')};if($failure){$facts.Add('ReplicationErrorObserved')}
  if($failure -and $collection -eq 'Complete'){$health='ConfirmedUnhealthy'}elseif($success -and $collection -eq 'Complete'){$health='ConfirmedHealthy'}
}
'Nltest'{
  if($lower -match 'nerr_success|status\s*=\s*0x0|the command completed successfully'){$facts.Add('NetlogonSuccessObserved');if($collection -eq 'Complete'){$health='ConfirmedHealthy'}}
  if($lower -match 'no logon servers|trust relationship.*failed|status\s*=\s*[1-9]'){$facts.Add('NetlogonFailureObserved');if($collection -eq 'Complete'){$health='ConfirmedUnhealthy'}}
}
'W32tm'{
  if($lower -match 'source:|stratum:|last successful sync time:'){$facts.Add('TimeStatusObserved');if($collection -eq 'Complete'){$health='ConfirmedHealthy'}}
  if($lower -match 'unsynchronized|no time data|error:'){$facts.Add('TimeFailureObserved');if($collection -eq 'Complete'){$health='ConfirmedUnhealthy'}}
}
'EventLog'{
  if($collection -eq 'Complete'){$facts.Add('EventLogQuerySucceeded');$health='NotDetected'}
}
}
if($collection -in @('AccessDenied','Empty','Unrecognized','Partial')){$health='Inconclusive'}
$sha=(Get-FileHash -LiteralPath $InputPath -Algorithm SHA256).Hash
[pscustomobject][ordered]@{SchemaVersion='1.0';Tool=$Tool;Target=$Target;ExecutionStatus=$execution;CollectionStatus=$collection;HealthDisposition=$health;ExitCode=$ExitCode;RawOutputPath=(Resolve-Path -LiteralPath $InputPath).Path;RawOutputSHA256=$sha;ParserVersion=$ParserVersion;ObservedFacts=@($facts.ToArray());Limitations=@($limits.ToArray());RecommendedFollowUp=if($health -eq 'Inconclusive'){'Repeat only the smallest required collection with corrected invocation or sufficient read access.'}else{'None'}}
