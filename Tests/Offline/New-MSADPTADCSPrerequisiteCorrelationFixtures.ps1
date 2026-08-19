<# .SYNOPSIS Creates neutral synthetic prerequisite-fact fixtures. .NOTES Version: 1.0.0 #>
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$OutputDirectory)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
function Write-Facts([string]$Name,[hashtable]$States){$Path=Join-Path $OutputDirectory ($Name+'.json');$Facts=foreach($Entry in $States.GetEnumerator()){[pscustomobject]@{id=$Entry.Key;state=$Entry.Value;evidence='synthetic'}};[pscustomobject]@{schemaVersion='1.0';scenario=$Name;facts=@($Facts)}|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $Path -Encoding UTF8;[pscustomobject]@{Scenario=$Name;FactsPath=$Path}}
$Index=@()
$Index+=Write-Facts 'IncompleteCollection' @{enterpriseCaPresent='Confirmed'}
$Index+=Write-Facts 'Esc1Satisfied' @{enterpriseCaPresent='Confirmed';templatePublished='Confirmed';effectiveLowPrivilegeEnrollment='Confirmed';enrolleeSuppliesIdentity='Confirmed';authenticationCapableEku='Confirmed';managerApprovalDisabled='Confirmed';authorizedSignaturesNotRequired='Confirmed';managerApprovalRequired='Not observed';authorizedSignaturesRequired='Not observed';noAuthenticationCapableEku='Not observed';noEffectiveEnrollmentPath='Not observed'}
$Index+=Write-Facts 'Esc1BlockedByApproval' @{enterpriseCaPresent='Confirmed';templatePublished='Confirmed';effectiveLowPrivilegeEnrollment='Confirmed';enrolleeSuppliesIdentity='Confirmed';authenticationCapableEku='Confirmed';managerApprovalDisabled='Not observed';authorizedSignaturesNotRequired='Confirmed';managerApprovalRequired='Confirmed'}
$Index+=Write-Facts 'Esc6FlagWithoutEnrollment' @{enterpriseCaPresent='Confirmed';editfAttributeSubjectAltName2Observed='Confirmed';effectiveLowPrivilegeEnrollmentOnAuthenticationTemplate='Not observed';caAcceptsRequests='Confirmed';noAuthenticationTemplateEnrollmentPath='Confirmed'}
$Index+=Write-Facts 'Esc11IncompleteRuntime' @{enterpriseCaPresent='Confirmed';rpcEnrollmentReachable='Confirmed';encryptedRpcRequestNotEnforced='Inconclusive';usableEnrollmentTemplatePath='Confirmed'}
$IndexPath=Join-Path $OutputDirectory 'correlation-fixture-index.json';$Index|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $IndexPath -Encoding UTF8;[pscustomobject]@{Status='Completed';ScenarioCount=$Index.Count;IndexPath=$IndexPath}
