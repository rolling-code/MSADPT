<#
.SYNOPSIS
    Starts a read-only MSADPT Active Directory assessment engagement.
.DESCRIPTION
    Imports the MSADPT controller and starts a new read-only assessment. By default,
    Active Directory queries use the current Windows identity. Supply -Credential only
    when an explicitly authorized alternate credential is required.
.VERSION
    0.2.0
#>
[CmdletBinding()]
param(
    [Parameter()]
    [PSCredential]$Credential,

    [Parameter()]
    [string]$DomainFQDN,

    [Parameter()]
    [string]$AdServer,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EngagementName = 'MSADPT-ReadOnly-Assessment',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot = (Join-Path -Path $PSScriptRoot -ChildPath 'Engagements'),

    [Parameter()]
    [switch]$SkipAdminCheck
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ControllerPath = Join-Path -Path $PSScriptRoot -ChildPath 'Controller\MSADPT.Controller.psm1'
if (-not (Test-Path -LiteralPath $ControllerPath -PathType Leaf)) {
    throw "Required controller module not found: $ControllerPath"
}

Import-Module $ControllerPath -Force -ErrorAction Stop

$AssessmentParameters = @{
    EngagementName = $EngagementName
    OutputRoot      = $OutputRoot
    SkipAdminCheck  = $SkipAdminCheck
}

if ($PSBoundParameters.ContainsKey('Credential') -and $null -ne $Credential) {
    $AssessmentParameters.Credential = $Credential
}

if (-not [string]::IsNullOrWhiteSpace($DomainFQDN)) {
    $AssessmentParameters.DomainFQDN = $DomainFQDN
}

if (-not [string]::IsNullOrWhiteSpace($AdServer)) {
    $AssessmentParameters.AdServer = $AdServer
}

Invoke-MSADPTAssessment @AssessmentParameters
