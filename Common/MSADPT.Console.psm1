<#
.SYNOPSIS
Provides consistent, automation-safe console progress output for MSADPT.
.NOTES
Version: 0.1.0
Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:MSADPTProgressState = [ordered]@{
    Activity = $null
    Total = 0
    Current = 0
    StartedUtc = $null
    Quiet = $false
    NoColor = $false
}

function Get-MSADPTConsoleColor {
    param([ValidateSet('Info','Action','Success','Warning','Error','Muted')][string]$Kind)
    if ($script:MSADPTProgressState.NoColor) { return 'Gray' }
    switch ($Kind) {
        'Info'    { 'Cyan' }
        'Action'  { 'Yellow' }
        'Success' { 'Green' }
        'Warning' { 'DarkYellow' }
        'Error'   { 'Red' }
        'Muted'   { 'DarkGray' }
    }
}

function Write-MSADPTConsoleEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateSet('Info','Action','Success','Warning','Error','Muted')][string]$Kind,
        [Parameter(Mandatory=$true)][string]$Message,
        [string]$Target,
        [string]$Code,
        [hashtable]$Data
    )

    $Event = [pscustomobject][ordered]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        Kind = $Kind
        Code = $Code
        Message = $Message
        Target = $Target
        Data = if ($null -ne $Data) { [pscustomobject]$Data } else { $null }
    }

    if (-not $script:MSADPTProgressState.Quiet) {
        $Prefix = switch ($Kind) {
            'Info'    { '[INFO]' }
            'Action'  { '[....]' }
            'Success' { '[ OK ]' }
            'Warning' { '[WARN]' }
            'Error'   { '[FAIL]' }
            'Muted'   { '[ -- ]' }
        }
        $Text = if ([string]::IsNullOrWhiteSpace($Target)) {
            '{0} {1}' -f $Prefix,$Message
        } else {
            '{0} {1}: {2}' -f $Prefix,$Target,$Message
        }
        Write-Host $Text -ForegroundColor (Get-MSADPTConsoleColor -Kind $Kind)
    }

    Write-Output $Event
}

function Start-MSADPTProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Activity,
        [Parameter(Mandatory=$true)][ValidateRange(0,2147483647)][int]$Total,
        [switch]$Quiet,
        [switch]$NoColor
    )

    $script:MSADPTProgressState.Activity = $Activity
    $script:MSADPTProgressState.Total = $Total
    $script:MSADPTProgressState.Current = 0
    $script:MSADPTProgressState.StartedUtc = (Get-Date).ToUniversalTime()
    $script:MSADPTProgressState.Quiet = [bool]$Quiet
    $script:MSADPTProgressState.NoColor = [bool]$NoColor

    Write-MSADPTConsoleEvent -Kind Info -Code 'ProgressStarted' -Message ("Started {0}; {1} item(s) scheduled." -f $Activity,$Total)
}

function Update-MSADPTProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Action,
        [string]$Target,
        [ValidateRange(0,2147483647)][int]$Current = -1,
        [hashtable]$Data
    )

    if ($Current -ge 0) {
        $script:MSADPTProgressState.Current = $Current
    } else {
        $script:MSADPTProgressState.Current++
    }

    $Total = [int]$script:MSADPTProgressState.Total
    $Position = [int]$script:MSADPTProgressState.Current
    $Percent = if ($Total -gt 0) { [math]::Min(100,[math]::Round(($Position / $Total) * 100,0)) } else { 0 }
    $Prefix = if ($Total -gt 0) { '[{0}/{1} {2}%]' -f $Position,$Total,$Percent } else { '[{0}]' -f $Position }
    $Message = '{0} {1}' -f $Prefix,$Action

    if (-not $script:MSADPTProgressState.Quiet) {
        Write-Progress -Activity ([string]$script:MSADPTProgressState.Activity) -Status $Message -PercentComplete $Percent
    }

    Write-MSADPTConsoleEvent -Kind Action -Code 'ProgressAction' -Message $Message -Target $Target -Data $Data
}

function Complete-MSADPTProgress {
    [CmdletBinding()]
    param(
        [string]$Message = 'Completed.',
        [ValidateSet('Success','Warning','Error')][string]$Outcome = 'Success',
        [hashtable]$Data
    )

    if (-not $script:MSADPTProgressState.Quiet) {
        Write-Progress -Activity ([string]$script:MSADPTProgressState.Activity) -Completed
    }

    $Elapsed = if ($null -ne $script:MSADPTProgressState.StartedUtc) {
        [math]::Round(((Get-Date).ToUniversalTime() - $script:MSADPTProgressState.StartedUtc).TotalSeconds,2)
    } else { $null }

    $Payload = @{
        Activity = $script:MSADPTProgressState.Activity
        Current = $script:MSADPTProgressState.Current
        Total = $script:MSADPTProgressState.Total
        ElapsedSeconds = $Elapsed
    }
    if ($null -ne $Data) {
        foreach ($Entry in $Data.GetEnumerator()) { $Payload[$Entry.Key] = $Entry.Value }
    }

    Write-MSADPTConsoleEvent -Kind $Outcome -Code 'ProgressCompleted' -Message $Message -Data $Payload
}

function Set-MSADPTConsoleMode {
    [CmdletBinding()]
    param([switch]$Quiet,[switch]$NoColor)
    $script:MSADPTProgressState.Quiet = [bool]$Quiet
    $script:MSADPTProgressState.NoColor = [bool]$NoColor
}

Export-ModuleMember -Function @(
    'Write-MSADPTConsoleEvent',
    'Start-MSADPTProgress',
    'Update-MSADPTProgress',
    'Complete-MSADPTProgress',
    'Set-MSADPTConsoleMode'
)
