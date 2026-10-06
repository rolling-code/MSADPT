<#
.SYNOPSIS
Collects the target forest Active Directory schema class GUID map for Directory Control evaluation.

.DESCRIPTION
Reads RootDSE and classSchema objects through the ActiveDirectory module and exports a deterministic
mapping between lDAPDisplayName and schemaIDGUID. The module is read-only and makes no directory changes.

.NOTES
Version: 1.0.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [string]$Server,

    [PSCredential]$Credential,

    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ModuleId = 'Invoke-MSADPTDirectoryControlSchemaClassMap'
$ModuleVersion = '1.0.1'

function Write-MSADPTStep {
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    $Text = '[{0,-12}] {1}' -f $State, $Message
    if ($NoColor) {
        Write-Host $Text
    }
    else {
        Write-Host $Text -ForegroundColor $Color
    }
}

if ($null -eq (Get-Module -ListAvailable -Name ActiveDirectory | Select-Object -First 1)) {
    throw 'ActiveDirectoryModuleUnavailable'
}

Import-Module ActiveDirectory -ErrorAction Stop

$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$CommonParameters = @{ ErrorAction = 'Stop' }
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $CommonParameters.Server = $Server
}
if ($null -ne $Credential) {
    $CommonParameters.Credential = $Credential
}

$Target = 'current forest'
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $Target = $Server
}

Write-MSADPTStep -State 'START' -Message "$ModuleId v$ModuleVersion" -Color Cyan
Write-MSADPTStep -State 'NETWORK' -Message "Target=$Target; protocol=ADWS/LDAP; operation=read RootDSE and classSchema objects; changes=None." -Color Magenta
Write-MSADPTStep -State 'SAFETY' -Message 'Read-only schema queries. Directory changes=None; remote changes=None.' -Color Yellow

$RootDse = Get-ADRootDSE @CommonParameters

$QueryParameters = $CommonParameters.Clone()
$QueryParameters.SearchBase = [string]$RootDse.SchemaNamingContext
$QueryParameters.LDAPFilter = '(objectClass=classSchema)'
$QueryParameters.Properties = @('lDAPDisplayName', 'schemaIDGUID', 'governsID', 'subClassOf')

$Rows = New-Object 'System.Collections.Generic.List[object]'
$Errors = New-Object 'System.Collections.Generic.List[object]'

foreach ($ClassObject in @(Get-ADObject @QueryParameters)) {
    try {
        $SchemaGuid = New-Object System.Guid (,$ClassObject.schemaIDGUID)
        $Rows.Add([pscustomobject][ordered]@{
            LdapDisplayName = [string]$ClassObject.lDAPDisplayName
            SchemaIdGuid = $SchemaGuid.ToString().ToLowerInvariant()
            GovernsId = [string]$ClassObject.governsID
            SubClassOf = [string]$ClassObject.subClassOf
            DistinguishedName = [string]$ClassObject.DistinguishedName
        })
    }
    catch {
        $Errors.Add([pscustomobject]@{
            DistinguishedName = [string]$ClassObject.DistinguishedName
            Error = $_.Exception.Message
        })
    }
}

$CsvPath = Join-Path $OutputDirectory 'directory-control-schema-class-map.csv'
$JsonPath = Join-Path $OutputDirectory 'directory-control-schema-class-map.json'
$ErrorPath = Join-Path $OutputDirectory 'directory-control-schema-class-operational-errors.json'
$SummaryPath = Join-Path $OutputDirectory 'directory-control-schema-class-summary.json'

$SortedRows = @($Rows.ToArray() | Sort-Object LdapDisplayName)
$SortedRows | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
$SortedRows | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $JsonPath -Encoding UTF8

if ($Errors.Count -eq 0) {
    [System.IO.File]::WriteAllText($ErrorPath, "[]`r`n", (New-Object System.Text.UTF8Encoding($false)))
}
else {
    $Errors.ToArray() | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ErrorPath -Encoding UTF8
}

$Summary = [pscustomobject][ordered]@{
    SchemaVersion = '1.0'
    ModuleId = $ModuleId
    ModuleVersion = $ModuleVersion
    Status = 'Completed'
    Disposition = if ($Rows.Count -gt 0) { 'Collected' } else { 'Inconclusive' }
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    SchemaNamingContext = [string]$RootDse.SchemaNamingContext
    ClassCount = $Rows.Count
    OperationalErrorCount = $Errors.Count
    Safety = [pscustomobject]@{
        NetworkActivity = 'ReadOnlyADQueries'
        DirectoryChanges = 'None'
        RemoteChanges = 'None'
    }
}
$Summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8

$ManifestFiles = @(
    Get-ChildItem -LiteralPath $OutputDirectory -File |
        Where-Object Name -ne 'evidence-manifest.json' |
        Sort-Object Name |
        ForEach-Object {
            [pscustomobject]@{
                Name = $_.Name
                Size = $_.Length
                SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        }
)

[pscustomobject]@{
    SchemaVersion = '1.0'
    Status = 'Completed'
    ModuleId = $ModuleId
    ModuleVersion = $ModuleVersion
    FileCount = $ManifestFiles.Count
    Files = $ManifestFiles
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'evidence-manifest.json') -Encoding UTF8

Write-MSADPTStep -State 'DONE' -Message "Schema classes=$($Rows.Count); errors=$($Errors.Count)." -Color Green

[pscustomobject][ordered]@{
    Status = 'Passed'
    ModuleId = $ModuleId
    ModuleVersion = $ModuleVersion
    ClassCount = $Rows.Count
    OperationalErrorCount = $Errors.Count
    ClassMapPath = $CsvPath
    NetworkActivity = 'ReadOnlyADQueries'
    RemoteChanges = 'None'
}
