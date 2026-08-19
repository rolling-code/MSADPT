<#
.SYNOPSIS
Analyzes an offline AD identity export for suspicious Unicode and normalized identity collisions.
.DESCRIPTION
Consumes JSON containing previously exported AD objects. It performs client-side Unicode inspection because
some directory matching behavior can ignore or normalize characters in ways that make server-side character
filters unreliable. The script does not contact Active Directory, resolve DNS, request tickets, change
passwords, modify objects, or perform authentication.
.NOTES
Version: 0.1.0
Execution class: offline_analysis
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InputPath,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$AnalyzerVersion = '0.1.0'
$Attributes = @('sAMAccountName','userPrincipalName','servicePrincipalName','cn','name','displayName','dNSHostName')

function Test-MSADPTSuspiciousCodePoint {
    param([int]$CodePoint, [Globalization.UnicodeCategory]$Category)
    if ($Category -in @(
        [Globalization.UnicodeCategory]::Control,
        [Globalization.UnicodeCategory]::Format,
        [Globalization.UnicodeCategory]::LineSeparator,
        [Globalization.UnicodeCategory]::ParagraphSeparator,
        [Globalization.UnicodeCategory]::SpaceSeparator
    )) { return $true }

    # Directional controls, zero-width/default-ignorable characters, variation selectors,
    # BOM/zero-width no-break space, interlinear annotation controls, and tag characters.
    if ($CodePoint -in 0x00AD,0x034F,0x061C,0x180E,0x200B,0x200C,0x200D,0x2060,0xFEFF) { return $true }
    if (($CodePoint -ge 0x200E -and $CodePoint -le 0x200F) -or
        ($CodePoint -ge 0x202A -and $CodePoint -le 0x202E) -or
        ($CodePoint -ge 0x2061 -and $CodePoint -le 0x206F) -or
        ($CodePoint -ge 0xFE00 -and $CodePoint -le 0xFE0F) -or
        ($CodePoint -ge 0xFFF9 -and $CodePoint -le 0xFFFB) -or
        ($CodePoint -ge 0xE0000 -and $CodePoint -le 0xE007F) -or
        ($CodePoint -ge 0xE0100 -and $CodePoint -le 0xE01EF)) { return $true }
    return $false
}

function Get-MSADPTUnicodeCharacters {
    param([string]$Value)
    $Rows = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Value) { return @() }
    $Enumerator = [Globalization.StringInfo]::GetTextElementEnumerator($Value)
    while ($Enumerator.MoveNext()) {
        $Element = [string]$Enumerator.GetTextElement()
        $CodePoint = [char]::ConvertToUtf32($Element,0)
        $Category = [char]::GetUnicodeCategory($Element,0)
        if (Test-MSADPTSuspiciousCodePoint -CodePoint $CodePoint -Category $Category) {
            $Rows.Add([pscustomobject][ordered]@{
                Index = [int]$Enumerator.ElementIndex
                CodePoint = ('U+{0:X4}' -f $CodePoint)
                Decimal = $CodePoint
                UnicodeCategory = [string]$Category
                Utf16Length = $Element.Length
            })
        }
    }
    return @($Rows.ToArray())
}

function Remove-MSADPTSuspiciousUnicode {
    param([string]$Value)
    if ($null -eq $Value) { return $null }
    $Builder = New-Object Text.StringBuilder
    $Enumerator = [Globalization.StringInfo]::GetTextElementEnumerator($Value)
    while ($Enumerator.MoveNext()) {
        $Element = [string]$Enumerator.GetTextElement()
        $CodePoint = [char]::ConvertToUtf32($Element,0)
        $Category = [char]::GetUnicodeCategory($Element,0)
        if (-not (Test-MSADPTSuspiciousCodePoint -CodePoint $CodePoint -Category $Category)) {
            [void]$Builder.Append($Element)
        }
    }
    return $Builder.ToString()
}

function Get-MSADPTCanonicalIdentityKey {
    param([string]$Value)
    if ($null -eq $Value) { return $null }
    $Compatibility = $Value.Normalize([Text.NormalizationForm]::FormKC)
    $WithoutSuspicious = Remove-MSADPTSuspiciousUnicode -Value $Compatibility
    $CollapsedWhitespace = [regex]::Replace($WithoutSuspicious, '\s+', ' ').Trim()
    return $CollapsedWhitespace.ToUpperInvariant()
}

function Get-MSADPTObjectProperty {
    param($Object,[string]$Name)
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) { return $null }
    return $Property.Value
}

if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) { throw "Input file not found: $InputPath" }
try { $Objects = @(Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json -ErrorAction Stop) }
catch { throw "InputJsonParseFailure: $($_.Exception.Message)" }

$ValueRecords = New-Object 'System.Collections.Generic.List[object]'
$Findings = New-Object 'System.Collections.Generic.List[object]'

foreach ($Object in $Objects) {
    $ObjectGuid = [string](Get-MSADPTObjectProperty $Object 'ObjectGuid')
    $ObjectSid = [string](Get-MSADPTObjectProperty $Object 'ObjectSid')
    $DistinguishedName = [string](Get-MSADPTObjectProperty $Object 'DistinguishedName')
    $ObjectClass = [string](Get-MSADPTObjectProperty $Object 'ObjectClass')

    foreach ($Attribute in $Attributes) {
        $RawProperty = Get-MSADPTObjectProperty $Object $Attribute
        if ($null -eq $RawProperty) { continue }
        $Values = if ($RawProperty -is [string]) { @([string]$RawProperty) } else { @($RawProperty | ForEach-Object { [string]$_ }) }
        foreach ($Value in $Values) {
            if ([string]::IsNullOrEmpty($Value)) { continue }
            $Suspicious = @(Get-MSADPTUnicodeCharacters -Value $Value)
            $FormKC = $Value.Normalize([Text.NormalizationForm]::FormKC)
            $Removed = Remove-MSADPTSuspiciousUnicode -Value $FormKC
            $Canonical = Get-MSADPTCanonicalIdentityKey -Value $Value
            $Record = [pscustomobject][ordered]@{
                ObjectGuid=$ObjectGuid;ObjectSid=$ObjectSid;DistinguishedName=$DistinguishedName;ObjectClass=$ObjectClass
                Attribute=$Attribute;RawValue=$Value;FormKCValue=$FormKC;SuspiciousRemovedValue=$Removed;CanonicalKey=$Canonical
                SuspiciousCharacters=$Suspicious
            }
            $ValueRecords.Add($Record)

            if ($Suspicious.Count -gt 0) {
                $Findings.Add([pscustomobject][ordered]@{
                    FindingType='SuspiciousUnicodeCodePoint';Attribute=$Attribute;RawValue=$Value;CanonicalKey=$Canonical
                    ObjectGuid=$ObjectGuid;ObjectSid=$ObjectSid;DistinguishedName=$DistinguishedName;ObjectClass=$ObjectClass
                    RelatedObjects=@();Evidence=@($Suspicious);Disposition='Observed'
                    Rationale='One or more control, format, separator, zero-width, directional, variation-selector, annotation, or tag code points were present.'
                    Limitations=@('Presence does not prove malicious use or exploitability.','Patch state and delegated attribute-write permissions are evaluated separately.')
                })
            }
            if ($Value -cne $FormKC) {
                $Findings.Add([pscustomobject][ordered]@{
                    FindingType='CompatibilityNormalizationChange';Attribute=$Attribute;RawValue=$Value;CanonicalKey=$Canonical
                    ObjectGuid=$ObjectGuid;ObjectSid=$ObjectSid;DistinguishedName=$DistinguishedName;ObjectClass=$ObjectClass
                    RelatedObjects=@();Evidence=@([pscustomobject]@{FormKCValue=$FormKC});Disposition='Observed'
                    Rationale='Unicode compatibility normalization changed the attribute value.'
                    Limitations=@('Normalization differences can be legitimate. Review the raw code points and identity context.')
                })
            }
            if ($FormKC -cne $Removed) {
                $Findings.Add([pscustomobject][ordered]@{
                    FindingType='SuspiciousCharacterRemovalChange';Attribute=$Attribute;RawValue=$Value;CanonicalKey=$Canonical
                    ObjectGuid=$ObjectGuid;ObjectSid=$ObjectSid;DistinguishedName=$DistinguishedName;ObjectClass=$ObjectClass
                    RelatedObjects=@();Evidence=@([pscustomobject]@{SuspiciousRemovedValue=$Removed});Disposition='Observed'
                    Rationale='Removing suspicious Unicode changed the normalized attribute value.'
                    Limitations=@('This is a detection lead, not proof that the directory ignores the same code point in every protocol path.')
                })
            }
        }
    }
}

$CollisionGroups = @(
    $ValueRecords.ToArray() |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.CanonicalKey) } |
        Group-Object Attribute,CanonicalKey |
        Where-Object {
            @($_.Group | Select-Object -ExpandProperty ObjectGuid -Unique).Count -gt 1
        }
)

foreach ($Group in $CollisionGroups) {
    $Members = @($Group.Group | Select-Object ObjectGuid,ObjectSid,DistinguishedName,ObjectClass,Attribute,RawValue,CanonicalKey)
    $Attribute = [string]$Members[0].Attribute
    $RawUnique = @($Members | Select-Object -ExpandProperty RawValue -Unique)
    $Type = if ($Attribute -eq 'servicePrincipalName') { 'NormalizedSpnCollision' } elseif ($RawUnique.Count -eq 1) { 'RawDuplicateAcrossObjects' } else { 'NormalizedIdentityCollision' }
    $Findings.Add([pscustomobject][ordered]@{
        FindingType=$Type;Attribute=$Attribute;RawValue=$null;CanonicalKey=[string]$Members[0].CanonicalKey
        ObjectGuid=$null;ObjectSid=$null;DistinguishedName=$null;ObjectClass=$null;RelatedObjects=$Members;Evidence=@();Disposition='Observed'
        Rationale='Multiple directory objects share the same client-side canonical key for this identity attribute.'
        Limitations=@('Collision detection uses FormKC, suspicious-character removal, whitespace collapse, and invariant uppercase.','A collision is not proof of KDC, LDAP, or password-change exploitability.','Validate domain-controller patch state and attribute-write permissions separately.')
    })
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$ValuesPath = Join-Path $OutputDirectory 'unicode-identity-values.json'
$FindingsPath = Join-Path $OutputDirectory 'unicode-identity-findings.json'
$SummaryPath = Join-Path $OutputDirectory 'unicode-identity-finding-summary.csv'
$ValueRecords.ToArray() | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ValuesPath -Encoding UTF8
$Findings.ToArray() | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $FindingsPath -Encoding UTF8
$Findings.ToArray() | Select-Object FindingType,Attribute,RawValue,CanonicalKey,ObjectGuid,ObjectSid,DistinguishedName,ObjectClass,@{N='RelatedObjectCount';E={@($_.RelatedObjects).Count}},Disposition,Rationale | Export-Csv -LiteralPath $SummaryPath -NoTypeInformation -Encoding UTF8

[pscustomobject][ordered]@{
    schemaVersion='1.0';analyzer='ADUnicodeIdentityAnomalies';analyzerVersion=$AnalyzerVersion;status='Completed';executionClass='offline_analysis'
    objectCount=$Objects.Count;valueCount=$ValueRecords.Count;findingCount=$Findings.Count
    suspiciousUnicodeFindingCount=@($Findings|Where-Object FindingType -eq 'SuspiciousUnicodeCodePoint').Count
    normalizedCollisionCount=@($Findings|Where-Object FindingType -in @('NormalizedIdentityCollision','NormalizedSpnCollision','RawDuplicateAcrossObjects')).Count
    evidence=@($ValuesPath,$FindingsPath,$SummaryPath)
    limitations=@('This analyzer does not validate patch state.','This analyzer does not determine effective write access to identity attributes.','This analyzer does not perform LDAP character searches because server-side comparison can ignore or normalize characters.','Findings are leads and not proof of exploitation.')
}
