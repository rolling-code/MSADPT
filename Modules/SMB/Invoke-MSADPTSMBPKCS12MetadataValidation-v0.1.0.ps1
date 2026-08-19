<#
.SYNOPSIS
Performs bounded, in-memory PKCS#12 metadata validation for evidence-selected SMB artifacts.

.DESCRIPTION
Consumes successful P1 content-validation results from MSADPT. Deduplicates the standard NETLOGON
and SYSVOL scripts aliases into logical artifacts, selects one evidence-recorded source path per
artifact, and reads each file into memory only when its size is within the configured limit.

The validator attempts PKCS#12 import with only two non-guessing password states: null and empty.
It uses EphemeralKeySet when supported and never installs a certificate into a persistent store.
It records only non-secret certificate metadata and whether a private key is present. It does not
export keys, save PFX bytes, test password lists, use a certificate for authentication, or change
any remote file.

.NOTES
Version: 0.1.0
Package identity: MSADPT-SMB-PKCS12-METADATA-VALIDATION
Execution class: authorized_bounded_read_only_live_validation
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$P1ValidationDirectory,

    [string]$OutputDirectory,

    [ValidateRange(4096, 10485760)]
    [int]$MaximumBytesPerArtifact = 10485760,

    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$PackageIdentity = 'MSADPT-SMB-PKCS12-METADATA-VALIDATION'
$PackageVersion = '0.1.0'
$OperationalErrors = New-Object 'System.Collections.Generic.List[object]'

function Write-Step {
    param(
        [string]$Status,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    if ($Quiet) {
        return
    }

    $Text = '[{0,-12}] {1}' -f $Status, $Message
    if ($NoColor) {
        Write-Host $Text
    }
    else {
        Write-Host $Text -ForegroundColor $Color
    }
}

function Require-File {
    param(
        [string]$Path,
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "RequiredFileMissing [$Label]: $Path"
    }

    if ((Get-Item -LiteralPath $Path).Length -eq 0) {
        throw "RequiredFileEmpty [$Label]: $Path"
    }
}

function Write-JsonArray {
    param(
        [object[]]$Rows,
        [string]$Path,
        [int]$Depth = 20
    )

    $Array = [object[]]@($Rows)
    if (@($Array).Count -eq 0) {
        [IO.File]::WriteAllText(
            $Path,
            "[]`r`n",
            (New-Object Text.UTF8Encoding($false))
        )
    }
    else {
        $Array |
            ConvertTo-Json -Depth $Depth |
            Set-Content -LiteralPath $Path -Encoding UTF8
    }

    $RoundTrip = [object[]]@(
        Get-Content -LiteralPath $Path -Raw |
            ConvertFrom-Json -ErrorAction Stop
    )

    if (@($RoundTrip).Count -ne @($Array).Count) {
        throw "JsonArrayRoundTripMismatch: $Path"
    }
}

function Write-JsonDocument {
    param(
        [object]$Document,
        [string]$Path,
        [int]$Depth = 20
    )

    $Document |
        ConvertTo-Json -Depth $Depth |
        Set-Content -LiteralPath $Path -Encoding UTF8

    $null = Get-Content -LiteralPath $Path -Raw |
        ConvertFrom-Json -ErrorAction Stop
}

function Convert-HtmlText {
    param([object]$Value)
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

function Add-OperationalError {
    param(
        [string]$ArtifactId,
        [string]$Stage,
        [string]$Target,
        [string]$UncPath,
        [string]$ErrorText
    )

    $OperationalErrors.Add([pscustomobject][ordered]@{
        ArtifactId = $ArtifactId
        Stage = $Stage
        Target = $Target
        UncPath = $UncPath
        Protocol = 'SMB'
        Port = 445
        Error = $ErrorText
    })
}

function Normalize-LogicalArtifactKey {
    param(
        [string]$Share,
        [string]$RelativePath
    )

    $Normalized = $RelativePath.Replace('/', '\').TrimStart('\').ToLowerInvariant()

    if ($Share -eq 'SYSVOL') {
        $Marker = '\scripts\'
        $MarkerIndex = $Normalized.IndexOf($Marker)
        if ($MarkerIndex -ge 0) {
            return $Normalized.Substring($MarkerIndex + $Marker.Length)
        }
    }

    if ($Share -eq 'NETLOGON') {
        return $Normalized
    }

    return ('{0}|{1}' -f $Share.ToUpperInvariant(), $Normalized)
}

function Get-UncPath {
    param(
        [string]$Target,
        [string]$Share,
        [string]$RelativePath
    )

    $CleanRelativePath = $RelativePath.Replace('/', '\').TrimStart('\')
    return "\\$Target\$Share\$CleanRelativePath"
}

function Read-CompleteBytesBounded {
    param(
        [string]$Path,
        [int]$MaximumBytes
    )

    $Stream = $null
    try {
        $Stream = New-Object IO.FileStream(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite
        )

        $Length = [int64]$Stream.Length
        if ($Length -gt $MaximumBytes) {
            throw "Artifact length $Length exceeds configured maximum $MaximumBytes bytes."
        }

        if ($Length -gt [int]::MaxValue) {
            throw "Artifact length $Length exceeds supported in-memory array size."
        }

        $Buffer = New-Object byte[] ([int]$Length)
        $TotalRead = 0
        while ($TotalRead -lt $Buffer.Length) {
            $BytesRead = $Stream.Read($Buffer, $TotalRead, $Buffer.Length - $TotalRead)
            if ($BytesRead -le 0) {
                break
            }
            $TotalRead += $BytesRead
        }

        if ($TotalRead -ne $Buffer.Length) {
            throw "Incomplete read: expected $($Buffer.Length) bytes and received $TotalRead bytes."
        }

        return [pscustomobject][ordered]@{
            Bytes = $Buffer
            Length = $Length
        }
    }
    finally {
        if ($null -ne $Stream) {
            $Stream.Dispose()
        }
    }
}

function Get-EphemeralImportFlags {
    $Flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
    $EphemeralName = 'EphemeralKeySet'

    if ([Enum]::GetNames([Security.Cryptography.X509Certificates.X509KeyStorageFlags]) -contains $EphemeralName) {
        $Flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    }

    return $Flags
}

function Import-Pkcs12CollectionSafely {
    param(
        [byte[]]$Bytes,
        [AllowNull()]
        [string]$Password,
        [Security.Cryptography.X509Certificates.X509KeyStorageFlags]$Flags
    )

    $Collection = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    $Collection.Import($Bytes, $Password, $Flags)
    return $Collection
}

function Get-CertificateMetadata {
    param(
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$ArtifactId,
        [int]$CertificateIndex
    )

    $EnhancedKeyUsages = New-Object 'System.Collections.Generic.List[object]'
    foreach ($Extension in $Certificate.Extensions) {
        if ($Extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($Usage in $Extension.EnhancedKeyUsages) {
                $EnhancedKeyUsages.Add([pscustomobject]@{
                    Oid = [string]$Usage.Value
                    FriendlyName = [string]$Usage.FriendlyName
                })
            }
        }
    }

    $KeyAlgorithm = $null
    $KeySize = $null
    try {
        $PublicKeyAlgorithm = $Certificate.PublicKey.Oid
        if ($null -ne $PublicKeyAlgorithm) {
            $KeyAlgorithm = [string]$PublicKeyAlgorithm.FriendlyName
            if ([string]::IsNullOrWhiteSpace($KeyAlgorithm)) {
                $KeyAlgorithm = [string]$PublicKeyAlgorithm.Value
            }
        }
    }
    catch { }

    try {
        $Rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
        if ($null -ne $Rsa) {
            $KeyAlgorithm = 'RSA'
            $KeySize = [int]$Rsa.KeySize
            $Rsa.Dispose()
        }
    }
    catch { }

    if ($null -eq $KeySize) {
        try {
            $Ecdsa = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Certificate)
            if ($null -ne $Ecdsa) {
                $KeyAlgorithm = 'ECDSA'
                $KeySize = [int]$Ecdsa.KeySize
                $Ecdsa.Dispose()
            }
        }
        catch { }
    }

    $Now = Get-Date
    $ValidityState = 'CurrentlyValid'
    if ($Certificate.NotAfter -lt $Now) {
        $ValidityState = 'Expired'
    }
    elseif ($Certificate.NotBefore -gt $Now) {
        $ValidityState = 'NotYetValid'
    }

    return [pscustomobject][ordered]@{
        ArtifactId = $ArtifactId
        CertificateIndex = $CertificateIndex
        Subject = [string]$Certificate.Subject
        Issuer = [string]$Certificate.Issuer
        SerialNumber = [string]$Certificate.SerialNumber
        Thumbprint = [string]$Certificate.Thumbprint
        NotBeforeUtc = $Certificate.NotBefore.ToUniversalTime().ToString('o')
        NotAfterUtc = $Certificate.NotAfter.ToUniversalTime().ToString('o')
        ValidityState = $ValidityState
        HasPrivateKey = [bool]$Certificate.HasPrivateKey
        KeyAlgorithm = $KeyAlgorithm
        KeySize = $KeySize
        EnhancedKeyUsages = [object[]]$EnhancedKeyUsages.ToArray()
    }
}

function Test-CertificateChain {
    param(
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$ArtifactId,
        [int]$CertificateIndex
    )

    $Chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    try {
        $Chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $Chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $BuildSucceeded = [bool]$Chain.Build($Certificate)
        $Statuses = [object[]]@(
            foreach ($Status in $Chain.ChainStatus) {
                [pscustomobject]@{
                    Status = [string]$Status.Status
                    StatusInformation = ([string]$Status.StatusInformation).Trim()
                }
            }
        )

        return [pscustomobject][ordered]@{
            ArtifactId = $ArtifactId
            CertificateIndex = $CertificateIndex
            BuildSucceeded = $BuildSucceeded
            RevocationChecked = $false
            Statuses = $Statuses
        }
    }
    finally {
        $Chain.Dispose()
    }
}

try {
    Write-Step -Status 'START' -Message "$PackageIdentity v$PackageVersion" -Color Cyan
    Write-Step -Status 'INFO' -Message 'In-memory PKCS#12 metadata validation. No guessing, export, authentication, or remote changes.' -Color DarkGray

    if (-not (Test-Path -LiteralPath $P1ValidationDirectory -PathType Container)) {
        throw "P1ValidationDirectoryMissing: $P1ValidationDirectory"
    }

    $ResultsPath = Join-Path $P1ValidationDirectory 'p1-content-validation-results.json'
    Require-File -Path $ResultsPath -Label 'P1 content-validation results'

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = Join-Path $P1ValidationDirectory 'PKCS12MetadataValidation-v0.1.0'
    }

    if (Test-Path -LiteralPath $OutputDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "OutputDirectoryNotEmpty: $OutputDirectory"
        }
    }

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $P1Results = [object[]]@(
        Get-Content -LiteralPath $ResultsPath -Raw |
            ConvertFrom-Json -ErrorAction Stop
    )

    $ReadablePfxRows = [object[]]@(
        $P1Results |
            Where-Object {
                [bool]$_.RemoteReadSucceeded -and
                [bool]$_.LocalAnalysisSucceeded -and
                ([IO.Path]::GetExtension([string]$_.RelativePath) -in @('.pfx', '.p12'))
            }
    )

    if (@($ReadablePfxRows).Count -eq 0) {
        throw 'No successfully read PFX or P12 artifacts were found in the P1 results.'
    }

    $GroupedArtifacts = @(
        $ReadablePfxRows |
            Group-Object {
                Normalize-LogicalArtifactKey -Share ([string]$_.Share) -RelativePath ([string]$_.RelativePath)
            }
    )

    $PlanList = New-Object 'System.Collections.Generic.List[object]'
    $ArtifactIndex = 0
    foreach ($Group in $GroupedArtifacts) {
        $ArtifactIndex++
        $Observations = [object[]]@($Group.Group)
        $Preferred = @(
            $Observations |
                Sort-Object `
                    @{Expression = { if ($_.Share -eq 'SYSVOL') { 0 } else { 1 } }},
                    Target,
                    RelativePath |
                Select-Object -First 1
        )[0]

        $AlternateRows = [object[]]@(
            $Observations |
                Where-Object {
                    $_.UncPath -ne $Preferred.UncPath
                } |
                Sort-Object Target, Share, RelativePath
        )

        $PlanList.Add([pscustomobject][ordered]@{
            ArtifactId = 'PKCS12-{0:D3}' -f $ArtifactIndex
            LogicalArtifactKey = [string]$Group.Name
            ObservationCount = @($Observations).Count
            PreferredTarget = [string]$Preferred.Target
            PreferredShare = [string]$Preferred.Share
            PreferredRelativePath = [string]$Preferred.RelativePath
            PreferredUncPath = [string]$Preferred.UncPath
            AlternateSources = [object[]]@(
                foreach ($Alternate in $AlternateRows) {
                    [pscustomobject]@{
                        Target = [string]$Alternate.Target
                        Share = [string]$Alternate.Share
                        RelativePath = [string]$Alternate.RelativePath
                        UncPath = [string]$Alternate.UncPath
                    }
                }
            )
            MaximumBytes = $MaximumBytesPerArtifact
            PasswordAttempts = @('NullPassword', 'EmptyPassword')
            EphemeralKeyStorage = $true
            PrivateKeyExport = $false
            AuthenticationAttempt = $false
            CompleteContentSaved = $false
            RemoteChange = $false
        })
    }
    $PlanRows = [object[]]$PlanList.ToArray()

    Write-Step -Status 'NETWORK' -Message 'Planned live network operations follow.' -Color Magenta
    Write-Step -Status 'SCOPE' -Message "Logical artifacts=$(@($PlanRows).Count); Protocol=SMB; Port=TCP/445; maxBytes=$MaximumBytesPerArtifact; passwordStates=Null,Empty only." -Color DarkCyan
    foreach ($Plan in $PlanRows) {
        Write-Step -Status 'TARGET' -Message "$($Plan.PreferredTarget) TCP/445 $($Plan.PreferredUncPath): complete bounded read into memory; ephemeral import; no export; no authentication; write=False" -Color DarkCyan
    }
    Write-Step -Status 'CHANGES' -Message 'Remote file changes=None; password guessing=None; private-key export=None; certificate-store persistence=None; authentication=None.' -Color DarkCyan

    $ArtifactResultList = New-Object 'System.Collections.Generic.List[object]'
    $CertificateList = New-Object 'System.Collections.Generic.List[object]'
    $ChainList = New-Object 'System.Collections.Generic.List[object]'
    $ImportAttemptList = New-Object 'System.Collections.Generic.List[object]'
    $ImportFlags = Get-EphemeralImportFlags

    $Position = 0
    foreach ($Plan in $PlanRows) {
        $Position++
        $SourceCandidates = New-Object 'System.Collections.Generic.List[object]'
        $SourceCandidates.Add([pscustomobject]@{
            Target = [string]$Plan.PreferredTarget
            Share = [string]$Plan.PreferredShare
            RelativePath = [string]$Plan.PreferredRelativePath
            UncPath = [string]$Plan.PreferredUncPath
        })
        foreach ($Alternate in [object[]]@($Plan.AlternateSources)) {
            $SourceCandidates.Add($Alternate)
        }

        $ReadSucceeded = $false
        $ArtifactBytes = $null
        $ReadLength = $null
        $SelectedSource = $null
        $ReadAttempts = 0
        $FinalReadError = $null

        foreach ($Source in [object[]]$SourceCandidates.ToArray()) {
            if ($ReadSucceeded) {
                break
            }

            $ReadAttempts++
            Write-Step -Status 'READ' -Message "$Position/$(@($PlanRows).Count) artifact=$($Plan.ArtifactId) attempt=$ReadAttempts target=$($Source.Target) path=$($Source.UncPath)" -Color Yellow

            try {
                $ReadResult = Read-CompleteBytesBounded -Path ([string]$Source.UncPath) -MaximumBytes $MaximumBytesPerArtifact
                $ArtifactBytes = [byte[]]$ReadResult.Bytes
                $ReadLength = [int64]$ReadResult.Length
                $SelectedSource = $Source
                $ReadSucceeded = $true
            }
            catch {
                $FinalReadError = $_.Exception.Message
                Add-OperationalError -ArtifactId ([string]$Plan.ArtifactId) -Stage 'ArtifactRead' -Target ([string]$Source.Target) -UncPath ([string]$Source.UncPath) -ErrorText $FinalReadError
            }
        }

        if (-not $ReadSucceeded) {
            $ArtifactResultList.Add([pscustomobject][ordered]@{
                ArtifactId = [string]$Plan.ArtifactId
                LogicalArtifactKey = [string]$Plan.LogicalArtifactKey
                ObservationCount = [int]$Plan.ObservationCount
                ReadSucceeded = $false
                ReadAttempts = $ReadAttempts
                SelectedTarget = $null
                SelectedUncPath = $null
                ArtifactLength = $null
                ImportSucceeded = $false
                SuccessfulPasswordState = $null
                PasswordProtectionDisposition = 'Inconclusive'
                CertificateCount = 0
                PrivateKeyCertificateCount = 0
                CurrentValidCertificateCount = 0
                ClientAuthenticationEkuCertificateCount = 0
                OverallDisposition = 'ArtifactUnavailable'
                CompleteContentSaved = $false
                PrivateKeyExported = $false
                AuthenticationAttempted = $false
                RemoteChange = $false
                Error = $FinalReadError
            })
            continue
        }

        $ImportSucceeded = $false
        $SuccessfulPasswordState = $null
        $Collection = $null
        $PasswordStates = [object[]]@(
            [pscustomobject]@{Name='NullPassword';Value=$null}
            [pscustomobject]@{Name='EmptyPassword';Value=''}
        )

        foreach ($PasswordState in $PasswordStates) {
            if ($ImportSucceeded) {
                break
            }

            try {
                $Collection = Import-Pkcs12CollectionSafely -Bytes $ArtifactBytes -Password $PasswordState.Value -Flags $ImportFlags
                $ImportSucceeded = $true
                $SuccessfulPasswordState = [string]$PasswordState.Name
                $ImportAttemptList.Add([pscustomobject][ordered]@{
                    ArtifactId = [string]$Plan.ArtifactId
                    PasswordState = [string]$PasswordState.Name
                    Succeeded = $true
                    ErrorCategory = $null
                    Error = $null
                })
            }
            catch {
                $ImportAttemptList.Add([pscustomobject][ordered]@{
                    ArtifactId = [string]$Plan.ArtifactId
                    PasswordState = [string]$PasswordState.Name
                    Succeeded = $false
                    ErrorCategory = $_.Exception.GetType().FullName
                    Error = $_.Exception.Message
                })
            }
        }

        $CertificateCount = 0
        $PrivateKeyCount = 0
        $CurrentlyValidCount = 0
        $ClientAuthEkuCount = 0
        $ArtifactDisposition = 'PasswordProtectedOrUnsupportedPkcs12'

        if ($ImportSucceeded) {
            $CertificateCount = [int]$Collection.Count
            $CertificateIndex = 0
            foreach ($Certificate in $Collection) {
                $CertificateIndex++
                $Metadata = Get-CertificateMetadata -Certificate $Certificate -ArtifactId ([string]$Plan.ArtifactId) -CertificateIndex $CertificateIndex
                $CertificateList.Add($Metadata)
                $ChainList.Add((Test-CertificateChain -Certificate $Certificate -ArtifactId ([string]$Plan.ArtifactId) -CertificateIndex $CertificateIndex))

                if ([bool]$Metadata.HasPrivateKey) {
                    $PrivateKeyCount++
                }
                if ([string]$Metadata.ValidityState -eq 'CurrentlyValid') {
                    $CurrentlyValidCount++
                }
                if (@($Metadata.EnhancedKeyUsages | Where-Object { $_.Oid -eq '1.3.6.1.5.5.7.3.2' }).Count -gt 0) {
                    $ClientAuthEkuCount++
                }
            }

            if ($CertificateCount -eq 0) {
                $ArtifactDisposition = 'ImportedContainerNoCertificatesDetected'
            }
            elseif ($PrivateKeyCount -gt 0 -and $SuccessfulPasswordState -in @('NullPassword', 'EmptyPassword')) {
                $ArtifactDisposition = 'PasswordlessPrivateKeyContainerConfirmed'
            }
            elseif ($PrivateKeyCount -eq 0) {
                $ArtifactDisposition = 'CertificateOnlyContainerConfirmed'
            }
            else {
                $ArtifactDisposition = 'ImportedContainerConfirmed'
            }
        }

        $ArtifactResultList.Add([pscustomobject][ordered]@{
            ArtifactId = [string]$Plan.ArtifactId
            LogicalArtifactKey = [string]$Plan.LogicalArtifactKey
            ObservationCount = [int]$Plan.ObservationCount
            ReadSucceeded = $true
            ReadAttempts = $ReadAttempts
            SelectedTarget = [string]$SelectedSource.Target
            SelectedUncPath = [string]$SelectedSource.UncPath
            ArtifactLength = $ReadLength
            ImportSucceeded = $ImportSucceeded
            SuccessfulPasswordState = $SuccessfulPasswordState
            PasswordProtectionDisposition = if ($ImportSucceeded) { 'NullOrEmptyPasswordAccepted' } else { 'PasswordRequiredOrUnsupportedFormat' }
            CertificateCount = $CertificateCount
            PrivateKeyCertificateCount = $PrivateKeyCount
            CurrentValidCertificateCount = $CurrentlyValidCount
            ClientAuthenticationEkuCertificateCount = $ClientAuthEkuCount
            OverallDisposition = $ArtifactDisposition
            CompleteContentSaved = $false
            PrivateKeyExported = $false
            AuthenticationAttempted = $false
            RemoteChange = $false
            Error = $null
        })

        if ($null -ne $Collection) {
            foreach ($Certificate in $Collection) {
                $Certificate.Dispose()
            }
            $Collection.Clear()
        }

        if ($null -ne $ArtifactBytes) {
            [Array]::Clear($ArtifactBytes, 0, $ArtifactBytes.Length)
            $ArtifactBytes = $null
        }
    }

    $ArtifactRows = [object[]]$ArtifactResultList.ToArray()
    $CertificateRows = [object[]]$CertificateList.ToArray()
    $ChainRows = [object[]]$ChainList.ToArray()
    $ImportAttemptRows = [object[]]$ImportAttemptList.ToArray()
    $ErrorRows = [object[]]$OperationalErrors.ToArray()

    $ReadableCount = [int]@($ArtifactRows | Where-Object { [bool]$_.ReadSucceeded }).Count
    $ImportedCount = [int]@($ArtifactRows | Where-Object { [bool]$_.ImportSucceeded }).Count
    $PasswordlessPrivateKeyCount = [int]@($ArtifactRows | Where-Object { $_.OverallDisposition -eq 'PasswordlessPrivateKeyContainerConfirmed' }).Count
    $CertificateOnlyCount = [int]@($ArtifactRows | Where-Object { $_.OverallDisposition -eq 'CertificateOnlyContainerConfirmed' }).Count
    $PasswordRequiredCount = [int]@($ArtifactRows | Where-Object { $_.OverallDisposition -eq 'PasswordProtectedOrUnsupportedPkcs12' }).Count
    $UnavailableCount = [int]@($ArtifactRows | Where-Object { $_.OverallDisposition -eq 'ArtifactUnavailable' }).Count

    $OverallDisposition = 'NoPasswordlessPrivateKeyContainerDetected'
    if ($PasswordlessPrivateKeyCount -gt 0) {
        $OverallDisposition = 'PasswordlessPrivateKeyContainerDetected'
    }
    elseif ($ImportedCount -gt 0) {
        $OverallDisposition = 'Pkcs12MetadataValidatedNoPasswordlessPrivateKeyDetected'
    }
    elseif ($ReadableCount -gt 0) {
        $OverallDisposition = 'ReadablePkcs12PasswordRequiredOrUnsupported'
    }
    else {
        $OverallDisposition = 'Pkcs12ValidationInconclusive'
    }

    $PlanJson = Join-Path $OutputDirectory 'pkcs12-validation-plan.json'
    $PlanCsv = Join-Path $OutputDirectory 'pkcs12-validation-plan.csv'
    $ArtifactsJson = Join-Path $OutputDirectory 'pkcs12-artifact-results.json'
    $ArtifactsCsv = Join-Path $OutputDirectory 'pkcs12-artifact-results.csv'
    $CertificatesJson = Join-Path $OutputDirectory 'pkcs12-certificate-metadata.json'
    $CertificatesCsv = Join-Path $OutputDirectory 'pkcs12-certificate-metadata.csv'
    $ChainsJson = Join-Path $OutputDirectory 'pkcs12-chain-results.json'
    $ChainsCsv = Join-Path $OutputDirectory 'pkcs12-chain-results.csv'
    $AttemptsJson = Join-Path $OutputDirectory 'pkcs12-import-attempts.json'
    $AttemptsCsv = Join-Path $OutputDirectory 'pkcs12-import-attempts.csv'
    $ErrorsJson = Join-Path $OutputDirectory 'operational-errors.json'

    Write-JsonArray -Rows $PlanRows -Path $PlanJson
    $PlanRows | Export-Csv -LiteralPath $PlanCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $ArtifactRows -Path $ArtifactsJson
    $ArtifactRows | Export-Csv -LiteralPath $ArtifactsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $CertificateRows -Path $CertificatesJson
    $CertificateRows | Export-Csv -LiteralPath $CertificatesCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $ChainRows -Path $ChainsJson
    $ChainRows | Export-Csv -LiteralPath $ChainsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $ImportAttemptRows -Path $AttemptsJson
    $ImportAttemptRows | Export-Csv -LiteralPath $AttemptsCsv -NoTypeInformation -Encoding UTF8
    Write-JsonArray -Rows $ErrorRows -Path $ErrorsJson

    $Summary = [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        PackageIdentity = $PackageIdentity
        PackageVersion = $PackageVersion
        Status = if (@($ErrorRows).Count -gt 0) { 'CompletedWithErrors' } else { 'Completed' }
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
        SourceP1ValidationDirectory = $P1ValidationDirectory
        OverallDisposition = $OverallDisposition
        Counts = [pscustomobject][ordered]@{
            ObservedP1Paths = @($ReadablePfxRows).Count
            LogicalArtifacts = @($PlanRows).Count
            ReadableArtifacts = $ReadableCount
            ImportedArtifacts = $ImportedCount
            PasswordlessPrivateKeyArtifacts = $PasswordlessPrivateKeyCount
            CertificateOnlyArtifacts = $CertificateOnlyCount
            PasswordRequiredOrUnsupportedArtifacts = $PasswordRequiredCount
            UnavailableArtifacts = $UnavailableCount
            Certificates = @($CertificateRows).Count
            OperationalErrors = @($ErrorRows).Count
        }
        InterpretationBoundary = @(
            'Import attempts used only null and empty passwords and did not guess passwords.',
            'Ephemeral key storage was requested when supported.',
            'Private keys were not exported or used.',
            'Certificate chain building disabled revocation checking to avoid external network activity.',
            'A passwordless private-key container is an exposure lead until identity mapping and authentication impact are reproduced.',
            'Complete PFX bytes were not saved and in-memory buffers were cleared after processing.'
        )
        Safety = [pscustomobject][ordered]@{
            MaximumBytesPerArtifact = $MaximumBytesPerArtifact
            PasswordStates = @('NullPassword', 'EmptyPassword')
            PasswordGuessing = 'None'
            EphemeralKeyStorageFlags = [string]$ImportFlags
            PersistentCertificateStore = 'None'
            PrivateKeyExport = 'None'
            AuthenticationAttempts = 'None'
            CompleteContentSaved = $false
            RemoteFileChanges = 'None'
            RelayAttempts = 'None'
            RemoteExecution = 'None'
            OllamaActivity = 'None'
        }
    }

    $SummaryPath = Join-Path $OutputDirectory 'pkcs12-metadata-validation-summary.json'
    Write-JsonDocument -Document $Summary -Path $SummaryPath

    $ArtifactHtml = ($ArtifactRows | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f
            (Convert-HtmlText $_.ArtifactId),
            (Convert-HtmlText $_.LogicalArtifactKey),
            (Convert-HtmlText $_.ImportSucceeded),
            (Convert-HtmlText $_.CertificateCount),
            (Convert-HtmlText $_.PrivateKeyCertificateCount),
            (Convert-HtmlText $_.OverallDisposition)
    }) -join "`n"

    $CertificateHtml = ($CertificateRows | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f
            (Convert-HtmlText $_.ArtifactId),
            (Convert-HtmlText $_.CertificateIndex),
            (Convert-HtmlText $_.Subject),
            (Convert-HtmlText $_.ValidityState),
            (Convert-HtmlText $_.HasPrivateKey),
            (Convert-HtmlText $_.EnhancedKeyUsages)
    }) -join "`n"

    $ReportPath = Join-Path $OutputDirectory 'MSADPT-SMB-PKCS12-Metadata-Validation.html'
    $Html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>MSADPT SMB PKCS#12 Metadata Validation</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#17202a}
h1,h2{color:#0b5cab}.card{border:1px solid #ccd6dd;border-radius:8px;padding:16px;margin:14px 0}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd6dd;padding:8px;text-align:left;vertical-align:top}
th{background:#eaf2f8}.note{color:#5d6d7e}
</style>
</head>
<body>
<h1>MSADPT SMB PKCS#12 Metadata Validation</h1>
<div class="card">
<b>Disposition:</b> $(Convert-HtmlText $OverallDisposition)<br>
<b>Observed P1 paths:</b> $(@($ReadablePfxRows).Count)<br>
<b>Logical artifacts:</b> $(@($PlanRows).Count)<br>
<b>Readable artifacts:</b> $ReadableCount<br>
<b>Imported artifacts:</b> $ImportedCount<br>
<b>Passwordless private-key artifacts:</b> $PasswordlessPrivateKeyCount<br>
<b>Certificates:</b> $(@($CertificateRows).Count)<br>
<b>Password guessing:</b> None<br>
<b>Private-key export:</b> None<br>
<b>Authentication attempts:</b> None<br>
<b>Complete contents saved:</b> No<br>
<b>Remote changes:</b> None
</div>
<h2>Artifact Results</h2>
<table><tr><th>Artifact</th><th>Logical key</th><th>Imported</th><th>Certificates</th><th>Private keys</th><th>Disposition</th></tr>$ArtifactHtml</table>
<h2>Certificate Metadata</h2>
<table><tr><th>Artifact</th><th>Index</th><th>Subject</th><th>Validity</th><th>Private key</th><th>EKUs</th></tr>$CertificateHtml</table>
<h2>Evidence</h2>
<ul>
<li><a href="pkcs12-validation-plan.csv">Validation plan</a></li>
<li><a href="pkcs12-artifact-results.csv">Artifact results</a></li>
<li><a href="pkcs12-certificate-metadata.csv">Certificate metadata</a></li>
<li><a href="pkcs12-chain-results.csv">Chain results</a></li>
<li><a href="pkcs12-import-attempts.csv">Import attempts</a></li>
<li><a href="operational-errors.json">Operational errors</a></li>
<li><a href="pkcs12-metadata-validation-summary.json">Summary</a></li>
</ul>
<p class="note">No PFX bytes, passwords, or private keys are retained. A reusable credential impact requires separate evidence-driven validation.</p>
</body>
</html>
"@

    [IO.File]::WriteAllText(
        $ReportPath,
        $Html,
        (New-Object Text.UTF8Encoding($false))
    )

    $Files = @(
        Get-ChildItem -LiteralPath $OutputDirectory -File |
            Where-Object { $_.Name -ne 'evidence-manifest.json' } |
            Sort-Object Name
    )
    $ManifestRows = [object[]]@(
        foreach ($File in $Files) {
            [pscustomobject]@{
                Name = $File.Name
                Size = [int64]$File.Length
                SHA256 = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
            }
        }
    )
    $ManifestPath = Join-Path $OutputDirectory 'evidence-manifest.json'
    Write-JsonDocument -Document ([pscustomobject]@{
        SchemaVersion = '1.0'
        Status = 'Completed'
        FileCount = @($ManifestRows).Count
        Files = $ManifestRows
    }) -Path $ManifestPath

    Write-Step -Status 'DONE' -Message "PKCS12 validation complete: observed-paths=$(@($ReadablePfxRows).Count), logical=$(@($PlanRows).Count), readable=$ReadableCount, imported=$ImportedCount, passwordless-private-key=$PasswordlessPrivateKeyCount, disposition=$OverallDisposition." -Color Green

    [pscustomobject][ordered]@{
        Status = if (@($ErrorRows).Count -gt 0) { 'PassedWithErrors' } else { 'Passed' }
        PackageIdentity = $PackageIdentity
        PackageVersion = $PackageVersion
        OverallDisposition = $OverallDisposition
        ObservedP1PathCount = @($ReadablePfxRows).Count
        LogicalArtifactCount = @($PlanRows).Count
        ReadableArtifactCount = $ReadableCount
        ImportedArtifactCount = $ImportedCount
        PasswordlessPrivateKeyArtifactCount = $PasswordlessPrivateKeyCount
        CertificateOnlyArtifactCount = $CertificateOnlyCount
        PasswordRequiredOrUnsupportedArtifactCount = $PasswordRequiredCount
        UnavailableArtifactCount = $UnavailableCount
        CertificateCount = @($CertificateRows).Count
        OperationalErrorCount = @($ErrorRows).Count
        OutputDirectory = $OutputDirectory
        HtmlReportPath = $ReportPath
        SummaryPath = $SummaryPath
        ManifestPath = $ManifestPath
        MaximumBytesPerArtifact = $MaximumBytesPerArtifact
        PasswordGuessing = 'None'
        EphemeralKeyStorageFlags = [string]$ImportFlags
        PrivateKeyExport = 'None'
        AuthenticationAttempts = 'None'
        CompleteContentSaved = 'No'
        RemoteFileChanges = 'None'
        RelayAttempts = 'None'
        RemoteExecution = 'None'
        OllamaActivity = 'None'
    }
}
catch {
    Write-Step -Status 'FAIL' -Message $_.Exception.Message -Color Red
    throw
}
