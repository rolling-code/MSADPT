<# .SYNOPSIS Creates neutral offline AD Unicode identity fixtures. .NOTES Version: 1.0.0 #>
[CmdletBinding()]param([Parameter(Mandatory=$true)][string]$OutputPath)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$Zws=[char]0x200B;$Zwj=[char]0x200C;$FullWidthA=[char]0xFF21
$Objects=@(
[pscustomobject]@{ObjectGuid='00000000-0000-0000-0000-000000000001';ObjectSid='S-1-5-21-111-222-333-1001';DistinguishedName='CN=ServiceA,DC=example,DC=test';ObjectClass='user';sAMAccountName='ServiceA';userPrincipalName='servicea@example.test';servicePrincipalName=@('HTTP/app.example.test');cn='ServiceA';name='ServiceA';displayName='Service A';dNSHostName=$null},
[pscustomobject]@{ObjectGuid='00000000-0000-0000-0000-000000000002';ObjectSid='S-1-5-21-111-222-333-1002';DistinguishedName='CN=ServiceHidden,DC=example,DC=test';ObjectClass='user';sAMAccountName=('Ser'+$Zws+'viceA');userPrincipalName=('service'+$Zwj+'a@example.test');servicePrincipalName=@(('HTTP/app'+$Zws+'.example.test'));cn=('Service'+$Zws+'A');name='ServiceHidden';displayName='Service Hidden';dNSHostName=$null},
[pscustomobject]@{ObjectGuid='00000000-0000-0000-0000-000000000003';ObjectSid='S-1-5-21-111-222-333-1003';DistinguishedName='CN=FullWidth,DC=example,DC=test';ObjectClass='user';sAMAccountName=($FullWidthA+'dmin');userPrincipalName='fullwidth@example.test';servicePrincipalName=@();cn='FullWidth';name='FullWidth';displayName='Full Width';dNSHostName=$null},
[pscustomobject]@{ObjectGuid='00000000-0000-0000-0000-000000000004';ObjectSid='S-1-5-21-111-222-333-1004';DistinguishedName='CN=Admin,DC=example,DC=test';ObjectClass='user';sAMAccountName='Admin';userPrincipalName='admin@example.test';servicePrincipalName=@();cn='Admin';name='Admin';displayName='Admin';dNSHostName=$null}
)
$Objects|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $OutputPath -Encoding UTF8
[pscustomobject]@{Status='Completed';ObjectCount=$Objects.Count;OutputPath=$OutputPath}
