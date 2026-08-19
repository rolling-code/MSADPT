<# .SYNOPSIS Scans publishable MSADPT files using neutral and optional local patterns. .VERSION 2.0.0 #>
[CmdletBinding()]param(
 [string]$MSADPTRoot=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
 [string]$LocalPatternPath=(Join-Path $PSScriptRoot 'sanitization-patterns.local.json')
)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$Patterns=New-Object 'System.Collections.Generic.List[object]'
$Patterns.Add([pscustomobject]@{name='Private IPv4';pattern='\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}(\.\d{1,3}){2}\b'})
$Patterns.Add([pscustomobject]@{name='Potential credential assignment';pattern='(?i)(password|token|secret|apikey|api_key)\s*=\s*[''\"][^''\"]+[''\"]'})
$Patterns.Add([pscustomobject]@{name='Corporate OneDrive path';pattern='(?i)OneDrive\s*-\s*[^\\/]+'})
if(Test-Path -LiteralPath $LocalPatternPath){$Local=Get-Content $LocalPatternPath -Raw|ConvertFrom-Json;foreach($Rule in @($Local.patterns)){$Patterns.Add($Rule)}}
$Excluded='\\(Engagements|Backups)\\|\\Tests\\Offline\\Results\\|sanitization-patterns\.(local|example)\.json$|github-sanitization-findings\.csv$|Test-MSADPTGitHubSanitization(\.ps1|V2\.ps1)$|MSADPT_scan_network2( - Copy)?\.ps1(\.txt)?$'
$Extensions=@('.ps1','.psm1','.psd1','.json','.md','.txt','.yml','.yaml','.csv','.gitignore')
$Findings=New-Object 'System.Collections.Generic.List[object]'
Write-Host '[INFO] Scanner excludes generated evidence, local/example pattern definitions, superseded sanitizers, and legacy network scanner files not admitted to the public release.' -ForegroundColor Cyan
foreach($File in @(Get-ChildItem $MSADPTRoot -File -Recurse|Where-Object{$Extensions-contains$_.Extension-or$_.Name-eq'.gitignore'})){
 if($File.FullName-match$Excluded){continue};$Number=0
 foreach($Line in Get-Content $File.FullName -ErrorAction SilentlyContinue){$Number++;foreach($Rule in $Patterns){if($Line-match[string]$Rule.pattern){$Findings.Add([pscustomobject]@{Rule=$Rule.name;File=$File.FullName.Substring($MSADPTRoot.Length).TrimStart('\');Line=$Number;Text=$Line.Trim()})}}}
}
$Out=Join-Path $MSADPTRoot 'github-sanitization-findings.csv';$Findings.ToArray()|Export-Csv $Out -NoTypeInformation -Encoding UTF8
if($Findings.Count){Write-Host ("[WARNING] {0} potential publication issues. Review {1}" -f $Findings.Count,$Out) -ForegroundColor Yellow;$Findings.ToArray()|Format-Table Rule,File,Line -AutoSize}else{Write-Host '[PASS] No configured publication patterns detected.' -ForegroundColor Green}
