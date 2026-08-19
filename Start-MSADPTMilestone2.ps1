<# .SYNOPSIS Runs one stateful MSADPT Milestone 2.1 cycle. .VERSION 0.2.0 #>
[CmdletBinding()]param([string]$EngagementPath,[ValidateSet('Ollama','Deterministic')][string]$Provider='Deterministic',[string]$OllamaUri='http://localhost:11434',[string]$Model='qwen3.5:9b',[PSCredential]$Credential,[switch]$DryRun)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';Import-Module (Join-Path $PSScriptRoot 'Controller\MSADPT.Reasoning.psm1') -Force
$p=@{MSADPTRoot=$PSScriptRoot;Provider=$Provider;OllamaUri=$OllamaUri;Model=$Model;DryRun=$DryRun};if($EngagementPath){$p.EngagementPath=$EngagementPath};if($Credential){$p.Credential=$Credential};Invoke-MSADPTReasoningCycle @p
