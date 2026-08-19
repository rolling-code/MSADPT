# MSADPT Milestone 2.2 Offline Validation

This offline harness validates the local Ollama decision provider with synthetic evidence only. It performs no Active Directory query and does not execute assessment collectors.

## Run

From the repository root:

`& '.\On-Prem Active Directory\MSADPT\Tests\Offline\Invoke-MSADPTOfflineLLMValidation.ps1'`

## Expected behavior

The harness first runs deterministic contract regression cases, then asks the installed local model to choose one of two eligible synthetic read-only modules. The returned decision must be valid JSON, select a registered eligible module, avoid a completed module, use an evidence-backed target, and remain read-only.

## GitHub sanitization

Run:

`& '.\On-Prem Active Directory\MSADPT\Tests\Offline\Test-MSADPTGitHubSanitization.ps1'`

Review every finding before publishing. The scanner is a guardrail, not proof that a repository is fully sanitized.
