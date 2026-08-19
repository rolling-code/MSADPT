# MSADPT Public Release Checklist

## Code admission
- Only fully refactored files are admitted.
- Every PowerShell file parses without errors.
- Executable modules have manifests, prerequisites, outputs, limitations, and execution classes.
- No placeholders, pasted-core comments, hard-coded targets, or incomplete functions remain.
- Read-only collectors are separated from authenticated validation and active testing.

## Evidence and privacy
- Engagements, evidence, reasoning records, ledgers, transcripts, and backups are excluded.
- Organization-specific patterns are kept in a local ignored configuration, not public source.
- Synthetic examples use example.test and documentation-safe identifiers.
- Repository sanitization results are manually reviewed.
- Staged Git content is inspected before commit.

## LLM controls
- Model output is JSON only.
- Thinking is disabled for structured decisions.
- Decisions are schema and policy validated.
- Only registered eligible modules can be selected.
- Completed modules cannot be repeated.
- Targets and evidence references must be present in the package.
- LLM-generated commands and code are never executed.

## Release validation
- Offline regression suite passes without Ollama.
- Live synthetic Ollama selection passes.
- Synthetic attack-path hypothesis test passes.
- No live AD access is needed for CI.
- Documentation covers installation, Ollama, Hugging Face fallback, architecture, safety, and troubleshooting.
