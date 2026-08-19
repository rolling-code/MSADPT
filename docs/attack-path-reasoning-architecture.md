# MSADPT Attack-Path Reasoning Architecture

MSADPT separates collection, reasoning, validation, and execution.

1. Registered collectors produce structured evidence.
2. The evidence index records files, hashes, and supported capabilities.
3. The ledger prevents duplicate module execution.
4. The LLM receives only eligible modules and evidence-backed targets.
5. The LLM proposes a hypothesis or collection decision in JSON.
6. Deterministic code validates schemas, policy, targets, prerequisites, and completion state.
7. Only known entry points can execute.
8. Active or state-changing validation remains outside the autonomous read-only workflow.

An attack-path hypothesis is not a finding. It records confirmed relationships, missing prerequisites, limitations, and the shortest safe validation. Conclusions use Confirmed, Likely or probable, Inconclusive, Not detected, or Not applicable.
