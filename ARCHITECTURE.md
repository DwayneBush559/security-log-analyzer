# Secure AI Incident Response Copilot — Architecture

## Goal

Turn security evidence into grounded incident-response guidance without allowing the model to invent unsupported procedures.

## Pipeline

1. **Security signal** — analyst question or finding from the existing log analyzer.
2. **Input guardrail** — reject common instruction-injection attempts.
3. **Retriever** — rank approved security runbooks against the question.
4. **Grounding gate** — answer only when retrieved evidence clears a minimum relevance score.
5. **Generator** — currently a deterministic baseline; the next phase plugs in IBM Granite.
6. **Output guardrail** — redact secrets before returning content.
7. **Citations** — return the runbook IDs used to ground the answer.
8. **Evaluation** — measure retrieval hit@1 and prompt-injection blocking.

## Why the baseline is deterministic

The first milestone isolates retrieval, security, grounding, and evaluation from model behavior. That gives the project measurable tests before an external LLM is introduced.

## Phase 2

Replace the baseline responder with an IBM Granite adapter while preserving the same interface and deterministic CI tests. Add:
- semantic embeddings
- chunk-level citations
- answer-faithfulness evaluation
- hallucination tests
- tool calling against the log analyzer
- role-aware access controls
- audit logging
