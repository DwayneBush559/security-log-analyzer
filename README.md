# Security Log Analyzer + Secure AI Incident Response Copilot

A Python cybersecurity project that detects suspicious log activity and adds a grounded AI incident-response layer on top of those findings.

The project is intentionally built in stages so each AI component can be measured and tested instead of hiding everything behind a chatbot interface.

## What the security analyzer detects

- repeated failed logins
- possible brute-force activity
- SQL-injection strings
- path traversal
- basic script-injection patterns

Analyzer output is structured JSON so it can feed another script, dashboard, or incident-response workflow.

## AI incident-response copilot

The copilot retrieves approved security runbooks and only answers when there is enough supporting evidence.

Current capabilities:

- grounded retrieval over incident-response runbooks
- source citations and retrieval scores
- minimum-evidence gate for unsupported questions
- prompt-injection detection
- secret redaction
- deterministic evaluation harness
- responder interface designed for an IBM Granite LLM adapter

### Current architecture

```text
Analyst question / security finding
              |
              v
     Prompt-injection guard
              |
              v
       Runbook retriever
              |
              v
       Evidence threshold
              |
              v
     Response generation
              |
              v
      Secret redaction
              |
              v
   Answer + source citations
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and next milestones.

## Why this is an AI-engineering project

The goal is not just to call an LLM API. The project separates and tests the parts that matter in a production AI system:

- retrieval quality
- grounding
- safety controls
- model abstraction
- evaluation
- observability through citations and scores

The first milestone uses a deterministic responder so retrieval and safety behavior can be tested reliably in CI. The next phase replaces that responder with IBM Granite while preserving the same testable interface.

## Run the log analyzer

```bash
python analyzer.py sample.log
```

## Run the tests

```bash
python -m unittest discover -v
```

## Run the AI evaluation harness

```bash
python run_eval.py
```

The current evaluation checks retrieval hit@1 for representative incidents and whether known prompt-injection attempts are blocked.

## Roadmap

- IBM Granite generation adapter
- semantic embedding retrieval
- chunk-level source citations
- hallucination / faithfulness evaluations
- tool calling into the log analyzer
- role-aware access control
- audit logging
- API service and lightweight analyst UI

## Skills demonstrated

- Python
- cybersecurity detection engineering
- retrieval-augmented generation architecture
- AI safety / prompt-injection defenses
- evaluation-driven AI development
- secure API and data handling concepts
- automated testing and GitHub Actions

## Author

**Dwayne Dwight Bush**  
Software Development • Cybersecurity • AI Systems
