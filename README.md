# Security Log Analyzer

A compact Python command-line tool that scans text logs for common security signals and produces structured findings.

## What it detects

- repeated failed logins
- possible brute-force activity
- SQL-injection strings
- path traversal
- basic script-injection patterns

The output is structured JSON so the findings can be consumed by another script, dashboard, or incident-response workflow.

## Skills demonstrated

- Python
- Cybersecurity detection logic
- Log parsing
- Regular expressions
- Severity scoring
- Structured JSON output
- Unit testing

## Run it

```bash
python analyzer.py sample.log
```

## Test it

```bash
python -m unittest test_analyzer.py
```

## Scope

This is intentionally a small portfolio project, not a replacement for a SIEM. The goal is to demonstrate how raw log data can be transformed into testable security findings with clear detection rules.

## Author

**Dwayne Dwight Bush**  
Software Development • Cybersecurity • AI Systems
