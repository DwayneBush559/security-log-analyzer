"""Input and output guardrails for the incident-response copilot."""

import re

INJECTION_PATTERNS = (
    re.compile(r"ignore (all|any|the|your)? ?(previous|prior) instructions", re.I),
    re.compile(r"(show|reveal|print).*(system prompt|hidden prompt|developer message)", re.I),
    re.compile(r"(disable|bypass).*(guardrail|safety|policy)", re.I),
)

SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_ -]?key\s*[:=]\s*)([^\s]+)"),
    re.compile(r"(?i)(password\s*[:=]\s*)([^\s]+)"),
    re.compile(r"(?i)(token\s*[:=]\s*)([^\s]+)"),
)


class UnsafePromptError(ValueError):
    pass


def validate_prompt(prompt: str) -> None:
    if any(pattern.search(prompt) for pattern in INJECTION_PATTERNS):
        raise UnsafePromptError("prompt contains a likely instruction-injection attempt")


def redact_secrets(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted
