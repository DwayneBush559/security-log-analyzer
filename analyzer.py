"""Security log analyzer for common web and authentication signals."""

from dataclasses import asdict, dataclass
import json
import re
from typing import Iterable

RULES = (
    ("failed_login", re.compile(r"failed login|authentication failed", re.I), 2),
    ("sql_injection", re.compile(r"(union\s+select|or\s+1=1|drop\s+table)", re.I), 5),
    ("path_traversal", re.compile(r"\.\./|\.\.\\", re.I), 4),
    ("script_injection", re.compile(r"<script|javascript:", re.I), 4),
)


@dataclass(frozen=True)
class Finding:
    line_number: int
    rule: str
    severity: str
    score: int
    evidence: str


def severity_for(score: int) -> str:
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def analyze_lines(lines: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    failed_by_ip: dict[str, int] = {}

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\n")
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        ip = ip_match.group(0) if ip_match else "unknown"

        for rule_name, pattern, score in RULES:
            if pattern.search(line):
                findings.append(
                    Finding(
                        line_number=line_number,
                        rule=rule_name,
                        severity=severity_for(score),
                        score=score,
                        evidence=line[:180],
                    )
                )
                if rule_name == "failed_login":
                    failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

    for ip, count in sorted(failed_by_ip.items()):
        if ip != "unknown" and count >= 3:
            findings.append(
                Finding(
                    line_number=0,
                    rule="possible_brute_force",
                    severity="high",
                    score=5,
                    evidence=f"{count} failed logins from {ip}",
                )
            )

    return findings


def analyze_file(path: str) -> list[Finding]:
    with open(path, "r", encoding="utf-8") as handle:
        return analyze_lines(handle)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Analyze a text log for simple security signals."
    )
    parser.add_argument("path")
    args = parser.parse_args()

    print(json.dumps([asdict(item) for item in analyze_file(args.path)], indent=2))
