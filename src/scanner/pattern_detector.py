"""YAML-based fast pattern detection for skill scanning."""

from __future__ import annotations

import re
import time
import uuid
from pathlib import Path

import yaml

from scanner.models import (
    CodeLocation,
    DetectionSource,
    Finding,
    LayerSummary,
    Severity,
    ThreatCategory,
)

_RULES_PATH = Path(__file__).parent.parent.parent / "rules" / "patterns.yml"


def _load_rules(path: Path = _RULES_PATH) -> list[dict]:
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("rules", [])


def _severity_from_str(s: str) -> Severity:
    return Severity(s.lower())


def _category_from_str(s: str) -> ThreatCategory:
    return ThreatCategory(s.lower())


def _compile_rule(rule: dict) -> re.Pattern | None:
    if "regex" in rule:
        flags = re.IGNORECASE if rule.get("ignore_case", True) else 0
        if rule.get("multiline", False):
            flags |= re.DOTALL
        return re.compile(rule["regex"], flags)
    return None


def scan_content(
    content: str,
    filename: str,
    rules: list[dict] | None = None,
) -> list[Finding]:
    """Run pattern-based detection on raw content."""
    if rules is None:
        rules = _load_rules()

    findings: list[Finding] = []
    lines = content.splitlines()

    for rule in rules:
        pattern = _compile_rule(rule)
        literals = rule.get("literals", [])
        ignore_case = rule.get("ignore_case", True)

        matches: list[tuple[int, int, str]] = []  # (line_start, line_end, matched_text)

        if pattern:
            for m in pattern.finditer(content):
                line_start = content[: m.start()].count("\n") + 1
                snippet = lines[line_start - 1] if line_start <= len(lines) else m.group()
                matches.append((line_start, line_start, snippet.strip()))

        for literal in literals:
            search = literal.lower() if ignore_case else literal
            haystack = content.lower() if ignore_case else content
            start = 0
            while True:
                idx = haystack.find(search, start)
                if idx == -1:
                    break
                line_start = content[:idx].count("\n") + 1
                snippet = lines[line_start - 1] if line_start <= len(lines) else literal
                matches.append((line_start, line_start, snippet.strip()))
                start = idx + len(literal)

        # Deduplicate matches by line
        seen_lines: set[int] = set()
        for line_start, line_end, snippet in matches:
            if line_start in seen_lines:
                continue
            seen_lines.add(line_start)

            # Apply exclusion patterns to reduce false positives
            exclusions = rule.get("exclude_patterns", [])
            if any(re.search(exc, snippet, re.IGNORECASE) for exc in exclusions):
                continue

            findings.append(
                Finding(
                    id=f"pat-{uuid.uuid4().hex[:8]}",
                    title=rule["title"],
                    description=rule["description"],
                    category=_category_from_str(rule["category"]),
                    severity=_severity_from_str(rule["severity"]),
                    source=DetectionSource.PATTERN,
                    confidence=rule.get("confidence", 0.75),
                    location=CodeLocation(
                        file=filename,
                        line_start=line_start,
                        line_end=line_end,
                        snippet=snippet[:200],
                    ),
                    evidence=snippet[:300],
                    remediation=rule.get("remediation"),
                    rule_id=rule.get("id"),
                )
            )

    return findings


def scan_files(file_map: dict[str, str]) -> tuple[list[Finding], LayerSummary]:
    """
    Scan a map of {filename: content} with pattern rules.

    Returns (findings, layer_summary).
    """
    start = time.perf_counter()
    rules = _load_rules()
    all_findings: list[Finding] = []

    for filename, content in file_map.items():
        all_findings.extend(scan_content(content, filename, rules))

    duration_ms = (time.perf_counter() - start) * 1000
    summary = LayerSummary(
        layer=DetectionSource.PATTERN,
        findings_count=len(all_findings),
        duration_ms=round(duration_ms, 2),
    )
    return all_findings, summary
