"""YARA-based detection for skill scanning."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

import yara

from scanner.models import (
    CodeLocation,
    DetectionSource,
    Finding,
    LayerSummary,
    Severity,
    ThreatCategory,
)

_RULES_DIR = Path(__file__).parent.parent.parent / "rules"

_YARA_FILES = {
    "prompt_injection": _RULES_DIR / "prompt_injection.yar",
    "data_exfiltration": _RULES_DIR / "data_exfiltration.yar",
    "malicious_code": _RULES_DIR / "malicious_code.yar",
}

# Maps YARA namespace → ThreatCategory
_NAMESPACE_CATEGORY: dict[str, ThreatCategory] = {
    "prompt_injection": ThreatCategory.PROMPT_INJECTION,
    "data_exfiltration": ThreatCategory.DATA_EXFILTRATION,
    "malicious_code": ThreatCategory.MALICIOUS_CODE,
}

# Maps YARA rule meta severity tags to Severity enum
_META_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _compile_rules() -> yara.Rules:
    sources: dict[str, str] = {}
    for namespace, path in _YARA_FILES.items():
        if path.exists():
            sources[namespace] = str(path)
    if not sources:
        raise FileNotFoundError(f"No YARA rule files found in {_RULES_DIR}")
    return yara.compile(filepaths=sources)


def _extract_meta(match: Any, key: str, default: Any = None) -> Any:
    return match.meta.get(key, default)


def _match_to_finding(
    match: Any,
    namespace: str,
    filename: str,
    content: str,
) -> list[Finding]:
    """Convert a single YARA match to one Finding per string match."""
    category = _NAMESPACE_CATEGORY.get(namespace, ThreatCategory.MALICIOUS_CODE)
    severity_str = _extract_meta(match, "severity", "medium")
    severity = _META_SEVERITY.get(severity_str.lower(), Severity.MEDIUM)
    confidence = float(_extract_meta(match, "confidence", "0.80"))
    title = _extract_meta(match, "title", match.rule)
    description = _extract_meta(match, "description", f"YARA rule '{match.rule}' matched.")
    remediation = _extract_meta(match, "remediation", None)

    lines = content.splitlines()
    findings: list[Finding] = []

    # Group matches by offset to avoid redundant findings for the same location
    seen_offsets: set[int] = set()
    for string_match in match.strings:
        for instance in string_match.instances:
            offset = instance.offset
            if offset in seen_offsets:
                continue
            seen_offsets.add(offset)

            line_start = content[:offset].count("\n") + 1
            snippet_line = lines[line_start - 1].strip() if line_start <= len(lines) else ""
            matched_data = instance.matched_data.decode("utf-8", errors="replace")

            findings.append(
                Finding(
                    id=f"yara-{uuid.uuid4().hex[:8]}",
                    title=title,
                    description=description,
                    category=category,
                    severity=severity,
                    source=DetectionSource.YARA,
                    confidence=min(confidence, 1.0),
                    location=CodeLocation(
                        file=filename,
                        line_start=line_start,
                        snippet=snippet_line[:200],
                    ),
                    evidence=matched_data[:300],
                    remediation=remediation,
                    rule_id=f"{namespace}/{match.rule}",
                )
            )

    return findings


def scan_content(
    content: str,
    filename: str,
    compiled_rules: yara.Rules | None = None,
) -> list[Finding]:
    """Run YARA rules against raw content string."""
    if compiled_rules is None:
        compiled_rules = _compile_rules()

    try:
        matches = compiled_rules.match(data=content.encode("utf-8", errors="replace"))
    except yara.Error:
        return []

    findings: list[Finding] = []
    for match in matches:
        findings.extend(_match_to_finding(match, match.namespace, filename, content))

    return findings


def scan_files(file_map: dict[str, str]) -> tuple[list[Finding], LayerSummary]:
    """
    Scan a map of {filename: content} with YARA rules.

    Returns (findings, layer_summary).
    """
    start = time.perf_counter()
    error: str | None = None

    try:
        compiled = _compile_rules()
    except Exception as e:
        error = str(e)
        duration_ms = (time.perf_counter() - start) * 1000
        return [], LayerSummary(
            layer=DetectionSource.YARA,
            findings_count=0,
            duration_ms=round(duration_ms, 2),
            error=error,
        )

    all_findings: list[Finding] = []
    for filename, content in file_map.items():
        all_findings.extend(scan_content(content, filename, compiled))

    duration_ms = (time.perf_counter() - start) * 1000
    summary = LayerSummary(
        layer=DetectionSource.YARA,
        findings_count=len(all_findings),
        duration_ms=round(duration_ms, 2),
        error=error,
    )
    return all_findings, summary
