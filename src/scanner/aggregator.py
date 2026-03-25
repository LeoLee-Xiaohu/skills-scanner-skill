"""
Multi-layer result aggregator with false-positive reduction.

Combines findings from pattern, YARA, dataflow, and LLM layers.
Uses a confidence-boosting strategy: when multiple layers flag the same
location/category, confidence is increased and severity can be escalated.
Lone low-confidence findings are downgraded or suppressed.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

from scanner.models import (
    DetectionSource,
    Finding,
    Severity,
    ThreatCategory,
)

# Confidence thresholds
_SUPPRESS_BELOW = 0.40      # Drop findings with confidence < this (unless LLM)
_SINGLE_SOURCE_CAP = 0.70   # Single-source findings capped at this confidence
_MULTI_SOURCE_BOOST = 0.15  # Added confidence per additional corroborating layer

# LLM findings below this threshold are downgraded one severity level
_LLM_DOWNGRADE_BELOW = 0.65


def _location_key(finding: Finding) -> str:
    """Stable key based on category + approximate location (file + line bucket)."""
    file = finding.location.file if finding.location else "unknown"
    line = finding.location.line_start if finding.location and finding.location.line_start else 0
    # Bucket to 5-line windows to group nearby findings
    bucket = (line // 5) * 5
    return f"{finding.category.value}::{file}::{bucket}"


def _severity_index(s: Severity) -> int:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return order.index(s)


def _bump_severity(s: Severity, levels: int = 1) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = min(_severity_index(s) + levels, len(order) - 1)
    return order[idx]


def _downgrade_severity(s: Severity, levels: int = 1) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = max(_severity_index(s) - levels, 0)
    return order[idx]


def _deduplicate_within_layer(findings: list[Finding]) -> list[Finding]:
    """Remove exact duplicates (same rule_id + file + line) within a single layer."""
    seen: set[str] = set()
    result: list[Finding] = []
    for f in findings:
        key = hashlib.md5(
            f"{f.rule_id}::{f.location}::{f.title}".encode()
        ).hexdigest()
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def aggregate(
    pattern_findings: list[Finding],
    yara_findings: list[Finding],
    dataflow_findings: list[Finding],
    llm_findings: list[Finding],
    enabled_layers: set[DetectionSource] | None = None,
) -> list[Finding]:
    """
    Merge findings from all layers, apply corroboration scoring, and reduce FPs.

    Returns a deduplicated, confidence-scored, severity-adjusted list of Findings,
    sorted by severity descending.
    """
    if enabled_layers is None:
        enabled_layers = set(DetectionSource)

    # Step 1: Gather all findings, dedup within each layer
    by_layer: dict[DetectionSource, list[Finding]] = {
        DetectionSource.PATTERN: _deduplicate_within_layer(pattern_findings),
        DetectionSource.YARA: _deduplicate_within_layer(yara_findings),
        DetectionSource.DATAFLOW: _deduplicate_within_layer(dataflow_findings),
        DetectionSource.LLM: _deduplicate_within_layer(llm_findings),
    }

    # Step 2: Group findings by location key across layers
    groups: dict[str, list[Finding]] = defaultdict(list)
    for layer, findings in by_layer.items():
        if layer not in enabled_layers:
            continue
        for f in findings:
            groups[_location_key(f)].append(f)

    # Step 3: Apply FP-reduction and corroboration logic per group
    final: list[Finding] = []
    for key, group in groups.items():
        layers_in_group = {f.source for f in group}
        corroboration_count = len(layers_in_group)

        for f in group:
            f = f.model_copy()  # don't mutate originals

            # Downgrade single low-confidence LLM findings
            if f.source == DetectionSource.LLM and f.confidence < _LLM_DOWNGRADE_BELOW:
                f = f.model_copy(update={"severity": _downgrade_severity(f.severity)})

            # Suppress very low confidence non-LLM findings
            if f.source != DetectionSource.LLM and f.confidence < _SUPPRESS_BELOW:
                continue

            # Cap single-source confidence
            adjusted_confidence = f.confidence
            if corroboration_count == 1:
                adjusted_confidence = min(adjusted_confidence, _SINGLE_SOURCE_CAP)
            else:
                # Boost confidence for each corroborating layer beyond the first
                boost = _MULTI_SOURCE_BOOST * (corroboration_count - 1)
                adjusted_confidence = min(adjusted_confidence + boost, 1.0)

            # Escalate severity if ≥3 layers agree
            adjusted_severity = f.severity
            if corroboration_count >= 3:
                adjusted_severity = _bump_severity(f.severity, levels=1)

            f = f.model_copy(
                update={
                    "confidence": round(adjusted_confidence, 3),
                    "severity": adjusted_severity,
                }
            )
            final.append(f)

    # Step 4: Remove cross-layer duplicates (keep highest confidence per location key)
    seen_keys: dict[str, Finding] = {}
    for f in final:
        loc_key = f"{f.category.value}::{f.location}::{f.title[:30]}"
        existing = seen_keys.get(loc_key)
        if existing is None or f.confidence > existing.confidence:
            seen_keys[loc_key] = f

    deduplicated = list(seen_keys.values())

    # Step 5: Sort by severity DESC, confidence DESC
    deduplicated.sort(
        key=lambda f: (_severity_index(f.severity), f.confidence),
        reverse=True,
    )
    return deduplicated
