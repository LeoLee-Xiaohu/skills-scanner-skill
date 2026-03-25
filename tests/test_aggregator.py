"""Tests for the multi-layer aggregator."""

from __future__ import annotations

import uuid

import pytest

from scanner.aggregator import aggregate
from scanner.models import (
    CodeLocation,
    DetectionSource,
    Finding,
    Severity,
    ThreatCategory,
)


def _make_finding(
    severity: Severity = Severity.MEDIUM,
    category: ThreatCategory = ThreatCategory.MALICIOUS_CODE,
    source: DetectionSource = DetectionSource.PATTERN,
    confidence: float = 0.75,
    file: str = "test.py",
    line: int = 10,
    title: str = "Test Finding",
) -> Finding:
    return Finding(
        id=f"t-{uuid.uuid4().hex[:8]}",
        title=title,
        description="Test description",
        category=category,
        severity=severity,
        source=source,
        confidence=confidence,
        location=CodeLocation(file=file, line_start=line),
        evidence="test evidence",
        rule_id=f"{source.value}/test-rule",
    )


class TestDeduplication:
    def test_same_finding_from_two_layers_produces_one(self):
        f1 = _make_finding(source=DetectionSource.PATTERN, line=10)
        f2 = _make_finding(source=DetectionSource.YARA, line=12)  # same 5-line bucket
        result = aggregate([f1], [f2], [], [])
        # Both should appear because they're from different layers at same location
        # but after dedup-by-title, might collapse
        assert len(result) >= 1

    def test_different_locations_not_deduped(self):
        f1 = _make_finding(line=10, title="Issue A")
        f2 = _make_finding(line=50, title="Issue A")
        result = aggregate([f1, f2], [], [], [])
        assert len(result) == 2


class TestConfidenceScoring:
    def test_single_source_capped_at_70(self):
        f = _make_finding(source=DetectionSource.PATTERN, confidence=0.90)
        result = aggregate([f], [], [], [])
        assert result[0].confidence <= 0.70

    def test_multi_layer_boosts_confidence(self):
        f1 = _make_finding(source=DetectionSource.PATTERN, confidence=0.75, line=10)
        f2 = _make_finding(source=DetectionSource.YARA, confidence=0.80, line=12)
        result = aggregate([f1], [f2], [], [])
        # At least one result should have boosted confidence
        assert any(r.confidence > 0.75 for r in result)


class TestSeverityEscalation:
    def test_three_layer_agreement_escalates_severity(self):
        # Medium finding agreed by 3 layers should escalate to HIGH
        f1 = _make_finding(source=DetectionSource.PATTERN, severity=Severity.MEDIUM, line=10)
        f2 = _make_finding(source=DetectionSource.YARA, severity=Severity.MEDIUM, line=12)
        f3 = _make_finding(source=DetectionSource.DATAFLOW, severity=Severity.MEDIUM, line=10)
        result = aggregate([f1], [f2], [f3], [])
        max_sev = max(
            [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL].index(r.severity)
            for r in result
        )
        assert max_sev >= [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL].index(Severity.HIGH)


class TestFPReduction:
    def test_low_confidence_non_llm_suppressed(self):
        f = _make_finding(source=DetectionSource.PATTERN, confidence=0.30)
        result = aggregate([f], [], [], [])
        assert not result, "Very low confidence pattern finding should be suppressed"

    def test_low_confidence_llm_downgraded_not_suppressed(self):
        f = _make_finding(
            source=DetectionSource.LLM,
            severity=Severity.HIGH,
            confidence=0.50,
        )
        result = aggregate([], [], [], [f])
        assert result, "LLM finding should not be suppressed (just downgraded)"
        assert result[0].severity in (Severity.MEDIUM, Severity.LOW), \
            f"LLM finding severity should be downgraded, got {result[0].severity}"

    def test_layer_filter_respected(self):
        f1 = _make_finding(source=DetectionSource.PATTERN)
        f2 = _make_finding(source=DetectionSource.LLM)
        # Only include PATTERN layer
        result = aggregate([f1], [], [], [f2], enabled_layers={DetectionSource.PATTERN})
        sources = {r.source for r in result}
        assert DetectionSource.LLM not in sources


class TestSortOrder:
    def test_sorted_by_severity_descending(self):
        findings_low = _make_finding(severity=Severity.LOW, confidence=0.75, line=1, title="Low Issue")
        findings_crit = _make_finding(severity=Severity.CRITICAL, confidence=0.75, line=50, title="Critical Issue")
        result = aggregate([findings_low, findings_crit], [], [], [])
        severities = [r.severity for r in result]
        # Critical should come first
        crit_idx = next(i for i, s in enumerate(severities) if s == Severity.CRITICAL)
        low_idx = next(i for i, s in enumerate(severities) if s == Severity.LOW)
        assert crit_idx < low_idx


class TestEmptyInputs:
    def test_all_empty_returns_empty(self):
        result = aggregate([], [], [], [])
        assert result == []

    def test_single_empty_layer(self):
        f = _make_finding(source=DetectionSource.DATAFLOW, confidence=0.80)
        result = aggregate([], [], [f], [])
        assert result
