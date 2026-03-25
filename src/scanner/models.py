"""Pydantic models for the skills-scanner-skill."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    MALICIOUS_CODE = "malicious_code"
    SUPPLY_CHAIN = "supply_chain"
    INFORMATION_DISCLOSURE = "information_disclosure"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return self == other or self < other


class DetectionSource(str, Enum):
    PATTERN = "pattern"
    YARA = "yara"
    DATAFLOW = "dataflow"
    LLM = "llm"


class CodeLocation(BaseModel):
    file: str
    line_start: int | None = None
    line_end: int | None = None
    column: int | None = None
    snippet: str | None = None

    def __str__(self) -> str:
        loc = self.file
        if self.line_start is not None:
            loc += f":{self.line_start}"
            if self.line_end and self.line_end != self.line_start:
                loc += f"-{self.line_end}"
        return loc


class Finding(BaseModel):
    """A single detected security issue."""

    id: str = Field(description="Unique finding identifier (slug)")
    title: str
    description: str
    category: ThreatCategory
    severity: Severity
    source: DetectionSource
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence [0,1]")
    location: CodeLocation | None = None
    evidence: str | None = Field(None, description="Matched text or code excerpt")
    remediation: str | None = None
    rule_id: str | None = Field(None, description="YARA/pattern rule that triggered this finding")
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("confidence")
    @classmethod
    def round_confidence(cls, v: float) -> float:
        return round(v, 3)


class ScanTarget(BaseModel):
    """Describes what was scanned."""

    path: str
    resolved_files: list[str] = Field(default_factory=list)
    total_files: int = 0
    skipped_files: list[str] = Field(default_factory=list)
    scan_duration_ms: float = 0.0


class LayerSummary(BaseModel):
    layer: DetectionSource
    findings_count: int
    duration_ms: float
    error: str | None = None


class ScanReport(BaseModel):
    """Complete security scan report."""

    scan_id: str
    target: ScanTarget
    findings: list[Finding] = Field(default_factory=list)
    layer_summaries: list[LayerSummary] = Field(default_factory=list)

    # Aggregated stats
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    overall_risk: Severity = Severity.INFO
    verdict: str = "PASS"  # PASS | WARN | FAIL
    summary: str = ""

    layers_enabled: list[DetectionSource] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        self._recompute_stats()

    def _recompute_stats(self) -> None:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        self.critical_count = counts[Severity.CRITICAL]
        self.high_count = counts[Severity.HIGH]
        self.medium_count = counts[Severity.MEDIUM]
        self.low_count = counts[Severity.LOW]
        self.info_count = counts[Severity.INFO]

        if self.critical_count > 0:
            self.overall_risk = Severity.CRITICAL
            self.verdict = "FAIL"
        elif self.high_count > 0:
            self.overall_risk = Severity.HIGH
            self.verdict = "FAIL"
        elif self.medium_count > 0:
            self.overall_risk = Severity.MEDIUM
            self.verdict = "WARN"
        elif self.low_count > 0:
            self.overall_risk = Severity.LOW
            self.verdict = "WARN"
        else:
            self.overall_risk = Severity.INFO
            self.verdict = "PASS"


class ScanRequest(BaseModel):
    """HTTP request body for /scan endpoint."""

    skill_path: str
    layers: list[DetectionSource] = Field(
        default_factory=lambda: list(DetectionSource)
    )
    severity_threshold: Severity = Severity.LOW
    max_file_size_kb: int = 512


class SnippetScanRequest(BaseModel):
    """HTTP request body for /scan/snippet endpoint."""

    content: str
    language: str = "auto"
    layers: list[DetectionSource] = Field(
        default_factory=lambda: [
            DetectionSource.PATTERN,
            DetectionSource.YARA,
            DetectionSource.LLM,
        ]
    )
