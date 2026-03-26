"""
Skills Scanner Skill — FastAPI app + Typer CLI

Exposes:
  - POST /scan            → scan a local or remote skill directory
  - POST /scan/snippet    → scan a raw code/YAML snippet
  - GET  /health          → liveness check
  - GET  /openapi.json    → OpenAPI spec consumed by copilot-skillset.yml

CLI commands:
  skills-scanner scan <path>       → scan a local skill
  skills-scanner scan-snippet      → scan piped stdin
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from rich.console import Console
from rich.table import Table

load_dotenv()

# ── Local imports ─────────────────────────────────────────────────────────────
from scanner import aggregator
from scanner import dataflow_analyzer
from scanner import llm_judge
from scanner import pattern_detector
from scanner import yara_detector
from scanner.models import (
    DetectionSource,
    Finding,
    LayerSummary,
    ScanReport,
    ScanRequest,
    ScanTarget,
    Severity,
    SnippetScanRequest,
)

# ── Config ────────────────────────────────────────────────────────────────────
SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs", ".yml", ".yaml", ".json", ".toml", ".env", ".md", ".txt", ".sh"}

console = Console()
cli = typer.Typer(name="skills-scanner", help="Scan AI agent skills for security threats.")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Skills Scanner Skill",
    description=(
        "GitHub Copilot skill that detects prompt injection, data exfiltration, "
        "and malicious code patterns in AI agent skills."
    ),
    version="0.1.0",
)


# ── File loading ──────────────────────────────────────────────────────────────

def _load_skill_files(skill_path: str, max_file_size_kb: int = 512) -> tuple[dict[str, str], list[str]]:
    """
    Load all scannable files from a local directory or single file.
    Returns (file_map, skipped_files).
    """
    root = Path(skill_path).expanduser().resolve()
    file_map: dict[str, str] = {}
    skipped: list[str] = []
    max_bytes = max_file_size_kb * 1024

    if root.is_file():
        files = [root]
    elif root.is_dir():
        files = [
            p for p in root.rglob("*")
            if p.is_file()
            and p.suffix in SUPPORTED_EXTENSIONS
            and ".git" not in p.parts
            and "__pycache__" not in p.parts
            and "node_modules" not in p.parts
            and ".venv" not in p.parts
        ]
    else:
        raise FileNotFoundError(f"Path does not exist or is not accessible: {skill_path}")

    for f in files:
        if f.stat().st_size > max_bytes:
            skipped.append(str(f.relative_to(root.parent if root.is_file() else root)))
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            rel_path = str(f.relative_to(root.parent if root.is_file() else root))
            file_map[rel_path] = content
        except OSError:
            skipped.append(str(f))

    return file_map, skipped


# ── Core scan orchestrator ────────────────────────────────────────────────────

async def run_scan(
    file_map: dict[str, str],
    layers: list[DetectionSource],
    skill_path: str = "<snippet>",
    skipped_files: list[str] | None = None,
    max_file_size_kb: int = 512,
    severity_threshold: Severity = Severity.LOW,
) -> ScanReport:
    scan_id = uuid.uuid4().hex
    t0 = time.perf_counter()
    layers_set = set(layers)

    pat_findings: list[Finding] = []
    yara_findings: list[Finding] = []
    df_findings: list[Finding] = []
    llm_findings: list[Finding] = []
    layer_summaries: list[LayerSummary] = []
    llm_summary_text = ""

    # Run non-LLM layers (fast, can run concurrently)
    async def _run_pattern():
        if DetectionSource.PATTERN in layers_set:
            f, s = pattern_detector.scan_files(file_map)
            pat_findings.extend(f)
            layer_summaries.append(s)

    async def _run_yara():
        if DetectionSource.YARA in layers_set:
            f, s = yara_detector.scan_files(file_map)
            yara_findings.extend(f)
            layer_summaries.append(s)

    async def _run_dataflow():
        if DetectionSource.DATAFLOW in layers_set:
            f, s = dataflow_analyzer.scan_files(file_map)
            df_findings.extend(f)
            layer_summaries.append(s)

    await asyncio.gather(_run_pattern(), _run_yara(), _run_dataflow())

    # LLM layer runs after rule layers so it can consider prior findings
    if DetectionSource.LLM in layers_set:
        prior = pat_findings + yara_findings + df_findings
        f, s, llm_summary_text = await llm_judge.scan_files(file_map, prior_findings=prior)
        llm_findings.extend(f)
        layer_summaries.append(s)

    # Aggregate
    merged = aggregator.aggregate(
        pattern_findings=pat_findings,
        yara_findings=yara_findings,
        dataflow_findings=df_findings,
        llm_findings=llm_findings,
        enabled_layers=layers_set,
    )

    # Apply severity threshold filter
    severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    threshold_idx = severity_order.index(severity_threshold)
    filtered = [f for f in merged if severity_order.index(f.severity) >= threshold_idx]

    elapsed_ms = (time.perf_counter() - t0) * 1000

    target = ScanTarget(
        path=skill_path,
        resolved_files=list(file_map.keys()),
        total_files=len(file_map),
        skipped_files=skipped_files or [],
        scan_duration_ms=round(elapsed_ms, 2),
    )

    report = ScanReport(
        scan_id=scan_id,
        target=target,
        findings=filtered,
        layer_summaries=layer_summaries,
        layers_enabled=list(layers_set),
        summary=llm_summary_text or _auto_summary(filtered),
    )
    report._recompute_stats()
    return report


def _auto_summary(findings: list[Finding]) -> str:
    if not findings:
        return "No security issues detected. The skill appears clean across all enabled detection layers."
    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    cats = {f.category.value for f in findings}
    return (
        f"Found {len(findings)} issue(s) across {len(cats)} category/categories "
        f"({critical} critical, {high} high). "
        f"Categories: {', '.join(sorted(cats))}."
    )


# ── FastAPI routes ────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "skills-scanner"}


@app.post("/scan", response_model=ScanReport)
async def scan_skill(request: ScanRequest) -> ScanReport:
    try:
        file_map, skipped = _load_skill_files(request.skill_path, request.max_file_size_kb)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))

    if not file_map:
        raise HTTPException(status_code=422, detail="No scannable files found at the given path.")

    report = await run_scan(
        file_map=file_map,
        layers=request.layers,
        skill_path=request.skill_path,
        skipped_files=skipped,
        max_file_size_kb=request.max_file_size_kb,
        severity_threshold=request.severity_threshold,
    )
    return report


@app.post("/scan/snippet", response_model=ScanReport)
async def scan_snippet(request: SnippetScanRequest) -> ScanReport:
    lang = request.language
    if lang == "auto":
        # Heuristic language detection
        content = request.content.strip()
        if content.startswith("{") or content.startswith("["):
            lang = "json"
        elif ":" in content and not content.startswith("def ") and not content.startswith("class "):
            lang = "yaml"
        else:
            lang = "python"

    ext_map = {
        "python": ".py", "javascript": ".js", "typescript": ".ts",
        "yaml": ".yml", "json": ".json",
    }
    filename = f"snippet{ext_map.get(lang, '.txt')}"
    file_map = {filename: request.content}

    report = await run_scan(
        file_map=file_map,
        layers=request.layers,
        skill_path="<snippet>",
    )
    return report


# ── CLI ───────────────────────────────────────────────────────────────────────

def _print_report(report: ScanReport) -> None:
    """Pretty-print a ScanReport to the terminal."""
    verdict_color = {"PASS": "green", "WARN": "yellow", "FAIL": "red"}.get(report.verdict, "white")
    console.print(f"\n[bold]Scan ID:[/bold] {report.scan_id}")
    console.print(f"[bold]Path:[/bold]    {report.target.path}")
    console.print(f"[bold]Files:[/bold]   {report.target.total_files} scanned, {len(report.target.skipped_files)} skipped")
    console.print(f"[bold]Duration:[/bold] {report.target.scan_duration_ms:.1f}ms\n")
    console.print(f"[bold]Verdict:[/bold] [{verdict_color}]{report.verdict}[/{verdict_color}]  "
                  f"Risk: [bold]{report.overall_risk.value.upper()}[/bold]\n")

    if report.summary:
        console.print(f"[italic]{report.summary}[/italic]\n")

    if not report.findings:
        console.print("[green]✓ No findings.[/green]")
        return

    table = Table(title="Findings", show_lines=True)
    table.add_column("Severity", style="bold", width=9)
    table.add_column("Category", width=20)
    table.add_column("Title", width=36)
    table.add_column("Source", width=10)
    table.add_column("Confidence", width=10)
    table.add_column("Location", width=28)

    severity_colors = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "orange3",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    for f in report.findings:
        color = severity_colors.get(f.severity, "white")
        loc = str(f.location) if f.location else "—"
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.category.value,
            f.title,
            f.source.value,
            f"{f.confidence:.0%}",
            loc,
        )

    console.print(table)


@cli.command("scan")
def cli_scan(
    skill_path: Annotated[str, typer.Argument(help="Path to the skill directory or file to scan")],
    layers: Annotated[
        str,
        typer.Option("--layers", "-l", help="Comma-separated detection layers: pattern,yara,dataflow,llm"),
    ] = "pattern,yara,dataflow,llm",
    threshold: Annotated[
        str,
        typer.Option("--threshold", "-t", help="Minimum severity: critical|high|medium|low|info"),
    ] = "low",
    output_json: Annotated[bool, typer.Option("--json", help="Output raw JSON report")] = False,
    no_llm: Annotated[bool, typer.Option("--no-llm", help="Skip LLM-as-a-judge layer (faster)")] = False,
) -> None:
    """Scan an AI agent skill for security vulnerabilities."""
    layer_list = [DetectionSource(l.strip()) for l in layers.split(",") if l.strip()]
    if no_llm and DetectionSource.LLM in layer_list:
        layer_list.remove(DetectionSource.LLM)

    try:
        file_map, skipped = _load_skill_files(skill_path)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    if not file_map:
        console.print("[yellow]Warning:[/yellow] No scannable files found.")
        raise typer.Exit(0)

    try:
        sev_threshold = Severity(threshold)
    except ValueError:
        console.print(f"[red]Invalid threshold:[/red] {threshold}")
        raise typer.Exit(1)

    report = asyncio.run(
        run_scan(
            file_map=file_map,
            layers=layer_list,
            skill_path=skill_path,
            skipped_files=skipped,
            severity_threshold=sev_threshold,
        )
    )

    if output_json:
        print(report.model_dump_json(indent=2))
    else:
        _print_report(report)

    # Exit code: 0=PASS, 1=WARN, 2=FAIL
    exit_codes = {"PASS": 0, "WARN": 1, "FAIL": 2}
    raise typer.Exit(exit_codes.get(report.verdict, 1))


@cli.command("scan-snippet")
def cli_scan_snippet(
    content: Annotated[str | None, typer.Argument(help="Code snippet to scan (or pipe via stdin)")] = None,
    language: Annotated[str, typer.Option("--lang", help="Language: python|javascript|yaml|json|auto")] = "auto",
    output_json: Annotated[bool, typer.Option("--json", help="Output raw JSON report")] = False,
) -> None:
    """Scan a raw code or YAML snippet for security threats."""
    if content is None:
        content = sys.stdin.read()

    if not content.strip():
        console.print("[yellow]No content to scan.[/yellow]")
        raise typer.Exit(0)

    ext_map = {"python": ".py", "javascript": ".js", "typescript": ".ts", "yaml": ".yml", "json": ".json"}
    filename = f"snippet{ext_map.get(language, '.txt')}"
    file_map = {filename: content}

    report = asyncio.run(
        run_scan(
            file_map=file_map,
            layers=[DetectionSource.PATTERN, DetectionSource.YARA, DetectionSource.LLM],
            skill_path="<snippet>",
        )
    )

    if output_json:
        print(report.model_dump_json(indent=2))
    else:
        _print_report(report)

    exit_codes = {"PASS": 0, "WARN": 1, "FAIL": 2}
    raise typer.Exit(exit_codes.get(report.verdict, 1))


@cli.command("serve")
def cli_serve(
    host: str = "0.0.0.0",
    port: int = 8000,
    reload: bool = False,
) -> None:
    """Start the FastAPI server for use as a Copilot skillset endpoint."""
    uvicorn.run("main:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    cli()
