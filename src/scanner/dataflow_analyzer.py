"""
Python AST-based taint/dataflow analysis.

Tracks data flow from *sources* (user input, environment variables, external HTTP responses,
file reads, LLM outputs) to *sinks* (eval, exec, os.system, subprocess, outbound HTTP with
sensitive content, file writes outside sandbox).
"""

from __future__ import annotations

import ast
import time
import uuid
from pathlib import Path

from scanner.models import (
    CodeLocation,
    DetectionSource,
    Finding,
    LayerSummary,
    Severity,
    ThreatCategory,
)

# ──────────────────────────────────────────────────────────────────────────────
# Source patterns: attribute chains or names that represent untrusted data
# ──────────────────────────────────────────────────────────────────────────────
_TAINT_SOURCES: set[str] = {
    # User-supplied input
    "input",
    "sys.argv",
    "os.environ",
    "os.getenv",
    "environ",
    # HTTP / network responses
    "request.body",
    "request.json",
    "request.form",
    "request.args",
    "request.data",
    "request.get_json",
    "flask.request",
    "fastapi.Request",
    "response.text",
    "response.json",
    "response.content",
    "httpx.get",
    "httpx.post",
    "requests.get",
    "requests.post",
    "urllib.request.urlopen",
    # File reads
    "open",
    "pathlib.Path.read_text",
    "pathlib.Path.read_bytes",
    # LLM / agent output
    "runner.run",
    "Runner.run",
    "agent.run",
    "completion.choices",
    "message.content",
}

# ──────────────────────────────────────────────────────────────────────────────
# Sink patterns: function calls that can be dangerous with tainted data
# ──────────────────────────────────────────────────────────────────────────────
_CODE_EXECUTION_SINKS: dict[str, tuple[Severity, ThreatCategory, str]] = {
    "eval": (Severity.CRITICAL, ThreatCategory.MALICIOUS_CODE, "eval() with tainted data allows arbitrary code execution"),
    "exec": (Severity.CRITICAL, ThreatCategory.MALICIOUS_CODE, "exec() with tainted data allows arbitrary code execution"),
    "compile": (Severity.HIGH, ThreatCategory.MALICIOUS_CODE, "compile() with tainted data can execute attacker-controlled code"),
    "os.system": (Severity.CRITICAL, ThreatCategory.MALICIOUS_CODE, "os.system() with tainted data allows shell injection"),
    "os.popen": (Severity.CRITICAL, ThreatCategory.MALICIOUS_CODE, "os.popen() with tainted data allows shell injection"),
    "subprocess.call": (Severity.CRITICAL, ThreatCategory.MALICIOUS_CODE, "subprocess.call() with tainted data allows shell injection"),
    "subprocess.run": (Severity.HIGH, ThreatCategory.MALICIOUS_CODE, "subprocess.run() with tainted data; verify shell=False and sanitization"),
    "subprocess.Popen": (Severity.CRITICAL, ThreatCategory.MALICIOUS_CODE, "subprocess.Popen() with tainted data allows shell injection"),
    "subprocess.check_output": (Severity.HIGH, ThreatCategory.MALICIOUS_CODE, "subprocess.check_output() with tainted data"),
    "pickle.loads": (Severity.CRITICAL, ThreatCategory.MALICIOUS_CODE, "pickle.loads() with tainted data allows arbitrary code execution"),
    "yaml.load": (Severity.HIGH, ThreatCategory.MALICIOUS_CODE, "yaml.load() without Loader is unsafe with tainted data; use yaml.safe_load()"),
    "__import__": (Severity.HIGH, ThreatCategory.MALICIOUS_CODE, "Dynamic import with tainted module name"),
    "importlib.import_module": (Severity.HIGH, ThreatCategory.MALICIOUS_CODE, "Dynamic import with tainted module name"),
}

_EXFIL_SINKS: dict[str, tuple[Severity, ThreatCategory, str]] = {
    "requests.post": (Severity.HIGH, ThreatCategory.DATA_EXFILTRATION, "Outbound POST with potentially sensitive data"),
    "requests.get": (Severity.MEDIUM, ThreatCategory.DATA_EXFILTRATION, "Outbound GET with potentially sensitive data in parameters"),
    "requests.put": (Severity.HIGH, ThreatCategory.DATA_EXFILTRATION, "Outbound PUT with potentially sensitive data"),
    "httpx.post": (Severity.HIGH, ThreatCategory.DATA_EXFILTRATION, "Outbound POST with potentially sensitive data"),
    "httpx.get": (Severity.MEDIUM, ThreatCategory.DATA_EXFILTRATION, "Outbound GET with potentially sensitive data"),
    "httpx.AsyncClient.post": (Severity.HIGH, ThreatCategory.DATA_EXFILTRATION, "Async outbound POST with potentially sensitive data"),
    "urllib.request.urlopen": (Severity.MEDIUM, ThreatCategory.DATA_EXFILTRATION, "Outbound request with potentially sensitive data"),
    "socket.send": (Severity.HIGH, ThreatCategory.DATA_EXFILTRATION, "Raw socket send with potentially sensitive data"),
    "socket.sendall": (Severity.HIGH, ThreatCategory.DATA_EXFILTRATION, "Raw socket send with potentially sensitive data"),
    "smtp.sendmail": (Severity.HIGH, ThreatCategory.DATA_EXFILTRATION, "Email send with potentially sensitive data"),
}

_ALL_SINKS = {**_CODE_EXECUTION_SINKS, **_EXFIL_SINKS}


def _call_name(node: ast.Call) -> str:
    """Extract the dotted name of a function call."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        current: ast.expr = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _attr_chain(node: ast.Attribute) -> str:
    """Extract the dotted name from an attribute access (e.g., os.environ → 'os.environ')."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _is_tainted(node: ast.expr, tainted_names: set[str]) -> bool:
    """Heuristic: is this expression derived from a tainted source?"""
    if isinstance(node, ast.Name):
        return node.id in tainted_names

    if isinstance(node, ast.Call):
        name = _call_name(node)
        # Match exact source names, prefixed method calls (os.environ.get), or suffix matches
        if any(
            name == src
            or name.startswith(src + ".")
            or name.endswith("." + src.split(".")[-1])
            for src in _TAINT_SOURCES
        ):
            return True
        # Method called on a tainted object (e.g., file_obj.read(), response.json())
        if isinstance(node.func, ast.Attribute) and _is_tainted(node.func.value, tainted_names):
            return True
        # Taint propagates through arguments (e.g., format(tainted))
        return any(_is_tainted(arg, tainted_names) for arg in node.args)

    if isinstance(node, ast.Attribute):
        # Check if the full attribute chain names a taint source (e.g., os.environ["key"])
        chain = _attr_chain(node)
        if any(chain == src or chain.startswith(src) for src in _TAINT_SOURCES):
            return True
        return _is_tainted(node.value, tainted_names)

    if isinstance(node, ast.Subscript):
        # Taint propagates through subscript access: tainted_dict["key"], os.environ["KEY"]
        return _is_tainted(node.value, tainted_names)

    if isinstance(node, (ast.JoinedStr, ast.FormattedValue)):
        if isinstance(node, ast.JoinedStr):
            return any(_is_tainted(v, tainted_names) for v in node.values)
        return _is_tainted(node.value, tainted_names)

    if isinstance(node, ast.BinOp):
        return _is_tainted(node.left, tainted_names) or _is_tainted(node.right, tainted_names)

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_is_tainted(e, tainted_names) for e in node.elts)

    if isinstance(node, ast.Dict):
        return any(_is_tainted(v, tainted_names) for v in node.values if v is not None)

    if isinstance(node, ast.IfExp):
        # Ternary: tainted if either branch is tainted
        return _is_tainted(node.body, tainted_names) or _is_tainted(node.orelse, tainted_names)

    return False


class _TaintVisitor(ast.NodeVisitor):
    """Walk an AST, tracking taint assignments and flagging dangerous sink calls."""

    def __init__(self, filename: str, source_lines: list[str]) -> None:
        self.filename = filename
        self.source_lines = source_lines
        self.tainted: set[str] = set()
        self.findings: list[Finding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Treat all function parameters as tainted (conservative: callers may pass external data)."""
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            self.tainted.add(arg.arg)
        if node.args.vararg:
            self.tainted.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted.add(node.args.kwarg.arg)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        """Propagate taint through assignments."""
        if _is_tainted(node.value, self.tainted):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if _is_tainted(node.value, self.tainted):
            if isinstance(node.target, ast.Name):
                self.tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value and _is_tainted(node.value, self.tainted):
            if isinstance(node.target, ast.Name):
                self.tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)

        # Check for direct taint-source calls that initialize tainted variables
        # (handled in Assign visitor)

        # Check sink calls — use exact name match to avoid cross-matching
        # (e.g., Runner.run must NOT trigger the subprocess.run sink rule)
        for sink_name, (severity, category, description) in _ALL_SINKS.items():
            if name != sink_name:
                continue

            tainted_args = [
                arg for arg in node.args if _is_tainted(arg, self.tainted)
            ]
            tainted_kwargs = [
                kw for kw in node.keywords if kw.value and _is_tainted(kw.value, self.tainted)
            ]

            if tainted_args or tainted_kwargs:
                line = node.lineno
                snippet = self.source_lines[line - 1].strip() if line <= len(self.source_lines) else ""
                self.findings.append(
                    Finding(
                        id=f"df-{uuid.uuid4().hex[:8]}",
                        title=f"Tainted data flows into {name}()",
                        description=description,
                        category=category,
                        severity=severity,
                        source=DetectionSource.DATAFLOW,
                        confidence=0.85,
                        location=CodeLocation(
                            file=self.filename,
                            line_start=line,
                            snippet=snippet[:200],
                        ),
                        evidence=snippet[:300],
                        remediation=_remediation(name),
                        rule_id=f"dataflow/{sink_name}",
                    )
                )

        self.generic_visit(node)

    # Also propagate taint through for-loop variables
    def visit_For(self, node: ast.For) -> None:
        if _is_tainted(node.iter, self.tainted):
            if isinstance(node.target, ast.Name):
                self.tainted.add(node.target.id)
        self.generic_visit(node)

    # Propagate taint through comprehensions
    def visit_ListComp(self, node: ast.ListComp) -> None:
        for gen in node.generators:
            if _is_tainted(gen.iter, self.tainted) and isinstance(gen.target, ast.Name):
                self.tainted.add(gen.target.id)
        self.generic_visit(node)


def _remediation(sink: str) -> str:
    if "eval" in sink or "exec" in sink or "compile" in sink:
        return "Never pass user-controlled or external data to eval/exec. Use ast.literal_eval for safe parsing."
    if "os.system" in sink or "subprocess" in sink or "os.popen" in sink:
        return "Use subprocess with shell=False and a list of arguments. Validate and sanitize all inputs."
    if "pickle" in sink:
        return "Use json, msgpack, or another safe serialization format instead of pickle for untrusted data."
    if "yaml.load" in sink:
        return "Use yaml.safe_load() instead of yaml.load() to prevent code execution via YAML deserialization."
    if "requests" in sink or "httpx" in sink or "urllib" in sink:
        return "Audit all outbound network calls. Ensure sensitive data (env vars, credentials, user data) is not sent to external endpoints."
    if "socket" in sink:
        return "Audit raw socket usage. Sensitive data must not be transmitted to external hosts without authorization."
    if "__import__" in sink or "importlib" in sink:
        return "Never use dynamic imports with untrusted input. Allowlist permitted module names."
    return "Sanitize and validate all external input before passing to this function."


def scan_content(content: str, filename: str) -> list[Finding]:
    """Run AST taint analysis on Python source content."""
    try:
        tree = ast.parse(content, filename=filename)
    except SyntaxError:
        return []

    lines = content.splitlines()
    visitor = _TaintVisitor(filename=filename, source_lines=lines)
    visitor.visit(tree)
    return visitor.findings


def scan_files(file_map: dict[str, str]) -> tuple[list[Finding], LayerSummary]:
    """
    Run dataflow analysis on Python files only.

    Returns (findings, layer_summary).
    """
    start = time.perf_counter()
    all_findings: list[Finding] = []

    for filename, content in file_map.items():
        if not filename.endswith(".py"):
            continue
        all_findings.extend(scan_content(content, filename))

    duration_ms = (time.perf_counter() - start) * 1000
    summary = LayerSummary(
        layer=DetectionSource.DATAFLOW,
        findings_count=len(all_findings),
        duration_ms=round(duration_ms, 2),
    )
    return all_findings, summary
