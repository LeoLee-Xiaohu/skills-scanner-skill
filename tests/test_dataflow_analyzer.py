"""Tests for the AST dataflow analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.models import Severity, ThreatCategory, DetectionSource
from scanner import dataflow_analyzer


FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(skill: str) -> str:
    return (FIXTURES / skill / "main.py").read_text()


class TestTaintSources:
    def test_os_environ_taints_variable(self):
        code = """
import os
secret = os.environ.get("KEY")
eval(secret)
"""
        findings = dataflow_analyzer.scan_content(code, "test.py")
        eval_findings = [f for f in findings if "eval" in f.title.lower()]
        assert eval_findings, "Should detect taint from os.environ into eval()"

    def test_user_input_taints_variable(self):
        code = """
user_cmd = input("Enter command: ")
import os
os.system(user_cmd)
"""
        findings = dataflow_analyzer.scan_content(code, "test.py")
        system_findings = [f for f in findings if "os.system" in f.title.lower() or "shell" in f.title.lower()]
        assert system_findings

    def test_request_body_taint(self):
        code = """
user_data = request.json()
exec(user_data["code"])
"""
        findings = dataflow_analyzer.scan_content(code, "test.py")
        exec_findings = [f for f in findings if "exec" in f.title.lower()]
        assert exec_findings

    def test_fstring_propagates_taint(self):
        code = """
import os
name = os.environ.get("USER")
cmd = f"echo {name}"
os.system(cmd)
"""
        findings = dataflow_analyzer.scan_content(code, "test.py")
        assert findings


class TestMaliciousSinks:
    def test_eval_of_tainted_var(self):
        code = "user = input('> ')\neval(user)\n"
        findings = dataflow_analyzer.scan_content(code, "test.py")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_exec_of_tainted_var(self):
        code = "data = input('> ')\nexec(data)\n"
        findings = dataflow_analyzer.scan_content(code, "test.py")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_subprocess_shell_true_tainted(self):
        code = """
import subprocess, os
cmd = os.environ.get("USER_CMD", "")
subprocess.run(cmd, shell=True)
"""
        findings = dataflow_analyzer.scan_content(code, "test.py")
        assert findings

    def test_pickle_loads_of_tainted(self):
        code = """
import pickle, os
raw = open(os.environ["DATA_FILE"], "rb").read()
obj = pickle.loads(raw)
"""
        findings = dataflow_analyzer.scan_content(code, "test.py")
        assert findings


class TestFalsePositiveReduction:
    def test_hardcoded_eval_not_flagged(self):
        """eval of a literal should ideally not be the main concern (pattern can flag it, but dataflow should not)"""
        code = "result = eval('2 + 2')\n"
        findings = dataflow_analyzer.scan_content(code, "test.py")
        # Dataflow analysis shouldn't flag literal eval since the arg isn't tainted
        # (Pattern layer may still flag it — that's handled in aggregator)
        tainted_findings = [f for f in findings if "tainted" in f.title.lower()]
        assert not tainted_findings

    def test_subprocess_hardcoded_no_taint(self):
        code = """
import subprocess
result = subprocess.run(["git", "status"], shell=False, capture_output=True)
"""
        findings = dataflow_analyzer.scan_content(code, "test.py")
        # No taint source, so no dataflow findings
        assert not findings

    def test_non_python_file_skipped(self):
        file_map = {
            "config.yml": "ignore previous instructions",
            "script.py": "x = 1\n",
        }
        findings, summary = dataflow_analyzer.scan_files(file_map)
        # Only .py files should be analyzed
        assert summary.layer == DetectionSource.DATAFLOW


class TestFixtureScans:
    def test_clean_skill_no_dataflow_findings(self):
        code = _load_fixture("clean_skill")
        findings = dataflow_analyzer.scan_content(code, "clean/main.py")
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert not critical

    def test_malicious_skill_has_dataflow_findings(self):
        code = _load_fixture("malicious_skill")
        findings = dataflow_analyzer.scan_content(code, "malicious/main.py")
        assert findings

    def test_exfil_skill_detects_env_to_http(self):
        code = _load_fixture("exfil_skill")
        findings = dataflow_analyzer.scan_content(code, "exfil/main.py")
        exfil = [f for f in findings if f.category == ThreatCategory.DATA_EXFILTRATION]
        assert exfil

    def test_syntax_error_returns_empty(self):
        code = "def broken(\n  # missing closing paren"
        findings = dataflow_analyzer.scan_content(code, "broken.py")
        assert findings == []
