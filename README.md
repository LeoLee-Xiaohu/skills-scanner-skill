# skills-scanner-skill

A **GitHub Copilot skill** that scans AI agent skills for security threats — detecting **prompt injection**, **data exfiltration**, and **malicious code patterns** using a four-layer detection pipeline that maximizes coverage while minimizing false positives.

## Architecture

```
Skill Files
    │
    ▼
┌────────────────────────────────────────┐
│  Layer 1: Pattern Detector             │  Fast YAML regex/literal rules
│  Layer 2: YARA Rules                   │  Multi-line, binary-safe matching
│  Layer 3: AST Dataflow Analyzer        │  Python taint-flow source→sink
└────────────────────────────────────────┘
    │  (findings + code snippets)
    ▼
┌────────────────────────────────────────┐
│  Layer 4: LLM-as-a-Judge              │  Semantic analysis via GPT-4o
└────────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────────┐
│  Aggregator                            │  Corroboration scoring + FP reduction
└────────────────────────────────────────┘
    │
    ▼
  ScanReport (JSON)  →  PASS / WARN / FAIL
```

**FP-reduction logic:**
- Single-source findings are confidence-capped at 70%
- Each corroborating layer adds +15% confidence boost
- ≥3 layers agreeing escalates severity by one level
- Lone LLM findings below 65% confidence are downgraded one severity level
- Findings below 40% confidence are suppressed entirely

## Detection Categories

| Category | What it catches |
|---|---|
| `prompt_injection` | Jailbreaks, instruction overrides, system prompt leaks, indirect injection via tool outputs |
| `data_exfiltration` | Credential harvesting chains, webhook relay, base64+HTTP exfil, DNS tunnelling |
| `malicious_code` | `eval`/`exec` of external data, shell injection, pickle deserialization, obfuscated payloads, runtime `pip install` |
| `supply_chain` | Typosquatting packages, runtime code download+exec, network calls in setup.py |
| `information_disclosure` | Hardcoded API keys (OpenAI, AWS, GitHub PAT), passwords in source |

## Quick Start

```bash
# Install
git clone https://github.com/your-org/skills-scanner-skill
cd skills-scanner-skill
uv sync

# Copy and configure environment
cp .env.example .env
# Edit .env: add your OPENAI_API_KEY

# Scan a local skill directory
uv run skills-scanner scan /path/to/my-skill

# Scan without LLM layer (fast, no API key needed)
uv run skills-scanner scan /path/to/my-skill --no-llm

# Scan only specific layers
uv run skills-scanner scan /path/to/my-skill --layers pattern,yara,dataflow

# Only show HIGH+ findings
uv run skills-scanner scan /path/to/my-skill --threshold high

# Get JSON output (for CI integration)
uv run skills-scanner scan /path/to/my-skill --json

# Scan a code snippet from stdin
echo "eval(user_input)" | uv run skills-scanner scan-snippet --lang python

# Start the Copilot skillset HTTP server
uv run skills-scanner serve
```

## Exit Codes

| Code | Verdict | Meaning |
|---|---|---|
| 0 | PASS | No findings at or above the threshold |
| 1 | WARN | Medium or low severity findings |
| 2 | FAIL | High or critical severity findings |

## As a GitHub Copilot Extension

Register the skill server via `copilot-skillset.yml`. Once deployed:

```
@skills-scanner scan_skill skill_path=/path/to/skill
@skills-scanner scan_snippet content="os.system(user_input)"
```

The server exposes:
- `POST /scan` — scan a local skill path
- `POST /scan/snippet` — scan raw code/YAML
- `GET /health` — liveness check
- `GET /openapi.json` — OpenAPI spec for skillset registration

## File Structure

```
skills-scanner-skill/
├── copilot-skillset.yml        # Copilot Extensions skillset manifest
├── pyproject.toml
├── main.py                     # FastAPI app + Typer CLI entry point
├── src/scanner/
│   ├── models.py               # Pydantic: ScanTarget, Finding, ScanReport
│   ├── pattern_detector.py     # YAML regex/literal pattern detection
│   ├── yara_detector.py        # YARA rule-based detection
│   ├── dataflow_analyzer.py    # Python AST taint-flow analysis
│   ├── llm_judge.py            # LLM-as-a-judge via openai-agents
│   └── aggregator.py           # Multi-layer result aggregation + FP reduction
├── rules/
│   ├── patterns.yml            # ~20 YAML detection patterns
│   ├── prompt_injection.yar    # 5 YARA rules for prompt injection
│   ├── data_exfiltration.yar   # 5 YARA rules for data exfiltration
│   └── malicious_code.yar      # 8 YARA rules for malicious code
└── tests/
    ├── fixtures/{clean,injection,exfil,malicious,benign_llm}_skill/
    └── test_{pattern_detector,yara_detector,dataflow_analyzer,aggregator}.py
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | required for LLM layer | OpenAI API key |
| `SCANNER_LLM_MODEL` | `gpt-4o` | Override the judge model |

## Adding Custom Rules

**Pattern rules** (`rules/patterns.yml`):
```yaml
rules:
  - id: MY-001
    title: "My Custom Rule"
    description: "Detects my custom threat pattern"
    category: malicious_code    # or prompt_injection, data_exfiltration
    severity: high              # critical, high, medium, low, info
    confidence: 0.80
    regex: 'my_dangerous_function\s*\('
    remediation: "How to fix this"
```

**YARA rules** — add a new `.yar` file to `rules/` and register it in `src/scanner/yara_detector.py`.

## Running Tests

```bash
uv run pytest tests/ -v
```

All 55 tests cover pattern detection, YARA rule compilation and matching, AST dataflow taint propagation, and aggregation logic across clean, injected, exfil, and malicious fixture skills.

