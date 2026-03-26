---
name: skills-scanner
description: Security scanner for AI agent skills. Scans skill directories (SKILL.md-based custom skills, GitHub Copilot extensions, openai-agents projects, or any AI agent codebase) for prompt injection, data exfiltration, and malicious code before installation or use. Use this skill whenever the user asks to scan, audit, check, review, or verify the safety of a downloaded or third-party skill.
---

# Skills Scanner — Instructions for Claude

This skill scans AI agent skill directories for three categories of security threat:

| Threat | Examples |
|---|---|
| **Prompt injection** | Jailbreaks, instruction overrides, `[SYSTEM]:` smuggling, system-prompt extraction |
| **Data exfiltration** | Credential harvesting → outbound HTTP, base64-encode-then-POST, DNS tunnelling |
| **Malicious code** | `eval`/`exec` of tainted data, `pickle.loads`, shell injection, runtime `pip install`, hardcoded secrets |

Detection uses four layers: YAML pattern rules, YARA rules, Python AST taint-flow analysis, and LLM-as-a-judge.

---

## How to Run a Scan

### Step 1 — Confirm the target path exists

```bash
ls -la "<TARGET_PATH>"
```

If the path does not exist, tell the user and stop.

### Step 2 — Locate the scanner and run the scan

Use the `scan.sh` script bundled with this skill. Its location is the **same directory** as this SKILL.md file. Determine that directory, then run:

```bash
bash "<SKILL_DIR>/scan.sh" "<TARGET_PATH>"
```

`scan.sh` automatically handles dependency installation and produces a structured JSON report followed by a human-readable summary.

**Example** (substitute actual paths):
```bash
# Skill is installed at ~/.claude/skills/skills-scanner/
bash ~/.claude/skills/skills-scanner/scan.sh ~/Downloads/someone-elses-skill/
```

### Step 3 — Interpret and present the results

The script outputs a JSON report. Parse the following fields to present results to the user:

| Field | Meaning |
|---|---|
| `verdict` | `PASS` / `WARN` / `FAIL` |
| `overall_risk` | `info` / `low` / `medium` / `high` / `critical` |
| `critical_count`, `high_count`, `medium_count` | Finding counts by severity |
| `summary` | One-paragraph security assessment |
| `findings[]` | Array of individual findings (see below) |

**Each finding has:**
- `severity` — `critical` / `high` / `medium` / `low` / `info`
- `category` — `prompt_injection` / `data_exfiltration` / `malicious_code` / `supply_chain` / `information_disclosure`
- `title` — Short threat name
- `description` — Detailed explanation
- `source` — Which layer detected it: `pattern` / `yara` / `dataflow` / `llm`
- `confidence` — Detection confidence 0.0–1.0
- `location` — File and line number
- `evidence` — Matched code or text
- `remediation` — How to fix it

### Step 4 — Give the user a clear recommendation

Based on the verdict:

- **`PASS`** — The skill appears clean. Summarise what was checked and note any `info`-level findings.
- **`WARN`** — Caution recommended. List medium/low findings and explain what they mean.
- **`FAIL`** — Do **not** install or run this skill. Summarise critical/high findings and explain the specific risks. Show the evidence and remediation for each critical finding.

Always tell the user:
1. How many files were scanned
2. Which detection layers ran
3. The overall verdict and risk level
4. A concise list of findings (severity, category, file:line, one-sentence description)
5. Your recommendation (safe to use / use with caution / do not use)

---

## Scan Options

You can pass flags to scan.sh to customise the scan:

| Flag | Effect |
|---|---|
| `--no-llm` | Skip LLM layer (much faster, no OpenAI API key required) |
| `--threshold high` | Only show high+ findings |
| `--layers pattern,yara,dataflow` | Choose specific layers |

Example — fast scan without LLM:
```bash
bash "<SKILL_DIR>/scan.sh" "<TARGET_PATH>" --no-llm
```

---

## Troubleshooting

**"uv: command not found"** — Install uv: `curl -Lsf https://astral.sh/uv/install.sh | sh`

**"No scannable files found"** — The target path may be empty or contain only unsupported file types (.txt, .png etc.). Check with `ls -la "<TARGET_PATH>"`.

**LLM layer fails** — Set `OPENAI_API_KEY` in your environment, or re-run with `--no-llm`. The other three layers still provide strong coverage.

**YARA compile error** — The rules directory may be missing. Verify `<SKILL_DIR>/rules/*.yar` exist.
