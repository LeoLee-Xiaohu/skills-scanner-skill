# Skills Security Scan Report — gstack

**Target:** `https://github.com/garrytan/gstack`
**Scan Date:** 2026-03-27 05:04:06 UTC
**Scanner:** skills-scanner (layers: pattern, yara, dataflow)
**LLM Layer:** Disabled (no OPENAI_API_KEY)

---

## Overall Result

| Metric | Value |
|---|---|
| **Verdict** | ❌ FAIL |
| **Overall Risk** | 🔴 CRITICAL |
| **Critical Findings** | 99 |
| **High Findings** | 16 |
| **Medium Findings** | 0 |
| **Low Findings** | 0 |
| **Files with Findings** | 25 |

**Summary:** Found 115 issue(s) across 3 category/categories (99 critical, 16 high). Categories: data_exfiltration, malicious_code, prompt_injection.

---

## Findings by Category

| Category | Count |
|---|---|
| `malicious_code` | 63 |
| `data_exfiltration` | 51 |
| `prompt_injection` | 1 |

---

## Findings by File

### `ARCHITECTURE.md` — 2 finding(s) `CRITICAL×2`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 361 | `curl` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 286 | `subprocess` |

### `BROWSER.md` — 3 finding(s) `HIGH×3`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| HIGH | data_exfiltration | Sensitive Keywords Combined with Network Output | 243 | `password` |
| HIGH | data_exfiltration | Sensitive Keywords Combined with Network Output | 131 | `Authorization:` |
| HIGH | data_exfiltration | Sensitive Keywords Combined with Network Output | 281 | `fetch(` |

### `CHANGELOG.md` — 4 finding(s) `HIGH×4`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| HIGH | data_exfiltration | Suspicious Webhook or Callback URL | 379 | `webhook` |
| HIGH | data_exfiltration | Suspicious Webhook or Callback URL | 388 | `webhook` |
| HIGH | data_exfiltration | Suspicious Webhook or Callback URL | 954 | `fetch(` |
| HIGH | data_exfiltration | Suspicious Webhook or Callback URL | 993 | `fetch(` |

### `browse/src/bun-polyfill.cjs` — 4 finding(s) `HIGH×4`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| HIGH | data_exfiltration | Base64 Encoding Before Network Transmission | 51 | `Buffer.from` |
| HIGH | data_exfiltration | Base64 Encoding Before Network Transmission | 82 | `Buffer.from` |
| HIGH | data_exfiltration | Base64 Encoding Before Network Transmission | 83 | `Buffer.from` |
| HIGH | data_exfiltration | Base64 Encoding Before Network Transmission | 43 | `fetch(` |

### `browse/src/cli.ts` — 13 finding(s) `CRITICAL×13`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 18 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 21 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 243 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 253 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 527 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 588 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 611 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 669 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 137 | `fetch(` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 393 | `fetch(` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 507 | `fetch(` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 568 | `fetch(` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 646 | `fetch(` |

### `browse/src/sidebar-agent.ts` — 7 finding(s) `CRITICAL×7`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 16 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 17 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 20 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 186 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 222 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 76 | `fetch(` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 96 | `fetch(` |

### `browse/test/cookie-import-browser.test.ts` — 3 finding(s) `HIGH×3`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| HIGH | malicious_code | Hardcoded Credentials or API Keys | 8 | `password = "test-keychain-password"` |
| HIGH | malicious_code | Hardcoded Credentials or API Keys | 26 | `PASSWORD = 'test-keychain-password'` |
| HIGH | malicious_code | Hardcoded Credentials or API Keys | 30 | `PASSWORD = 'test-linux-secret'` |

### `browse/test/sidebar-agent-roundtrip.test.ts` — 4 finding(s) `CRITICAL×4`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 79 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 110 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 111 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 31 | `fetch(` |

### `browse/test/sidebar-integration.test.ts` — 3 finding(s) `CRITICAL×3`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 43 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 4 | `fetch(` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 29 | `fetch(` |

### `cso/SKILL.md` — 6 finding(s) `CRITICAL×6`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | prompt_injection | Ignore Previous Instructions (literal) | 562 | `- `IGNORE PREVIOUS`, `system override`, `disregard`, `forget your instructions` ` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 562 | `curl` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 572 | `curl` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 539 | `exec(` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 595 | `exec(` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 597 | `eval(` |

### `plan-eng-review/SKILL.md` — 5 finding(s) `CRITICAL×5`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | eval() with Non-Literal Argument | 576 | `- Critical LLM call that needs a quality eval (e.g., prompt change → test output` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 579 | `EVAL (mark` |
| CRITICAL | malicious_code | eval() with Non-Literal Argument | 649 | `- Whether it's a unit test, E2E test, or eval (use the decision matrix)` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 581 | `eval (e` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 661 | `eval (use` |

### `review/SKILL.md` — 3 finding(s) `CRITICAL×3`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | eval() with Non-Literal Argument | 728 | `- Critical LLM call that needs a quality eval (e.g., prompt change → test output` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 735 | `EVAL (mark` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 739 | `eval (e` |

### `scripts/gen-skill-docs.ts` — 9 finding(s) `CRITICAL×9`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | eval() with Non-Literal Argument | 1725 | `- Critical LLM call that needs a quality eval (e.g., prompt change → test output` |
| CRITICAL | malicious_code | eval() with Non-Literal Argument | 1805 | `- Whether it's a unit test, E2E test, or eval (use the decision matrix)` |
| CRITICAL | malicious_code | exec() with Non-Literal Argument | 2900 | `while ((m = matcherRegex.exec(tmplContent)) !== null) {` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 1745 | `EVAL (mark` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 1849 | `eval (use` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 2965 | `exec(tmplContent` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 2965 | `exec(` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 603 | `curl` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 1105 | `Curl` |

### `scripts/resolvers/codex-helpers.ts` — 2 finding(s) `CRITICAL×2`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | exec() with Non-Literal Argument | 114 | `while ((m = matcherRegex.exec(tmplContent)) !== null) {` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 114 | `exec(tmplContent` |

### `scripts/resolvers/review.ts` — 6 finding(s) `CRITICAL×6`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 807 | `Exec(_ctx` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 807 | `Exec(` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 826 | `curl` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 827 | `curl` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 828 | `curl` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 832 | `curl` |

### `scripts/resolvers/testing.ts` — 5 finding(s) `CRITICAL×5`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | eval() with Non-Literal Argument | 310 | `- Critical LLM call that needs a quality eval (e.g., prompt change → test output` |
| CRITICAL | malicious_code | eval() with Non-Literal Argument | 390 | `- Whether it's a unit test, E2E test, or eval (use the decision matrix)` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 320 | `EVAL (mark` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 323 | `eval (e` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 412 | `eval (use` |

### `scripts/resolvers/utility.ts` — 1 finding(s) `CRITICAL×1`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 3 | `Eval(ctx` |

### `ship/SKILL.md` — 3 finding(s) `CRITICAL×3`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | eval() with Non-Literal Argument | 954 | `- Critical LLM call that needs a quality eval (e.g., prompt change → test output` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 959 | `EVAL (mark` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 961 | `eval (e` |

### `test/helpers/session-runner.ts` — 1 finding(s) `HIGH×1`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| HIGH | malicious_code | Runtime Package Installation | 2 | `subprocess runner for skill E2E testing.
 *
 * Spawns `claude -p` as a completel` |

### `test/skill-e2e-cso.test.ts` — 2 finding(s) `CRITICAL×1` `HIGH×1`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | Hardcoded OpenAI API Key | 45 | `const API_KEY = "sk-1234567890abcdef1234567890abcdef";` |
| HIGH | malicious_code | Hardcoded Credentials or API Keys | 45 | `sk-1234567890abcdef1234567890abcdef` |

### `test/skill-e2e-qa-bugs.test.ts` — 1 finding(s) `CRITICAL×1`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 52 | `Eval(fixture` |

### `test/skill-e2e-sidebar.test.ts` — 11 finding(s) `CRITICAL×11`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 57 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 184 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 214 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 45 | `fetch(` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 171 | `fetch(` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 186 | `curl` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 220 | `curl` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 15 | `Subprocess` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 30 | `Subprocess` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 155 | `Subprocess` |
| CRITICAL | malicious_code | Dynamic Code Download and Execution | 156 | `Subprocess` |

### `test/skill-e2e.test.ts` — 9 finding(s) `CRITICAL×9`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 22 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 30 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 31 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 734 | `process.env` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 1388 | `fetch(` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 1482 | `fetch(` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 2510 | `fetch(` |
| CRITICAL | data_exfiltration | Credential Harvesting Chain | 2637 | `fetch(` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 763 | `Eval(fixture` |

### `test/skill-validation.test.ts` — 2 finding(s) `CRITICAL×2`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | exec() with Non-Literal Argument | 182 | `while ((match = usagePattern.exec(content)) !== null) {` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 182 | `exec(content` |

### `test/touchfiles.test.ts` — 6 finding(s) `CRITICAL×6`

| Severity | Category | Title | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | malicious_code | exec() with Non-Literal Argument | 222 | `while ((match = testNameRegex.exec(e2eContent)) !== null) {` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 222 | `exec(e2eContent` |
| CRITICAL | malicious_code | exec() with Non-Literal Argument | 232 | `while ((match = plantedBugRegex.exec(e2eContent)) !== null) {` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 232 | `exec(e2eContent` |
| CRITICAL | malicious_code | exec() with Non-Literal Argument | 287 | `while ((match = nameRegex.exec(llmContent)) !== null) {` |
| CRITICAL | malicious_code | eval() or exec() of Non-Literal Expression | 287 | `exec(llmContent` |

---

## ⚠️ False Positive Analysis

Many findings appear to be **false positives** based on context:

| Finding | File | Assessment |
|---|---|---|
| `exec()` with Non-Literal Argument | `test/skill-validation.test.ts:182` | **False positive** — `RegExp.exec()` for pattern matching, not code execution |
| Hardcoded OpenAI API Key | `test/skill-e2e-cso.test.ts:45` | **Low risk** — Placeholder/dummy key `sk-1234567890abcdef...` in test file |
| Ignore Previous Instructions | `cso/SKILL.md:562` | **False positive** — Listing injection patterns to *detect*, not injecting |
| Dynamic Code Download (curl) | `ARCHITECTURE.md` | **False positive** — Documentation reference, not executable code |
| Credential Harvesting Chain | `test/skill-e2e.test.ts` | **False positive** — `process.env` read for test config (EVALS flag) |
| Base64 Encoding | `browse/src/bun-polyfill.cjs` | **False positive** — Standard HTTP response buffering |
| Webhook URL | `CHANGELOG.md` | **False positive** — Documentation/changelog text |
| Runtime Package Installation | `test/helpers/session-runner.ts` | **False positive** — Comment describing subprocess spawning for E2E tests |

---

## Genuinely Suspicious Findings (Require Review)

The following findings warrant deeper manual review:

| Severity | File | Finding | Notes |
|---|---|---|---|
| HIGH | `browse/src/cli.ts` | Network + credential patterns | Browser automation with cookie/session handling — verify scope |
| CRITICAL | `browse/src/sidebar-agent.ts` | Data exfiltration patterns | Agent that reads browser state and sends data — verify destinations |
| CRITICAL | `scripts/resolvers/review.ts` | Multiple data patterns | Review resolver with network calls — verify no unexpected outbound |
| CRITICAL | `scripts/gen-skill-docs.ts` | Multiple patterns | Script generates docs with dynamic content — check for template injection |

---

## Recommendation

**⚠️ DO NOT use blindly — manual review required for `browse/` components.**

The scanner verdict is FAIL (critical), but the vast majority of findings are **false positives** caused by:
- Test files with placeholder credentials
- Markdown documentation mentioning injection keywords as examples
- Standard JavaScript patterns (`RegExp.exec`, `Buffer.from`) misidentified as threats

**Real concerns to verify manually:**
1. `browse/src/sidebar-agent.ts` — An agent that reads browser session/cookies and communicates with a sidebar. Verify what data is sent and where.
2. `browse/src/cli.ts` — Browser CLI with network + credential patterns. Audit the data flow for cookies/tokens.
3. `scripts/resolvers/*.ts` — Several resolvers with dynamic code patterns. Confirm they don't accept untrusted input.

**Skills that appear clean (no findings):** `autoplan`, `benchmark`, `canary`, `careful`, `codex`, `connect-chrome`, `design-consultation`, `design-review`, `document-release`, `freeze`, `gstack-upgrade`, `guard`, `investigate`, `land-and-deploy`, `office-hours`, `plan-ceo-review`, `plan-design-review`, `plan-eng-review` (partial), `qa`, `qa-only`, `retro`, `setup-browser-cookies`, `setup-deploy`, `ship` (partial), `unfreeze`

---

*Generated by skills-scanner | Layers: pattern, yara, dataflow | LLM layer: disabled*
