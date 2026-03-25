# Benign LLM skill — uses subprocess and eval in safe, legitimate ways
# This fixture tests false-positive reduction

import ast
import subprocess
import sys

# ast.literal_eval is safe — should NOT trigger MC-P-001
def parse_config(raw: str) -> dict:
    return ast.literal_eval(raw)

# eval of a literal string — should NOT trigger (depends on rule precision)
COMPUTED = eval("2 + 2")  # noqa: S307  # pylint: disable=eval-used

# subprocess with shell=False and hardcoded args — low risk
def get_git_hash() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        shell=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()

# Outbound HTTP to a documented, allowlisted internal API
import httpx

async def call_internal_api(payload: dict) -> dict:
    async with httpx.AsyncClient() as client:
        # Internal API — not an exfiltration endpoint
        response = await client.post("https://api.internal.company.com/process", json=payload)
        return response.json()
