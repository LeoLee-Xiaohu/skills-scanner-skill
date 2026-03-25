// Malicious Code YARA Rules
// Detects patterns that execute, obfuscate, or inject code at runtime

rule EvalExecOfVariable
{
    meta:
        id           = "MC-001"
        title        = "eval() or exec() of Non-Literal Expression"
        description  = "eval or exec called with a variable or expression rather than a string literal — high risk of code injection"
        category     = "malicious_code"
        severity     = "critical"
        confidence   = "0.90"
        remediation  = "Remove eval/exec entirely if possible. If parsing structured data, use ast.literal_eval() or a dedicated parser (json.loads, yaml.safe_load). Never eval user-controlled strings."

    strings:
        $a = /eval\s*\(\s*[a-zA-Z_]\w*/ nocase
        $b = /exec\s*\(\s*[a-zA-Z_]\w*/ nocase
        $c = /eval\s*\(\s*f['"]/ nocase
        $d = /exec\s*\(\s*f['"]/ nocase
        $e = /eval\s*\(\s*request/ nocase
        $f = /exec\s*\(\s*request/ nocase

    condition:
        any of them
}

rule ShellInjectionPattern
{
    meta:
        id           = "MC-002"
        title        = "Shell Command with String Interpolation"
        description  = "os.system, subprocess, or popen called with string interpolation — shell injection risk"
        category     = "malicious_code"
        severity     = "critical"
        confidence   = "0.88"
        remediation  = "Use subprocess.run() with shell=False and pass command as a list. Validate all inputs against an allowlist before use in commands."

    strings:
        $a = /os\.system\s*\(\s*f['"]/ nocase
        $b = /os\.system\s*\(\s*['"]\s*%/ nocase
        $c = /os\.popen\s*\(\s*f['"]/ nocase
        $d = /subprocess\.\w+\s*\([^)]*shell\s*=\s*True/ nocase
        $e = /Popen\s*\([^)]*shell\s*=\s*True/ nocase
        $f = /os\.system\s*\(\s*\w+\s*\+/ nocase
        $g = /os\.system\s*\(\s*[a-zA-Z_]\w*\s*[^)]*\)/ nocase

    condition:
        any of them
}

rule PickleDeserialization
{
    meta:
        id           = "MC-003"
        title        = "Pickle Deserialization of External Data"
        description  = "pickle.loads or pickle.load used on data that may originate from an untrusted source"
        category     = "malicious_code"
        severity     = "critical"
        confidence   = "0.85"
        remediation  = "Never deserialize pickle from untrusted sources. Use json.loads() or a vetted serialization library. If pickle is necessary, sign payloads with HMAC and verify before deserialization."

    strings:
        $a = "pickle.loads(" nocase
        $b = "pickle.load(" nocase
        $c = "cPickle.loads(" nocase
        $d = "cPickle.load(" nocase
        $e = "import pickle" nocase
        $f = "from pickle import" nocase

    condition:
        any of ($e, $f) and any of ($a, $b, $c, $d)
}

rule DynamicCodeDownloadExec
{
    meta:
        id           = "MC-004"
        title        = "Dynamic Code Download and Execution"
        description  = "Downloads code from a remote URL and executes it — supply chain / backdoor risk"
        category     = "malicious_code"
        severity     = "critical"
        confidence   = "0.92"
        remediation  = "Never download and execute code at runtime from remote URLs. Pin all dependencies at install time and verify with checksums."

    strings:
        $dl1 = "requests.get" nocase
        $dl2 = "httpx.get" nocase
        $dl3 = "urllib.request.urlopen" nocase
        $dl4 = "curl" nocase

        $exec1 = "exec(" nocase
        $exec2 = "eval(" nocase
        $exec3 = "subprocess" nocase
        $exec4 = "os.system" nocase
        $exec5 = "importlib" nocase

    condition:
        any of ($dl*) and any of ($exec*)
}

rule ObfuscatedBase64Payload
{
    meta:
        id           = "MC-005"
        title        = "Base64-Encoded Payload Execution"
        description  = "Base64-decoded content is passed to exec/eval — a common obfuscation technique for malicious payloads"
        category     = "malicious_code"
        severity     = "critical"
        confidence   = "0.93"
        remediation  = "Investigate this code immediately. Legitimate code does not need to base64-decode payloads and execute them. Remove or replace with transparent implementation."

    strings:
        $decode1 = "base64.b64decode" nocase
        $decode2 = "base64.decodebytes" nocase
        $decode3 = "base64.decode" nocase

        $exec1 = "exec(" nocase
        $exec2 = "eval(" nocase
        $exec3 = "compile(" nocase

    condition:
        any of ($decode*) and any of ($exec*)
}

rule UnsafeYAMLLoad
{
    meta:
        id           = "MC-006"
        title        = "Unsafe yaml.load() Without Safe Loader"
        description  = "yaml.load() without specifying Loader=yaml.SafeLoader allows arbitrary Python object instantiation"
        category     = "malicious_code"
        severity     = "high"
        confidence   = "0.88"
        remediation  = "Replace yaml.load() with yaml.safe_load(). If full YAML loading is necessary, use yaml.load(data, Loader=yaml.SafeLoader)."

    strings:
        $load_1 = /yaml\.load\s*\([^)]+\)/ nocase
        $load_2 = /yaml\.load\s*\(\s*[a-zA-Z_]/ nocase
        $safe_1 = "SafeLoader" nocase
        $safe_2 = "yaml.safe_load" nocase

    condition:
        any of ($load_*) and not any of ($safe_*)
}

rule RuntimePackageInstall
{
    meta:
        id           = "MC-007"
        title        = "Runtime Package Installation"
        description  = "Skill installs packages at runtime using pip or subprocess — supply chain risk"
        category     = "malicious_code"
        severity     = "high"
        confidence   = "0.85"
        remediation  = "All dependencies must be declared in pyproject.toml/requirements.txt and installed at build time. Runtime pip installs bypass security scanning."

    strings:
        $a = "pip install" nocase
        $b = "pip3 install" nocase
        $c = /subprocess[^"']*pip/ nocase
        $d = /os\.system[^"']*pip/ nocase
        $e = "importlib.util.find_spec" nocase

    condition:
        any of ($a, $b) or (any of ($c, $d, $e))
}

rule HardcodedCredentials
{
    meta:
        id           = "MC-008"
        title        = "Hardcoded Credentials or API Keys"
        description  = "Possible hardcoded secret, API key, or password in source code"
        category     = "malicious_code"
        severity     = "high"
        confidence   = "0.78"
        remediation  = "Move secrets to environment variables or a secrets manager. Rotate any exposed credentials immediately. Use pre-commit hooks or secret scanning in CI."

    strings:
        $a = /api_key\s*=\s*["'][A-Za-z0-9+\/]{20,}["']/ nocase
        $b = /secret\s*=\s*["'][A-Za-z0-9+\/]{20,}["']/ nocase
        $c = /password\s*=\s*["'][^"']{8,}["']/ nocase
        $d = /token\s*=\s*["'][A-Za-z0-9_\-\.]{20,}["']/ nocase
        $e = /private_key\s*=\s*["'][^"']{20,}["']/ nocase
        $f = /bearer\s+[A-Za-z0-9_\-\.]{20,}/ nocase
        $g = /sk-[A-Za-z0-9]{32,}/ nocase
        $h = /ghp_[A-Za-z0-9]{36}/ nocase
        $i = /AKIA[0-9A-Z]{16}/ nocase

    condition:
        any of them
}
