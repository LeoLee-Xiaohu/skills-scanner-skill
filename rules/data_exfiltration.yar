// Data Exfiltration YARA Rules
// Detects patterns that indicate unauthorized data being sent to external endpoints

rule CredentialHarvestingChain
{
    meta:
        id           = "DE-001"
        title        = "Credential Harvesting Chain"
        description  = "Code reads environment variables (likely credentials) and performs network operations"
        category     = "data_exfiltration"
        severity     = "critical"
        confidence   = "0.88"
        remediation  = "Audit all network calls. Credentials and secrets must never be sent to external endpoints. Use secret management services (Vault, AWS Secrets Manager) instead of environment variables where possible."

    strings:
        $env_read1  = "os.environ" nocase
        $env_read2  = "os.getenv" nocase
        $env_read3  = "environ.get" nocase
        $env_read4  = "process.env" nocase
        $net_send1  = "requests.post" nocase
        $net_send2  = "requests.get" nocase
        $net_send3  = "httpx.post" nocase
        $net_send4  = "fetch(" nocase
        $net_send5  = "axios.post" nocase
        $net_send6  = "urllib.request" nocase

    condition:
        any of ($env_read*) and any of ($net_send*)
}

rule WebhookExfiltration
{
    meta:
        id           = "DE-002"
        title        = "Suspicious Webhook or Callback URL"
        description  = "Data being sent to webhook/callback services often used for exfiltration"
        category     = "data_exfiltration"
        severity     = "high"
        confidence   = "0.82"
        remediation  = "Audit all outbound HTTP requests. Restrict outbound connections to allowlisted domains. Flag any use of generic webhook relay services."

    strings:
        $hook1 = "webhook" nocase
        $hook2 = "requestbin" nocase
        $hook3 = "pipedream" nocase
        $hook4 = "ngrok" nocase
        $hook5 = "burpcollaborator" nocase
        $hook6 = "interact.sh" nocase
        $hook7 = "canarytokens" nocase
        $hook8 = "webhook.site" nocase
        $hook9 = "beeceptor" nocase
        $hook10 = "postb.in" nocase

        $send1 = "requests.post" nocase
        $send2 = "httpx.post" nocase
        $send3 = "fetch(" nocase
        $send4 = "axios.post" nocase

    condition:
        any of ($hook*) and any of ($send*)
}

rule Base64DataLeakChain
{
    meta:
        id           = "DE-003"
        title        = "Base64 Encoding Before Network Transmission"
        description  = "Data is base64-encoded before being sent externally — a common data exfiltration obfuscation technique"
        category     = "data_exfiltration"
        severity     = "high"
        confidence   = "0.75"
        remediation  = "Review why data is being base64-encoded before network transmission. Legitimate uses exist but this combination warrants audit."

    strings:
        $b64_1 = "base64.b64encode" nocase
        $b64_2 = "base64.encodebytes" nocase
        $b64_3 = "btoa(" nocase
        $b64_4 = "Buffer.from" nocase

        $net1 = "requests.post" nocase
        $net2 = "requests.get" nocase
        $net3 = "httpx.post" nocase
        $net4 = "fetch(" nocase
        $net5 = "axios" nocase

    condition:
        any of ($b64*) and any of ($net*)
}

rule DNSExfiltration
{
    meta:
        id           = "DE-004"
        title        = "DNS-Based Exfiltration Indicator"
        description  = "Data being embedded in DNS queries — a stealthy exfiltration channel"
        category     = "data_exfiltration"
        severity     = "high"
        confidence   = "0.80"
        remediation  = "Audit all DNS resolution calls. Data must not be embedded in hostnames for resolution."

    strings:
        $dns1 = "socket.getaddrinfo" nocase
        $dns2 = "socket.gethostbyname" nocase
        $dns3 = "dns.resolver" nocase
        $dns4 = "dnspython" nocase

        $concat1 = /['"]\s*\+\s*\w+\s*\+\s*['"][^'"]*\./ nocase
        $subdomain = /f["'][^"']*\{[^}]+\}\.[^"']{3,20}["']/ nocase

    condition:
        any of ($dns*) and (any of ($concat*, $subdomain))
}

rule SensitiveKeywordExfil
{
    meta:
        id           = "DE-005"
        title        = "Sensitive Keywords Combined with Network Output"
        description  = "Secrets, API keys, or credentials referenced near outbound network calls"
        category     = "data_exfiltration"
        severity     = "high"
        confidence   = "0.72"
        remediation  = "Ensure credentials and API keys are never passed as parameters to outbound HTTP calls. Use server-side proxies that authenticate on behalf of the skill."

    strings:
        $secret1 = "api_key" nocase
        $secret2 = "secret_key" nocase
        $secret3 = "access_token" nocase
        $secret4 = "private_key" nocase
        $secret5 = "password" nocase
        $secret6 = "bearer_token" nocase
        $secret7 = "Authorization:" nocase
        $secret8 = "X-API-Key:" nocase

        $net1 = "requests.post" nocase
        $net2 = "requests.get" nocase
        $net3 = "httpx.post" nocase
        $net4 = "httpx.get" nocase
        $net5 = "fetch(" nocase

    condition:
        2 of ($secret*) and any of ($net*)
}
