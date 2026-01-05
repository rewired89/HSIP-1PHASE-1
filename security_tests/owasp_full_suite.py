"""
OWASP Top 10 - Complete Attack Suite
Runs all OWASP attack vectors simultaneously
"""
from mitmproxy import http
import time

attack_count = 0
start_time = time.time()

def request(flow: http.HTTPFlow):
    global attack_count
    attack_count += 1

    elapsed = time.time() - start_time
    print(f"\n{'='*70}")
    print(f"[OWASP ATTACK #{attack_count}] Target: {flow.request.url}")
    print(f"[TIME] {elapsed:.1f}s since start")
    print(f"{'='*70}")

    # A01: Broken Access Control
    print(f"[A01] Broken Access Control")
    flow.request.headers["X-Admin"] = "true"
    flow.request.headers["X-User-Role"] = "administrator"
    if "/status" in flow.request.path:
        flow.request.path = flow.request.path + "/../admin"
    print(f"  - Privilege escalation attempt")
    print(f"  - Path traversal: {flow.request.path}")

    # A02: Cryptographic Failures
    print(f"[A02] Cryptographic Failures")
    flow.request.headers["X-Dump-Keys"] = "true"
    flow.request.headers["X-Cipher-Preference"] = "NULL"
    print(f"  - Requested key exposure")
    print(f"  - Requested weak cipher")

    # A03: Injection
    print(f"[A03] Injection Attacks")
    flow.request.headers["X-SQL"] = "' OR '1'='1"
    flow.request.headers["X-CMD"] = "; cat /etc/passwd"
    flow.request.headers["X-XSS"] = "<script>alert('XSS')</script>"
    print(f"  - SQL injection payload")
    print(f"  - Command injection payload")
    print(f"  - XSS injection payload")

    # A07: Authentication Failures
    print(f"[A07] Authentication Bypass")
    flow.request.headers["Authorization"] = "Bearer forged-token-12345"
    flow.request.headers["Cookie"] = "sessionid=attacker-session"
    print(f"  - Forged Bearer token")
    print(f"  - Session fixation")

    # A08: Integrity Failures
    print(f"[A08] Integrity Tampering")
    if flow.request.content:
        flow.request.content = flow.request.content + b"__TAMPERED__"
        print(f"  - Tampered with request body")
    if "Signature" in flow.request.headers:
        flow.request.headers["Signature"] = "FORGED"
        print(f"  - Forged signature")

    # A10: SSRF
    print(f"[A10] SSRF Attempt")
    flow.request.headers["X-Fetch-URL"] = "http://localhost:8787/admin"
    flow.request.headers["X-Proxy-To"] = "http://169.254.169.254/latest/meta-data/"
    print(f"  - Attempted internal network access")
    print(f"  - Attempted metadata endpoint access")

    print(f"\n[SUMMARY] Launched 6 OWASP attack categories")

def response(flow: http.HTTPFlow):
    if not flow.response:
        print(f"\n[RESULT] No response (connection failed)")
        print(f"[VERDICT] HSIP may have blocked the attack at connection level")
        return

    print(f"\n[RESPONSE]")
    print(f"  Status: {flow.response.status_code}")
    print(f"  Size: {len(flow.response.content)} bytes")

    # Analyze response
    content = str(flow.response.content).lower()

    vulnerabilities_found = []

    if flow.response.status_code == 200:
        if "admin" in content or "key" in content:
            vulnerabilities_found.append("Possible access control bypass")
        if "root:" in content or "passwd" in content:
            vulnerabilities_found.append("Possible command injection")
        if "metadata" in content:
            vulnerabilities_found.append("Possible SSRF")
        if "__tampered__" in content:
            vulnerabilities_found.append("Tampered data processed")

    if vulnerabilities_found:
        print(f"\n[CRITICAL] Vulnerabilities detected:")
        for vuln in vulnerabilities_found:
            print(f"  ⚠️  {vuln}")
    elif flow.response.status_code >= 400:
        print(f"\n[PASS] ✓ HSIP blocked the attack (status {flow.response.status_code})")
    else:
        print(f"\n[INFO] Response returned, no obvious vulnerabilities")

    # Try to tamper with response
    original_content = flow.response.content
    flow.response.content = b"ATTACKER_CONTROLLED_RESPONSE"
    print(f"\n[A08] Tampered with response ({len(original_content)} -> {len(flow.response.content)} bytes)")

    print(f"{'='*70}\n")

def done():
    print(f"\n{'='*70}")
    print(f"[OWASP TEST COMPLETE]")
    print(f"[STATS] Total attacks: {attack_count}")
    print(f"[STATS] Duration: {time.time() - start_time:.1f}s")
    print(f"{'='*70}\n")

addons = []
