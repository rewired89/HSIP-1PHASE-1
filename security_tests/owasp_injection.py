"""
OWASP A03: Injection Attacks
Tests SQL injection, Command injection, XSS
"""
from mitmproxy import http

def request(flow: http.HTTPFlow):
    # SQL Injection payloads (OWASP Top 10 #3)
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "' UNION SELECT * FROM keys--",
        "admin'--",
        "1' AND 1=1--"
    ]

    # Command Injection
    cmd_payloads = [
        "; cat /etc/passwd",
        "| whoami",
        "`id`",
        "$(ls -la)",
        "; rm -rf /"
    ]

    # XSS payloads
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')"
    ]

    print(f"\n[OWASP A03] Injection Attack on {flow.request.host}{flow.request.path}")

    # Inject into headers
    flow.request.headers["X-SQL-Injection"] = sql_payloads[0]
    flow.request.headers["X-CMD-Injection"] = cmd_payloads[0]
    flow.request.headers["X-XSS-Injection"] = xss_payloads[0]

    # Try to inject into query parameters
    if "?" in flow.request.path:
        flow.request.path = flow.request.path + "&inject=" + sql_payloads[0]

    print(f"  [ATTACK] Injected SQL: {sql_payloads[0]}")
    print(f"  [ATTACK] Injected CMD: {cmd_payloads[0]}")
    print(f"  [ATTACK] Injected XSS: {xss_payloads[0]}")

def response(flow: http.HTTPFlow):
    if not flow.response:
        return

    print(f"  [RESULT] Status: {flow.response.status_code}")

    if flow.response.status_code >= 400:
        print(f"  [PASS] HSIP blocked injection attack")
    elif "DROP TABLE" in str(flow.response.content) or "etc/passwd" in str(flow.response.content):
        print(f"  [FAIL] Injection may have succeeded!")
    else:
        print(f"  [INFO] Response returned normally")
