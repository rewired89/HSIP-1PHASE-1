"""
HSIP Security Test: HTTP Header Injection Attack
Tests if HSIP detects tampering via AAD (Additional Authenticated Data)
"""

from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    """Inject malicious headers to test HSIP's AAD protection"""

    print(f"[ATTACK] Intercepted request to {flow.request.host}")

    # Attack 1: Inject malicious headers
    flow.request.headers["X-Injected-Header"] = "malicious_value"
    flow.request.headers["X-SQLi"] = "' OR '1'='1"
    flow.request.headers["X-XSS"] = "<script>alert('xss')</script>"

    # Attack 2: Manipulate Content-Length to cause buffer issues
    original_length = flow.request.headers.get("Content-Length", "0")
    flow.request.headers["Content-Length"] = "999999"

    # Attack 3: Try to inject CRLF
    flow.request.headers["X-CRLF"] = "value\r\nX-Injected: malicious"

    print(f"[ATTACK] Injected malicious headers")
    print(f"[ATTACK] Original Content-Length: {original_length}")
    print(f"[ATTACK] Modified Content-Length: 999999")

def response(flow: http.HTTPFlow) -> None:
    """Log response to see if attack succeeded"""
    if flow.response:
        print(f"[RESULT] Response status: {flow.response.status_code}")
        if flow.response.status_code >= 400:
            print("[PASS] HSIP blocked the attack (error response)")
        else:
            print("[FAIL] Attack may have succeeded (success response)")
