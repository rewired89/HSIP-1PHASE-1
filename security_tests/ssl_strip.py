"""
HSIP Security Test: SSL Stripping Attack
Attempts to downgrade HTTPS to HTTP to test protocol-level encryption enforcement
"""

from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    """Attempt to strip SSL/TLS and downgrade to plaintext"""

    original_scheme = flow.request.scheme

    if flow.request.scheme == "https":
        print(f"[ATTACK] Intercepted HTTPS request to {flow.request.host}")
        print(f"[ATTACK] Attempting SSL strip: HTTPS -> HTTP")

        # Try to downgrade to HTTP
        flow.request.scheme = "http"
        flow.request.port = 80

        # Remove security headers
        if "Strict-Transport-Security" in flow.request.headers:
            del flow.request.headers["Strict-Transport-Security"]

        if "Upgrade-Insecure-Requests" in flow.request.headers:
            del flow.request.headers["Upgrade-Insecure-Requests"]

        print(f"[ATTACK] Stripped SSL: {original_scheme} -> {flow.request.scheme}")
        print(f"[ATTACK] Expected: HSIP enforces encryption at protocol level")
        print(f"[ATTACK] Expected: Connection should fail or be rejected")
    else:
        print(f"[INFO] HTTP request to {flow.request.host} (already plaintext)")

def response(flow: http.HTTPFlow) -> None:
    """Check if SSL stripping was successful"""

    if not flow.response:
        print("[PASS] No response - connection likely failed (good)")
        return

    print(f"[RESULT] Got response: {flow.response.status_code}")

    if flow.request.scheme == "http" and flow.response.status_code < 400:
        print("[FAIL] SSL strip succeeded - got successful HTTP response!")
        print("[FAIL] HSIP should enforce encryption, not allow HTTP fallback")
    else:
        print("[PASS] SSL strip blocked or failed")
