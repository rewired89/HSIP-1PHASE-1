"""
HSIP Security Test: Response Tampering Attack
Tests if HSIP's ChaCha20-Poly1305 AEAD detects tampered responses
"""

from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    """Tamper with response data to test AEAD authentication"""

    if not flow.response:
        return

    print(f"[ATTACK] Intercepted response from {flow.request.host}")
    print(f"[ATTACK] Original status: {flow.response.status_code}")
    print(f"[ATTACK] Original content length: {len(flow.response.content)}")

    # Attack 1: Replace entire response body
    original_content = flow.response.content
    flow.response.content = b"TAMPERED_DATA_BY_ATTACKER"

    # Attack 2: Modify response headers
    flow.response.headers["X-Tampered"] = "true"

    # Attack 3: Change status code
    original_status = flow.response.status_code
    flow.response.status_code = 200

    print(f"[ATTACK] Tampered response body")
    print(f"[ATTACK] Changed status: {original_status} -> {flow.response.status_code}")
    print(f"[ATTACK] Expected: HSIP AEAD should detect tampering and reject")

def request(flow: http.HTTPFlow) -> None:
    """Track request for correlation"""
    print(f"[INFO] Request: {flow.request.method} {flow.request.url}")
