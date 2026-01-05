"""
OWASP A02: Cryptographic Failures
Tests weak encryption, plaintext exposure, session hijacking
"""
from mitmproxy import http

def request(flow: http.HTTPFlow):
    print(f"\n[OWASP A02] Cryptographic Failures Attack on {flow.request.url}")

    # Try to force downgrade to HTTP
    if flow.request.scheme == "https":
        print(f"  [ATTACK] Attempting SSL strip: HTTPS -> HTTP")
        flow.request.scheme = "http"
        flow.request.port = 80

    # Try to expose session tokens
    flow.request.headers["X-Request-Token"] = "EXPOSE_SESSION_TOKEN"
    flow.request.headers["X-Dump-Keys"] = "true"

    # Try to force weak cipher
    flow.request.headers["Accept-Encoding"] = "plaintext"
    flow.request.headers["X-Cipher-Preference"] = "NULL"

    print(f"  [ATTACK] Attempted SSL downgrade")
    print(f"  [ATTACK] Requested token exposure")
    print(f"  [ATTACK] Requested weak cipher")

def response(flow: http.HTTPFlow):
    if not flow.response:
        print(f"  [PASS] No response (connection failed - encryption enforced)")
        return

    print(f"  [RESULT] Status: {flow.response.status_code}")

    # Check if sensitive data is exposed
    content = str(flow.response.content).lower()
    if "key" in content or "token" in content or "secret" in content:
        print(f"  [WARN] Response contains key/token/secret keywords!")

    # Check if response is plaintext when it should be encrypted
    if flow.request.scheme == "http" and flow.response.status_code == 200:
        print(f"  [FAIL] SSL downgrade succeeded - got plaintext response!")
    else:
        print(f"  [PASS] Encryption enforced")
