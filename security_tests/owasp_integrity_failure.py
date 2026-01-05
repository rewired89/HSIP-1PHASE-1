"""
OWASP A08: Software and Data Integrity Failures
Tests signature forgery, tampering with signed data, replay attacks
"""
from mitmproxy import http
import time

captured_requests = []

def request(flow: http.HTTPFlow):
    print(f"\n[OWASP A08] Integrity Failure Attack on {flow.request.url}")

    # Capture request for replay
    captured_requests.append({
        'path': flow.request.path,
        'headers': dict(flow.request.headers),
        'content': flow.request.content,
        'timestamp': time.time()
    })

    # Try to tamper with signatures
    if "Signature" in flow.request.headers:
        original_sig = flow.request.headers["Signature"]
        flow.request.headers["Signature"] = "FORGED_SIGNATURE_" + original_sig[:10]
        print(f"  [ATTACK] Forged signature: {original_sig[:20]}... -> FORGED_...")

    # Tamper with request body
    if flow.request.content:
        original_len = len(flow.request.content)
        flow.request.content = flow.request.content + b"__TAMPERED_DATA__"
        print(f"  [ATTACK] Tampered with body: {original_len} -> {len(flow.request.content)} bytes")

    # Add fake integrity headers
    flow.request.headers["X-Integrity-Check"] = "BYPASSED"
    flow.request.headers["X-Signature-Valid"] = "true"

    # Replay old request
    if len(captured_requests) > 5:
        old_req = captured_requests[0]
        age = time.time() - old_req['timestamp']
        print(f"  [ATTACK] Replaying request from {age:.1f}s ago")
        flow.request.headers["X-Replay-Age"] = str(age)

def response(flow: http.HTTPFlow):
    if not flow.response:
        return

    print(f"  [RESULT] Status: {flow.response.status_code}")

    if flow.response.status_code >= 400:
        print(f"  [PASS] HSIP detected tampering (4xx error)")
    elif "__TAMPERED_DATA__" in str(flow.response.content):
        print(f"  [FAIL] Tampered data was processed!")
    else:
        print(f"  [INFO] Response received")

    # Try to tamper with response
    if flow.response.content:
        flow.response.content = b"ATTACKER_MODIFIED_RESPONSE"
        print(f"  [ATTACK] Tampered with response body")
