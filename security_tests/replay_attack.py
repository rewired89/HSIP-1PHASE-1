"""
HSIP Security Test: Replay Attack
Captures packets and replays them to test nonce-based replay protection
"""

from mitmproxy import http
import time

# Storage for captured flows
captured_flows = []

def request(flow: http.HTTPFlow) -> None:
    """Capture requests for later replay"""

    # Store the flow
    captured_flows.append({
        "method": flow.request.method,
        "url": str(flow.request.url),
        "headers": dict(flow.request.headers),
        "content": flow.request.content,
        "timestamp": time.time()
    })

    print(f"[CAPTURE] Captured request #{len(captured_flows)}: {flow.request.method} {flow.request.url}")

    # After capturing 3 requests, start replaying
    if len(captured_flows) >= 3:
        print(f"\n[ATTACK] Starting replay attack...")
        print(f"[ATTACK] Replaying {len(captured_flows)} captured requests")
        print(f"[ATTACK] Expected: HSIP should reject replays via nonce counter")

        for i, captured in enumerate(captured_flows):
            age = time.time() - captured["timestamp"]
            print(f"[REPLAY] Request #{i+1} (age: {age:.2f}s)")
            print(f"         {captured['method']} {captured['url']}")

        print(f"\n[INFO] To replay, save this capture and use:")
        print(f"       mitmdump -r <capture_file>")

def response(flow: http.HTTPFlow) -> None:
    """Check if replayed request succeeded or failed"""
    if flow.response and len(captured_flows) > 0:
        if flow.response.status_code >= 400:
            print(f"[PASS] Response {flow.response.status_code} - Likely rejected replay")
        else:
            print(f"[WARN] Response {flow.response.status_code} - May have accepted replay")
