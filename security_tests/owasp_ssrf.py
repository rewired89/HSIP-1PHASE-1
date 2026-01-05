"""
OWASP A10: Server-Side Request Forgery (SSRF)
Tests internal network access, metadata endpoint access
"""
from mitmproxy import http

ssrf_targets = [
    "http://localhost:8787/admin",
    "http://127.0.0.1:8787/keys",
    "http://0.0.0.0:8787/config",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/",  # GCP metadata
    "file:///etc/passwd",
    "file:///c:/windows/system32/config/sam",
]

attempt = 0

def request(flow: http.HTTPFlow):
    global attempt

    target = ssrf_targets[attempt % len(ssrf_targets)]
    attempt += 1

    print(f"\n[OWASP A10] SSRF Attack #{attempt}")
    print(f"  [ATTACK] Trying to access: {target}")

    # Try to make server fetch internal resource
    flow.request.headers["X-Fetch-URL"] = target
    flow.request.headers["X-Proxy-To"] = target
    flow.request.headers["X-Forward-To"] = target

    # URL parameter injection
    if "?" in flow.request.path:
        flow.request.path = flow.request.path + "&url=" + target

    # Referer header SSRF
    flow.request.headers["Referer"] = target

    print(f"  [ATTACK] Injected SSRF payloads in headers")

def response(flow: http.HTTPFlow):
    if not flow.response:
        return

    print(f"  [RESULT] Status: {flow.response.status_code}")

    content = str(flow.response.content).lower()

    # Check if we got internal data
    if any(keyword in content for keyword in ["passwd", "root:", "admin", "metadata", "secret"]):
        print(f"  [FAIL] SSRF succeeded - got internal data!")
        print(f"  [DATA] Response preview: {str(flow.response.content)[:200]}")
    elif flow.response.status_code == 200:
        print(f"  [INFO] Got 200 but no sensitive data visible")
    else:
        print(f"  [PASS] SSRF blocked or failed")
