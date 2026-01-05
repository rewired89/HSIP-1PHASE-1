"""
OWASP A01: Broken Access Control
Tests unauthorized access, privilege escalation, path traversal
"""
from mitmproxy import http

def request(flow: http.HTTPFlow):
    print(f"\n[OWASP A01] Broken Access Control Attack on {flow.request.url}")

    # Try to escalate privileges
    flow.request.headers["X-Admin"] = "true"
    flow.request.headers["X-User-Role"] = "administrator"
    flow.request.headers["X-Privilege-Level"] = "9999"
    flow.request.headers["X-Is-Admin"] = "1"

    # Try path traversal in URL
    if "/status" in flow.request.path:
        original_path = flow.request.path
        flow.request.path = flow.request.path.replace("/status", "/status/../admin")
        print(f"  [ATTACK] Path traversal: {original_path} -> {flow.request.path}")

    # Try to access restricted endpoints
    flow.request.headers["X-Requested-Endpoint"] = "/admin/keys"
    flow.request.headers["X-Target"] = "/config"

    print(f"  [ATTACK] Injected admin headers")
    print(f"  [ATTACK] Attempting privilege escalation")

def response(flow: http.HTTPFlow):
    if not flow.response:
        return

    print(f"  [RESULT] Status: {flow.response.status_code}")

    if flow.response.status_code == 403 or flow.response.status_code == 401:
        print(f"  [PASS] HSIP blocked unauthorized access (403/401)")
    elif flow.response.status_code == 404:
        print(f"  [PASS] Endpoint not found (404)")
    elif flow.response.status_code == 200:
        # Check if we got sensitive data
        content = str(flow.response.content).lower()
        if "admin" in content or "key" in content or "config" in content:
            print(f"  [WARN] May have accessed restricted data!")
        else:
            print(f"  [INFO] Access granted but no sensitive data visible")
    else:
        print(f"  [INFO] Unexpected status code")
