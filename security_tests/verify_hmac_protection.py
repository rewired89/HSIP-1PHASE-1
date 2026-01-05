#!/usr/bin/env python3
"""
HSIP HMAC Signature Verification - Client-Side Protection Demo

This script demonstrates how a proper HSIP client would detect
response tampering using HMAC signature verification.

Usage:
    python verify_hmac_protection.py [--proxy]

Without --proxy: Shows legitimate signed response
With --proxy: Shows how client detects tampering
"""

import requests
import json
import hmac
import hashlib
import sys

# This is the same key used by the daemon (in production, would be configured)
HMAC_KEY = b"HSIP-DAEMON-RESPONSE-INTEGRITY-KEY-V1-CHANGE-IN-PRODUCTION"

def verify_response_signature(response_json):
    """
    Verify HMAC signature on daemon response.

    Returns:
        (bool, str): (is_valid, message)
    """
    try:
        # Parse response
        if not isinstance(response_json, dict):
            return False, "Response is not JSON object"

        # Check required fields
        if "data" not in response_json:
            return False, "Missing 'data' field - response may be tampered"

        if "signature" not in response_json:
            return False, "Missing 'signature' field - response may be tampered"

        if "sig_alg" not in response_json:
            return False, "Missing 'sig_alg' field - response may be tampered"

        # Verify algorithm
        if response_json["sig_alg"] != "HMAC-SHA256":
            return False, f"Unknown signature algorithm: {response_json['sig_alg']}"

        # Extract components
        data = response_json["data"]
        received_signature = response_json["signature"]

        # Compute expected signature
        data_json = json.dumps(data, separators=(',', ':')).encode()
        expected_mac = hmac.new(HMAC_KEY, data_json, hashlib.sha256)
        expected_signature = expected_mac.hexdigest()

        # Constant-time comparison (important for security)
        if not hmac.compare_digest(received_signature, expected_signature):
            return False, f"SIGNATURE MISMATCH - Response has been tampered!\n  Expected: {expected_signature[:32]}...\n  Received: {received_signature[:32]}..."

        return True, "Signature valid - response is authentic"

    except json.JSONDecodeError:
        return False, "Response is not valid JSON - likely tampered"
    except Exception as e:
        return False, f"Verification error: {e}"


def test_endpoint(use_proxy=False):
    """Test /status endpoint with or without proxy"""

    url = "http://localhost:8787/status"
    proxies = {"http": "http://localhost:8080"} if use_proxy else None

    print("="*70)
    print(f"Testing HSIP Daemon - {'WITH PROXY (attack)' if use_proxy else 'DIRECT (no attack)'}")
    print("="*70)
    print(f"URL: {url}")
    if use_proxy:
        print(f"Proxy: {proxies['http']}")
    print()

    try:
        # Make request
        response = requests.get(url, proxies=proxies, timeout=5)

        print(f"HTTP Status: {response.status_code}")
        print(f"Content-Type: {response.headers.get('content-type', 'N/A')}")
        print()

        # Show raw response
        print("Raw Response:")
        print("-" * 70)
        print(response.text[:500])
        if len(response.text) > 500:
            print(f"... ({len(response.text)} bytes total)")
        print("-" * 70)
        print()

        # Try to parse as JSON
        try:
            response_json = response.json()
            print("✓ Response is valid JSON")
            print()

            # Verify signature
            is_valid, message = verify_response_signature(response_json)

            if is_valid:
                print("✅ SIGNATURE VERIFICATION: PASSED")
                print(f"   {message}")
                print()
                print("🔒 Response is AUTHENTIC - Safe to use")
                print()
                print("Response data:")
                print(json.dumps(response_json["data"], indent=2))
                return True
            else:
                print("❌ SIGNATURE VERIFICATION: FAILED")
                print(f"   {message}")
                print()
                print("🚨 SECURITY ALERT: Response has been TAMPERED!")
                print("   DO NOT trust this data. Possible MITM attack detected.")
                return False

        except json.JSONDecodeError:
            print("✗ Response is NOT valid JSON")
            print()
            print("❌ SIGNATURE VERIFICATION: FAILED")
            print("   Response is not in expected format - likely tampered")
            print()
            print("🚨 SECURITY ALERT: Response has been TAMPERED!")
            print("   DO NOT trust this data. Possible MITM attack detected.")
            return False

    except requests.exceptions.ProxyError:
        print("❌ ERROR: Cannot connect through proxy")
        print("   Make sure mitmproxy is running: mitmdump --listen-port 8080")
        return False
    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Cannot connect to daemon")
        print("   Make sure daemon is running: ./target/release/hsip-cli daemon")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False


if __name__ == "__main__":
    use_proxy = "--proxy" in sys.argv

    print()
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║  HSIP HMAC Signature Verification Demo                           ║")
    print("║  Testing Response Integrity Protection (OWASP A08 Defense)       ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")
    print()

    result = test_endpoint(use_proxy)

    print()
    print("="*70)
    if result:
        print("RESULT: Response is authentic and safe to use ✅")
    else:
        print("RESULT: Response failed verification - REJECTED ❌")
    print("="*70)
    print()

    # Exit code for automation
    sys.exit(0 if result else 1)
