#!/usr/bin/env python3
"""Quick test script to find and test Kohler Anthem API."""

import requests
import base64
import json
import sys

if len(sys.argv) < 2:
    print("Usage: python3 test_api.py <IP_ADDRESS>")
    sys.exit(1)

ANTHEM_IP = sys.argv[1]

def test(endpoint, params=None):
    url = f"http://{ANTHEM_IP}/{endpoint}"
    try:
        r = requests.get(url, params=params, timeout=5)
        print(f"\n{endpoint}: {r.status_code}")
        print(f"Raw: {r.text[:200]}")
        try:
            decoded = base64.b64decode(r.text)
            print(f"Decoded: {json.loads(decoded)}")
        except:
            pass
    except Exception as e:
        print(f"{endpoint}: ERROR - {e}")

print(f"Testing {ANTHEM_IP}...")
test("system_info.cgi")
test("values.cgi")
test("status.cgi")
