#!/usr/bin/env python3
"""mitmproxy script to capture Kohler APIM subscription key.

This script runs inside mitmproxy and watches for requests to the Kohler API,
extracting the Ocp-Apim-Subscription-Key header.

Usage:
    mitmproxy -s capture_apim_key.py
    mitmweb -s capture_apim_key.py
"""

import json
import os
from pathlib import Path

from mitmproxy import http

# File to save captured secrets
BUILD_DIR = Path(__file__).parent.parent / ".build"
CAPTURED_FILE = BUILD_DIR / "captured_apim_key.json"

# Track what we've captured
captured = {
    "apim_key": None,
    "requests": []
}


def request(flow: http.HTTPFlow) -> None:
    """Intercept requests and look for APIM key."""
    global captured

    # Only care about Kohler API requests
    host = flow.request.host
    if "kohler" not in host.lower():
        return

    # Log the request
    req_info = {
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "host": host,
    }

    # Look for APIM subscription key
    apim_key = flow.request.headers.get("Ocp-Apim-Subscription-Key")
    if apim_key:
        req_info["apim_key"] = apim_key
        if not captured["apim_key"]:
            captured["apim_key"] = apim_key
            print("\n" + "=" * 60)
            print("FOUND APIM SUBSCRIPTION KEY!")
            print("=" * 60)
            print(f"\nKey: {apim_key}")
            print(f"\nSaved to: {CAPTURED_FILE}")
            print("\nYou can now press Ctrl+C to stop mitmproxy.")
            print("=" * 60 + "\n")

            # Save to file
            BUILD_DIR.mkdir(parents=True, exist_ok=True)
            CAPTURED_FILE.write_text(json.dumps(captured, indent=2))

    captured["requests"].append(req_info)

    # Print request info
    print(f"[Kohler] {flow.request.method} {flow.request.path}")
    if apim_key:
        print(f"         APIM Key: {apim_key[:8]}...{apim_key[-4:]}")


def done():
    """Called when mitmproxy shuts down."""
    if captured["apim_key"]:
        print(f"\n\nCaptured APIM key saved to: {CAPTURED_FILE}")
    else:
        print("\n\nNo APIM key was captured.")
        print("Make sure you:")
        print("  1. Configured Android proxy correctly")
        print("  2. Installed mitmproxy CA certificate")
        print("  3. Logged into the Kohler Konnect app")
