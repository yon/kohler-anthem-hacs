#!/usr/bin/env python3
"""Enhanced API discovery script for Kohler Anthem Digital Shower.

Tests various endpoints and HTTP methods to discover the device API.
"""

import base64
import json
import sys
import time
from typing import Any

import requests


def test_endpoint(
    base_url: str,
    endpoint: str,
    method: str = "GET",
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
) -> None:
    """Test a single endpoint and print results."""
    url = f"{base_url}/{endpoint}"
    
    try:
        if method == "GET":
            resp = requests.get(url, params=params, timeout=5)
            print_response(endpoint, method, resp, params)
        elif method == "POST":
            resp = requests.post(url, json=data, params=params, timeout=5)
            print_response(endpoint, method, resp, params, data)
        elif method == "PUT":
            resp = requests.put(url, json=data, params=params, timeout=5)
            print_response(endpoint, method, resp, params, data)
    except requests.exceptions.Timeout:
        print(f"  ❌ {endpoint} ({method}): TIMEOUT")
    except requests.exceptions.RequestException as e:
        print(f"  ❌ {endpoint} ({method}): ERROR - {e}")
    except Exception as e:
        print(f"  ❌ {endpoint} ({method}): UNEXPECTED ERROR - {e}")


def print_response(
    endpoint: str,
    method: str,
    resp: requests.Response,
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
) -> None:
    """Print formatted response information."""
    status_icon = "✅" if resp.status_code == 200 else "⚠️" if resp.status_code < 400 else "❌"
    print(f"  {status_icon} {endpoint} ({method}): {resp.status_code} {resp.reason}")
    
    if params:
        print(f"     Params: {params}")
    if data:
        print(f"     Data: {data}")
    
    try:
        text = resp.text
        content_type = resp.headers.get("Content-Type", "unknown")
        print(f"     Content-Type: {content_type}")
        print(f"     Content-Length: {len(text)} bytes")
        
        # Try to decode as JSON
        try:
            json_data = resp.json()
            print(f"     JSON: {json.dumps(json_data, indent=6)}")
        except:
            # Try base64 decode
            try:
                decoded = base64.b64decode(text)
                try:
                    json_data = json.loads(decoded)
                    print(f"     Base64->JSON: {json.dumps(json_data, indent=6)}")
                except:
                    print(f"     Base64->Text: {decoded[:200]}")
            except:
                # Print raw text (truncated)
                preview = text[:200].replace("\n", "\\n")
                print(f"     Raw: {preview}{'...' if len(text) > 200 else ''}")
    except Exception as e:
        print(f"     Error reading response: {e}")


def discover_api(ip_address: str) -> None:
    """Discover API endpoints on the Kohler Anthem device."""
    base_url = f"http://{ip_address}"
    
    print(f"\n{'='*60}")
    print(f"Discovering Kohler Anthem API at {ip_address}")
    print(f"{'='*60}\n")
    
    # Common CGI endpoints to test
    cgi_endpoints = [
        "system_info.cgi",
        "values.cgi",
        "status.cgi",
        "control.cgi",
        "config.cgi",
        "info.cgi",
        "state.cgi",
        "settings.cgi",
        "api/status",
        "api/values",
        "api/control",
        "api/system",
    ]
    
    # Common REST-style endpoints
    rest_endpoints = [
        "api/v1/status",
        "api/v1/values",
        "api/v1/control",
        "api/v1/system",
        "status",
        "values",
        "control",
    ]
    
    # Test root endpoint
    print("Testing root endpoint:")
    test_endpoint(base_url, "")
    
    # Test CGI endpoints
    print("\nTesting CGI endpoints (GET):")
    for endpoint in cgi_endpoints:
        test_endpoint(base_url, endpoint)
        time.sleep(0.1)  # Small delay between requests
    
    # Test REST endpoints
    print("\nTesting REST endpoints (GET):")
    for endpoint in rest_endpoints:
        test_endpoint(base_url, endpoint)
        time.sleep(0.1)
    
    # Test POST methods on likely control endpoints
    print("\nTesting POST methods on control endpoints:")
    control_endpoints = ["control.cgi", "api/control", "api/v1/control", "control"]
    for endpoint in control_endpoints:
        # Test with different command structures
        test_commands = [
            {"action": "start", "temperature": 100},
            {"cmd": "start", "temp": 100},
            {"command": "start_shower", "temp": 100},
        ]
        for cmd in test_commands:
            test_endpoint(base_url, endpoint, "POST", data=cmd)
            time.sleep(0.1)
    
    # Test status endpoint with different query params
    print("\nTesting status endpoint with query parameters:")
    status_params = [
        {"format": "json"},
        {"type": "all"},
        {"full": "1"},
    ]
    for params in status_params:
        test_endpoint(base_url, "status.cgi", params=params)
        time.sleep(0.1)
    
    print(f"\n{'='*60}")
    print("Discovery complete!")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 discover_api.py <IP_ADDRESS>")
        print("Example: python3 discover_api.py 10.10.3.84")
        sys.exit(1)
    
    ip_address = sys.argv[1]
    discover_api(ip_address)
