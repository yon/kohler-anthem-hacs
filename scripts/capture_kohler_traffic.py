#!/usr/bin/env python3
"""
Mitmproxy addon script to capture and analyze Kohler Konnect app traffic.

This script captures:
- APIM subscription key (Ocp-Apim-Subscription-Key header)
- API endpoints and their request/response formats
- Authentication tokens
- IoT Hub connection strings
- Device IDs and configuration

Usage:
    mitmdump -s capture_kohler_traffic.py -w kohler_traffic.flow

    Or with web interface:
    mitmweb -s capture_kohler_traffic.py
"""

import json
import os
import re
from datetime import datetime
from mitmproxy import http, ctx

# Output directory for captured data
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "captured_traffic")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Domains to capture
KOHLER_DOMAINS = [
    "kohler",
    "konnectkohler",
    "azure-api.net",
    "azure-devices.net",
    "b2clogin.com",
    "azurewebsites.net",
]

# Captured data storage
captured_data = {
    "apim_subscription_keys": set(),
    "access_tokens": set(),
    "refresh_tokens": set(),
    "device_ids": set(),
    "connection_strings": set(),
    "endpoints": {},
    "requests": [],
}


def is_kohler_traffic(flow: http.HTTPFlow) -> bool:
    """Check if this is Kohler-related traffic."""
    host = flow.request.host.lower()
    return any(domain in host for domain in KOHLER_DOMAINS)


def extract_secrets(flow: http.HTTPFlow) -> dict:
    """Extract secrets and important data from request/response."""
    secrets = {}

    # Check request headers
    headers = dict(flow.request.headers)

    # APIM Subscription Key
    for key in ["Ocp-Apim-Subscription-Key", "ocp-apim-subscription-key"]:
        if key in headers:
            secrets["apim_subscription_key"] = headers[key]
            captured_data["apim_subscription_keys"].add(headers[key])
            ctx.log.info(f"*** FOUND APIM SUBSCRIPTION KEY: {headers[key]}")

    # Authorization token
    auth_header = headers.get("Authorization", headers.get("authorization", ""))
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        secrets["access_token"] = token[:50] + "..."
        captured_data["access_tokens"].add(token)

    # Check request body for secrets
    if flow.request.content:
        try:
            body = flow.request.content.decode("utf-8", errors="ignore")

            # Look for connection strings
            conn_str_match = re.search(r'HostName=[^;]+;DeviceId=[^;]+;SharedAccessKey=[^"}\s]+', body)
            if conn_str_match:
                secrets["connection_string"] = conn_str_match.group()
                captured_data["connection_strings"].add(conn_str_match.group())
                ctx.log.info(f"*** FOUND CONNECTION STRING")

            # Look for device IDs
            device_id_match = re.search(r'"deviceId"\s*:\s*"([^"]+)"', body, re.IGNORECASE)
            if device_id_match:
                secrets["device_id"] = device_id_match.group(1)
                captured_data["device_ids"].add(device_id_match.group(1))
        except Exception:
            pass

    # Check response body for secrets
    if flow.response and flow.response.content:
        try:
            body = flow.response.content.decode("utf-8", errors="ignore")

            # Look for connection strings
            conn_str_match = re.search(r'HostName=[^;]+;DeviceId=[^;]+;SharedAccessKey=[^"}\s]+', body)
            if conn_str_match:
                secrets["connection_string"] = conn_str_match.group()
                captured_data["connection_strings"].add(conn_str_match.group())
                ctx.log.info(f"*** FOUND CONNECTION STRING IN RESPONSE")

            # Look for device IDs
            device_id_match = re.search(r'"deviceId"\s*:\s*"([^"]+)"', body, re.IGNORECASE)
            if device_id_match:
                secrets["device_id"] = device_id_match.group(1)
                captured_data["device_ids"].add(device_id_match.group(1))

            # Look for tokens in response
            token_match = re.search(r'"access_token"\s*:\s*"([^"]+)"', body)
            if token_match:
                captured_data["access_tokens"].add(token_match.group(1))

            refresh_match = re.search(r'"refresh_token"\s*:\s*"([^"]+)"', body)
            if refresh_match:
                captured_data["refresh_tokens"].add(refresh_match.group(1))

        except Exception:
            pass

    return secrets


def response(flow: http.HTTPFlow) -> None:
    """Called when a response is received."""
    if not is_kohler_traffic(flow):
        return

    # Extract secrets
    secrets = extract_secrets(flow)

    # Build request info
    request_info = {
        "timestamp": datetime.now().isoformat(),
        "method": flow.request.method,
        "url": flow.request.url,
        "host": flow.request.host,
        "path": flow.request.path,
        "request_headers": dict(flow.request.headers),
        "response_status": flow.response.status_code if flow.response else None,
        "response_headers": dict(flow.response.headers) if flow.response else None,
        "secrets_found": secrets,
    }

    # Add request body if JSON
    if flow.request.content:
        try:
            content_type = flow.request.headers.get("content-type", "")
            if "json" in content_type or "form" in content_type:
                body = flow.request.content.decode("utf-8", errors="ignore")
                if "json" in content_type:
                    try:
                        request_info["request_body"] = json.loads(body)
                    except json.JSONDecodeError:
                        request_info["request_body"] = body[:2000]
                else:
                    request_info["request_body"] = body[:2000]
        except Exception:
            pass

    # Add response body if JSON
    if flow.response and flow.response.content:
        try:
            content_type = flow.response.headers.get("content-type", "")
            if "json" in content_type:
                body = flow.response.content.decode("utf-8", errors="ignore")
                try:
                    request_info["response_body"] = json.loads(body)
                except json.JSONDecodeError:
                    request_info["response_body"] = body[:5000]
        except Exception:
            pass

    # Store endpoint info
    endpoint_key = f"{flow.request.method} {flow.request.host}{flow.request.path.split('?')[0]}"
    if endpoint_key not in captured_data["endpoints"]:
        captured_data["endpoints"][endpoint_key] = []
    captured_data["endpoints"][endpoint_key].append(request_info)

    # Store full request
    captured_data["requests"].append(request_info)

    # Log important requests
    ctx.log.info(f"Captured: {flow.request.method} {flow.request.url[:100]} -> {flow.response.status_code if flow.response else 'N/A'}")

    # Save to file incrementally
    save_captured_data()


def save_captured_data():
    """Save captured data to files."""
    # Save summary
    summary = {
        "apim_subscription_keys": list(captured_data["apim_subscription_keys"]),
        "access_tokens_count": len(captured_data["access_tokens"]),
        "device_ids": list(captured_data["device_ids"]),
        "connection_strings": list(captured_data["connection_strings"]),
        "endpoints_discovered": list(captured_data["endpoints"].keys()),
        "total_requests": len(captured_data["requests"]),
    }

    with open(os.path.join(OUTPUT_DIR, "capture_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # Save all requests
    with open(os.path.join(OUTPUT_DIR, "all_requests.json"), "w") as f:
        json.dump(captured_data["requests"], f, indent=2, default=str)

    # Save secrets separately (for easy access)
    secrets = {
        "apim_subscription_keys": list(captured_data["apim_subscription_keys"]),
        "access_tokens": list(captured_data["access_tokens"]),
        "refresh_tokens": list(captured_data["refresh_tokens"]),
        "device_ids": list(captured_data["device_ids"]),
        "connection_strings": list(captured_data["connection_strings"]),
    }
    with open(os.path.join(OUTPUT_DIR, "secrets.json"), "w") as f:
        json.dump(secrets, f, indent=2)


def done():
    """Called when mitmproxy is shutting down."""
    save_captured_data()

    print("\n" + "="*60)
    print("CAPTURE COMPLETE - SUMMARY")
    print("="*60)
    print(f"\nAPIM Subscription Keys Found: {len(captured_data['apim_subscription_keys'])}")
    for key in captured_data["apim_subscription_keys"]:
        print(f"  - {key}")

    print(f"\nDevice IDs Found: {len(captured_data['device_ids'])}")
    for did in captured_data["device_ids"]:
        print(f"  - {did}")

    print(f"\nConnection Strings Found: {len(captured_data['connection_strings'])}")
    for cs in captured_data["connection_strings"]:
        print(f"  - {cs[:80]}...")

    print(f"\nEndpoints Discovered: {len(captured_data['endpoints'])}")
    for ep in captured_data["endpoints"]:
        print(f"  - {ep}")

    print(f"\nTotal Requests Captured: {len(captured_data['requests'])}")
    print(f"\nOutput saved to: {OUTPUT_DIR}/")
    print("="*60)
