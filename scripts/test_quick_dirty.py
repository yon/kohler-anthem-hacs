#!/usr/bin/env python3
"""Quick and dirty test script to authenticate, discover device, and control shower.

This script tests the actual API calls before implementing the full integration.

Requirements:
    pip install msal aiohttp azure-iot-device

Usage:
    source ../.env
    python3 test_quick_dirty.py
    # or with explicit credentials:
    python3 test_quick_dirty.py username password
"""

import asyncio
import base64
import json
import os
import sys
from typing import Any, Optional, List

try:
    import aiohttp
    import msal
    from azure.iot.device.aio import IoTHubDeviceClient
    from azure.iot.device import Message
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("\nInstall dependencies with:")
    print("  pip install msal aiohttp azure-iot-device")
    sys.exit(1)

# =============================================================================
# Configuration - load from environment or use defaults
# =============================================================================

# Azure AD B2C Configuration
# The konnectkohler tenant is from the APK - we'll try multiple policies
AZURE_TENANT = "konnectkohler.onmicrosoft.com"
AZURE_CLIENT_ID = os.environ.get("KOHLER_CLIENT_ID")
if not AZURE_CLIENT_ID:
    print("Error: KOHLER_CLIENT_ID environment variable required")
    print("Run: source ../.env")
    sys.exit(1)
AZURE_API_RESOURCE = os.environ.get("KOHLER_API_RESOURCE")
if not AZURE_API_RESOURCE:
    print("Error: KOHLER_API_RESOURCE environment variable required")
    print("Run: source ../.env")
    sys.exit(1)

# Policies to try (in order of preference)
AZURE_POLICIES = [
    "B2C_1_ROPC_Auth",
    "B2C_1_ROPC",
    "B2C_1A_ROPC_Auth",
    "B2C_1A_signin",  # May not support ROPC but try anyway
]

# APIM Subscription Key
APIM_SUBSCRIPTION_KEY = os.environ.get("KOHLER_APIM_KEY")
if not APIM_SUBSCRIPTION_KEY:
    print("Error: KOHLER_APIM_KEY environment variable required")
    print("Run: source ../.env")
    sys.exit(1)

# IoT Hub
IOT_HUB_HOST = os.environ.get("KOHLER_IOT_HUB_HOST", "prd-hub.azure-devices.net")

# API Base URLs (api-kohler-us.kohler.io is the working endpoint)
KOHLER_API_BASE = "https://api-kohler-us.kohler.io"
PLATFORM_API_BASE = KOHLER_API_BASE


async def authenticate(username: str, password: str) -> Optional[dict]:
    """Authenticate with Azure AD B2C using ROPC flow, trying multiple policies."""
    print(f"\n{'='*60}")
    print("Step 1: Authenticating...")
    print(f"{'='*60}")
    print(f"   Tenant: {AZURE_TENANT}")
    print(f"   Client ID: {AZURE_CLIENT_ID}")

    scopes = f"openid offline_access https://{AZURE_TENANT}/{AZURE_API_RESOURCE}/apiaccess"

    async with aiohttp.ClientSession() as session:
        for policy in AZURE_POLICIES:
            token_url = f"https://konnectkohler.b2clogin.com/tfp/{AZURE_TENANT}/{policy}/oauth2/v2.0/token"
            print(f"\n   Trying policy: {policy}")
            print(f"   URL: {token_url}")

            data = {
                "grant_type": "password",
                "client_id": AZURE_CLIENT_ID,
                "username": username,
                "password": password,
                "scope": scopes,
            }

            try:
                async with session.post(token_url, data=data, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    print(f"   Status: {resp.status}")

                    if resp.status == 200:
                        result = await resp.json()
                        if "access_token" in result:
                            print("Authentication successful!")
                            print(f"   Access token: {result['access_token'][:50]}...")

                            # Decode JWT to see claims
                            token_parts = result['access_token'].split('.')
                            if len(token_parts) >= 2:
                                payload = token_parts[1] + '=' * (4 - len(token_parts[1]) % 4)
                                try:
                                    decoded = json.loads(base64.urlsafe_b64decode(payload))
                                    print(f"\n   JWT Claims:")
                                    for key, value in decoded.items():
                                        print(f"      {key}: {value}")
                                except Exception as e:
                                    print(f"   Could not decode JWT: {e}")

                            return result
                    else:
                        try:
                            result = await resp.json()
                            error = result.get("error_description", result.get("error", "Unknown"))[:150]
                            print(f"   Failed: {error}")
                        except:
                            text = await resp.text()
                            print(f"   Failed: {text[:150]}")

            except Exception as err:
                print(f"   Error: {err}")

    print("\nAll ROPC policies failed. The B2C tenant may not support password flow.")
    return None


async def discover_devices(access_token: str, customer_id: Optional[str] = None) -> List[dict]:
    """Discover user's devices."""
    print(f"\n{'='*60}")
    print("Step 2: Discovering devices...")
    print(f"{'='*60}")

    # Headers with subscription key
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Ocp-Apim-Subscription-Key": APIM_SUBSCRIPTION_KEY,
    }

    # Endpoints to try (customer-specific endpoint worked in testing)
    endpoints = [
        # Primary: customer-specific endpoint (worked!)
        f"{KOHLER_API_BASE}/devices/api/v1/device-management/customer-device/{customer_id}" if customer_id else None,
        # Fallback: generic endpoint
        f"{KOHLER_API_BASE}/devices/api/v1/device-management/customer-device",
        # Azure APIM (may require mTLS)
        "https://az-amer-prod-kohlerkonnect-apim.azure-api.net/token/api/v1/CustomerDevice",
    ]
    endpoints = [e for e in endpoints if e]  # Filter None
    
    async with aiohttp.ClientSession() as session:
        for endpoint in endpoints:
            try:
                print(f"\nTrying endpoint: {endpoint}")
                async with session.get(
                    endpoint, 
                    headers=headers, 
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    print(f"   Status: {resp.status}")
                    
                    if resp.status == 200:
                        data = await resp.json()
                        print(f"✅ Success! Response:")
                        print(json.dumps(data, indent=2))

                        # Parse devices - handle nested customerHome[].devices[] structure
                        devices = []
                        if isinstance(data, dict):
                            # Check for customerHome structure (Kohler's actual format)
                            customer_homes = data.get("customerHome", [])
                            for home in customer_homes:
                                home_name = home.get("homeName", "Unknown Home")
                                home_id = home.get("homeId")
                                for device in home.get("devices", []):
                                    device_info = {
                                        "device_id": device.get("deviceId"),
                                        "name": device.get("logicalName") or device.get("name"),
                                        "sku": device.get("sku"),
                                        "serial_number": device.get("serialNumber"),
                                        "home_name": home_name,
                                        "home_id": home_id,
                                        "is_active": device.get("isActive"),
                                        "is_provisioned": device.get("isProvisioned"),
                                        # IoT Hub connection string - critical for MQTT!
                                        "connection_string": device.get("connectionString") or device.get("connection_string"),
                                        "iot_hub_name": device.get("iotHubName") or device.get("hubName"),
                                    }
                                    if device_info["device_id"]:
                                        devices.append(device_info)

                            # Also try flat device list (Azure APIM format)
                            if not devices:
                                device_list = data.get("devices", data.get("data", data.get("items", [])))
                                if not device_list and isinstance(data, list):
                                    device_list = data  # Response might be direct array
                                for device in device_list if device_list else []:
                                    if isinstance(device, dict):
                                        device_info = {
                                            "device_id": device.get("deviceId") or device.get("device_id") or device.get("id"),
                                            "name": device.get("name") or device.get("deviceName") or device.get("logicalName"),
                                            "sku": device.get("sku") or device.get("model"),
                                            # IoT Hub connection string - critical for MQTT!
                                            "connection_string": device.get("connectionString") or device.get("connection_string"),
                                            "iot_hub_name": device.get("iotHubName") or device.get("hubName"),
                                        }
                                        if device_info["device_id"]:
                                            devices.append(device_info)

                        print(f"\n✅ Found {len(devices)} device(s):")
                        for i, device in enumerate(devices, 1):
                            print(f"   {i}. {device.get('name', 'Unknown')} (ID: {device['device_id']})")
                            print(f"      SKU: {device.get('sku')}, Home: {device.get('home_name')}")
                            # Check if we got connection string
                            conn_str = device.get('connection_string')
                            if conn_str:
                                print(f"      ✅ IoT Hub Connection String: {conn_str[:60]}...")
                            else:
                                print(f"      ⚠️  No IoT Hub connection string in response")

                        return devices
                    
                    elif resp.status == 401:
                        print(f"   ❌ Unauthorized - token may be invalid")
                        text = await resp.text()
                        print(f"   Response: {text[:200]}")
                    
                    else:
                        text = await resp.text()
                        print(f"   Response: {text[:200]}")
                        
            except aiohttp.ClientError as err:
                print(f"   ❌ Connection error: {err}")
            except Exception as err:
                print(f"   ❌ Error: {err}")
                import traceback
                traceback.print_exc()
    
    print("\n❌ Failed to discover devices from any endpoint")
    return []


async def connect_iot_hub(connection_string: str) -> Optional[IoTHubDeviceClient]:
    """Connect to Azure IoT Hub."""
    print(f"\n{'='*60}")
    print("Step 3: Connecting to IoT Hub...")
    print(f"{'='*60}")
    
    try:
        client = IoTHubDeviceClient.create_from_connection_string(connection_string)
        await client.connect()
        print("✅ Connected to IoT Hub!")
        return client
    except Exception as err:
        print(f"❌ Failed to connect to IoT Hub: {err}")
        import traceback
        traceback.print_exc()
        return None


async def send_command_via_iot_hub(client: IoTHubDeviceClient, command: dict) -> bool:
    """Send command via IoT Hub."""
    print(f"\n{'='*60}")
    print("Step 4: Sending command via IoT Hub...")
    print(f"{'='*60}")
    
    try:
        message = Message(json.dumps(command))
        message.content_type = "application/json"
        message.content_encoding = "utf-8"
        
        await client.send_message(message)
        print(f"✅ Command sent: {json.dumps(command, indent=2)}")
        return True
    except Exception as err:
        print(f"❌ Failed to send command: {err}")
        import traceback
        traceback.print_exc()
        return False


async def get_device_status(access_token: str, device_id: str, customer_id: str) -> Optional[dict]:
    """Get device status and configuration."""
    print(f"\n{'='*60}")
    print("Step 3b: Getting device status...")
    print(f"{'='*60}")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Ocp-Apim-Subscription-Key": APIM_SUBSCRIPTION_KEY,
    }

    # Try various status/settings endpoints
    endpoints = [
        f"{KOHLER_API_BASE}/platform/api/v1/mobile/settings/{customer_id}/{device_id}",
        f"{KOHLER_API_BASE}/platform/api/v1/gcs/{device_id}/status",
        f"{KOHLER_API_BASE}/platform/api/v1/devices/{device_id}/status",
    ]

    async with aiohttp.ClientSession() as session:
        for endpoint in endpoints:
            try:
                print(f"\nTrying: {endpoint}")
                async with session.get(endpoint, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    print(f"   Status: {resp.status}")
                    if resp.status == 200:
                        data = await resp.json()
                        print(f"✅ Got device status:")
                        print(json.dumps(data, indent=2)[:2000])
                        return data
                    else:
                        text = await resp.text()
                        print(f"   Response: {text[:200]}")
            except Exception as err:
                print(f"   Error: {err}")

    return None


async def send_warmup(access_token: str, device_id: str, tenant_id: str) -> bool:
    """Send warmup command via Platform API (tested working 2026-01-10)."""
    print(f"\n{'='*60}")
    print("Testing: Warmup Command")
    print(f"{'='*60}")

    endpoint = f"{PLATFORM_API_BASE}/platform/api/v1/commands/gcs/warmup"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Ocp-Apim-Subscription-Key": APIM_SUBSCRIPTION_KEY,
    }
    payload = {
        "deviceId": device_id,
        "sku": "GCS",
        "tenantId": tenant_id,
    }

    print(f"   Endpoint: {endpoint}")
    print(f"   Payload: {json.dumps(payload, indent=2)}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(endpoint, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                text = await resp.text()
                print(f"   Status: {resp.status}")
                if resp.status in (200, 201, 202):
                    print(f"   ✅ Warmup command sent successfully!")
                    return True
                else:
                    print(f"   ❌ Failed: {text[:200]}")
        except Exception as err:
            print(f"   ❌ Error: {err}")
    return False


async def send_preset_control(access_token: str, device_id: str, tenant_id: str, preset_id: str) -> bool:
    """Start or stop preset via Platform API (tested working 2026-01-10).

    Args:
        preset_id: "1"-"5" to start preset, "0" to stop shower
    """
    print(f"\n{'='*60}")
    action = "Stop shower" if preset_id == "0" else f"Start preset {preset_id}"
    print(f"Testing: {action}")
    print(f"{'='*60}")

    endpoint = f"{PLATFORM_API_BASE}/platform/api/v1/commands/gcs/controlpresetorexperience"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Ocp-Apim-Subscription-Key": APIM_SUBSCRIPTION_KEY,
    }
    payload = {
        "deviceId": device_id,
        "sku": "GCS",
        "tenantId": tenant_id,
        "presetOrExperienceId": preset_id,
    }

    print(f"   Endpoint: {endpoint}")
    print(f"   Payload: {json.dumps(payload, indent=2)}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(endpoint, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                text = await resp.text()
                print(f"   Status: {resp.status}")
                if resp.status in (200, 201, 202):
                    print(f"   ✅ {action} command sent successfully!")
                    return True
                else:
                    print(f"   ❌ Failed: {text[:200]}")
        except Exception as err:
            print(f"   ❌ Error: {err}")
    return False


async def test_valve_control(access_token: str, device_id: str, tenant_id: str,
                            primary_valve: str = "0179c840",
                            secondary_valve: str = "1179c840") -> bool:
    """Test direct valve control (writesolostatus) with correct payload format.

    Valve value format: [prefix][temp][flow][mode]
        - prefix: 01=primary, 11=secondary
        - temp: 00-E8 (15-48.8°C)
        - flow: 00-C8 (0-100%)
        - mode: 00=off, 01=shower, 02=tub, 03=tub+on, 40=stop

    Examples:
        - "0179c801" = primary, 37.7°C, 100% flow, showerhead on
        - "1179c801" = secondary, 37.7°C, 100% flow, handshower on
        - "0179c840" = primary, 37.7°C, 100% flow, STOP
    """
    print(f"\n{'='*60}")
    print("Testing: Direct Valve Control (writesolostatus)")
    print(f"{'='*60}")

    endpoint = f"{PLATFORM_API_BASE}/platform/api/v1/commands/gcs/writesolostatus"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Ocp-Apim-Subscription-Key": APIM_SUBSCRIPTION_KEY,
    }

    # Use the exact payload format captured from the app
    payload = {
        "gcsValveControlModel": {
            "primaryValve1": primary_valve,
            "secondaryValve1": secondary_valve,
            "secondaryValve2": "00000000",
            "secondaryValve3": "00000000",
            "secondaryValve4": "00000000",
            "secondaryValve5": "00000000",
            "secondaryValve6": "00000000",
            "secondaryValve7": "00000000",
        },
        "deviceId": device_id,
        "sku": "GCS",
        "tenantId": tenant_id,
    }

    print(f"   Endpoint: {endpoint}")
    print(f"   Payload: {json.dumps(payload, indent=2)}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(endpoint, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                text = await resp.text()
                print(f"   Status: {resp.status}")
                if resp.status in (200, 201, 202):
                    print(f"   ✅ Valve control succeeded!")
                    print(f"   Response: {text[:200]}")
                    return True
                else:
                    print(f"   ❌ Failed: {text[:200]}")
        except Exception as err:
            print(f"   ❌ Error: {err}")
    return False


async def main():
    """Main test function."""
    # Get credentials from args, environment, or interactive input
    if len(sys.argv) >= 3:
        username = sys.argv[1]
        password = sys.argv[2]
    elif os.environ.get("KOHLER_USERNAME") and os.environ.get("KOHLER_PASSWORD"):
        username = os.environ["KOHLER_USERNAME"]
        password = os.environ["KOHLER_PASSWORD"]
        print("Using credentials from environment variables")
    else:
        # Interactive mode
        print("\n" + "="*60)
        print("Kohler Anthem Quick & Dirty Test")
        print("="*60)
        print("\nNo credentials found. Either:")
        print("  1. source ../.env  (then re-run)")
        print("  2. python3 test_quick_dirty.py <email> <password>")
        print("\nEnter your Kohler Konnect credentials:")
        username = input("Email/Username: ").strip()
        import getpass
        password = getpass.getpass("Password: ")
    
    print("\n" + "="*60)
    print("Kohler Anthem Quick & Dirty Test")
    print("="*60)
    print(f"Username: {username}")
    print(f"Password: {'*' * len(password)}")
    
    # Step 1: Authenticate
    auth_result = await authenticate(username, password)
    if not auth_result:
        print("\n❌ Cannot proceed without authentication")
        sys.exit(1)

    access_token = auth_result["access_token"]

    # Extract customer_id from JWT token
    customer_id = None
    try:
        import base64
        token_parts = access_token.split('.')
        if len(token_parts) >= 2:
            payload = token_parts[1] + '=' * (4 - len(token_parts[1]) % 4)
            decoded = json.loads(base64.urlsafe_b64decode(payload))
            # Try different claims that might contain customer ID
            customer_id = decoded.get("oid") or decoded.get("sub") or decoded.get("objectId")
            if customer_id:
                print(f"\n   Customer ID from JWT: {customer_id}")
    except Exception as e:
        print(f"   Could not extract customer ID from JWT: {e}")

    # Step 2: Discover devices
    devices = await discover_devices(access_token, customer_id)
    if not devices:
        print("\n❌ No devices found. Cannot proceed.")
        sys.exit(1)
    
    # Use first device
    device = devices[0]
    device_id = device["device_id"]
    connection_string = device.get("connection_string")

    print(f"\n{'='*60}")
    print(f"Using device: {device.get('name', 'Unknown')} (ID: {device_id})")
    print(f"{'='*60}")

    if connection_string:
        print(f"\n✅ Found IoT Hub connection string!")
        print(f"   Connection string: {connection_string[:80]}...")
    else:
        print(f"\n⚠️  No IoT Hub connection string found in device discovery response")
        print(f"   Real-time status updates require MQTT which needs the connection string")

    # Step 3: Test Platform API commands
    print(f"\n{'='*60}")
    print("Step 3: Testing Platform API Commands")
    print(f"{'='*60}")

    # Track test results
    test_results = {}

    # Test warmup (working)
    test_results["warmup"] = await send_warmup(access_token, device_id, customer_id)

    # Test preset control - use preset 1 then stop (preset 0)
    # Note: This will actually affect the shower if it's connected!
    print(f"\n   Note: Skipping preset control to avoid actually starting shower.")
    print(f"   To test preset control, uncomment the lines below.")
    # test_results["preset_start"] = await send_preset_control(access_token, device_id, customer_id, "1")
    # test_results["preset_stop"] = await send_preset_control(access_token, device_id, customer_id, "0")
    test_results["preset_control"] = "skipped"

    # Test valve control (known to return 404)
    test_results["valve_control"] = await test_valve_control(access_token, device_id, customer_id)

    # Step 4: Try IoT Hub if we have connection string
    test_results["iot_hub"] = False
    if connection_string:
        print(f"\n{'='*60}")
        print("Step 4: Testing IoT Hub connection (MQTT)...")
        print(f"{'='*60}")

        iot_client = await connect_iot_hub(connection_string)
        if iot_client:
            try:
                twin = await iot_client.get_twin()
                print(f"\n✅ Got device twin (reported properties):")
                print(json.dumps(twin.get("reported", {}), indent=2)[:2000])
                test_results["iot_hub"] = True
            except Exception as e:
                print(f"   Could not get device twin: {e}")

            await iot_client.disconnect()
        else:
            print("\n❌ Failed to connect to IoT Hub")

    # Summary
    print(f"\n{'='*60}")
    print("TEST RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"  ✅ Authentication: Success")
    print(f"  ✅ Device Discovery: Found {len(devices)} device(s)")
    print(f"     Device ID: {device_id}")
    print(f"     Tenant ID: {customer_id}")
    print()
    print("  Platform API Commands:")
    print(f"     Warmup: {'✅ Working' if test_results.get('warmup') else '❌ Failed'}")
    if test_results.get("preset_control") == "skipped":
        print(f"     Preset Control: ⏭️  Skipped (uncomment to test)")
    else:
        print(f"     Preset Control: {'✅ Working' if test_results.get('preset_start') else '❌ Failed'}")
    print(f"     Valve Control: {'✅ Working' if test_results.get('valve_control') else '❌ Failed (may need session state)'}")
    print()
    if connection_string:
        print(f"  IoT Hub (MQTT): {'✅ Connected' if test_results.get('iot_hub') else '❌ Failed'}")
    else:
        print(f"  IoT Hub (MQTT): ⚠️  No connection string available")
    print()
    print("  Working Features:")
    print("     - Authentication via Azure AD B2C (ROPC flow)")
    print("     - Device discovery via REST API")
    print("     - Warmup command")
    print("     - Start/Stop presets (1-5, 0 to stop)")
    print()
    print("  Not Working:")
    print("     - Direct valve/temperature control (API returns 404)")
    print("     - Real-time status (needs IoT Hub connection string)")


if __name__ == "__main__":
    asyncio.run(main())
