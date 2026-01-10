#!/usr/bin/env python3
"""Helper script to guide network traffic capture for Kohler Anthem API discovery.

This script provides instructions and can help set up network monitoring tools.
"""

import sys


def print_instructions():
    """Print instructions for capturing network traffic."""
    print("=" * 70)
    print("Kohler Anthem API Discovery - Network Traffic Capture Guide")
    print("=" * 70)
    print()
    print("To discover the device discovery API and IoT Hub endpoints, you need")
    print("to capture network traffic from the Kohler Konnect mobile app.")
    print()
    print("METHOD 1: Using mitmproxy (Recommended)")
    print("-" * 70)
    print("1. Install mitmproxy: pip install mitmproxy")
    print("2. Start mitmproxy: mitmproxy -p 8080")
    print("3. Configure your phone to use the proxy (your computer's IP:8080)")
    print("4. Install mitmproxy CA certificate on your phone")
    print("5. Open Kohler Konnect app and log in")
    print("6. Navigate to device list/control")
    print("7. Look for API calls to:")
    print("   - Device discovery endpoints (likely *.azurewebsites.net or similar)")
    print("   - IoT Hub endpoints (*.azure-devices.net)")
    print("   - Device provisioning endpoints")
    print()
    print("METHOD 2: Using Frida (for SSL pinning bypass)")
    print("-" * 70)
    print("If the app uses SSL pinning, you may need Frida to bypass it:")
    print("1. Install Frida on rooted Android device")
    print("2. Use frida-ssl-pinning-bypass script")
    print("3. Run app with Frida attached")
    print("4. Capture traffic with mitmproxy")
    print()
    print("METHOD 3: Using Azure IoT Explorer")
    print("-" * 70)
    print("If you can get the IoT Hub connection string:")
    print("1. Download Azure IoT Explorer")
    print("2. Connect using the connection string")
    print("3. Monitor device-to-cloud and cloud-to-device messages")
    print("4. Document message formats")
    print()
    print("WHAT TO LOOK FOR:")
    print("-" * 70)
    print("1. Device Discovery API:")
    print("   - Endpoint that returns list of devices after login")
    print("   - Response should contain device IDs and connection strings")
    print()
    print("2. IoT Hub Connection String Format:")
    print("   - Format: HostName=<hub>.azure-devices.net;DeviceId=<id>;SharedAccessKey=<key>")
    print("   - Or: HostName=<hub>.azure-devices.net;DeviceId=<id>;SharedAccessSignature=<sig>")
    print()
    print("3. Command Message Format:")
    print("   - JSON structure for sending commands (start, stop, temperature)")
    print("   - Message properties/headers")
    print()
    print("4. Status/Telemetry Format:")
    print("   - Device twin reported properties")
    print("   - Telemetry message structure")
    print()
    print("=" * 70)
    print()
    print("Once you capture the traffic, save the relevant API calls and")
    print("update the integration code with the discovered endpoints.")


if __name__ == "__main__":
    print_instructions()
