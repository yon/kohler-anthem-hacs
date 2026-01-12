#!/usr/bin/env python3
"""Capture APIM key by running Frida and parsing its output.

The Frida bypass script hooks SecurePreferences and prints the APIM key
when the app stores it. This wrapper script captures that output and
saves the key to .build/captured_apim_key.json.

Usage:
    python3 capture_apim_via_frida.py
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
BUILD_DIR = PROJECT_DIR / ".build"
CAPTURED_FILE = BUILD_DIR / "captured_apim_key.json"
FRIDA_SCRIPT = SCRIPT_DIR / "frida_bypass.js"

# Find frida binary
FRIDA_PATHS = [
    "frida",
    os.path.expanduser("~/Library/Python/3.9/bin/frida"),
    "/usr/local/bin/frida",
]


def find_frida():
    """Find the frida binary."""
    for path in FRIDA_PATHS:
        try:
            result = subprocess.run([path, "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                return path
        except FileNotFoundError:
            continue
    return None


def main():
    # Ensure build directory exists
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    # Find frida
    frida_path = find_frida()
    if not frida_path:
        print("ERROR: Could not find frida. Install with: pip install frida-tools")
        sys.exit(1)

    print()
    print("=" * 60)
    print("APIM Key Capture via Frida")
    print("=" * 60)
    print()
    print("This will launch the Kohler app with our bypass script.")
    print("The APIM key will be captured when the app stores it after login.")
    print()
    print("Instructions:")
    print("  1. Wait for the app to launch in the emulator")
    print("  2. Proceed through the location permission screen")
    print("  3. Log in with your Kohler account")
    print("  4. Watch for 'CAPTURED APIM SUBSCRIPTION KEY' below")
    print("  5. Press Ctrl+C to exit once you see the key")
    print()
    print("-" * 60)
    print()

    # Run frida and capture output
    cmd = [frida_path, "-U", "-f", "com.kohler.hermoth", "-l", str(FRIDA_SCRIPT)]

    captured_key = None
    key_pattern = re.compile(r"Key: ([a-f0-9]{32})")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        for line in process.stdout:
            print(line, end="")

            # Look for captured APIM key
            if "CAPTURED APIM SUBSCRIPTION KEY" in line:
                # Next line with "Key:" has the actual key
                pass
            match = key_pattern.search(line)
            if match and not captured_key:
                captured_key = match.group(1)
                print()
                print("=" * 60)
                print(f"Saving APIM key to: {CAPTURED_FILE}")
                print("=" * 60)
                print()

                # Save to file
                CAPTURED_FILE.write_text(json.dumps({"apim_key": captured_key}, indent=2))

    except KeyboardInterrupt:
        print()
        print()
        if captured_key:
            print(f"APIM key saved to: {CAPTURED_FILE}")
            print()
            print("Next step: make env")
        else:
            print("No APIM key was captured.")
            print("Make sure you logged into the app before pressing Ctrl+C.")
    finally:
        try:
            process.terminate()
        except:
            pass

    return 0 if captured_key else 1


if __name__ == "__main__":
    sys.exit(main())
