#!/usr/bin/env python3
"""Extract API endpoints from the Kohler Konnect APK.

This script searches the extracted APK for API endpoints and URLs.
"""

import re
import subprocess
import sys
from pathlib import Path

APK_DIR = Path(__file__).parent.parent / "apk_extracted" / "base_extracted"


def extract_strings_from_dex():
    """Extract strings from DEX files."""
    endpoints = set()
    
    for dex_file in APK_DIR.glob("classes*.dex"):
        try:
            result = subprocess.run(
                ["strings", str(dex_file)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            for line in result.stdout.split("\n"):
                # Look for HTTPS URLs
                urls = re.findall(r"https?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[^\s\"']*)?", line)
                endpoints.update(urls)
                
                # Look for API endpoint patterns
                if re.search(r"(api|endpoint|device|iot)", line, re.I):
                    if "http" in line.lower():
                        endpoints.add(line.strip())
        except Exception as e:
            print(f"Error processing {dex_file}: {e}", file=sys.stderr)
    
    return sorted(endpoints)


def main():
    """Main function."""
    print("Extracting API endpoints from APK...")
    print("=" * 70)
    
    endpoints = extract_strings_from_dex()
    
    # Filter and categorize
    api_endpoints = [e for e in endpoints if "api" in e.lower() or "kohler" in e.lower() or "azure" in e.lower()]
    device_endpoints = [e for e in endpoints if "device" in e.lower()]
    iot_endpoints = [e for e in endpoints if "iot" in e.lower() or "hub" in e.lower()]
    
    print("\nAPI Endpoints:")
    print("-" * 70)
    for endpoint in api_endpoints[:20]:
        print(f"  {endpoint}")
    
    print("\nDevice-related Endpoints:")
    print("-" * 70)
    for endpoint in device_endpoints[:20]:
        print(f"  {endpoint}")
    
    print("\nIoT/Hub Endpoints:")
    print("-" * 70)
    for endpoint in iot_endpoints[:20]:
        print(f"  {endpoint}")


if __name__ == "__main__":
    main()
