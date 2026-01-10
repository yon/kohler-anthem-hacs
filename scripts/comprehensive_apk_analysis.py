#!/usr/bin/env python3
"""Comprehensive APK analysis script for Kohler Anthem integration.

Extracts API endpoints, models, authentication details, and device control patterns.
"""

import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

APK_DIR = Path(__file__).parent.parent / "apk_extracted" / "base_extracted"


def extract_strings_from_dex():
    """Extract all strings from DEX files."""
    all_strings = []
    for dex_file in sorted(APK_DIR.glob("classes*.dex")):
        try:
            result = subprocess.run(
                ["strings", str(dex_file)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            all_strings.extend(result.stdout.split("\n"))
        except Exception as e:
            print(f"Error processing {dex_file}: {e}", file=sys.stderr)
    return all_strings


def extract_urls(strings):
    """Extract HTTP/HTTPS URLs."""
    urls = set()
    url_pattern = re.compile(r"https?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[^\s\"'<>]*)?")
    for s in strings:
        urls.update(url_pattern.findall(s))
    return sorted(urls)


def extract_api_endpoints(strings):
    """Extract API endpoint patterns."""
    endpoints = defaultdict(list)
    
    # Look for endpoint patterns
    patterns = [
        (r"/(api|token|device|customer|anthem|iot)[^\"'\s]*", "endpoint"),
        (r"https://[^\"'\s]+/(api|token|device)[^\"'\s]*", "full_url"),
        (r"@(GET|POST|PUT|DELETE|PATCH)\(" + r'["\']([^"\']+)["\']', "retrofit"),
    ]
    
    for pattern, category in patterns:
        for s in strings:
            matches = re.finditer(pattern, s, re.IGNORECASE)
            for match in matches:
                endpoints[category].append(match.group(0))
    
    return {k: sorted(set(v)) for k, v in endpoints.items()}


def extract_class_names(strings):
    """Extract Java/Kotlin class names related to Anthem."""
    classes = set()
    pattern = re.compile(r"Lcom/kohler/hermoth[^;]+")
    for s in strings:
        classes.update(pattern.findall(s))
    return sorted(classes)


def extract_models(strings):
    """Extract model/response/request class names."""
    models = defaultdict(list)
    patterns = [
        (r"(\w+Model)", "model"),
        (r"(\w+Response)", "response"),
        (r"(\w+Request)", "request"),
        (r"(\w+DTO)", "dto"),
    ]
    
    for pattern, category in patterns:
        for s in strings:
            matches = re.finditer(pattern, s)
            for match in matches:
                if "anthem" in match.group(1).lower() or "device" in match.group(1).lower() or "iot" in match.group(1).lower():
                    models[category].append(match.group(1))
    
    return {k: sorted(set(v)) for k, v in models.items()}


def extract_control_commands(strings):
    """Extract device control command patterns."""
    commands = []
    patterns = [
        r"(start|stop|set|get|update|control).*shower",
        r"(start|stop|set|get|update|control).*valve",
        r"(start|stop|set|get|update|control).*temperature",
        r"(start|stop|set|get|update|control).*outlet",
    ]
    
    for pattern in patterns:
        for s in strings:
            matches = re.finditer(pattern, s, re.IGNORECASE)
            for match in matches:
                commands.append(match.group(0))
    
    return sorted(set(commands))


def extract_json_configs():
    """Extract and parse JSON configuration files."""
    configs = {}
    json_files = [
        "res/raw/msal_config.json",
        "res/raw/auth_config_se.json",
        "res/raw/auth_config_uat.json",
        "res/raw/auth_config_release.json",
        "assets/deviceconfig.properties",
    ]
    
    for json_file in json_files:
        file_path = APK_DIR / json_file
        if file_path.exists():
            try:
                if json_file.endswith(".json"):
                    with open(file_path) as f:
                        configs[json_file] = json.load(f)
                else:
                    with open(file_path) as f:
                        configs[json_file] = f.read()
            except Exception as e:
                print(f"Error reading {json_file}: {e}", file=sys.stderr)
    
    return configs


def main():
    """Main analysis function."""
    print("=" * 80)
    print("Comprehensive Kohler Anthem APK Analysis")
    print("=" * 80)
    print()
    
    print("Extracting strings from DEX files...")
    strings = extract_strings_from_dex()
    print(f"Extracted {len(strings)} strings")
    print()
    
    print("Extracting URLs...")
    urls = extract_urls(strings)
    print(f"Found {len(urls)} URLs")
    print("\nRelevant URLs:")
    for url in [u for u in urls if any(x in u.lower() for x in ["kohler", "azure", "api", "iot", "device"])]:
        print(f"  {url}")
    print()
    
    print("Extracting API endpoints...")
    endpoints = extract_api_endpoints(strings)
    for category, values in endpoints.items():
        print(f"\n{category.upper()} ({len(values)}):")
        for v in values[:20]:  # Limit output
            print(f"  {v}")
    print()
    
    print("Extracting Anthem-related classes...")
    classes = extract_class_names(strings)
    print(f"Found {len(classes)} Anthem classes")
    print("\nSample classes:")
    for cls in classes[:30]:
        print(f"  {cls}")
    print()
    
    print("Extracting models...")
    models = extract_models(strings)
    for category, values in models.items():
        print(f"\n{category.upper()} ({len(values)}):")
        for v in values[:15]:
            print(f"  {v}")
    print()
    
    print("Extracting control commands...")
    commands = extract_control_commands(strings)
    print(f"Found {len(commands)} command patterns")
    for cmd in commands[:20]:
        print(f"  {cmd}")
    print()
    
    print("Extracting JSON configurations...")
    configs = extract_json_configs()
    for filename, content in configs.items():
        print(f"\n{filename}:")
        if isinstance(content, dict):
            print(json.dumps(content, indent=2))
        else:
            print(content[:500])
    print()
    
    # Save detailed results
    results = {
        "urls": urls,
        "endpoints": endpoints,
        "classes": classes,
        "models": models,
        "commands": commands,
        "configs": configs,
    }
    
    output_file = Path(__file__).parent.parent / "apk_analysis_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {output_file}")
    print("=" * 80)


if __name__ == "__main__":
    main()
