# Kohler Anthem - Development Tools

Tools for capturing and analyzing Kohler Konnect app traffic.

## Quick Start

```bash
cd dev
make capture    # Launch app with bypass + traffic capture
```

## What This Does

1. Loads `scripts/frida_bypass.js` - bypasses all app protections (root, emulator, SSL, proxy detection)
2. Loads `dev/scripts/frida_capture_hooks.js` - captures HTTP, MQTT, and command traffic
3. Saves output to `dev/output/capture_<timestamp>.log`

## Captured Traffic

The capture hooks log:
- `[HTTP]` - REST API requests (OkHttp)
- `[IOT HUB]` - IoT Hub connection strings
- `[IOT MESSAGE]` - Messages sent to IoT Hub
- `[MQTT]` - MQTT connections and publishes
- `[GSON]` - Command objects being serialized
- `[RETROFIT]` - Request bodies

## Directory Structure

```
dev/
├── Makefile                    # Dev-only make targets
├── README.md                   # This file
├── apk/                        # Place APK here for extraction
├── output/                     # Capture logs
└── scripts/
    ├── frida_capture_hooks.js  # Traffic capture (capture-only, no bypass)
    └── frida_dev_capture.py    # Python wrapper that loads both scripts
```

## Prerequisites

1. Genymotion emulator running
2. frida-server running on emulator:
   ```bash
   make frida-start   # from project root
   ```
3. Kohler Konnect APK installed on emulator

## Make Targets

```bash
make capture   # Launch app with traffic capture
make logs      # List recent capture logs
make latest    # View latest capture log
make clean     # Remove capture logs
```

## Tips

- Clear app data between captures for clean sessions:
  ```bash
  adb shell pm clear com.kohler.hermoth
  ```
- The bypass script is shared with production (`scripts/frida_bypass.js`)
- Only the capture hooks are dev-specific
