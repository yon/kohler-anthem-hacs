# Session State - 2026-01-12

## Current Status

**All major API functionality is now working!**

## What's Working

### 1. Authentication
- Azure AD B2C ROPC flow
- Token endpoint: `https://konnectkohler.b2clogin.com/tfp/konnectkohler.onmicrosoft.com/B2C_1_ROPC_Auth/oauth2/v2.0/token`

### 2. Device Discovery
- Endpoint: `GET /devices/api/v1/device-management/customer-device/{customer_id}`
- Returns device list with deviceId, SKU, home info

### 3. Warmup Command
- Endpoint: `POST /platform/api/v1/commands/gcs/warmup`
- Returns 201 Created

### 4. Preset Control
- Endpoint: `POST /platform/api/v1/commands/gcs/controlpresetorexperience`
- preset_id "0" = stop, "1"-"5" = start preset
- Returns 201 Created

### 5. Direct Valve Control (FIXED!)
- **Correct Endpoint:** `POST /platform/api/v1/commands/gcs/solowritesystem`
- **NOT** `writesolostatus` (which returns 404)
- Returns 201 Created with correlationId

**Valve Value Format (4 bytes):**
```
[prefix][temp][flow][mode]
   01     79    c8    01
```

| Byte | Field | Range | Description |
|------|-------|-------|-------------|
| 0 | Prefix | `01`/`11` | `01`=primaryValve1, `11`=secondaryValve1 |
| 1 | Temp | `00`-`E8` | 15°C - 48.8°C |
| 2 | Flow | `00`-`C8` | 0% - 100% |
| 3 | Mode | see below | Outlet state |

**Mode Values:**
- `00` = Off
- `01` = Shower mode on
- `02` = Bathtub filler
- `03` = Bathtub mode + on
- `40` = Full stop/standby

## My Device Configuration

Device: `gcs-sio3225nc9`

| # | Outlet | Valve | Mode | Example |
|---|--------|-------|------|---------|
| 1 | Showerhead | primaryValve1 | `01` | `0179c801` |
| 2 | Bathtub Filler | primaryValve1 | `02` | `0179c802` |
| 3 | Shower Handshower | secondaryValve1 | `01` | `1179c801` |
| 4 | Bathtub Handheld | secondaryValve1 | `03` | `1179c803` |

## What's Left To Do

### High Priority
1. **Implement Home Assistant integration** - All API pieces are working, can now build the HA component

### Nice to Have
2. **Capture IoT Hub connection string** - For real-time status updates via MQTT
3. **Decode preset hexString format** - Understand how presets encode valve settings

## Key Files

```
kohler-anthem-hacs/
├── scripts/
│   ├── frida_bypass.js          # All bypasses + APIM key capture
│   ├── frida_capture_apim.py    # Production: capture APIM key only
│   └── test_quick_dirty.py      # API test script (all working!)
├── dev/
│   ├── Makefile                 # Dev-only targets (capture, mitmproxy)
│   ├── scripts/
│   │   ├── frida_capture_hooks.js   # Traffic capture hooks
│   │   ├── frida_dev_capture.py     # Wrapper for dev capture
│   │   ├── frida_proxy_inject.js    # Inject proxy settings for mitmproxy
│   │   └── mitmproxy_capture.py     # mitmproxy addon for HTTP capture
│   ├── docs/
│   │   ├── VALVE_PROTOCOL.md    # Complete protocol reference
│   │   ├── MY_DEVICE.md         # Personal device configuration
│   │   └── SESSION_STATE.md     # This file
│   └── output/
│       └── mitmproxy_http.log   # HTTP capture data
└── docs/
    └── API.md                   # API reference (updated)
```

## Environment

- Device ID: `gcs-sio3225nc9`
- Tenant ID: `cfd22e16-f7be-4038-b7ff-bf08790b8ec4`
- Emulator: Genymotion (Samsung Galaxy S10)
- Frida: 17.5.2
- App: Kohler Konnect (com.kohler.hermoth)

## Commands Reference

```bash
# Production setup
make extract      # Extract secrets from APK
make bypass       # Capture APIM key via Frida
make env          # Generate .env file
make test         # Test API (all working!)

# Development
cd dev
make capture      # Full traffic capture (Frida)
make mitmproxy    # HTTP capture (mitmproxy)
make proxy-on     # Enable proxy on emulator
make proxy-off    # Disable proxy on emulator
make logs         # List capture logs
make latest       # View latest log
```

## Key Discovery

The endpoint for direct valve control is `solowritesystem`, NOT `writesolostatus`:

```
POST https://api-kohler-us.kohler.io/platform/api/v1/commands/gcs/solowritesystem
```

This was discovered by capturing actual HTTP traffic via mitmproxy on 2026-01-12.

## Test Results

```
Platform API Commands:
   Warmup: ✅ Working
   Preset Control: ✅ Working
   Valve Control: ✅ Working

Working Features:
   - Authentication via Azure AD B2C (ROPC flow)
   - Device discovery via REST API
   - Warmup command
   - Start/Stop presets (1-5, 0 to stop)
   - Direct valve/temperature control (solowritesystem)
```
