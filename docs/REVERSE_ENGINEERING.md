# Reverse Engineering Notes

How the Kohler Anthem API was reverse-engineered from the Kohler Konnect Android app.

## Architecture

The Kohler Anthem shower uses a cloud-only architecture:

```
Mobile App ──► Azure AD B2C ──► Authentication
     │
     ├──► api-kohler-us.kohler.io ──► REST API (commands)
     │
     └──► prd-hub.azure-devices.net ──► IoT Hub MQTT (status)
```

No local API exists. All communication is cloud-based.

## Tools Used

1. **APK Analysis** - Decompiled with jadx, searched for endpoints/models
2. **Frida** - Bypassed SSL pinning and root detection
3. **mitmproxy** - Captured actual API traffic

## APK Analysis

### Key Discoveries

**Package:** `com.kohler.hermoth`

**Authentication Config (msal_config.json):**
- Client ID: `$KOHLER_CLIENT_ID`
- Authority: `konnectkohler.b2clogin.com`
- Policy: `B2C_1A_signin` (interactive) or `B2C_1_ROPC_Auth` (password flow)

**API Patterns:**
- Base URL: `api-kohler-us.kohler.io`
- Commands: `/platform/api/v1/commands/gcs/{action}`
- Devices: `/devices/api/v1/device-management/customer-device/{id}`

**Data Models Found:**
- `AnthemWriteSoloStatusRequestModel` - Valve control
- `AnthemWritePresetStartRequestModel` - Preset start
- `MqttAnthemPresetDataModel` - MQTT status

### Statistics

- 509,792 strings extracted
- 4,318 Anthem-related classes
- 180 URLs found
- 50+ API endpoints discovered

## Frida Bypass

The app has multiple protections that must be bypassed:

### Required Bypasses

1. **Emulator Detection** - Spoof Build properties as Samsung Galaxy S21
2. **Root Detection** - Hook `Is.b.n()` (Kohler's obfuscated root check)
3. **SSL Pinning** - Hook TrustManagerImpl to accept all certificates

### Frida Command

```bash
frida -D 127.0.0.1:6555 -f com.kohler.hermoth -l scripts/ssl_bypass.js
```

Key: Use spawn mode (`-f`) to hook before app initialization.

### Bypasses That Weren't Needed

- Native access()/stat() hooks
- Firebase App Check / Play Integrity
- Proxy detection
- Package manager checks

## mitmproxy Capture

### Setup

1. Start mitmproxy on host:
   ```bash
   mitmweb --listen-host 0.0.0.0 --listen-port 8080
   ```

2. Configure Android to use proxy

3. Install mitmproxy CA cert on Android

4. Run Frida to bypass SSL pinning

5. Use Kohler app and capture traffic

### Key Values Captured

| Value | Source |
|-------|--------|
| APIM Subscription Key | `Ocp-Apim-Subscription-Key` header |
| Device ID | Device discovery response |
| Tenant ID | JWT token claims |

## IoT Hub MQTT

### Connection String

Not returned by REST API. Must capture from app via Frida.

Format:
```
HostName=prd-hub.azure-devices.net;DeviceId={id};SharedAccessKey={key}
```

The SharedAccessKey changes per session (provisioned dynamically).

### Message Flow

- Mobile app connects as: `Android_{customer_id}_{suffix}`
- Shower device ID: `gcs-{serial}`
- Status updates via telemetry messages
- Commands via Direct Methods (`ExecuteControlCommand`)

## Dead Ends

### Endpoints That Don't Work

- `kohlerproduat.onmicrosoft.com` - Doesn't exist (documentation error)
- `prd-apim.kohler.com` - DNS doesn't resolve
- `writesolostatus` endpoint - Returns 404
- `writepresetstart` endpoint - Returns 404

### APK Patching

Tried patching APK with frida-gadget but app has integrity checking. Frida server is more reliable.

## Files

| File | Purpose |
|------|---------|
| `scripts/ssl_bypass.js` | Frida SSL/root bypass script |
| `scripts/test_quick_dirty.py` | API test script |
| `scripts/comprehensive_apk_analysis.py` | APK string extraction |
| `apk_analysis_results.json` | Extracted APK data |
