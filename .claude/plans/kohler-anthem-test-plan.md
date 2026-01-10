# Kohler Anthem Integration Plan

**Status: COMPLETED (2026-01-10)**

## Goal

Create a Home Assistant custom integration for the Kohler Anthem Digital Shower.

## Results

### Working

- Authentication via Azure AD B2C (ROPC flow with `konnectkohler` tenant)
- Device discovery via REST API
- Warmup command (`/commands/gcs/warmup`)
- Preset control (`/commands/gcs/controlpresetorexperience`)

### Not Working

- Direct valve/temperature control (`writesolostatus` returns 404)
- Real-time status via MQTT (needs IoT Hub connection string not provided by API)

## Configuration

| Value | Source |
|-------|--------|
| `KOHLER_CLIENT_ID` | APK (static) |
| `KOHLER_APIM_KEY` | mitmproxy capture (static) |
| `KOHLER_USERNAME` | User account |
| `KOHLER_PASSWORD` | User account |
| `KOHLER_DEVICE_ID` | Device discovery response |
| `KOHLER_TENANT_ID` | JWT claims |

## Next Steps

1. Implement Home Assistant entities (switch for warmup, select for presets)
2. Investigate IoT Hub connection string source for real-time status
3. Test bath fill and other untested endpoints
