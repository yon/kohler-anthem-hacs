# Kohler Anthem Digital Shower - Home Assistant Integration

Home Assistant custom integration for the Kohler Anthem Digital Shower system.

## Status (2026-01-10)

| Feature | Status |
|---------|--------|
| Authentication (Azure AD B2C) | ✅ Working |
| Device Discovery | ✅ Working |
| Warmup Command | ✅ Working |
| Start/Stop Presets | ✅ Working |
| Direct Valve Control | ❌ API returns 404 |
| Real-time Status (MQTT) | ❌ Needs IoT Hub connection string |

## Working API Commands

```bash
# Warmup - preheats water
POST /platform/api/v1/commands/gcs/warmup
{"deviceId": "...", "sku": "GCS", "tenantId": "..."}

# Start preset (1-5)
POST /platform/api/v1/commands/gcs/controlpresetorexperience
{"deviceId": "...", "sku": "GCS", "tenantId": "...", "presetOrExperienceId": "1"}

# Stop shower
POST /platform/api/v1/commands/gcs/controlpresetorexperience
{"deviceId": "...", "sku": "GCS", "tenantId": "...", "presetOrExperienceId": "0"}
```

## Setup

**First time?** Follow the complete setup guide: **[SETUP.md](SETUP.md)**

```bash
make install   # Install tools (Homebrew, Python, Frida, etc.)
make extract   # Extract client_id/api_resource from APK
make bypass    # Launch app with Frida (captures APIM key)
make env       # Generate .env file interactively
make test      # Test authentication and device discovery
```

## Architecture

- **Authentication**: Azure AD B2C (ROPC flow)
- **API Base**: `https://api-kohler-us.kohler.io`
- **Device Communication**: REST API for commands, MQTT for status (not yet implemented)

## Configuration

Copy `kohler.env.example` to `.env` and fill in:

| Variable | Source | Changes |
|----------|--------|---------|
| `KOHLER_CLIENT_ID` | APK | Never |
| `KOHLER_APIM_KEY` | Frida capture | Periodically (fetched from Firebase) |
| `KOHLER_USERNAME` | Your account | Never |
| `KOHLER_PASSWORD` | Your account | Never |
| `KOHLER_DEVICE_ID` | Device discovery | Per device |
| `KOHLER_TENANT_ID` | JWT claims | Per user |

## Installation (HACS)

1. Add this repository as a custom repository in HACS
2. Search for "Kohler Anthem"
3. Install and restart Home Assistant
4. Add integration via Settings → Devices & Services

## Known Limitations

- **No direct temperature control**: The `writesolostatus` endpoint returns 404. Temperature can only be set via presets.
- **No real-time status**: IoT Hub connection string is not returned by the REST API. Status updates require MQTT which needs further reverse engineering.
- **Cloud-dependent**: No local API exists.

## Documentation

See `docs/` for:
- `API.md` - Complete API reference (authentication, endpoints, payloads)
- `REVERSE_ENGINEERING.md` - How the API was discovered (APK analysis, Frida, mitmproxy)

## License

MIT
