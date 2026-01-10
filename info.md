# Kohler Anthem Digital Shower Integration

Control your Kohler Anthem Digital Shower system from Home Assistant via Azure IoT Hub.

## Features

- **Climate Entity** - Set and monitor shower temperature
- **Switch Entity** - Turn water on/off
- **Sensor Entity** - Monitor shower status and settings
- **Cloud Integration** - Uses Azure IoT Hub (same as Kohler Konnect app)

## Quick Start

1. Add the integration via Settings → Devices & Services
2. Enter your Kohler Konnect credentials (email and password)
3. The integration will authenticate and attempt to discover your device
4. Start controlling your shower!

## Important Notes

This integration uses the same cloud API as the Kohler Konnect mobile app. The device discovery API endpoint may need to be configured - see the README for details on capturing network traffic to discover the correct endpoint.

**Status**: Authentication works, but device discovery requires the API endpoint to be discovered via network traffic capture.

## Support

For detailed setup instructions, troubleshooting, and reverse engineering guidance, see the [full README](https://github.com/yourusername/kohler-anthem-hacs).
