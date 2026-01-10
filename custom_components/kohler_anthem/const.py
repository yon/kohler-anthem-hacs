"""Constants for the Kohler Anthem integration."""

DOMAIN = "kohler_anthem"

# Configuration
CONF_USERNAME = "username"
CONF_PASSWORD = "password"

# Azure AD B2C Configuration
# konnectkohler tenant with B2C_1_ROPC_Auth policy works for ROPC flow (tested 2026-01-10)
AZURE_TENANT = "konnectkohler.onmicrosoft.com"
AZURE_POLICY = "B2C_1_ROPC_Auth"
AZURE_AUTHORITY = f"https://konnectkohler.b2clogin.com/tfp/{AZURE_TENANT}/{AZURE_POLICY}/"
# Client ID must be provided via config entry (extracted from APK)
CONF_CLIENT_ID = "client_id"
# API Resource must be provided via config entry (extracted from APK)
CONF_API_RESOURCE = "api_resource"

# API Configuration
# api-kohler-us.kohler.io is the working endpoint (tested 2026-01-10)
# prd-apim.kohler.com does not resolve
KOHLER_API_BASE = "https://api-kohler-us.kohler.io"

# APIM Subscription Key - must be provided via config entry
# Capture via mitmproxy from Kohler Konnect app (see docs/REVERSE_ENGINEERING.md)
CONF_APIM_KEY = "apim_key"

# Device Discovery API (tested 2026-01-10)
# Endpoint: /devices/api/v1/device-management/customer-device/{customer_id}
DEVICE_DISCOVERY_API_BASE = KOHLER_API_BASE
DEVICE_DISCOVERY_ENDPOINT = "/devices/api/v1/device-management/customer-device"

# Platform API (Device Control)
PLATFORM_API_BASE = KOHLER_API_BASE
PLATFORM_API_PRODUCT = "gcs"  # GCS = Gateway Control System (Anthem)

# Platform API Endpoints (tested 2026-01-10)
# Working endpoints:
PLATFORM_ENDPOINT_WARMUP = f"/platform/api/v1/commands/{PLATFORM_API_PRODUCT}/warmup"  # 201 Created
PLATFORM_ENDPOINT_PRESET_CONTROL = f"/platform/api/v1/commands/{PLATFORM_API_PRODUCT}/controlpresetorexperience"  # 201 Created

# Not working (return 404):
PLATFORM_ENDPOINT_VALVE_CONTROL = f"/platform/api/v1/commands/{PLATFORM_API_PRODUCT}/writesolostatus"  # 404
PLATFORM_ENDPOINT_PRESET_START = f"/platform/api/v1/commands/{PLATFORM_API_PRODUCT}/writepresetstart"  # 404

# Untested endpoints:
PLATFORM_ENDPOINT_BATHFILL = f"/platform/api/v1/commands/{PLATFORM_API_PRODUCT}/bathfillervolume"
PLATFORM_ENDPOINT_PRESET_CREATE = f"/platform/api/v1/commands/{PLATFORM_API_PRODUCT}/createpreset"
PLATFORM_ENDPOINT_UI_CONFIG = f"/platform/api/v1/commands/{PLATFORM_API_PRODUCT}/writeuiconfig"
PLATFORM_ENDPOINT_FACTORY_RESET = f"/platform/api/v1/commands/{PLATFORM_API_PRODUCT}/factoryreset"

# Defaults
DEFAULT_SCAN_INTERVAL = 30  # seconds
DEFAULT_TIMEOUT = 30

# Platforms
PLATFORMS = ["climate", "switch", "sensor"]

# Anthem Device Configuration
ANTHEM_MIN_TEMP_F = 59
ANTHEM_MAX_TEMP_F = 120
ANTHEM_MIN_TEMP_C = 15
ANTHEM_MAX_TEMP_C = 49
ANTHEM_DEFAULT_TEMP_F = 110

# Attributes
ATTR_DEVICE_ID = "device_id"
ATTR_TEMPERATURE = "temperature"
ATTR_STATE = "state"
