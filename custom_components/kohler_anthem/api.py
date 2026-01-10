"""API client for Kohler Anthem Digital Shower via Azure IoT Hub."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import aiohttp
from azure.iot.device.aio import IoTHubDeviceClient
from azure.iot.device import Message

from .const import (
    APIM_SUBSCRIPTION_KEY,
    AZURE_AUTHORITY,
    AZURE_CLIENT_ID,
    AZURE_SCOPES,
    DEFAULT_TIMEOUT,
    DEVICE_DISCOVERY_API_BASE,
    DEVICE_DISCOVERY_ENDPOINT,
)

_LOGGER = logging.getLogger(__name__)


class KohlerAnthemAPI:
    """API client for Kohler Anthem via Azure IoT Hub."""

    def __init__(self, username: str, password: str) -> None:
        """Initialize the API client."""
        self.username = username
        self.password = password
        self._access_token = None
        self._refresh_token = None
        self._iot_client = None
        self._device_id = None
        self._connection_string = None
        self._session = None
        self._devices = []

    async def authenticate(self) -> bool:
        """Authenticate with Azure AD B2C and get access token."""
        try:
            # Use direct token endpoint with ROPC flow
            # Note: B2C_1_ROPC_Auth policy supports username/password flow
            token_url = f"{AZURE_AUTHORITY}oauth2/v2.0/token"

            if not self._session:
                self._session = aiohttp.ClientSession()

            scope = " ".join(["openid", "offline_access"] + AZURE_SCOPES)
            data = {
                "grant_type": "password",
                "client_id": AZURE_CLIENT_ID,
                "username": self.username,
                "password": self.password,
                "scope": scope,
            }

            async with self._session.post(token_url, data=data) as resp:
                result = await resp.json()

                if resp.status == 200 and "access_token" in result:
                    self._access_token = result["access_token"]
                    self._refresh_token = result.get("refresh_token")
                    _LOGGER.info("Successfully authenticated with Azure AD B2C")
                    return True
                else:
                    error = result.get("error_description", result.get("error"))
                    _LOGGER.error("Authentication failed: %s", error)
                    return False

        except Exception as err:
            _LOGGER.error("Authentication error: %s", err)
            return False

    async def discover_devices(self, apim_subscription_key: str | None = None) -> list[dict[str, Any]]:
        """Discover user's devices via device discovery API.

        Args:
            apim_subscription_key: Azure API Management subscription key.
                                   Defaults to APIM_SUBSCRIPTION_KEY from const.py.

        Returns:
            List of device dictionaries with device_id and connection_string.
        """
        if not self._access_token:
            _LOGGER.error("Not authenticated. Call authenticate() first.")
            return []

        if not self._session:
            self._session = aiohttp.ClientSession()

        # Use default subscription key if not provided
        subscription_key = apim_subscription_key or APIM_SUBSCRIPTION_KEY

        # Device discovery endpoint (discovered via mitmproxy traffic capture)
        endpoint = f"{DEVICE_DISCOVERY_API_BASE}{DEVICE_DISCOVERY_ENDPOINT}"

        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key,
        }

        try:
            _LOGGER.debug("Trying device discovery endpoint: %s", endpoint)
            async with self._session.get(
                endpoint, headers=headers, timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    _LOGGER.info("Successfully discovered devices from %s", endpoint)
                    self._devices = self._parse_devices_response(data)
                    return self._devices
                elif resp.status == 401:
                    text = await resp.text()
                    _LOGGER.warning("Authentication expired, attempting token refresh")
                    if await self._refresh_access_token():
                        return await self.discover_devices(apim_subscription_key)
                    _LOGGER.error("Device discovery failed: %s", text[:200])
                elif resp.status == 404:
                    _LOGGER.warning("Device discovery endpoint returned 404")
                else:
                    text = await resp.text()
                    _LOGGER.error("Device discovery failed: %d - %s", resp.status, text[:200])
        except aiohttp.ClientError as err:
            _LOGGER.error("Error connecting to device discovery API: %s", err)
        except Exception as err:
            _LOGGER.error("Unexpected error during device discovery: %s", err)

        return []

    def _parse_devices_response(self, data: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
        """Parse device discovery API response.
        
        This will need to be updated once the actual response format is known.
        """
        devices = []
        
        # Handle different possible response formats
        if isinstance(data, list):
            device_list = data
        elif isinstance(data, dict):
            # Try common keys
            device_list = data.get("devices", data.get("data", data.get("items", [])))
        else:
            _LOGGER.warning("Unexpected device response format: %s", type(data))
            return []
        
        for device in device_list:
            if isinstance(device, dict):
                device_info = {
                    "device_id": device.get("deviceId") or device.get("device_id") or device.get("id"),
                    "connection_string": device.get("connectionString") or device.get("connection_string"),
                    "name": device.get("name") or device.get("deviceName"),
                    "model": device.get("model") or device.get("deviceModel"),
                }
                if device_info["device_id"]:
                    devices.append(device_info)
        
        return devices

    async def _refresh_access_token(self) -> bool:
        """Refresh the access token using refresh token."""
        if not self._refresh_token:
            _LOGGER.warning("No refresh token available, need to re-authenticate")
            return await self.authenticate()
        
        try:
            app = msal.PublicClientApplication(
                AZURE_CLIENT_ID,
                authority=AZURE_AUTHORITY,
            )
            
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: app.acquire_token_by_refresh_token(
                    self._refresh_token,
                    scopes=AZURE_SCOPES,
                ),
            )
            
            if "access_token" in result:
                self._access_token = result["access_token"]
                self._refresh_token = result.get("refresh_token", self._refresh_token)
                _LOGGER.info("Successfully refreshed access token")
                return True
            else:
                _LOGGER.warning("Failed to refresh token, need to re-authenticate")
                return await self.authenticate()
        except Exception as err:
            _LOGGER.error("Error refreshing token: %s", err)
            return False

    async def connect_device(self, device_id: str | None = None, connection_string: str | None = None) -> bool:
        """Connect to IoT Hub device.
        
        If device_id is not provided, uses the first discovered device.
        If connection_string is not provided, uses the connection_string from discovered device.
        """
        try:
            # If no device specified, try to use first discovered device
            if not device_id or not connection_string:
                if not self._devices:
                    await self.discover_devices()
                
                if not self._devices:
                    _LOGGER.error("No devices discovered. Cannot connect.")
                    return False
                
                # Use first device if not specified
                device = self._devices[0]
                device_id = device_id or device["device_id"]
                connection_string = connection_string or device["connection_string"]
                
                if not connection_string:
                    _LOGGER.error("No connection string available for device %s", device_id)
                    return False
            
            self._device_id = device_id
            self._connection_string = connection_string

            # Create IoT Hub device client
            self._iot_client = IoTHubDeviceClient.create_from_connection_string(
                connection_string
            )
            
            # Set up message handler for telemetry
            self._iot_client.on_message_received = self._on_message_received

            await self._iot_client.connect()
            _LOGGER.info("Connected to IoT Hub for device %s", device_id)
            return True

        except Exception as err:
            _LOGGER.error("Failed to connect to IoT Hub: %s", err)
            return False

    def _on_message_received(self, message: Message) -> None:
        """Handle incoming messages from IoT Hub."""
        try:
            data = json.loads(message.data)
            _LOGGER.debug("Received message from device: %s", data)
            # Store latest message for status polling
            self._latest_message = data
        except Exception as err:
            _LOGGER.warning("Error parsing message from device: %s", err)

    async def send_command(self, command: dict) -> bool:
        """Send command to device via IoT Hub."""
        if not self._iot_client:
            _LOGGER.error("Not connected to IoT Hub")
            return False

        try:
            message = Message(json.dumps(command))
            message.content_type = "application/json"
            message.content_encoding = "utf-8"

            await self._iot_client.send_message(message)
            _LOGGER.debug("Sent command: %s", command)
            return True

        except Exception as err:
            _LOGGER.error("Failed to send command: %s", err)
            return False

    async def start_shower(self, temperature: int = 100) -> bool:
        """Start the shower with specified temperature."""
        command = {
            "action": "start_shower",
            "temperature": temperature,
            "unit": "fahrenheit"
        }
        return await self.send_command(command)

    async def stop_shower(self) -> bool:
        """Stop the shower."""
        command = {
            "action": "stop_shower"
        }
        return await self.send_command(command)

    async def set_temperature(self, temperature: int) -> bool:
        """Set shower temperature."""
        command = {
            "action": "set_temperature",
            "temperature": temperature,
            "unit": "fahrenheit"
        }
        return await self.send_command(command)

    async def get_status(self) -> dict[str, Any] | None:
        """Get current device status from device twin or latest telemetry."""
        if not self._iot_client:
            return {
                "connected": False,
                "device_id": self._device_id,
            }
        
        try:
            # Try to get device twin
            twin = await self._iot_client.get_twin()
            reported_properties = twin.get("reported", {})
            
            # Combine with latest message if available
            status = {
                "connected": True,
                "device_id": self._device_id,
                **reported_properties,
            }
            
            # If we have a latest message, merge it in
            if hasattr(self, "_latest_message"):
                status.update(self._latest_message)
            
            return status
        except Exception as err:
            _LOGGER.warning("Error getting device status: %s", err)
            # Fallback to basic status
            return {
                "connected": self._iot_client is not None,
                "device_id": self._device_id,
            }

    async def disconnect(self) -> None:
        """Disconnect from IoT Hub and cleanup."""
        if self._iot_client:
            await self._iot_client.disconnect()
            self._iot_client = None
        
        if self._session:
            await self._session.close()
            self._session = None