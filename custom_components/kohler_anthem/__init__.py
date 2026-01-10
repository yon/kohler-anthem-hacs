"""The Kohler Anthem Digital Shower integration."""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import KohlerAnthemAPI
from .const import CONF_USERNAME, CONF_PASSWORD, DEFAULT_SCAN_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.CLIMATE, Platform.SWITCH, Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Kohler Anthem from a config entry."""
    username = entry.data[CONF_USERNAME]
    password = entry.data[CONF_PASSWORD]

    api = KohlerAnthemAPI(username, password)

    # Authenticate with Azure AD B2C
    if not await api.authenticate():
        _LOGGER.error("Failed to authenticate with Azure AD B2C")
        return False

    # Discover devices and connect to first device
    devices = await api.discover_devices()
    if not devices:
        _LOGGER.warning(
            "No devices discovered. This may be because the device discovery API endpoint "
            "has not been configured yet. Please capture network traffic from the Kohler "
            "Konnect app to find the correct endpoint."
        )
        # Continue anyway - user might manually provide connection string later
    else:
        _LOGGER.info("Discovered %d device(s)", len(devices))
        # Connect to first device
        if not await api.connect_device():
            _LOGGER.error("Failed to connect to device")
            return False

    async def async_update_data():
        """Fetch data from API."""
        try:
            return await api.get_status()
        except Exception as err:
            raise UpdateFailed(f"Error communicating with API: {err}") from err

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=DOMAIN,
        update_method=async_update_data,
        update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
    )

    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "api": api,
        "coordinator": coordinator,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        data = hass.data[DOMAIN].pop(entry.entry_id)
        # Disconnect from IoT Hub
        if api := data.get("api"):
            await api.disconnect()

    return unload_ok
