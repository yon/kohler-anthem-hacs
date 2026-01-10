"""Switch platform for Kohler Anthem shower."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import ANTHEM_DEFAULT_TEMP_F, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Kohler Anthem switch entities."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    api = data["api"]
    coordinator = data["coordinator"]

    async_add_entities([KohlerAnthemValveSwitch(coordinator, api, config_entry)])


class KohlerAnthemValveSwitch(CoordinatorEntity, SwitchEntity):
    """Representation of a Kohler Anthem valve switch."""

    def __init__(self, coordinator, api, config_entry):
        """Initialize the switch."""
        super().__init__(coordinator)
        self._api = api
        self._attr_unique_id = f"{config_entry.entry_id}_valve"
        self._attr_name = "Kohler Anthem Valve"
        self._attr_is_on = False

    @property
    def is_on(self) -> bool:
        """Return true if the valve is on."""
        if self.coordinator.data:
            # Parse valve state from status data
            # Try different possible keys based on actual API response format
            state = (
                self.coordinator.data.get("valve_on")
                or self.coordinator.data.get("valveOn")
                or self.coordinator.data.get("running")
                or self.coordinator.data.get("state") == "on"
                or self.coordinator.data.get("status") == "running"
            )
            if state is not None:
                if isinstance(state, bool):
                    return state
                if isinstance(state, str):
                    return state.lower() in ("on", "running", "active", "started")
        return self._attr_is_on

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the valve on."""
        success = await self._api.start_shower(ANTHEM_DEFAULT_TEMP_F)
        if success:
            self._attr_is_on = True
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the valve off."""
        success = await self._api.stop_shower()
        if success:
            self._attr_is_on = False
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()
