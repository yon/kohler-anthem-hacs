"""Sensor platform for Kohler Anthem shower."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Kohler Anthem sensor entities."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    coordinator = data["coordinator"]

    async_add_entities([KohlerAnthemStatusSensor(coordinator, config_entry)])


class KohlerAnthemStatusSensor(CoordinatorEntity, SensorEntity):
    """Representation of a Kohler Anthem status sensor."""

    def __init__(self, coordinator, config_entry):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{config_entry.entry_id}_status"
        self._attr_name = "Kohler Anthem Status"

    @property
    def native_value(self) -> str | None:
        """Return the state of the sensor."""
        if not self.coordinator.data:
            return "Unknown"
        
        data = self.coordinator.data
        
        # Parse status from API response
        # Try different possible keys based on actual API response format
        state = (
            data.get("state")
            or data.get("status")
            or data.get("running")
            or data.get("valve_on")
        )
        
        if state is not None:
            if isinstance(state, bool):
                return "Running" if state else "Off"
            if isinstance(state, str):
                state_lower = state.lower()
                if state_lower in ("on", "running", "active", "started"):
                    return "Running"
                elif state_lower in ("off", "stopped", "inactive"):
                    return "Off"
                return state
        
        # Fallback: check if connected
        if data.get("connected"):
            return "Connected"
        
        return "Unknown"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        if self.coordinator.data:
            return dict(self.coordinator.data)
        return {}
