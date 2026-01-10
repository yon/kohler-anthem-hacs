"""Climate platform for Kohler Anthem shower."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    ANTHEM_DEFAULT_TEMP_F,
    ANTHEM_MAX_TEMP_F,
    ANTHEM_MIN_TEMP_F,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Kohler Anthem climate entities."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    api = data["api"]
    coordinator = data["coordinator"]

    async_add_entities([KohlerAnthemClimate(coordinator, api, config_entry)])


class KohlerAnthemClimate(CoordinatorEntity, ClimateEntity):
    """Representation of a Kohler Anthem shower temperature control."""

    _attr_temperature_unit = UnitOfTemperature.FAHRENHEIT
    _attr_supported_features = ClimateEntityFeature.TARGET_TEMPERATURE
    _attr_hvac_modes = [HVACMode.OFF, HVACMode.HEAT]
    _attr_min_temp = ANTHEM_MIN_TEMP_F
    _attr_max_temp = ANTHEM_MAX_TEMP_F
    _attr_target_temperature_step = 1

    def __init__(self, coordinator, api, config_entry):
        """Initialize the climate entity."""
        super().__init__(coordinator)
        self._api = api
        self._attr_unique_id = f"{config_entry.entry_id}_climate"
        self._attr_name = "Kohler Anthem Shower"
        self._attr_hvac_mode = HVACMode.OFF
        self._attr_target_temperature = ANTHEM_DEFAULT_TEMP_F

    @property
    def current_temperature(self) -> float | None:
        """Return the current temperature."""
        if self.coordinator.data:
            # Parse temperature from status data
            # Try different possible keys based on actual API response format
            temp = (
                self.coordinator.data.get("currentTemperature")
                or self.coordinator.data.get("current_temperature")
                or self.coordinator.data.get("temperature")
                or self.coordinator.data.get("temp")
            )
            if temp is not None:
                try:
                    return float(temp)
                except (ValueError, TypeError):
                    pass
        return None

    @property
    def hvac_mode(self) -> HVACMode:
        """Return current operation mode."""
        if self.coordinator.data:
            # Parse state from status data
            state = (
                self.coordinator.data.get("state")
                or self.coordinator.data.get("status")
                or self.coordinator.data.get("running")
            )
            if state:
                # Check if shower is running
                if isinstance(state, bool):
                    return HVACMode.HEAT if state else HVACMode.OFF
                if isinstance(state, str):
                    state_lower = state.lower()
                    if state_lower in ("on", "running", "active", "started"):
                        return HVACMode.HEAT
        return self._attr_hvac_mode

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Set new target temperature."""
        if (temperature := kwargs.get(ATTR_TEMPERATURE)) is None:
            return

        # Clamp temperature to valid range
        temperature = max(ANTHEM_MIN_TEMP_F, min(ANTHEM_MAX_TEMP_F, temperature))
        
        # If shower is running, update temperature
        if self._attr_hvac_mode == HVACMode.HEAT:
            await self._api.set_temperature(int(temperature))
        
        self._attr_target_temperature = temperature
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set new target hvac mode."""
        if hvac_mode == HVACMode.HEAT:
            # Start shower with current target temperature
            success = await self._api.start_shower(int(self._attr_target_temperature))
            if success:
                self._attr_hvac_mode = HVACMode.HEAT
        elif hvac_mode == HVACMode.OFF:
            # Stop shower
            success = await self._api.stop_shower()
            if success:
                self._attr_hvac_mode = HVACMode.OFF

        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()
