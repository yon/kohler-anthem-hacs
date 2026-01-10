"""Config flow for Kohler Anthem integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult
import homeassistant.helpers.config_validation as cv

from .api import KohlerAnthemAPI
from .const import CONF_USERNAME, CONF_PASSWORD, DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
    }
)


class KohlerAnthemConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Kohler Anthem."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            username = user_input[CONF_USERNAME]
            password = user_input[CONF_PASSWORD]

            # Test authentication
            api = KohlerAnthemAPI(username, password)
            try:
                if await api.authenticate():
                    await self.async_set_unique_id(username.lower())
                    self._abort_if_unique_id_configured()

                    return self.async_create_entry(
                        title=f"Kohler Anthem ({username})",
                        data=user_input,
                    )
                else:
                    errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )
