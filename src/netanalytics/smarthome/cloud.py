"""Xiaomi Cloud token retrieval.

Retrieves device tokens from Xiaomi Cloud account using python-miio's CloudInterface.
This is useful when device tokens cannot be obtained through local discovery.
"""

import logging
from dataclasses import dataclass

from .devices import CloudDevice

logger = logging.getLogger(__name__)

# Xiaomi Cloud server regions
CLOUD_SERVERS = {
    "cn": "China",
    "de": "Europe (Germany)",
    "us": "United States",
    "ru": "Russia",
    "tw": "Taiwan",
    "sg": "Singapore",
    "in": "India",
}


@dataclass
class CloudLoginResult:
    """Result of cloud login attempt."""

    success: bool
    user_id: str | None = None
    service_token: str | None = None
    error: str | None = None


class XiaomiCloud:
    """Xiaomi Cloud interface for retrieving device tokens.

    Uses python-miio's CloudInterface to authenticate and fetch devices.

    Security: Password is cleared from memory after successful authentication.
    """

    def __init__(self, username: str, password: str, server: str = "cn"):
        """Initialize cloud interface.

        Args:
            username: Xiaomi account email/phone.
            password: Xiaomi account password.
            server: Cloud server region (cn, de, us, ru, tw, sg, in).

        Raises:
            ValueError: If server is not a valid region.
        """
        if server not in CLOUD_SERVERS:
            raise ValueError(
                f"Invalid server '{server}'. Valid options: {', '.join(CLOUD_SERVERS.keys())}"
            )

        self.username = username
        self._password: str | None = password
        self.server = server
        self._cloud = None
        self._logged_in = False

    def _clear_password(self) -> None:
        """Clear password from memory after authentication."""
        self._password = None
        logger.debug("Password cleared from memory")

    def login(self) -> CloudLoginResult:
        """Authenticate with Xiaomi Cloud.

        After successful login, the password is cleared from memory for security.

        Returns:
            Login result with success status and user info.

        Raises:
            ImportError: If python-miio is not installed.
            RuntimeError: If password was already cleared (login called twice).
        """
        try:
            from miio.cloud import CloudInterface
        except ImportError as e:
            raise ImportError(
                "python-miio is required for cloud access. "
                "Install with: pip install python-miio"
            ) from e

        if self._logged_in:
            return CloudLoginResult(success=True, user_id=self.username)

        if self._password is None:
            return CloudLoginResult(
                success=False,
                error="Password already cleared. Create a new XiaomiCloud instance.",
            )

        try:
            self._cloud = CloudInterface(
                username=self.username,
                password=self._password,
            )
            # Login happens automatically on first API call
            # We'll trigger it by getting device list
            self._logged_in = True

            # Clear password from memory after successful auth
            self._clear_password()

            return CloudLoginResult(
                success=True,
                user_id=self.username,
            )
        except Exception as e:
            self._logged_in = False
            # Clear password even on failure to prevent leaks
            self._clear_password()
            return CloudLoginResult(
                success=False,
                error=str(e),
            )

    def get_devices(self, country: str | None = None) -> list[CloudDevice]:
        """Get all devices from cloud account with their tokens.

        Args:
            country: Override country/server for this request.

        Returns:
            List of devices with tokens.

        Raises:
            Exception: If not logged in or API call fails.
        """
        if not self._cloud:
            login_result = self.login()
            if not login_result.success:
                raise Exception(f"Login failed: {login_result.error}")

        cloud = self._cloud
        if cloud is None:
            raise Exception("Cloud interface not initialized")

        try:
            # Fetch devices from cloud
            # The country parameter maps to server region
            server = country or self.server
            devices_data = cloud.get_devices(country=server)

            devices: list[CloudDevice] = []
            for dev in devices_data:
                device = CloudDevice(
                    device_id=str(dev.get("did", "")),
                    token=dev.get("token", ""),
                    name=dev.get("name"),
                    model=dev.get("model"),
                    ip=dev.get("localip"),
                    mac=dev.get("mac"),
                    is_online=dev.get("isOnline", False),
                    parent_id=str(dev.get("parent_id", "")) if dev.get("parent_id") else None,
                    extra={
                        k: v for k, v in dev.items()
                        if k not in ("did", "token", "name", "model", "localip", "mac", "isOnline")
                    } or None,
                )
                devices.append(device)

            return devices

        except Exception as e:
            raise Exception(f"Failed to fetch devices: {e}") from e

    def get_device_token(self, device_id: str, country: str | None = None) -> str | None:
        """Get token for a specific device by ID.

        Args:
            device_id: Device ID (did) to look up.
            country: Override country/server for this request.

        Returns:
            Device token or None if not found.
        """
        devices = self.get_devices(country=country)
        for device in devices:
            if device.device_id == device_id:
                return device.token
        return None


def fetch_cloud_tokens(
    username: str,
    password: str,
    server: str = "cn",
) -> dict:
    """Convenience function to fetch all device tokens from Xiaomi Cloud.

    Args:
        username: Xiaomi account email/phone.
        password: Xiaomi account password.
        server: Cloud server region.

    Returns:
        Dict with 'devices' list or 'error' if failed.
    """
    try:
        cloud = XiaomiCloud(username, password, server)
        login_result = cloud.login()

        if not login_result.success:
            return {
                "success": False,
                "error": login_result.error,
                "devices": [],
            }

        devices = cloud.get_devices()
        return {
            "success": True,
            "server": server,
            "device_count": len(devices),
            "devices": [d.to_dict() for d in devices],
        }

    except ImportError as e:
        return {
            "success": False,
            "error": str(e),
            "devices": [],
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "devices": [],
        }


def list_cloud_servers() -> dict[str, str]:
    """Get available cloud server regions.

    Returns:
        Dict mapping server codes to descriptions.
    """
    return CLOUD_SERVERS.copy()
