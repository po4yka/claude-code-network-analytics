"""Xiaomi device interactions using python-miio.

Wraps python-miio library to provide device info retrieval and status queries.
"""

import logging
import socket
from dataclasses import dataclass
from typing import Any

from .devices import MiioDeviceInfo, SmartHomeDevice

logger = logging.getLogger(__name__)


# Custom exception classes for better error handling
class DeviceConnectionError(Exception):
    """Raised when device is unreachable or connection fails."""

    pass


class DeviceAuthError(Exception):
    """Raised when device token is invalid or auth fails."""

    pass


class DeviceTimeoutError(Exception):
    """Raised when device doesn't respond within timeout."""

    pass


class DeviceProtocolError(Exception):
    """Raised when device sends invalid/unexpected response."""

    pass


def _get_miio_imports():
    """Import miio module with proper error handling.

    Returns:
        Tuple of (Device, DeviceException) classes.

    Raises:
        ImportError: If python-miio is not installed.
    """
    try:
        from miio import Device, DeviceException

        return Device, DeviceException
    except ImportError as e:
        raise ImportError(
            "python-miio is required for device interactions. "
            "Install with: pip install python-miio"
        ) from e


def _handle_device_exception(e: Exception, operation: str, ip: str) -> Exception:
    """Convert miio exceptions to our typed exceptions.

    Args:
        e: Original exception.
        operation: Description of operation that failed.
        ip: Device IP address.

    Returns:
        Typed exception for the error condition.
    """
    error_msg = str(e).lower()

    # Check for timeout-related errors
    if isinstance(e, socket.timeout) or "timeout" in error_msg:
        return DeviceTimeoutError(f"Device {ip} timed out during {operation}")

    # Check for auth-related errors
    if any(
        x in error_msg
        for x in ("invalid token", "token error", "authentication", "forbidden")
    ):
        return DeviceAuthError(f"Authentication failed for {ip}: {e}")

    # Check for connection errors
    if any(
        x in error_msg
        for x in ("connection reset", "network unreachable", "host unreachable", "no route")
    ):
        return DeviceConnectionError(f"Cannot connect to {ip}: {e}")

    # Check for protocol errors
    if any(x in error_msg for x in ("invalid response", "protocol error", "unknown")):
        return DeviceProtocolError(f"Protocol error from {ip}: {e}")

    # Generic device error
    return DeviceConnectionError(f"{operation} failed for {ip}: {e}")


@dataclass
class XiaomiDeviceStatus:
    """Status of a Xiaomi device."""

    device_id: str
    model: str | None
    firmware: str | None
    hardware: str | None
    mac: str | None
    is_online: bool
    properties: dict[str, Any] | None = None
    raw_response: dict | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "device_id": self.device_id,
            "model": self.model,
            "firmware": self.firmware,
            "hardware": self.hardware,
            "mac": self.mac,
            "is_online": self.is_online,
            "properties": self.properties,
            "raw_response": self.raw_response,
        }


def get_device_info(ip: str, token: str, timeout: float = 5.0) -> MiioDeviceInfo:
    """Get device information using miIO protocol.

    Connects to the device and retrieves basic information including
    model, firmware version, hardware version, and MAC address.

    Args:
        ip: Device IP address.
        token: Device token (32 hex characters).
        timeout: Connection timeout in seconds.

    Returns:
        Device information.

    Raises:
        ImportError: If python-miio is not installed.
        DeviceConnectionError: If device is unreachable.
        DeviceAuthError: If token is invalid.
        DeviceTimeoutError: If device doesn't respond.
    """
    Device, DeviceException = _get_miio_imports()

    logger.debug("Getting device info for %s", ip)
    try:
        device = Device(ip=ip, token=token, timeout=timeout)
        info = device.info()

        logger.debug("Got device info: model=%s, firmware=%s", info.model, info.firmware_version)
        return MiioDeviceInfo(
            ip=ip,
            device_id=str(info.raw.get("did", "")),
            token=token,
            model=info.model,
            firmware=info.firmware_version,
            hardware=info.hardware_version,
            mac=info.mac_address,
            raw_info=info.raw,
        )
    except socket.timeout as e:
        raise DeviceTimeoutError(f"Device {ip} timed out") from e
    except DeviceException as e:
        raise _handle_device_exception(e, "get_device_info", ip) from e
    except OSError as e:
        raise DeviceConnectionError(f"Network error connecting to {ip}: {e}") from e


def get_device_status(ip: str, token: str, timeout: float = 5.0) -> XiaomiDeviceStatus:
    """Get detailed device status.

    Retrieves device info and attempts to get device-specific status
    properties depending on the device type.

    Args:
        ip: Device IP address.
        token: Device token (32 hex characters).
        timeout: Connection timeout in seconds.

    Returns:
        Device status with properties.

    Raises:
        ImportError: If python-miio is not installed.
        DeviceConnectionError: If device is unreachable.
        DeviceAuthError: If token is invalid.
        DeviceTimeoutError: If device doesn't respond.
    """
    Device, DeviceException = _get_miio_imports()

    logger.debug("Getting device status for %s", ip)
    try:
        device = Device(ip=ip, token=token, timeout=timeout)
        info = device.info()

        # Try to get status - this varies by device type
        properties = None
        try:
            # Generic status query
            status = device.send("get_prop", ["all"])
            if status:
                properties = {"status": status}
        except DeviceException as e:
            logger.debug("get_prop failed (device may not support it): %s", e)

        return XiaomiDeviceStatus(
            device_id=str(info.raw.get("did", "")),
            model=info.model,
            firmware=info.firmware_version,
            hardware=info.hardware_version,
            mac=info.mac_address,
            is_online=True,
            properties=properties,
            raw_response=info.raw,
        )
    except socket.timeout as e:
        raise DeviceTimeoutError(f"Device {ip} timed out") from e
    except DeviceException as e:
        raise _handle_device_exception(e, "get_device_status", ip) from e
    except OSError as e:
        raise DeviceConnectionError(f"Network error connecting to {ip}: {e}") from e


def create_typed_device(ip: str, token: str, model: str | None = None) -> Any:
    """Create a device-specific instance using python-miio's DeviceFactory.

    This allows using device-specific commands and properties.

    Args:
        ip: Device IP address.
        token: Device token (32 hex characters).
        model: Optional device model. If not provided, will be auto-detected.

    Returns:
        Device-specific instance (e.g., Yeelight, VacuumCleaner, etc.).

    Raises:
        ImportError: If python-miio is not installed.
        Exception: If device creation fails.
    """
    try:
        from miio import Device, DeviceFactory
    except ImportError as e:
        raise ImportError(
            "python-miio is required for device interactions. "
            "Install with: pip install python-miio"
        ) from e

    # If model not provided, detect it first
    if model is None:
        device = Device(ip=ip, token=token)
        info = device.info()
        model = info.model

    if model:
        try:
            return DeviceFactory.create(ip, token, model=model)
        except Exception:
            # Fallback to generic device
            pass

    return Device(ip=ip, token=token)


def send_command(
    ip: str,
    token: str,
    method: str,
    params: list[Any] | None = None,
    timeout: float = 5.0,
) -> Any:
    """Send a raw miIO command to a device.

    Args:
        ip: Device IP address.
        token: Device token (32 hex characters).
        method: miIO method name (e.g., "get_prop", "set_power").
        params: Optional method parameters.
        timeout: Command timeout in seconds.

    Returns:
        Command response from the device.

    Raises:
        ImportError: If python-miio is not installed.
        DeviceConnectionError: If device is unreachable.
        DeviceAuthError: If token is invalid.
        DeviceTimeoutError: If command times out.
    """
    Device, DeviceException = _get_miio_imports()

    logger.debug("Sending command %s to %s with params %s", method, ip, params)
    try:
        device = Device(ip=ip, token=token, timeout=timeout)
        result = device.send(method, params or [])
        logger.debug("Command result: %s", result)
        return result
    except socket.timeout as e:
        raise DeviceTimeoutError(f"Command {method} to {ip} timed out") from e
    except DeviceException as e:
        raise _handle_device_exception(e, f"send_command({method})", ip) from e
    except OSError as e:
        raise DeviceConnectionError(f"Network error sending command to {ip}: {e}") from e


def validate_token(token: str) -> bool:
    """Validate a device token format.

    Args:
        token: Token to validate.

    Returns:
        True if valid, False otherwise.
    """
    if not token:
        return False

    # Token should be 32 hex characters
    if len(token) != 32:
        return False

    try:
        int(token, 16)
        return True
    except ValueError:
        return False


def check_device_connectivity(ip: str, token: str, timeout: float = 5.0) -> dict:
    """Check if a device is reachable and responsive.

    Args:
        ip: Device IP address.
        token: Device token.
        timeout: Connection timeout in seconds.

    Returns:
        Dict with connectivity status and device info if successful.
        On failure, includes error_type for programmatic handling.
    """
    try:
        Device, DeviceException = _get_miio_imports()
    except ImportError:
        return {
            "reachable": False,
            "error": "python-miio not installed",
            "error_type": "import_error",
        }

    logger.debug("Checking connectivity to %s", ip)
    try:
        device = Device(ip=ip, token=token, timeout=timeout)
        info = device.info()

        return {
            "reachable": True,
            "model": info.model,
            "firmware": info.firmware_version,
            "device_id": str(info.raw.get("did", "")),
        }
    except socket.timeout:
        return {
            "reachable": False,
            "error": f"Device {ip} did not respond within {timeout}s",
            "error_type": "timeout",
        }
    except DeviceException as e:
        error_msg = str(e).lower()
        error_type = "device_error"
        if any(x in error_msg for x in ("token", "auth", "forbidden")):
            error_type = "auth_error"
        return {
            "reachable": False,
            "error": str(e),
            "error_type": error_type,
        }
    except OSError as e:
        return {
            "reachable": False,
            "error": f"Network error: {e}",
            "error_type": "network_error",
        }


def info_to_smart_home_device(info: MiioDeviceInfo, token: str) -> SmartHomeDevice:
    """Convert MiioDeviceInfo to SmartHomeDevice with token.

    Args:
        info: Device info from discovery or query.
        token: Known device token.

    Returns:
        SmartHomeDevice instance with token set.
    """
    device = info.to_smart_home_device()
    device.token = token
    device.is_token_available = validate_token(token)
    return device


# Common property names for different device types
COMMON_PROPERTIES = {
    "power": ["power", "on", "is_on"],
    "temperature": ["temperature", "temp", "aqi"],
    "humidity": ["humidity", "rh"],
    "brightness": ["brightness", "bright", "level"],
    "mode": ["mode", "fan_level", "speed"],
    "battery": ["battery", "battery_level"],
}


@dataclass
class DeviceProperties:
    """Device properties retrieved from polling."""

    power: bool | None = None
    temperature: float | None = None
    humidity: float | None = None
    brightness: int | None = None
    mode: str | None = None
    battery: int | None = None
    raw_properties: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "power": self.power,
            "temperature": self.temperature,
            "humidity": self.humidity,
            "brightness": self.brightness,
            "mode": self.mode,
            "battery": self.battery,
            "raw_properties": self.raw_properties,
        }


def get_device_properties(
    ip: str,
    token: str,
    properties: list[str] | None = None,
    timeout: float = 5.0,
) -> DeviceProperties:
    """Get specific device properties (read-only status polling).

    This function queries the device for common properties like power state,
    temperature, humidity, brightness, etc. It's designed for status monitoring
    and does NOT send control commands.

    Args:
        ip: Device IP address.
        token: Device token (32 hex characters).
        properties: List of property names to query. If None, queries all common properties.
                   Options: power, temperature, humidity, brightness, mode, battery
        timeout: Query timeout in seconds.

    Returns:
        DeviceProperties with available values.

    Raises:
        ImportError: If python-miio is not installed.
        DeviceConnectionError: If device is unreachable.
        DeviceAuthError: If token is invalid.
        DeviceTimeoutError: If device doesn't respond.
    """
    Device, DeviceException = _get_miio_imports()

    if properties is None:
        properties = list(COMMON_PROPERTIES.keys())

    logger.debug("Getting properties %s from %s", properties, ip)

    result = DeviceProperties()
    raw_props: dict[str, Any] = {}

    try:
        device = Device(ip=ip, token=token, timeout=timeout)

        # Try each property group
        for prop_name in properties:
            if prop_name not in COMMON_PROPERTIES:
                logger.warning("Unknown property: %s", prop_name)
                continue

            # Try each possible name for this property
            for miio_name in COMMON_PROPERTIES[prop_name]:
                try:
                    response = device.send("get_prop", [miio_name])
                    if response and response[0] is not None:
                        raw_props[prop_name] = response[0]
                        _set_property_value(result, prop_name, response[0])
                        break
                except DeviceException:
                    # Property not supported, try next name
                    continue

        result.raw_properties = raw_props if raw_props else None
        return result

    except socket.timeout as e:
        raise DeviceTimeoutError(f"Device {ip} timed out while polling properties") from e
    except DeviceException as e:
        raise _handle_device_exception(e, "get_device_properties", ip) from e
    except OSError as e:
        raise DeviceConnectionError(f"Network error polling {ip}: {e}") from e


def _set_property_value(props: DeviceProperties, name: str, value: Any) -> None:
    """Set a property value with type conversion.

    Args:
        props: DeviceProperties instance to update.
        name: Property name.
        value: Raw value from device.
    """
    try:
        if name == "power":
            # Handle various power state formats
            if isinstance(value, bool):
                props.power = value
            elif isinstance(value, str):
                props.power = value.lower() in ("on", "true", "1")
            elif isinstance(value, int):
                props.power = value != 0
        elif name == "temperature":
            props.temperature = float(value)
        elif name == "humidity":
            props.humidity = float(value)
        elif name == "brightness":
            props.brightness = int(value)
        elif name == "mode":
            props.mode = str(value)
        elif name == "battery":
            props.battery = int(value)
    except (ValueError, TypeError) as e:
        logger.debug("Failed to convert %s value %s: %s", name, value, e)
