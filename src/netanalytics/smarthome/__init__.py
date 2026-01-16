"""Smart home device discovery and interaction module.

Supports discovery and control of:
- Xiaomi WiFi devices (via miIO protocol)
- Aqara Zigbee gateways
- Yeelight devices
- Matter-compatible devices

Example usage:
    >>> from netanalytics.smarthome import discover_all, get_device_info
    >>>
    >>> # Discover all smart home devices
    >>> result = discover_all(timeout=5.0)
    >>> print(f"Found {result.total_count} devices")
    >>>
    >>> # Get info for a specific device (requires token)
    >>> info = get_device_info("192.168.1.100", "0123456789abcdef0123456789abcdef")
    >>> print(f"Device: {info.model}")
"""

from .cloud import (
    CloudLoginResult,
    XiaomiCloud,
    fetch_cloud_tokens,
    list_cloud_servers,
)
from .devices import (
    AqaraGateway,
    CloudDevice,
    DeviceType,
    MatterDevice,
    MiioDeviceInfo,
    SmartHomeDevice,
    SmartHomeDiscoveryResult,
)
from .discovery import (
    discover_all,
    discover_aqara_gateways,
    discover_matter_devices,
    discover_miio_broadcast,
    discover_miio_mdns,
    get_smart_home_devices,
)
from .xiaomi import (
    XiaomiDeviceStatus,
    check_device_connectivity,
    create_typed_device,
    get_device_info,
    get_device_status,
    info_to_smart_home_device,
    send_command,
    validate_token,
)

__all__ = [
    # Device types
    "DeviceType",
    "SmartHomeDevice",
    "MiioDeviceInfo",
    "AqaraGateway",
    "MatterDevice",
    "CloudDevice",
    "SmartHomeDiscoveryResult",
    "XiaomiDeviceStatus",
    "CloudLoginResult",
    # Discovery
    "discover_all",
    "discover_miio_broadcast",
    "discover_miio_mdns",
    "discover_aqara_gateways",
    "discover_matter_devices",
    "get_smart_home_devices",
    # Xiaomi device interactions
    "get_device_info",
    "get_device_status",
    "create_typed_device",
    "send_command",
    "validate_token",
    "check_device_connectivity",
    "info_to_smart_home_device",
    # Cloud
    "XiaomiCloud",
    "fetch_cloud_tokens",
    "list_cloud_servers",
]
