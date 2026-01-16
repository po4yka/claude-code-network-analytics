"""Smart home device data models and result types."""

from dataclasses import dataclass, field
from enum import Enum


class DeviceType(Enum):
    """Smart home device types."""

    XIAOMI = "xiaomi"
    AQARA = "aqara"
    YEELIGHT = "yeelight"
    MATTER = "matter"
    UNKNOWN = "unknown"


@dataclass
class SmartHomeDevice:
    """Represents a discovered smart home device."""

    ip: str
    device_type: DeviceType
    mac: str | None = None
    device_id: str | None = None
    model: str | None = None
    token: str | None = None
    firmware: str | None = None
    is_token_available: bool = False
    name: str | None = None
    extra: dict | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "ip": self.ip,
            "mac": self.mac,
            "device_id": self.device_id,
            "device_type": self.device_type.value,
            "model": self.model,
            "token": self.token if self.is_token_available else None,
            "firmware": self.firmware,
            "is_token_available": self.is_token_available,
            "name": self.name,
            "extra": self.extra,
        }


@dataclass
class MiioDeviceInfo:
    """Device info from miIO protocol."""

    ip: str
    device_id: str
    token: str | None
    model: str | None = None
    firmware: str | None = None
    hardware: str | None = None
    mac: str | None = None
    raw_info: dict | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "ip": self.ip,
            "device_id": self.device_id,
            "token": self.token,
            "model": self.model,
            "firmware": self.firmware,
            "hardware": self.hardware,
            "mac": self.mac,
            "raw_info": self.raw_info,
        }

    def to_smart_home_device(self) -> SmartHomeDevice:
        """Convert to SmartHomeDevice."""
        device_type = DeviceType.XIAOMI
        if self.model:
            model_lower = self.model.lower()
            if "yeelight" in model_lower or "yeelink" in model_lower:
                device_type = DeviceType.YEELIGHT
            elif "lumi" in model_lower or "aqara" in model_lower:
                device_type = DeviceType.AQARA

        return SmartHomeDevice(
            ip=self.ip,
            mac=self.mac,
            device_id=self.device_id,
            device_type=device_type,
            model=self.model,
            token=self.token,
            firmware=self.firmware,
            is_token_available=self.token is not None and self.token != "0" * 32,
            extra=self.raw_info,
        )


@dataclass
class AqaraGateway:
    """Aqara Zigbee gateway."""

    ip: str
    port: int = 9898
    sid: str | None = None
    model: str | None = None
    proto_version: str | None = None
    extra: dict | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "ip": self.ip,
            "port": self.port,
            "sid": self.sid,
            "model": self.model,
            "proto_version": self.proto_version,
            "extra": self.extra,
        }

    def to_smart_home_device(self) -> SmartHomeDevice:
        """Convert to SmartHomeDevice."""
        return SmartHomeDevice(
            ip=self.ip,
            device_id=self.sid,
            device_type=DeviceType.AQARA,
            model=self.model,
            is_token_available=False,
            extra=self.extra,
        )


@dataclass
class MatterDevice:
    """Matter-compatible device discovered via mDNS."""

    ip: str
    name: str | None = None
    port: int | None = None
    service_type: str | None = None
    vendor_id: int | None = None
    product_id: int | None = None
    discriminator: int | None = None
    extra: dict | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "ip": self.ip,
            "name": self.name,
            "port": self.port,
            "service_type": self.service_type,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "discriminator": self.discriminator,
            "extra": self.extra,
        }

    def to_smart_home_device(self) -> SmartHomeDevice:
        """Convert to SmartHomeDevice."""
        return SmartHomeDevice(
            ip=self.ip,
            device_type=DeviceType.MATTER,
            name=self.name,
            is_token_available=False,
            extra=self.extra,
        )


@dataclass
class SmartHomeDiscoveryResult:
    """Result of smart home device discovery."""

    miio_devices: list[MiioDeviceInfo] = field(default_factory=list)
    aqara_gateways: list[AqaraGateway] = field(default_factory=list)
    matter_devices: list[MatterDevice] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        """Total number of discovered devices."""
        return len(self.miio_devices) + len(self.aqara_gateways) + len(self.matter_devices)

    def all_devices(self) -> list[SmartHomeDevice]:
        """Get all devices as SmartHomeDevice instances."""
        devices: list[SmartHomeDevice] = []
        for d in self.miio_devices:
            devices.append(d.to_smart_home_device())
        for g in self.aqara_gateways:
            devices.append(g.to_smart_home_device())
        for m in self.matter_devices:
            devices.append(m.to_smart_home_device())
        return devices

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "total_count": self.total_count,
            "miio_devices": [d.to_dict() for d in self.miio_devices],
            "aqara_gateways": [g.to_dict() for g in self.aqara_gateways],
            "matter_devices": [m.to_dict() for m in self.matter_devices],
            "all_devices": [d.to_dict() for d in self.all_devices()],
        }


@dataclass
class CloudDevice:
    """Device retrieved from Xiaomi Cloud."""

    device_id: str
    token: str
    name: str | None = None
    model: str | None = None
    ip: str | None = None
    mac: str | None = None
    is_online: bool = False
    parent_id: str | None = None
    extra: dict | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "device_id": self.device_id,
            "token": self.token,
            "name": self.name,
            "model": self.model,
            "ip": self.ip,
            "mac": self.mac,
            "is_online": self.is_online,
            "parent_id": self.parent_id,
            "extra": self.extra,
        }
