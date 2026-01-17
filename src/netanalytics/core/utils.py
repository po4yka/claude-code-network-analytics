"""Utility functions for Network Analytics Toolkit."""

import os
import re
import socket
import subprocess
import sys
from collections.abc import Callable
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from pathlib import Path
from typing import Any

import psutil

from .config import get_config
from .exceptions import PermissionError, ValidationError


def is_root() -> bool:
    """Check if running with root/admin privileges."""
    return os.geteuid() == 0


def require_root(operation: str) -> Callable:
    """Decorator to require root privileges for an operation."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not is_root():
                raise PermissionError(
                    operation,
                    "Run with sudo or use pkexec for GUI elevation",
                )
            return func(*args, **kwargs)

        return wrapper

    return decorator


def elevate_privileges() -> bool:
    """Attempt to elevate privileges using sudo or pkexec."""
    if is_root():
        return True

    # Try pkexec first (GUI-friendly)
    if subprocess.run(["which", "pkexec"], capture_output=True).returncode == 0:
        try:
            subprocess.run(
                ["pkexec", sys.executable] + sys.argv,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            pass

    # Fall back to sudo
    try:
        subprocess.run(
            ["sudo", sys.executable] + sys.argv,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def validate_ip(ip_str: str) -> IPv4Address | IPv6Address:
    """Validate and parse an IP address string."""
    try:
        ip = ip_address(ip_str)
        if ip.version == 6:
            raise ValidationError(f"IPv6 address not supported: {ip_str}")
        return ip
    except ValueError as e:
        raise ValidationError(f"Invalid IP address: {ip_str}", str(e)) from e


def resolve_target(target: str) -> str:
    """Resolve a hostname or IP string to an IPv4 address string."""
    try:
        return str(validate_ip(target))
    except ValidationError:
        pass

    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        raise ValidationError(f"Invalid hostname or IP: {target}", str(e)) from e


def validate_network(network_str: str) -> IPv4Network | IPv6Network:
    """Validate and parse a network CIDR string."""
    try:
        net = ip_network(network_str, strict=False)
        if net.version == 6:
            raise ValidationError(f"IPv6 networks are not supported: {network_str}")
        return net
    except ValueError as e:
        raise ValidationError(f"Invalid network: {network_str}", str(e)) from e


def validate_port_range(port_range: str) -> list[int]:
    """Parse and validate a port range string (e.g., '1-1000' or '22,80,443')."""
    ports: list[int] = []

    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            match = re.match(r"^(\d+)-(\d+)$", part)
            if not match:
                raise ValidationError(f"Invalid port range format: {part}")
            try:
                start, end = int(match.group(1)), int(match.group(2))
            except ValueError as e:
                raise ValidationError(f"Invalid port range format: {part}", str(e)) from e
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValidationError(f"Port numbers must be 1-65535: {part}")
            if start > end:
                raise ValidationError(f"Invalid range (start > end): {part}")
            ports.extend(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError as e:
                raise ValidationError(f"Invalid port number: {part}", str(e)) from e
            if not 1 <= port <= 65535:
                raise ValidationError(f"Port number must be 1-65535: {port}")
            ports.append(port)

    return sorted(set(ports))


def get_interfaces() -> dict[str, dict[str, str | int | bool | None]]:
    """Get available network interfaces with their addresses."""
    interfaces: dict[str, dict[str, str | int | bool | None]] = {}

    for name, addrs in psutil.net_if_addrs().items():
        interface_info: dict[str, str | int | bool | None] = {
            "ipv4": None,
            "ipv6": None,
            "mac": None,
        }

        for addr in addrs:
            if addr.family.name == "AF_INET":
                interface_info["ipv4"] = addr.address
                interface_info["netmask"] = addr.netmask
            elif addr.family.name == "AF_INET6":
                interface_info["ipv6"] = addr.address
            elif addr.family.name == "AF_PACKET" or addr.family.name == "AF_LINK":
                interface_info["mac"] = addr.address

        # Get interface stats
        stats = psutil.net_if_stats().get(name)
        if stats:
            interface_info["is_up"] = stats.isup
            interface_info["speed"] = stats.speed
            interface_info["mtu"] = stats.mtu

        interfaces[name] = interface_info

    return interfaces


def get_default_interface() -> str | None:
    """Get the default network interface (one with a gateway)."""
    _ = psutil.net_if_stats()  # Reserved for future gateway lookup
    interfaces = get_interfaces()

    # Find first interface that is up and has an IPv4 address
    for name, info in interfaces.items():
        if info.get("is_up") and info.get("ipv4") and not name.startswith("lo"):
            return name

    return None


def ensure_results_dir() -> Path:
    """Ensure results directory exists and return its path."""
    config = get_config()
    config.results_dir.mkdir(parents=True, exist_ok=True)
    return config.results_dir


def format_mac(mac: str) -> str:
    """Format MAC address consistently."""
    mac = mac.replace("-", ":").lower()
    parts = mac.split(":")
    if len(parts) == 6:
        return ":".join(p.zfill(2) for p in parts)
    return mac


def resolve_hostname(ip: str) -> str | None:
    """Attempt to resolve IP to hostname."""
    import socket

    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def check_dependency(name: str) -> bool:
    """Check if an external command is available."""
    return subprocess.run(["which", name], capture_output=True).returncode == 0


def get_oui_vendor(mac: str) -> str | None:
    """Look up vendor from MAC OUI (first 3 octets)."""
    # Basic OUI lookup - in production, use a full OUI database
    oui_map = {
        # Infrastructure
        "00:00:0c": "Cisco",
        "00:1a:2b": "Hewlett-Packard",
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "dc:a6:32": "Raspberry Pi",
        "b8:27:eb": "Raspberry Pi",
        # Xiaomi Communications
        "28:6c:07": "Xiaomi",
        "64:cc:2e": "Xiaomi",
        "78:11:dc": "Xiaomi",
        "7c:49:eb": "Xiaomi",
        "04:cf:8c": "Xiaomi",
        "18:59:36": "Xiaomi",
        "f8:a4:5f": "Xiaomi",
        "00:9e:c8": "Xiaomi",
        "0c:1d:af": "Xiaomi",
        "10:2a:b3": "Xiaomi",
        "14:f6:5a": "Xiaomi",
        "20:34:fb": "Xiaomi",
        "34:80:b3": "Xiaomi",
        "38:a4:ed": "Xiaomi",
        "3c:bd:3e": "Xiaomi",
        "44:23:7c": "Xiaomi",
        "50:8f:4c": "Xiaomi",
        "58:44:98": "Xiaomi",
        "64:b4:73": "Xiaomi",
        "68:ab:1e": "Xiaomi",
        "74:23:44": "Xiaomi",
        "7c:1c:68": "Xiaomi",
        "84:f3:eb": "Xiaomi",
        "8c:be:be": "Xiaomi",
        "9c:99:a0": "Xiaomi",
        "a4:77:33": "Xiaomi",
        "ac:c1:ee": "Xiaomi",
        "b0:e2:35": "Xiaomi",
        "c4:6a:b7": "Xiaomi",
        "d4:97:0b": "Xiaomi",
        "e4:46:da": "Xiaomi",
        "ec:d0:9f": "Xiaomi",
        "f0:b4:29": "Xiaomi",
        "fc:64:ba": "Xiaomi",
        # Lumi/Aqara (Xiaomi subsidiary)
        "50:64:2b": "Lumi/Aqara",
        "54:ef:44": "Lumi/Aqara",
        "04:cf:8c": "Lumi/Aqara",
        # Yeelight
        "7c:49:eb": "Yeelight",
        "44:23:7c": "Yeelight",
        # Roborock (Xiaomi ecosystem)
        "50:ec:50": "Roborock",
        "e4:aa:ec": "Roborock",
        # Dreame (Xiaomi ecosystem)
        "c8:47:8c": "Dreame",
    }

    mac_normalized = format_mac(mac)
    oui = mac_normalized[:8].lower()
    return oui_map.get(oui)
