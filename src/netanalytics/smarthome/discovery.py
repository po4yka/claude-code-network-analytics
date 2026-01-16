"""Multi-method smart home device discovery.

Supports discovery via:
- miIO protocol (Xiaomi WiFi devices) - UDP broadcast + mDNS
- Aqara gateway multicast discovery
- Matter device discovery via mDNS
"""

import contextlib
import json
import logging
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

from .devices import (
    AqaraGateway,
    MatterDevice,
    MiioDeviceInfo,
    SmartHomeDevice,
    SmartHomeDiscoveryResult,
)


# Discovery cache with TTL support
class DiscoveryCache:
    """Simple TTL-based cache for discovery results.

    Caches discovery results to avoid re-scanning the network on repeated calls.
    Cache entries expire after the configured TTL.
    """

    def __init__(self, default_ttl: float = 60.0):
        """Initialize cache.

        Args:
            default_ttl: Default time-to-live for cache entries in seconds.
        """
        self._cache: dict[str, tuple[SmartHomeDiscoveryResult, float]] = {}
        self._default_ttl = default_ttl

    def get(self, key: str) -> SmartHomeDiscoveryResult | None:
        """Get cached result if not expired.

        Args:
            key: Cache key (typically methods hash).

        Returns:
            Cached result or None if expired/not found.
        """
        if key not in self._cache:
            return None

        result, expiry = self._cache[key]
        if time.time() > expiry:
            del self._cache[key]
            return None

        logger.debug("Cache hit for key %s", key)
        return result

    def set(
        self,
        key: str,
        result: SmartHomeDiscoveryResult,
        ttl: float | None = None,
    ) -> None:
        """Store result in cache.

        Args:
            key: Cache key.
            result: Discovery result to cache.
            ttl: Time-to-live in seconds (uses default if None).
        """
        expiry = time.time() + (ttl if ttl is not None else self._default_ttl)
        self._cache[key] = (result, expiry)
        logger.debug("Cached result for key %s (expires in %.1fs)", key, ttl or self._default_ttl)

    def clear(self) -> None:
        """Clear all cached results."""
        self._cache.clear()
        logger.debug("Cache cleared")

    def invalidate(self, key: str) -> bool:
        """Remove specific key from cache.

        Args:
            key: Cache key to remove.

        Returns:
            True if key was found and removed, False otherwise.
        """
        if key in self._cache:
            del self._cache[key]
            return True
        return False


# Global cache instance
_discovery_cache = DiscoveryCache()

if TYPE_CHECKING:
    from zeroconf import ServiceInfo, Zeroconf

# miIO protocol constants
MIIO_PORT = 54321
MIIO_HELLO_PACKET = bytes.fromhex(
    "21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

# Aqara constants
AQARA_MULTICAST_IP = "224.0.0.50"
AQARA_MULTICAST_PORT = 4321
AQARA_GATEWAY_PORT = 9898


def discover_miio_broadcast(timeout: float = 5.0) -> list[MiioDeviceInfo]:
    """Discover miIO devices using UDP broadcast.

    Sends "hello" packet to UDP broadcast on port 54321 and listens for responses.
    Returns list of discovered devices with their device IDs and tokens (if exposed).

    Args:
        timeout: Discovery timeout in seconds.

    Returns:
        List of discovered miIO devices.
    """
    devices: list[MiioDeviceInfo] = []
    seen_ips: set[str] = set()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    try:
        # Send broadcast hello
        sock.sendto(MIIO_HELLO_PACKET, ("<broadcast>", MIIO_PORT))

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]

                if ip in seen_ips:
                    continue
                seen_ips.add(ip)

                device = _parse_miio_response(ip, data)
                if device:
                    devices.append(device)

            except TimeoutError:
                break
    finally:
        sock.close()

    return devices


def _parse_miio_response(ip: str, data: bytes) -> MiioDeviceInfo | None:
    """Parse miIO hello response packet.

    Packet structure (32 bytes):
    - 0-1: Magic (0x2131)
    - 2-3: Packet length
    - 4-7: Unknown
    - 8-11: Device ID
    - 12-15: Stamp
    - 16-31: MD5 checksum or token

    Args:
        ip: Source IP address.
        data: Raw packet data.

    Returns:
        Parsed device info or None if invalid.
    """
    if len(data) < 32:
        return None

    # Check magic bytes
    if data[0:2] != b"\x21\x31":
        return None

    # Extract device ID (big endian unsigned int at offset 8)
    device_id = struct.unpack(">I", data[8:12])[0]

    # Extract token (last 16 bytes of 32-byte header)
    # Note: For handshake response, this is all 0xff, meaning token not exposed
    token_bytes = data[16:32]
    if token_bytes == b"\xff" * 16 or token_bytes == b"\x00" * 16:
        token = None
    else:
        token = token_bytes.hex()

    return MiioDeviceInfo(
        ip=ip,
        device_id=str(device_id),
        token=token,
    )


def discover_miio_mdns(timeout: float = 5.0) -> list[MiioDeviceInfo]:
    """Discover miIO devices using mDNS service discovery.

    Uses zeroconf to find devices announcing `_miio._udp.local.` service.

    Args:
        timeout: Discovery timeout in seconds.

    Returns:
        List of discovered miIO devices.
    """
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    except ImportError:
        logger.debug("zeroconf not installed, skipping mDNS discovery")
        return []

    devices: list[MiioDeviceInfo] = []
    seen_ids: set[str] = set()

    class MiioListener(ServiceListener):
        def __init__(self, zc: "Zeroconf"):
            self.zc = zc

        def add_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            info: ServiceInfo | None = zc.get_service_info(type_, name)
            if info and info.parsed_addresses():
                device = _parse_mdns_service(name, info)
                if device and device.device_id not in seen_ids:
                    seen_ids.add(device.device_id)
                    devices.append(device)

        def remove_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            pass

        def update_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            pass

    zc = Zeroconf()
    try:
        listener = MiioListener(zc)
        ServiceBrowser(zc, "_miio._udp.local.", listener)
        time.sleep(timeout)
    except Exception as e:
        logger.warning("mDNS discovery error: %s", e)
    finally:
        zc.close()

    return devices


def _parse_mdns_service(name: str, info: "ServiceInfo") -> MiioDeviceInfo | None:
    """Parse miIO mDNS service info.

    Service name format: model_deviceid._miio._udp.local.
    Properties may contain mac, model, fw_ver, etc.

    Args:
        name: Service name.
        info: Zeroconf ServiceInfo object.

    Returns:
        Parsed device info or None if invalid.
    """
    addresses = info.parsed_addresses()
    if not addresses:
        return None

    ip = addresses[0]

    # Parse name: model_deviceid._miio._udp.local.
    # Example: yeelink-light-bslamp2_miio123456789._miio._udp.local.
    parts = name.replace("._miio._udp.local.", "").rsplit("_", 1)

    model = None
    device_id = None

    if len(parts) == 2:
        model = parts[0]
        # device_id typically starts with "miio"
        device_id = parts[1].replace("miio", "") if parts[1].startswith("miio") else parts[1]
    elif len(parts) == 1:
        device_id = parts[0]

    # Extract properties
    props = {}
    for key, value in info.properties.items():
        if isinstance(key, bytes):
            key = key.decode("utf-8", errors="ignore")
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="ignore")
        props[key] = value

    mac = props.get("mac")
    firmware = props.get("fw_ver")

    return MiioDeviceInfo(
        ip=ip,
        device_id=device_id or "",
        token=None,  # mDNS doesn't expose tokens
        model=model or props.get("model"),
        firmware=firmware,
        mac=mac,
        raw_info=props if props else None,
    )


def discover_aqara_gateways(timeout: float = 5.0) -> list[AqaraGateway]:
    """Discover Aqara/Lumi Zigbee gateways via multicast.

    Sends "whois" command to multicast group 224.0.0.50:4321.
    Gateways respond with their SID, model, and protocol version.

    Args:
        timeout: Discovery timeout in seconds.

    Returns:
        List of discovered Aqara gateways.
    """
    gateways: list[AqaraGateway] = []
    seen_sids: set[str] = set()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)

    try:
        # Join multicast group
        mreq = struct.pack("4sl", socket.inet_aton(AQARA_MULTICAST_IP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        # Send whois command
        whois_cmd = json.dumps({"cmd": "whois"}).encode("utf-8")
        sock.sendto(whois_cmd, (AQARA_MULTICAST_IP, AQARA_MULTICAST_PORT))

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]

                gateway = _parse_aqara_response(ip, data)
                if gateway and gateway.sid and gateway.sid not in seen_sids:
                    seen_sids.add(gateway.sid)
                    gateways.append(gateway)

            except TimeoutError:
                break
    except OSError:
        # Multicast may not be supported
        pass
    finally:
        sock.close()

    return gateways


def _validate_aqara_response(response: dict) -> tuple[bool, str | None]:
    """Validate Aqara gateway response schema.

    Args:
        response: Parsed JSON response.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not isinstance(response, dict):
        return False, "Response is not a JSON object"

    cmd = response.get("cmd")
    if cmd != "iam":
        return False, f"Unexpected command: {cmd}"

    # Port should be a valid integer string or integer
    port = response.get("port")
    if port is not None:
        try:
            port_int = int(port)
            if not (1 <= port_int <= 65535):
                return False, f"Port out of range: {port_int}"
        except (ValueError, TypeError):
            return False, f"Invalid port value: {port}"

    return True, None


def _parse_aqara_response(ip: str, data: bytes) -> AqaraGateway | None:
    """Parse Aqara gateway response.

    Response format (JSON):
    {"cmd": "iam", "port": "9898", "sid": "...", "model": "gateway", "proto_version": "1.0.0"}

    Args:
        ip: Source IP address.
        data: Raw response data.

    Returns:
        Parsed gateway info or None if invalid.
    """
    try:
        response = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.debug("Failed to parse Aqara response: %s", e)
        return None

    # Validate schema
    is_valid, error = _validate_aqara_response(response)
    if not is_valid:
        logger.debug("Invalid Aqara response from %s: %s", ip, error)
        return None

    # Parse port with fallback
    try:
        port = int(response.get("port", AQARA_GATEWAY_PORT))
    except (ValueError, TypeError):
        port = AQARA_GATEWAY_PORT

    return AqaraGateway(
        ip=ip,
        port=port,
        sid=response.get("sid"),
        model=response.get("model"),
        proto_version=response.get("proto_version"),
        extra=response,
    )


def discover_matter_devices(timeout: float = 5.0) -> list[MatterDevice]:
    """Discover Matter-compatible devices via mDNS.

    Searches for `_matter._tcp.local.` and `_matterc._udp.local.` services.

    Args:
        timeout: Discovery timeout in seconds.

    Returns:
        List of discovered Matter devices.
    """
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    except ImportError:
        logger.debug("zeroconf not installed, skipping Matter discovery")
        return []

    devices: list[MatterDevice] = []
    seen_names: set[str] = set()

    class MatterListener(ServiceListener):
        def __init__(self, zc: "Zeroconf"):
            self.zc = zc

        def add_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            if name in seen_names:
                return
            seen_names.add(name)

            info: ServiceInfo | None = zc.get_service_info(type_, name)
            if info and info.parsed_addresses():
                device = _parse_matter_service(name, type_, info)
                if device:
                    devices.append(device)

        def remove_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            pass

        def update_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            pass

    zc = Zeroconf()
    try:
        listener = MatterListener(zc)

        # Matter operational service and commissioning service
        ServiceBrowser(zc, "_matter._tcp.local.", listener)
        ServiceBrowser(zc, "_matterc._udp.local.", listener)

        time.sleep(timeout)
    except Exception as e:
        logger.warning("Matter discovery error: %s", e)
    finally:
        zc.close()

    return devices


def _parse_matter_service(name: str, type_: str, info: "ServiceInfo") -> MatterDevice | None:
    """Parse Matter mDNS service info.

    Args:
        name: Service name.
        type_: Service type.
        info: Zeroconf ServiceInfo object.

    Returns:
        Parsed device info or None if invalid.
    """
    addresses = info.parsed_addresses()
    if not addresses:
        return None

    ip = addresses[0]

    # Extract properties
    props = {}
    for key, value in info.properties.items():
        if isinstance(key, bytes):
            key = key.decode("utf-8", errors="ignore")
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="ignore")
        props[key] = value

    # Try to parse Matter-specific properties
    vendor_id = None
    product_id = None
    discriminator = None

    # Vendor ID and Product ID may be in "VP" property as "VID+PID" format
    if "VP" in props:
        try:
            vp = props["VP"]
            if "+" in vp:
                vid_str, pid_str = vp.split("+", 1)
                vendor_id = int(vid_str)
                product_id = int(pid_str)
        except (ValueError, TypeError):
            pass

    # Discriminator may be in "D" property
    if "D" in props:
        with contextlib.suppress(ValueError, TypeError):
            discriminator = int(props["D"])

    return MatterDevice(
        ip=ip,
        name=name.replace(f".{type_}", ""),
        port=info.port,
        service_type=type_,
        vendor_id=vendor_id,
        product_id=product_id,
        discriminator=discriminator,
        extra=props if props else None,
    )


def discover_all(
    timeout: float = 5.0,
    methods: list[str] | None = None,
    parallel: bool = True,
    use_cache: bool = True,
    cache_ttl: float | None = None,
) -> SmartHomeDiscoveryResult:
    """Discover all smart home devices using multiple methods.

    Args:
        timeout: Discovery timeout per method in seconds.
        methods: List of methods to use. Options: "miio", "mdns", "aqara", "matter".
                If None, uses all methods.
        parallel: Run discovery methods in parallel (default: True).
                  Reduces total time from ~20s to ~5s for all methods.
        use_cache: Use cached results if available (default: True).
        cache_ttl: Cache TTL in seconds (default: 60s). Set to 0 to disable caching.

    Returns:
        Combined discovery results from all methods.
    """
    if methods is None:
        methods = ["miio", "mdns", "aqara", "matter"]

    # Generate cache key from methods
    cache_key = f"discover:{','.join(sorted(methods))}:{timeout}"

    # Check cache first
    if use_cache and cache_ttl != 0:
        cached = _discovery_cache.get(cache_key)
        if cached is not None:
            return cached

    result = SmartHomeDiscoveryResult()
    seen_miio_ips: set[str] = set()

    # Map method names to discovery functions
    method_funcs = {
        "miio": lambda: ("miio", discover_miio_broadcast(timeout)),
        "mdns": lambda: ("mdns", discover_miio_mdns(timeout)),
        "aqara": lambda: ("aqara", discover_aqara_gateways(timeout)),
        "matter": lambda: ("matter", discover_matter_devices(timeout)),
    }

    if parallel and len(methods) > 1:
        # Run discovery methods in parallel
        logger.debug("Running parallel discovery with methods: %s", methods)
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(method_funcs[m]): m
                for m in methods
                if m in method_funcs
            }

            for future in as_completed(futures):
                method_name = futures[future]
                try:
                    name, devices = future.result()
                    logger.debug("Method %s found %d devices", name, len(devices))
                    _merge_results(result, name, devices, seen_miio_ips)
                except Exception as e:
                    logger.warning("Discovery method %s failed: %s", method_name, e)
    else:
        # Sequential discovery
        for method in methods:
            if method in method_funcs:
                try:
                    name, devices = method_funcs[method]()
                    _merge_results(result, name, devices, seen_miio_ips)
                except Exception as e:
                    logger.warning("Discovery method %s failed: %s", method, e)

    # Cache the result
    if use_cache and cache_ttl != 0:
        _discovery_cache.set(cache_key, result, cache_ttl)

    return result


def clear_discovery_cache() -> None:
    """Clear the global discovery cache.

    Call this to force a fresh network scan on the next discover_all() call.
    """
    _discovery_cache.clear()


def _merge_results(
    result: SmartHomeDiscoveryResult,
    method: str,
    devices: list,
    seen_miio_ips: set[str],
) -> None:
    """Merge discovered devices into result, avoiding duplicates.

    Args:
        result: Result object to merge into.
        method: Discovery method name.
        devices: List of discovered devices.
        seen_miio_ips: Set of already-seen miIO device IPs.
    """
    if method in ("miio", "mdns"):
        for device in devices:
            if device.ip not in seen_miio_ips:
                seen_miio_ips.add(device.ip)
                result.miio_devices.append(device)
    elif method == "aqara":
        result.aqara_gateways.extend(devices)
    elif method == "matter":
        result.matter_devices.extend(devices)


def get_smart_home_devices(
    timeout: float = 5.0,
    methods: list[str] | None = None,
) -> list[SmartHomeDevice]:
    """Convenience function to get all devices as SmartHomeDevice instances.

    Args:
        timeout: Discovery timeout per method in seconds.
        methods: List of discovery methods to use.

    Returns:
        List of all discovered devices as SmartHomeDevice instances.
    """
    result = discover_all(timeout=timeout, methods=methods)
    return result.all_devices()


@contextlib.contextmanager
def _aqara_socket(gateway_ip: str, port: int = AQARA_GATEWAY_PORT, timeout: float = 5.0):
    """Context manager for Aqara gateway socket connection.

    Args:
        gateway_ip: Gateway IP address.
        port: Gateway port (default: 9898).
        timeout: Socket timeout in seconds.

    Yields:
        Configured UDP socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        yield sock
    finally:
        sock.close()


def get_aqara_subdevices(
    gateway_ip: str,
    password: str | None = None,
    timeout: float = 5.0,
) -> list[dict]:
    """Get list of sub-devices connected to an Aqara gateway.

    This queries the gateway for all Zigbee devices (sensors, switches, etc.)
    connected to it. Sub-devices include:
    - Motion sensors
    - Door/window sensors
    - Temperature/humidity sensors
    - Smart plugs and switches
    - Water leak sensors
    - Vibration sensors

    Args:
        gateway_ip: Aqara gateway IP address.
        password: Gateway password (optional, may be required for some operations).
        timeout: Query timeout in seconds.

    Returns:
        List of sub-device dictionaries with sid, model, and status.
        Returns empty list if gateway doesn't respond or doesn't support this command.

    Note:
        This is a read-only operation. No commands are sent to sub-devices.
    """
    subdevices: list[dict] = []

    try:
        with _aqara_socket(gateway_ip, timeout=timeout) as sock:
            # Send get_id_list command to get all sub-device SIDs
            cmd = json.dumps({"cmd": "get_id_list"}).encode("utf-8")
            sock.sendto(cmd, (gateway_ip, AQARA_GATEWAY_PORT))

            try:
                data, _ = sock.recvfrom(4096)
                response = json.loads(data.decode("utf-8"))
            except (TimeoutError, json.JSONDecodeError) as e:
                logger.warning("Failed to get device list from gateway: %s", e)
                return []

            if response.get("cmd") != "get_id_list_ack":
                logger.warning("Unexpected response from gateway: %s", response.get("cmd"))
                return []

            # Parse the device SID list
            sid_list_str = response.get("data", "[]")
            try:
                sid_list = json.loads(sid_list_str)
            except json.JSONDecodeError:
                logger.warning("Invalid SID list format: %s", sid_list_str)
                return []

            # Query each sub-device for its details
            for sid in sid_list:
                device_info = _query_aqara_subdevice(sock, gateway_ip, str(sid), timeout)
                if device_info:
                    subdevices.append(device_info)

    except OSError as e:
        logger.warning("Failed to connect to Aqara gateway %s: %s", gateway_ip, e)
        return []

    return subdevices


def _query_aqara_subdevice(
    sock: socket.socket,
    gateway_ip: str,
    sid: str,
    timeout: float,
) -> dict | None:
    """Query a single Aqara sub-device for its details.

    Args:
        sock: Open UDP socket.
        gateway_ip: Gateway IP address.
        sid: Sub-device SID.
        timeout: Query timeout.

    Returns:
        Device info dict or None if query failed.
    """
    cmd = json.dumps({"cmd": "read", "sid": sid}).encode("utf-8")
    sock.sendto(cmd, (gateway_ip, AQARA_GATEWAY_PORT))

    try:
        # Short timeout for individual device queries
        sock.settimeout(min(timeout, 2.0))
        data, _ = sock.recvfrom(4096)
        response = json.loads(data.decode("utf-8"))
    except (TimeoutError, json.JSONDecodeError) as e:
        logger.debug("Failed to query sub-device %s: %s", sid, e)
        return None

    if response.get("cmd") != "read_ack":
        return None

    # Parse device data
    device_data_str = response.get("data", "{}")
    try:
        device_data = json.loads(device_data_str)
    except json.JSONDecodeError:
        device_data = {}

    return {
        "sid": sid,
        "model": response.get("model"),
        "short_id": response.get("short_id"),
        "data": device_data,
    }
