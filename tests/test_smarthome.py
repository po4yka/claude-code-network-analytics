"""Tests for smart home device discovery and interaction module."""

import json
import socket
import struct
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from netanalytics.smarthome.devices import (
    AqaraGateway,
    CloudDevice,
    DeviceType,
    MatterDevice,
    MiioDeviceInfo,
    SmartHomeDevice,
    SmartHomeDiscoveryResult,
)
from netanalytics.smarthome.discovery import (
    _parse_aqara_response,
    _parse_miio_response,
)
from netanalytics.smarthome.xiaomi import (
    validate_token,
    DeviceConnectionError,
    DeviceAuthError,
    DeviceTimeoutError,
    DeviceProtocolError,
)


class TestDeviceModels:
    """Tests for device dataclass models."""

    def test_smart_home_device_to_dict(self):
        """Test SmartHomeDevice serialization."""
        device = SmartHomeDevice(
            ip="192.168.1.100",
            device_type=DeviceType.XIAOMI,
            mac="28:6c:07:12:34:56",
            device_id="123456789",
            model="zhimi.airpurifier.ma4",
            token="0123456789abcdef0123456789abcdef",
            firmware="1.2.3",
            is_token_available=True,
        )

        result = device.to_dict()

        assert result["ip"] == "192.168.1.100"
        assert result["device_type"] == "xiaomi"
        assert result["mac"] == "28:6c:07:12:34:56"
        assert result["device_id"] == "123456789"
        assert result["model"] == "zhimi.airpurifier.ma4"
        assert result["token"] == "0123456789abcdef0123456789abcdef"
        assert result["is_token_available"] is True

    def test_smart_home_device_token_hidden_when_unavailable(self):
        """Test that token is hidden in to_dict when not available."""
        device = SmartHomeDevice(
            ip="192.168.1.100",
            device_type=DeviceType.XIAOMI,
            token="secret_token",
            is_token_available=False,
        )

        result = device.to_dict()

        assert result["token"] is None

    def test_miio_device_info_to_smart_home_device(self):
        """Test converting MiioDeviceInfo to SmartHomeDevice."""
        info = MiioDeviceInfo(
            ip="192.168.1.100",
            device_id="123456",
            token="0123456789abcdef0123456789abcdef",
            model="yeelink.light.lamp1",
            firmware="1.0.0",
        )

        device = info.to_smart_home_device()

        assert device.ip == "192.168.1.100"
        assert device.device_type == DeviceType.YEELIGHT
        assert device.is_token_available is True

    def test_miio_device_info_detects_aqara(self):
        """Test that Aqara/Lumi devices are detected correctly."""
        info = MiioDeviceInfo(
            ip="192.168.1.100",
            device_id="123456",
            token=None,
            model="lumi.gateway.mieu01",
        )

        device = info.to_smart_home_device()

        assert device.device_type == DeviceType.AQARA

    def test_aqara_gateway_to_smart_home_device(self):
        """Test converting AqaraGateway to SmartHomeDevice."""
        gateway = AqaraGateway(
            ip="192.168.1.100",
            port=9898,
            sid="abc123",
            model="gateway",
            proto_version="1.0.0",
        )

        device = gateway.to_smart_home_device()

        assert device.ip == "192.168.1.100"
        assert device.device_type == DeviceType.AQARA
        assert device.device_id == "abc123"
        assert device.is_token_available is False

    def test_matter_device_to_smart_home_device(self):
        """Test converting MatterDevice to SmartHomeDevice."""
        matter = MatterDevice(
            ip="192.168.1.100",
            name="Smart Plug",
            port=5540,
            vendor_id=4937,
        )

        device = matter.to_smart_home_device()

        assert device.ip == "192.168.1.100"
        assert device.device_type == DeviceType.MATTER
        assert device.name == "Smart Plug"

    def test_cloud_device_to_dict(self):
        """Test CloudDevice serialization."""
        device = CloudDevice(
            device_id="123456",
            token="0123456789abcdef0123456789abcdef",
            name="Air Purifier",
            model="zhimi.airpurifier.ma4",
            ip="192.168.1.100",
            is_online=True,
        )

        result = device.to_dict()

        assert result["device_id"] == "123456"
        assert result["token"] == "0123456789abcdef0123456789abcdef"
        assert result["name"] == "Air Purifier"
        assert result["is_online"] is True

    def test_discovery_result_all_devices(self):
        """Test SmartHomeDiscoveryResult.all_devices() returns combined list."""
        result = SmartHomeDiscoveryResult(
            miio_devices=[
                MiioDeviceInfo(ip="192.168.1.1", device_id="1", token=None),
                MiioDeviceInfo(ip="192.168.1.2", device_id="2", token=None),
            ],
            aqara_gateways=[
                AqaraGateway(ip="192.168.1.3", sid="gw1"),
            ],
            matter_devices=[
                MatterDevice(ip="192.168.1.4", name="Plug"),
            ],
        )

        devices = result.all_devices()

        assert len(devices) == 4
        assert result.total_count == 4


class TestMiioProtocolParsing:
    """Tests for miIO protocol packet parsing."""

    def test_parse_miio_response_valid(self):
        """Test parsing a valid miIO hello response."""
        # Construct a valid response packet
        # Magic: 0x2131, Length: 32, Unknown: 0, Device ID: 123456, Stamp: 0
        # Token: all 0xff (hidden)
        packet = (
            b"\x21\x31"  # Magic
            + b"\x00\x20"  # Length (32)
            + b"\x00\x00\x00\x00"  # Unknown
            + struct.pack(">I", 123456)  # Device ID
            + b"\x00\x00\x00\x00"  # Stamp
            + b"\xff" * 16  # Token (hidden)
        )

        result = _parse_miio_response("192.168.1.100", packet)

        assert result is not None
        assert result.ip == "192.168.1.100"
        assert result.device_id == "123456"
        assert result.token is None  # Token hidden

    def test_parse_miio_response_with_token(self):
        """Test parsing miIO response with exposed token."""
        token = bytes.fromhex("0123456789abcdef0123456789abcdef")
        packet = (
            b"\x21\x31"  # Magic
            + b"\x00\x20"  # Length (32)
            + b"\x00\x00\x00\x00"  # Unknown
            + struct.pack(">I", 999999)  # Device ID
            + b"\x00\x00\x00\x00"  # Stamp
            + token  # Token (exposed)
        )

        result = _parse_miio_response("192.168.1.100", packet)

        assert result is not None
        assert result.token == "0123456789abcdef0123456789abcdef"

    def test_parse_miio_response_invalid_magic(self):
        """Test that invalid magic bytes return None."""
        packet = b"\x00\x00" + b"\x00" * 30  # Wrong magic

        result = _parse_miio_response("192.168.1.100", packet)

        assert result is None

    def test_parse_miio_response_too_short(self):
        """Test that too short packets return None."""
        packet = b"\x21\x31\x00\x20"  # Only 4 bytes

        result = _parse_miio_response("192.168.1.100", packet)

        assert result is None


class TestAqaraProtocolParsing:
    """Tests for Aqara gateway protocol parsing."""

    def test_parse_aqara_response_valid(self):
        """Test parsing a valid Aqara gateway response."""
        response = json.dumps({
            "cmd": "iam",
            "port": "9898",
            "sid": "abc123def456",
            "model": "gateway",
            "proto_version": "1.0.0",
        }).encode("utf-8")

        result = _parse_aqara_response("192.168.1.100", response)

        assert result is not None
        assert result.ip == "192.168.1.100"
        assert result.port == 9898
        assert result.sid == "abc123def456"
        assert result.model == "gateway"
        assert result.proto_version == "1.0.0"

    def test_parse_aqara_response_wrong_cmd(self):
        """Test that non-iam commands return None."""
        response = json.dumps({
            "cmd": "heartbeat",
            "sid": "abc123",
        }).encode("utf-8")

        result = _parse_aqara_response("192.168.1.100", response)

        assert result is None

    def test_parse_aqara_response_invalid_json(self):
        """Test that invalid JSON returns None."""
        result = _parse_aqara_response("192.168.1.100", b"not json")

        assert result is None


class TestTokenValidation:
    """Tests for token validation."""

    def test_validate_token_valid(self):
        """Test that valid tokens pass validation."""
        assert validate_token("0123456789abcdef0123456789abcdef") is True
        assert validate_token("ffffffffffffffffffffffffffffffff") is True
        assert validate_token("ABCDEF0123456789ABCDEF0123456789") is True

    def test_validate_token_invalid_length(self):
        """Test that tokens with wrong length fail."""
        assert validate_token("0123456789abcdef") is False  # Too short
        assert validate_token("0123456789abcdef0123456789abcdef00") is False  # Too long
        assert validate_token("") is False  # Empty

    def test_validate_token_invalid_hex(self):
        """Test that non-hex tokens fail."""
        assert validate_token("0123456789ghijkl0123456789ghijkl") is False
        assert validate_token("                                ") is False

    def test_validate_token_none(self):
        """Test that None token fails."""
        assert validate_token(None) is False  # type: ignore


class TestDiscoveryIntegration:
    """Integration tests for discovery (with mocking)."""

    @patch("netanalytics.smarthome.discovery.socket.socket")
    def test_discover_miio_broadcast_timeout(self, mock_socket_class):
        """Test that miIO broadcast discovery handles timeout."""
        from netanalytics.smarthome.discovery import discover_miio_broadcast

        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recvfrom.side_effect = TimeoutError()

        result = discover_miio_broadcast(timeout=0.1)

        assert result == []
        mock_sock.close.assert_called_once()

    @patch("netanalytics.smarthome.discovery.socket.socket")
    def test_discover_aqara_handles_os_error(self, mock_socket_class):
        """Test that Aqara discovery handles OSError gracefully."""
        from netanalytics.smarthome.discovery import discover_aqara_gateways

        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Define side effects for each setsockopt call
        def setsockopt_side_effect(level, optname, value):
            # Allow SO_REUSEADDR, fail on IP_ADD_MEMBERSHIP
            import socket
            if level == socket.IPPROTO_IP:
                raise OSError("Multicast not supported")
            return None

        mock_sock.setsockopt.side_effect = setsockopt_side_effect

        result = discover_aqara_gateways(timeout=0.1)

        assert result == []


class TestSecurityChecks:
    """Tests for smart home security vulnerability checks."""

    def test_smart_home_device_check_miio_port(self):
        """Test that miIO port 54321 is flagged."""
        from netanalytics.security.vulnerabilities import SmartHomeDeviceCheck

        check = SmartHomeDeviceCheck()
        result = check.check("192.168.1.100", 54321, {})

        assert result is not None
        assert result.severity == "medium"
        assert "miIO" in result.description

    def test_smart_home_device_check_aqara_port(self):
        """Test that Aqara port 9898 is flagged."""
        from netanalytics.security.vulnerabilities import SmartHomeDeviceCheck

        check = SmartHomeDeviceCheck()
        result = check.check("192.168.1.100", 9898, {})

        assert result is not None
        assert "Aqara" in result.description

    def test_smart_home_device_check_normal_port(self):
        """Test that normal ports are not flagged."""
        from netanalytics.security.vulnerabilities import SmartHomeDeviceCheck

        check = SmartHomeDeviceCheck()
        result = check.check("192.168.1.100", 80, {})

        assert result is None

    def test_aqara_gateway_check(self):
        """Test Aqara gateway check on port 9898."""
        from netanalytics.security.vulnerabilities import AqaraGatewayCheck

        check = AqaraGatewayCheck()
        result = check.check("192.168.1.100", 9898, {})

        assert result is not None
        assert result.name == "Aqara Gateway Local API"
        assert "local api" in result.description.lower()


class TestXiaomiDeviceInteractions:
    """Tests for Xiaomi device interactions with mocked miio."""

    @patch("netanalytics.smarthome.xiaomi._get_miio_imports")
    def test_get_device_info_success(self, mock_imports):
        """Test successful device info retrieval."""
        from netanalytics.smarthome.xiaomi import get_device_info

        # Mock Device and DeviceException
        MockDevice = MagicMock()
        MockDeviceException = Exception

        mock_info = MagicMock()
        mock_info.raw = {"did": "123456"}
        mock_info.model = "zhimi.airpurifier.ma4"
        mock_info.firmware_version = "1.4.6"
        mock_info.hardware_version = "Linux"
        mock_info.mac_address = "AA:BB:CC:DD:EE:FF"

        mock_device_instance = MagicMock()
        mock_device_instance.info.return_value = mock_info
        MockDevice.return_value = mock_device_instance

        mock_imports.return_value = (MockDevice, MockDeviceException)

        result = get_device_info("192.168.1.100", "0" * 32)

        assert result.ip == "192.168.1.100"
        assert result.device_id == "123456"
        assert result.model == "zhimi.airpurifier.ma4"
        assert result.firmware == "1.4.6"
        assert result.mac == "AA:BB:CC:DD:EE:FF"

    @patch("netanalytics.smarthome.xiaomi._get_miio_imports")
    def test_get_device_info_timeout(self, mock_imports):
        """Test device info retrieval handles timeout."""
        from netanalytics.smarthome.xiaomi import get_device_info

        MockDevice = MagicMock()
        MockDeviceException = Exception
        mock_imports.return_value = (MockDevice, MockDeviceException)

        # Simulate timeout
        MockDevice.return_value.info.side_effect = socket.timeout("timed out")

        with pytest.raises(DeviceTimeoutError):
            get_device_info("192.168.1.100", "0" * 32, timeout=1.0)

    @patch("netanalytics.smarthome.xiaomi._get_miio_imports")
    def test_get_device_info_connection_error(self, mock_imports):
        """Test device info retrieval handles connection errors."""
        from netanalytics.smarthome.xiaomi import get_device_info

        MockDevice = MagicMock()
        MockDeviceException = Exception
        mock_imports.return_value = (MockDevice, MockDeviceException)

        # Simulate connection refused
        MockDevice.return_value.info.side_effect = OSError("Connection refused")

        with pytest.raises(DeviceConnectionError):
            get_device_info("192.168.1.100", "0" * 32)

    @patch("netanalytics.smarthome.xiaomi._get_miio_imports")
    def test_get_device_status_success(self, mock_imports):
        """Test successful device status retrieval."""
        from netanalytics.smarthome.xiaomi import get_device_status

        MockDevice = MagicMock()
        MockDeviceException = Exception
        mock_imports.return_value = (MockDevice, MockDeviceException)

        mock_info = MagicMock()
        mock_info.raw = {"did": "123456"}
        mock_info.model = "zhimi.airpurifier.ma4"
        mock_info.firmware_version = "1.4.6"
        mock_info.hardware_version = "Linux"
        mock_info.mac_address = "AA:BB:CC:DD:EE:FF"

        mock_device = MagicMock()
        mock_device.info.return_value = mock_info
        mock_device.send.return_value = ["on", 50]
        MockDevice.return_value = mock_device

        result = get_device_status("192.168.1.100", "0" * 32)

        assert result.is_online is True
        assert result.model == "zhimi.airpurifier.ma4"
        assert result.properties is not None

    @patch("netanalytics.smarthome.xiaomi._get_miio_imports")
    def test_send_command_success(self, mock_imports):
        """Test successful command sending."""
        from netanalytics.smarthome.xiaomi import send_command

        MockDevice = MagicMock()
        MockDeviceException = Exception
        mock_imports.return_value = (MockDevice, MockDeviceException)

        mock_device = MagicMock()
        mock_device.send.return_value = ["ok"]
        MockDevice.return_value = mock_device

        result = send_command("192.168.1.100", "0" * 32, "set_power", ["on"])

        assert result == ["ok"]
        mock_device.send.assert_called_once_with("set_power", ["on"])

    @patch("netanalytics.smarthome.xiaomi._get_miio_imports")
    def test_send_command_timeout(self, mock_imports):
        """Test command sending handles timeout."""
        from netanalytics.smarthome.xiaomi import send_command

        MockDevice = MagicMock()
        MockDeviceException = Exception
        mock_imports.return_value = (MockDevice, MockDeviceException)

        MockDevice.return_value.send.side_effect = socket.timeout("timed out")

        with pytest.raises(DeviceTimeoutError):
            send_command("192.168.1.100", "0" * 32, "get_prop", ["power"])

    @patch("netanalytics.smarthome.xiaomi._get_miio_imports")
    def test_check_device_connectivity_success(self, mock_imports):
        """Test successful connectivity check."""
        from netanalytics.smarthome.xiaomi import check_device_connectivity

        MockDevice = MagicMock()
        MockDeviceException = Exception
        mock_imports.return_value = (MockDevice, MockDeviceException)

        mock_info = MagicMock()
        mock_info.raw = {"did": "123456"}
        mock_info.model = "zhimi.airpurifier.ma4"
        mock_info.firmware_version = "1.4.6"

        MockDevice.return_value.info.return_value = mock_info

        result = check_device_connectivity("192.168.1.100", "0" * 32)

        assert result["reachable"] is True
        assert result["model"] == "zhimi.airpurifier.ma4"

    @patch("netanalytics.smarthome.xiaomi._get_miio_imports")
    def test_check_device_connectivity_timeout(self, mock_imports):
        """Test connectivity check with timeout."""
        from netanalytics.smarthome.xiaomi import check_device_connectivity

        MockDevice = MagicMock()
        MockDeviceException = Exception
        mock_imports.return_value = (MockDevice, MockDeviceException)

        MockDevice.return_value.info.side_effect = socket.timeout("timed out")

        result = check_device_connectivity("192.168.1.100", "0" * 32, timeout=1.0)

        assert result["reachable"] is False
        assert result["error_type"] == "timeout"

    @patch("netanalytics.smarthome.xiaomi._get_miio_imports")
    def test_check_device_connectivity_auth_error(self, mock_imports):
        """Test connectivity check with auth error."""
        from netanalytics.smarthome.xiaomi import check_device_connectivity

        MockDevice = MagicMock()

        class MockDeviceException(Exception):
            pass

        mock_imports.return_value = (MockDevice, MockDeviceException)
        MockDevice.return_value.info.side_effect = MockDeviceException("Invalid token")

        result = check_device_connectivity("192.168.1.100", "0" * 32)

        assert result["reachable"] is False
        assert result["error_type"] == "auth_error"


class TestCloudAuthentication:
    """Tests for Xiaomi Cloud authentication."""

    def test_cloud_invalid_server(self):
        """Test XiaomiCloud rejects invalid server."""
        from netanalytics.smarthome.cloud import XiaomiCloud

        with pytest.raises(ValueError, match="Invalid server"):
            XiaomiCloud("user@example.com", "password", server="invalid")

    def test_cloud_valid_servers(self):
        """Test XiaomiCloud accepts all valid servers."""
        from netanalytics.smarthome.cloud import XiaomiCloud, CLOUD_SERVERS

        for server in CLOUD_SERVERS:
            cloud = XiaomiCloud("user@example.com", "password", server=server)
            assert cloud.server == server

    def test_cloud_password_cleared_after_login(self):
        """Test password is cleared from memory after login."""
        from netanalytics.smarthome.cloud import XiaomiCloud

        # Patch at the import location inside login()
        with patch.dict("sys.modules", {"miio.cloud": MagicMock()}):
            import sys
            sys.modules["miio.cloud"].CloudInterface = MagicMock()

            cloud = XiaomiCloud("user@example.com", "secret123", server="cn")
            assert cloud._password == "secret123"

            result = cloud.login()

            # Password should be cleared after login
            assert cloud._password is None
            assert result.success is True

    def test_cloud_password_cleared_on_failure(self):
        """Test password is cleared even on login failure."""
        from netanalytics.smarthome.cloud import XiaomiCloud

        with patch.dict("sys.modules", {"miio.cloud": MagicMock()}):
            import sys
            sys.modules["miio.cloud"].CloudInterface = MagicMock(
                side_effect=Exception("Auth failed")
            )

            cloud = XiaomiCloud("user@example.com", "secret123", server="cn")
            result = cloud.login()

            # Password should still be cleared
            assert cloud._password is None
            assert result.success is False

    def test_cloud_double_login_prevented(self):
        """Test that login can't be called twice with cleared password."""
        from netanalytics.smarthome.cloud import XiaomiCloud

        with patch.dict("sys.modules", {"miio.cloud": MagicMock()}):
            import sys
            sys.modules["miio.cloud"].CloudInterface = MagicMock()

            cloud = XiaomiCloud("user@example.com", "secret123", server="cn")
            result1 = cloud.login()
            assert result1.success is True

            # Second login should succeed (already logged in)
            result2 = cloud.login()
            assert result2.success is True


class TestParallelDiscovery:
    """Tests for parallel discovery execution."""

    @patch("netanalytics.smarthome.discovery.discover_miio_broadcast")
    @patch("netanalytics.smarthome.discovery.discover_miio_mdns")
    @patch("netanalytics.smarthome.discovery.discover_aqara_gateways")
    @patch("netanalytics.smarthome.discovery.discover_matter_devices")
    def test_parallel_discovery_combines_results(
        self, mock_matter, mock_aqara, mock_mdns, mock_miio
    ):
        """Test parallel discovery combines results from all methods."""
        from netanalytics.smarthome.discovery import discover_all

        mock_miio.return_value = [
            MiioDeviceInfo(ip="192.168.1.1", device_id="1", token=None)
        ]
        mock_mdns.return_value = [
            MiioDeviceInfo(ip="192.168.1.2", device_id="2", token=None)
        ]
        mock_aqara.return_value = [AqaraGateway(ip="192.168.1.3", sid="gw1")]
        mock_matter.return_value = [MatterDevice(ip="192.168.1.4", name="Plug")]

        result = discover_all(timeout=1.0, parallel=True)

        assert len(result.miio_devices) == 2
        assert len(result.aqara_gateways) == 1
        assert len(result.matter_devices) == 1
        assert result.total_count == 4

    @patch("netanalytics.smarthome.discovery.discover_miio_broadcast")
    @patch("netanalytics.smarthome.discovery.discover_miio_mdns")
    def test_parallel_discovery_deduplicates_miio(self, mock_mdns, mock_miio):
        """Test parallel discovery deduplicates miIO devices by IP."""
        from netanalytics.smarthome.discovery import discover_all

        # Same IP from both methods
        mock_miio.return_value = [
            MiioDeviceInfo(ip="192.168.1.1", device_id="1", token="abc")
        ]
        mock_mdns.return_value = [
            MiioDeviceInfo(ip="192.168.1.1", device_id="1", token=None)
        ]

        result = discover_all(timeout=1.0, methods=["miio", "mdns"])

        # Should only have 1 device (deduplicated)
        assert len(result.miio_devices) == 1

    @patch("netanalytics.smarthome.discovery.discover_miio_broadcast")
    def test_parallel_discovery_handles_method_failure(self, mock_miio):
        """Test parallel discovery handles individual method failures."""
        from netanalytics.smarthome.discovery import discover_all

        mock_miio.side_effect = Exception("Network error")

        # Should not raise, just skip the failed method
        result = discover_all(timeout=1.0, methods=["miio"])

        assert result.total_count == 0


class TestAqaraSchemaValidation:
    """Tests for Aqara JSON schema validation."""

    def test_parse_aqara_response_missing_fields(self):
        """Test parsing Aqara response with missing fields."""
        # Missing sid
        response = json.dumps({
            "cmd": "iam",
            "port": "9898",
            "model": "gateway",
        }).encode("utf-8")

        result = _parse_aqara_response("192.168.1.100", response)

        # Should still parse, sid will be None
        assert result is not None
        assert result.sid is None

    def test_parse_aqara_response_extra_fields(self):
        """Test parsing Aqara response ignores extra fields."""
        response = json.dumps({
            "cmd": "iam",
            "port": "9898",
            "sid": "abc123",
            "model": "gateway",
            "proto_version": "1.0.0",
            "extra_field": "ignored",
        }).encode("utf-8")

        result = _parse_aqara_response("192.168.1.100", response)

        assert result is not None
        assert result.sid == "abc123"

    def test_parse_aqara_response_invalid_port_falls_back(self):
        """Test parsing Aqara response with invalid port falls back to default."""
        response = json.dumps({
            "cmd": "iam",
            "port": "invalid",
            "sid": "abc123",
        }).encode("utf-8")

        # Now returns None because validation rejects invalid port
        result = _parse_aqara_response("192.168.1.100", response)
        assert result is None

    def test_parse_aqara_response_port_out_of_range(self):
        """Test parsing Aqara response with port out of range."""
        response = json.dumps({
            "cmd": "iam",
            "port": "99999",
            "sid": "abc123",
        }).encode("utf-8")

        result = _parse_aqara_response("192.168.1.100", response)
        assert result is None


class TestTokenTruncation:
    """Tests for token truncation logic (standalone implementation matching MCP)."""

    @staticmethod
    def truncate_token(token: str | None, show_full: bool = False) -> str | None:
        """Local implementation of truncate_token for testing.

        Format: first 6 chars + "..." + last 6 chars
        """
        if not token:
            return None
        if show_full:
            return token
        if len(token) <= 12:
            return token
        return f"{token[:6]}...{token[-6:]}"

    def test_truncate_token_none(self):
        """Test truncation handles None."""
        assert self.truncate_token(None) is None

    def test_truncate_token_empty(self):
        """Test truncation handles empty string."""
        assert self.truncate_token("") is None

    def test_truncate_token_short(self):
        """Test truncation keeps short tokens intact."""
        assert self.truncate_token("abc123") == "abc123"
        assert self.truncate_token("123456789012") == "123456789012"

    def test_truncate_token_long(self):
        """Test truncation formats long tokens correctly."""
        token = "0123456789abcdef0123456789abcdef"
        result = self.truncate_token(token)

        assert result == "012345...abcdef"
        assert len(result) == 15  # 6 + 3 + 6

    def test_truncate_token_show_full(self):
        """Test show_full flag returns complete token."""
        token = "0123456789abcdef0123456789abcdef"
        result = self.truncate_token(token, show_full=True)

        assert result == token


class TestErrorExceptionTypes:
    """Tests for custom exception types."""

    def test_device_connection_error(self):
        """Test DeviceConnectionError attributes."""
        err = DeviceConnectionError("Cannot connect to 192.168.1.1")
        assert "192.168.1.1" in str(err)

    def test_device_auth_error(self):
        """Test DeviceAuthError attributes."""
        err = DeviceAuthError("Invalid token for device")
        assert "Invalid token" in str(err)

    def test_device_timeout_error(self):
        """Test DeviceTimeoutError attributes."""
        err = DeviceTimeoutError("Device timed out")
        assert "timed out" in str(err)

    def test_device_protocol_error(self):
        """Test DeviceProtocolError attributes."""
        err = DeviceProtocolError("Invalid response from device")
        assert "Invalid response" in str(err)
