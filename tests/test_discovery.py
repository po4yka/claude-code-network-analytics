"""Tests for discovery module."""

import pytest
from unittest.mock import patch, MagicMock

from netanalytics.discovery.port_scan import (
    PortState,
    PortResult,
    ScanResult,
    get_service_name,
    COMMON_SERVICES,
)


class TestPortState:
    """Test port state enumeration."""

    def test_port_states(self):
        """Test all port states."""
        assert PortState.OPEN.value == "open"
        assert PortState.CLOSED.value == "closed"
        assert PortState.FILTERED.value == "filtered"


class TestServiceNames:
    """Test service name lookup."""

    def test_common_services(self):
        """Test common service port mapping."""
        assert get_service_name(22) == "ssh"
        assert get_service_name(80) == "http"
        assert get_service_name(443) == "https"
        assert get_service_name(3306) == "mysql"

    def test_unknown_port(self):
        """Test unknown port returns None."""
        assert get_service_name(12345) is None


class TestPortResult:
    """Test PortResult dataclass."""

    def test_port_result_creation(self):
        """Test creating PortResult."""
        result = PortResult(
            port=80,
            state=PortState.OPEN,
            service="http",
            banner="Apache",
            response_time=0.05,
        )
        assert result.port == 80
        assert result.state == PortState.OPEN

    def test_port_result_to_dict(self):
        """Test PortResult serialization."""
        result = PortResult(
            port=22,
            state=PortState.OPEN,
            service="ssh",
            banner="OpenSSH",
            response_time=0.02,
        )
        data = result.to_dict()
        assert data["port"] == 22
        assert data["state"] == "open"
        assert data["service"] == "ssh"


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_get_open_ports(self):
        """Test filtering open ports."""
        from datetime import datetime

        ports = [
            PortResult(22, PortState.OPEN, "ssh", None, 0.01),
            PortResult(23, PortState.CLOSED, "telnet", None, 0.01),
            PortResult(80, PortState.OPEN, "http", None, 0.01),
            PortResult(443, PortState.FILTERED, "https", None, None),
        ]

        result = ScanResult(
            target="192.168.1.1",
            ports=ports,
            scan_type="connect",
            start_time=datetime.now(),
            end_time=datetime.now(),
            open_count=2,
            closed_count=1,
            filtered_count=1,
        )

        open_ports = result.get_open_ports()
        assert len(open_ports) == 2
        assert all(p.state == PortState.OPEN for p in open_ports)
