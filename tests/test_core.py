"""Tests for core module."""

import pytest
from pathlib import Path

from netanalytics.core.config import Config, ScanConfig, get_config
from netanalytics.core.exceptions import (
    NetAnalyticsError,
    ScanError,
    ValidationError,
)
from netanalytics.core.utils import (
    validate_ip,
    validate_network,
    validate_port_range,
    format_mac,
)


class TestConfig:
    """Test configuration management."""

    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        assert config.results_dir == Path("./results")
        assert config.verbose is False
        assert config.fast_mode is False

    def test_scan_config_defaults(self):
        """Test default scan configuration."""
        config = ScanConfig()
        assert config.default_ports == "1-1000"
        assert config.timeout == 2.0
        assert config.rate_limit == 100


class TestValidation:
    """Test input validation functions."""

    def test_validate_ip_valid(self):
        """Test valid IP addresses."""
        assert str(validate_ip("192.168.1.1")) == "192.168.1.1"
        assert str(validate_ip("10.0.0.1")) == "10.0.0.1"
        assert str(validate_ip("127.0.0.1")) == "127.0.0.1"

    def test_validate_ip_invalid(self):
        """Test invalid IP addresses."""
        with pytest.raises(ValidationError):
            validate_ip("256.1.1.1")
        with pytest.raises(ValidationError):
            validate_ip("not.an.ip")
        with pytest.raises(ValidationError):
            validate_ip("")

    def test_validate_network_valid(self):
        """Test valid network CIDR."""
        net = validate_network("192.168.1.0/24")
        assert str(net) == "192.168.1.0/24"

        net = validate_network("10.0.0.0/8")
        assert str(net) == "10.0.0.0/8"

    def test_validate_network_invalid(self):
        """Test invalid network CIDR."""
        with pytest.raises(ValidationError):
            validate_network("192.168.1.0/33")
        with pytest.raises(ValidationError):
            validate_network("not.a.network")

    def test_validate_port_range_single(self):
        """Test single port validation."""
        ports = validate_port_range("80")
        assert ports == [80]

    def test_validate_port_range_range(self):
        """Test port range validation."""
        ports = validate_port_range("1-10")
        assert ports == list(range(1, 11))

    def test_validate_port_range_list(self):
        """Test port list validation."""
        ports = validate_port_range("22,80,443")
        assert ports == [22, 80, 443]

    def test_validate_port_range_mixed(self):
        """Test mixed port specification."""
        ports = validate_port_range("22,80-82,443")
        assert ports == [22, 80, 81, 82, 443]

    def test_validate_port_range_invalid(self):
        """Test invalid port specifications."""
        with pytest.raises(ValidationError):
            validate_port_range("0")  # Port 0 invalid
        with pytest.raises(ValidationError):
            validate_port_range("65536")  # Too high
        with pytest.raises(ValidationError):
            validate_port_range("100-50")  # Reversed range


class TestFormatting:
    """Test formatting functions."""

    def test_format_mac_colons(self):
        """Test MAC address with colons."""
        assert format_mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"

    def test_format_mac_dashes(self):
        """Test MAC address with dashes."""
        assert format_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"

    def test_format_mac_uppercase(self):
        """Test uppercase MAC address."""
        assert format_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


class TestExceptions:
    """Test custom exceptions."""

    def test_base_exception(self):
        """Test base NetAnalyticsError."""
        err = NetAnalyticsError("Test error", "Details")
        assert str(err) == "Test error: Details"

    def test_scan_error(self):
        """Test ScanError."""
        err = ScanError("Scan failed", "Connection refused")
        assert "Scan failed" in str(err)

    def test_validation_error(self):
        """Test ValidationError."""
        err = ValidationError("Invalid input", "Expected integer")
        assert "Invalid input" in str(err)
