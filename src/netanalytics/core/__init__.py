"""Core module - configuration, exceptions, and utilities."""

from .config import Config, get_config
from .exceptions import (
    CaptureError,
    NetAnalyticsError,
    NetworkError,
    PermissionError,
    ScanError,
    TimeoutError,
)
from .utils import (
    ensure_results_dir,
    get_interfaces,
    is_root,
    require_root,
    validate_ip,
    validate_network,
    validate_port_range,
)

__all__ = [
    "Config",
    "get_config",
    "NetAnalyticsError",
    "ScanError",
    "CaptureError",
    "PermissionError",
    "NetworkError",
    "TimeoutError",
    "is_root",
    "require_root",
    "validate_ip",
    "validate_network",
    "validate_port_range",
    "get_interfaces",
    "ensure_results_dir",
]
