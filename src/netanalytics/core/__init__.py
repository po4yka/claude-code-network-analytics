"""Core module - configuration, exceptions, and utilities."""

from .config import Config, get_config
from .exceptions import (
    NetAnalyticsError,
    ScanError,
    CaptureError,
    PermissionError,
    NetworkError,
    TimeoutError,
)
from .utils import (
    is_root,
    require_root,
    validate_ip,
    validate_network,
    validate_port_range,
    get_interfaces,
    ensure_results_dir,
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
