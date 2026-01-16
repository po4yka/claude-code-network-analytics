"""Custom exceptions for Network Analytics Toolkit."""


class NetAnalyticsError(Exception):
    """Base exception for all Network Analytics errors."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        if self.details:
            return f"{self.message}: {self.details}"
        return self.message


class ScanError(NetAnalyticsError):
    """Error during network scanning operations."""

    pass


class CaptureError(NetAnalyticsError):
    """Error during traffic capture operations."""

    pass


class PermissionError(NetAnalyticsError):
    """Insufficient permissions for operation."""

    def __init__(self, operation: str, details: str | None = None):
        message = f"Insufficient permissions for {operation}"
        super().__init__(message, details)
        self.operation = operation


class NetworkError(NetAnalyticsError):
    """Network-related error (unreachable host, interface issue)."""

    pass


class TimeoutError(NetAnalyticsError):
    """Operation timed out."""

    def __init__(self, operation: str, timeout: float):
        message = f"{operation} timed out after {timeout}s"
        super().__init__(message)
        self.operation = operation
        self.timeout = timeout


class ValidationError(NetAnalyticsError):
    """Input validation error."""

    pass


class DependencyError(NetAnalyticsError):
    """Missing external dependency."""

    def __init__(self, dependency: str, install_hint: str | None = None):
        message = f"Missing dependency: {dependency}"
        super().__init__(message, install_hint)
        self.dependency = dependency
        self.install_hint = install_hint
