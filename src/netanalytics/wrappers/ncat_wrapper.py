"""Wrapper for ncat (Netcat) utility."""

import contextlib
import socket
import subprocess
from dataclasses import dataclass

from ..core.exceptions import DependencyError, NetworkError
from ..core.utils import check_dependency


@dataclass
class BannerResult:
    """Result of banner grabbing."""

    host: str
    port: int
    banner: str | None
    success: bool
    error: str | None

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "banner": self.banner,
            "success": self.success,
            "error": self.error,
        }


class NcatClient:
    """Wrapper for ncat network utility."""

    def __init__(self) -> None:
        self.has_ncat = check_dependency("ncat")
        self.has_nc = check_dependency("nc")

        if not self.has_ncat and not self.has_nc:
            raise DependencyError(
                "ncat",
                "Install with: brew install nmap (includes ncat) or apt install ncat",
            )

    def _get_nc_command(self) -> str:
        """Get available netcat command."""
        return "ncat" if self.has_ncat else "nc"

    def grab_banner(
        self,
        host: str,
        port: int,
        timeout: float = 5.0,
        send_data: bytes | None = None,
    ) -> BannerResult:
        """
        Grab banner from a service.

        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout
            send_data: Data to send to trigger response

        Returns:
            BannerResult with banner data
        """
        # Use socket directly for better control
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((host, port))

            # Try to receive initial banner
            banner = None
            try:
                sock.setblocking(False)
                import select

                ready = select.select([sock], [], [], 2.0)
                if ready[0]:
                    banner = sock.recv(4096).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

            # If no banner and we have data to send, try that
            if not banner and send_data:
                sock.setblocking(True)
                sock.settimeout(timeout)
                sock.send(send_data)
                with contextlib.suppress(Exception):
                    banner = sock.recv(4096).decode("utf-8", errors="ignore").strip()

            # Try HTTP if still no banner
            if not banner:
                sock.setblocking(True)
                sock.settimeout(timeout)
                sock.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                with contextlib.suppress(Exception):
                    banner = sock.recv(4096).decode("utf-8", errors="ignore").strip()

            return BannerResult(
                host=host,
                port=port,
                banner=banner if banner else None,
                success=True,
                error=None,
            )

        except TimeoutError:
            return BannerResult(
                host=host,
                port=port,
                banner=None,
                success=False,
                error="Connection timeout",
            )
        except OSError as e:
            return BannerResult(
                host=host,
                port=port,
                banner=None,
                success=False,
                error=str(e),
            )
        finally:
            sock.close()

    def connect(
        self,
        host: str,
        port: int,
        timeout: float = 10.0,
    ) -> subprocess.Popen:
        """
        Open interactive connection to host:port.

        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout

        Returns:
            Subprocess handle for interactive use
        """
        nc_cmd = self._get_nc_command()
        cmd = [nc_cmd, "-v", host, str(port)]

        if self.has_ncat:
            cmd.extend(["-w", str(int(timeout))])

        try:
            return subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception as e:
            raise NetworkError(f"Failed to connect to {host}:{port}", str(e)) from e

    def send_receive(
        self,
        host: str,
        port: int,
        data: bytes,
        timeout: float = 5.0,
    ) -> bytes:
        """
        Send data and receive response.

        Args:
            host: Target host
            port: Target port
            data: Data to send
            timeout: Operation timeout

        Returns:
            Response data
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((host, port))
            sock.send(data)
            response = sock.recv(8192)
            return response
        except OSError as e:
            raise NetworkError(f"Send/receive failed to {host}:{port}", str(e)) from e
        finally:
            sock.close()

    def port_check(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """
        Check if a port is open.

        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout

        Returns:
            True if port is open
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((host, port))
            return result == 0
        finally:
            sock.close()

    def listen(
        self,
        port: int,
        timeout: float = 60.0,
    ) -> subprocess.Popen:
        """
        Start listening on a port.

        Args:
            port: Port to listen on
            timeout: Listen timeout

        Returns:
            Subprocess handle
        """
        nc_cmd = self._get_nc_command()
        cmd = [nc_cmd, "-l", "-p", str(port)]

        if self.has_ncat:
            cmd.extend(["-w", str(int(timeout))])

        try:
            return subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception as e:
            raise NetworkError(f"Failed to listen on port {port}", str(e)) from e
