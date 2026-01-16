"""Smart home tools for MCP server - Xiaomi/Aqara/Matter device discovery and control."""

from typing import Annotated

from fastmcp import FastMCP


def truncate_token(token: str | None, show_full: bool = False) -> str | None:
    """Truncate token for safe display in MCP responses.

    Format: first 6 chars + "..." + last 6 chars
    Example: "abc123...xyz789"

    Args:
        token: Full token string.
        show_full: If True, return full token without truncation.

    Returns:
        Truncated token or None if token is None/empty.
    """
    if not token:
        return None
    if show_full:
        return token
    if len(token) <= 12:
        return token
    return f"{token[:6]}...{token[-6:]}"


def register_smarthome_tools(mcp: FastMCP) -> None:
    """Register smart home tools with the MCP server."""

    @mcp.tool()
    def discover_smart_home_devices(
        method: Annotated[
            str,
            "Discovery method: 'all', 'miio', 'mdns', 'aqara', 'matter' (default: all)",
        ] = "all",
        timeout: Annotated[float, "Discovery timeout in seconds (default: 5.0)"] = 5.0,
        show_full_tokens: Annotated[
            bool,
            "Show full tokens instead of truncated (default: false for security)",
        ] = False,
    ) -> dict:
        """Discover Xiaomi/Aqara/Matter smart home devices on the local network.

        Supports multiple discovery methods:
        - miio: UDP broadcast discovery for Xiaomi WiFi devices
        - mdns: mDNS service discovery for miIO devices
        - aqara: Multicast discovery for Aqara Zigbee gateways
        - matter: mDNS discovery for Matter-compatible devices
        - all: All methods combined

        Returns device IPs, IDs, models, and tokens (if exposed).
        Note: Most devices don't expose tokens after initial setup.
        Use cloud_tokens to retrieve tokens from your Xiaomi account.

        SECURITY: Tokens are truncated by default. Use show_full_tokens=true
        only when you need to use the token for device control.
        """
        try:
            from netanalytics.smarthome import discover_all
        except ImportError:
            return {
                "error": "Smart home module not available. Install python-miio and zeroconf.",
                "devices": [],
            }

        methods = None if method == "all" else [method]

        try:
            result = discover_all(timeout=timeout, methods=methods)

            return {
                "method": method,
                "total_count": result.total_count,
                "tokens_truncated": not show_full_tokens,
                "miio_devices": [
                    {
                        "ip": d.ip,
                        "device_id": d.device_id,
                        "model": d.model,
                        "token": truncate_token(d.token, show_full_tokens),
                        "firmware": d.firmware,
                        "mac": d.mac,
                    }
                    for d in result.miio_devices
                ],
                "aqara_gateways": [
                    {
                        "ip": g.ip,
                        "sid": g.sid,
                        "model": g.model,
                        "proto_version": g.proto_version,
                    }
                    for g in result.aqara_gateways
                ],
                "matter_devices": [
                    {
                        "ip": m.ip,
                        "name": m.name,
                        "port": m.port,
                        "vendor_id": m.vendor_id,
                        "product_id": m.product_id,
                    }
                    for m in result.matter_devices
                ],
            }

        except Exception as e:
            return {"error": str(e), "devices": []}

    @mcp.tool()
    def get_smart_device_info(
        ip: Annotated[str, "Device IP address"],
        token: Annotated[str, "Device token (32 hex characters)"],
    ) -> dict:
        """Get detailed information from a Xiaomi smart device.

        Requires the device token which can be obtained from:
        - fetch_cloud_tokens (from Xiaomi Cloud account)
        - discover_smart_home_devices (only for uninitialized devices)

        Returns device model, firmware version, hardware version, and MAC address.
        """
        try:
            from netanalytics.smarthome import get_device_info, validate_token
        except ImportError:
            return {"error": "Smart home module not available. Install python-miio."}

        if not validate_token(token):
            return {"error": "Invalid token format. Token must be 32 hex characters."}

        try:
            info = get_device_info(ip, token)

            return {
                "ip": info.ip,
                "device_id": info.device_id,
                "model": info.model,
                "firmware": info.firmware,
                "hardware": info.hardware,
                "mac": info.mac,
                "raw_info": info.raw_info,
            }

        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    def check_smart_device_connectivity(
        ip: Annotated[str, "Device IP address"],
        token: Annotated[str, "Device token (32 hex characters)"],
    ) -> dict:
        """Check if a Xiaomi smart device is reachable and the token is valid.

        Returns connectivity status and basic device info if successful.
        Use this to verify a token works before using it for other operations.
        """
        try:
            from netanalytics.smarthome import check_device_connectivity, validate_token
        except ImportError:
            return {
                "reachable": False,
                "error": "Smart home module not available. Install python-miio.",
            }

        if not validate_token(token):
            return {
                "reachable": False,
                "error": "Invalid token format. Token must be 32 hex characters.",
            }

        return check_device_connectivity(ip, token)

    @mcp.tool()
    def fetch_cloud_tokens(
        username: Annotated[str, "Xiaomi account email or phone number"],
        password: Annotated[str, "Xiaomi account password"],
        server: Annotated[
            str,
            "Cloud server region: cn, de, us, ru, tw, sg, in (default: cn)",
        ] = "cn",
        show_full_tokens: Annotated[
            bool,
            "Show full tokens instead of truncated (default: false for security)",
        ] = False,
    ) -> dict:
        """Retrieve device tokens from Xiaomi Cloud account.

        This authenticates with your Xiaomi account and fetches all registered
        devices along with their tokens. Tokens are required to control devices locally.

        Server regions:
        - cn: China (default)
        - de: Europe (Germany)
        - us: United States
        - ru: Russia
        - tw: Taiwan
        - sg: Singapore
        - in: India

        WARNING: This transmits credentials to Xiaomi's servers.
        Tokens are sensitive - store them securely.

        SECURITY: Tokens are truncated by default. Use show_full_tokens=true
        only when you need to use the token for device control.
        """
        try:
            from netanalytics.smarthome import fetch_cloud_tokens as _fetch_tokens
        except ImportError:
            return {
                "success": False,
                "error": "Smart home module not available. Install python-miio.",
                "devices": [],
            }

        result = _fetch_tokens(username, password, server)

        # Truncate tokens in response for security
        if result.get("success") and not show_full_tokens:
            result["tokens_truncated"] = True
            for device in result.get("devices", []):
                if "token" in device:
                    device["token"] = truncate_token(device["token"], show_full_tokens)
        elif result.get("success"):
            result["tokens_truncated"] = False

        return result

    @mcp.tool()
    def send_smart_device_command(
        ip: Annotated[str, "Device IP address"],
        token: Annotated[str, "Device token (32 hex characters)"],
        method: Annotated[str, "miIO method name (e.g., 'get_prop', 'set_power')"],
        params: Annotated[
            str,
            "JSON-encoded parameters (e.g., '[\"power\"]' or '[]')",
        ] = "[]",
    ) -> dict:
        """Send a raw miIO command to a Xiaomi smart device.

        This allows executing device-specific commands using the miIO protocol.
        Common methods vary by device type:

        - get_prop: Get device properties
        - set_power: Turn on/off (params: ["on"] or ["off"])
        - set_bright: Set brightness (params: [1-100])

        Refer to python-miio documentation for device-specific commands.
        """
        try:
            from netanalytics.smarthome import send_command, validate_token
        except ImportError:
            return {"error": "Smart home module not available. Install python-miio."}

        if not validate_token(token):
            return {"error": "Invalid token format. Token must be 32 hex characters."}

        import json

        try:
            params_list = json.loads(params)
            if not isinstance(params_list, list):
                return {"error": "Params must be a JSON array."}
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON params: {e}"}

        try:
            result = send_command(ip, token, method, params_list)
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    def list_cloud_server_regions() -> dict:
        """List available Xiaomi Cloud server regions.

        Returns the available server region codes and their descriptions.
        Use these codes with fetch_cloud_tokens.
        """
        try:
            from netanalytics.smarthome import list_cloud_servers
        except ImportError:
            return {
                "error": "Smart home module not available.",
                "servers": {
                    "cn": "China",
                    "de": "Europe (Germany)",
                    "us": "United States",
                    "ru": "Russia",
                    "tw": "Taiwan",
                    "sg": "Singapore",
                    "in": "India",
                },
            }

        return {"servers": list_cloud_servers()}
