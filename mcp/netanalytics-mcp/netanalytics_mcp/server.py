"""Main MCP server for Network Analytics Toolkit.

This server exposes the netanalytics Python API via the Model Context Protocol,
enabling AI assistants to perform network discovery, scanning, traffic analysis,
topology mapping, and security assessment.
"""

from fastmcp import FastMCP

from .resources import register_resources
from .tools.discovery import register_discovery_tools
from .tools.reporting import register_reporting_tools
from .tools.security import register_security_tools
from .tools.smarthome import register_smarthome_tools
from .tools.topology import register_topology_tools
from .tools.traffic import register_traffic_tools

# Create the MCP server
mcp = FastMCP(
    "netanalytics",
    description=(
        "Network Analytics Toolkit - Discovery, scanning, traffic analysis, "
        "topology mapping, and security assessment"
    ),
)

# Register all tool modules
register_discovery_tools(mcp)
register_traffic_tools(mcp)
register_topology_tools(mcp)
register_security_tools(mcp)
register_smarthome_tools(mcp)
register_reporting_tools(mcp)
register_resources(mcp)


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
