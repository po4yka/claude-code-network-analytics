"""MCP Resources for Network Analytics Toolkit."""

import json

from fastmcp import FastMCP

from netanalytics.core.config import get_config
from netanalytics.core.utils import get_interfaces


def register_resources(mcp: FastMCP) -> None:
    """Register MCP resources."""

    @mcp.resource("netanalytics://config")
    def get_current_config() -> str:
        """Get current netanalytics configuration."""
        config = get_config()
        return json.dumps({
            "results_dir": str(config.results_dir),
            "verbose": config.verbose,
            "fast_mode": config.fast_mode,
            "rate_limit": config.rate_limit,
        }, indent=2)

    @mcp.resource("netanalytics://interfaces")
    def get_network_interfaces() -> str:
        """Get available network interfaces."""
        interfaces = get_interfaces()
        return json.dumps(interfaces, indent=2)

    @mcp.resource("netanalytics://results/{filename}")
    def get_result_file(filename: str) -> str:
        """Get contents of a result file."""
        config = get_config()
        file_path = config.results_dir / filename

        # Security: prevent directory traversal
        try:
            resolved = file_path.resolve()
            results_resolved = config.results_dir.resolve()
            if not str(resolved).startswith(str(results_resolved)):
                return json.dumps({"error": "Access denied: path outside results directory"})
        except Exception:
            return json.dumps({"error": "Invalid path"})

        if not file_path.exists():
            return json.dumps({"error": f"File not found: {filename}"})

        if not file_path.is_file():
            return json.dumps({"error": f"Not a file: {filename}"})

        # Read file based on type
        suffix = file_path.suffix.lower()
        if suffix == ".json":
            with open(file_path) as f:
                return f.read()
        elif suffix in (".pcap", ".pcapng", ".cap"):
            return json.dumps({
                "type": "pcap",
                "path": str(file_path),
                "size_bytes": file_path.stat().st_size,
                "message": "Binary pcap file - use analyze_pcap_file tool to analyze",
            })
        else:
            # Return first 10KB of text files
            with open(file_path) as f:
                content = f.read(10240)
                truncated = len(content) == 10240
            return json.dumps({
                "content": content,
                "truncated": truncated,
            })

    @mcp.resource("netanalytics://results")
    def list_results() -> str:
        """List all result files."""
        config = get_config()
        results_dir = config.results_dir

        files = []
        if results_dir.exists():
            for f in results_dir.iterdir():
                if f.is_file():
                    files.append({
                        "name": f.name,
                        "size_bytes": f.stat().st_size,
                        "modified": f.stat().st_mtime,
                    })

        return json.dumps({
            "results_dir": str(results_dir),
            "files": sorted(files, key=lambda x: x["modified"], reverse=True),
        }, indent=2)
