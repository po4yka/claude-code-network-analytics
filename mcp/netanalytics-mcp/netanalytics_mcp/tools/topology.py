"""Topology tools for MCP server - network graph building and analysis."""

import json
from pathlib import Path
from typing import Annotated

from fastmcp import FastMCP

from netanalytics.core.utils import is_root
from netanalytics.core.config import get_config
from netanalytics.topology import build_topology, calculate_metrics, visualize_topology


def register_topology_tools(mcp: FastMCP) -> None:
    """Register topology tools with the MCP server."""

    @mcp.tool()
    def build_network_topology(
        network: Annotated[str | None, "Network CIDR to scan (e.g., '192.168.1.0/24')"] = None,
        pcap_path: Annotated[str | None, "Path to pcap file to build topology from"] = None,
    ) -> dict:
        """Build a network topology graph from scanning or pcap analysis.

        Either provide a network CIDR to perform live discovery (requires root),
        or a pcap file path to build topology from captured traffic.

        Returns nodes (hosts) and edges (connections) as a graph structure.
        """
        if not network and not pcap_path:
            return {
                "error": "Must provide either 'network' for live scan or 'pcap_path' for offline analysis",
                "nodes": [],
                "edges": [],
            }

        if network and not is_root():
            return {
                "error": "Live topology discovery requires root privileges. Run with sudo or use pcap_path.",
                "requires_root": True,
                "nodes": [],
                "edges": [],
            }

        try:
            if pcap_path:
                from netanalytics.topology.builder import TopologyBuilder

                builder = TopologyBuilder()
                graph = builder.from_pcap(pcap_path)
            else:
                graph = build_topology(network)

            # Convert graph to dict
            nodes = []
            for node, attrs in graph.nodes(data=True):
                nodes.append({
                    "id": node,
                    "ip": attrs.get("ip", node),
                    "mac": attrs.get("mac"),
                    "hostname": attrs.get("hostname"),
                    "type": attrs.get("type", "host"),
                })

            edges = []
            for src, dst, attrs in graph.edges(data=True):
                edges.append({
                    "source": src,
                    "target": dst,
                    "weight": attrs.get("weight", 1),
                    "protocol": attrs.get("protocol"),
                })

            return {
                "source": network or pcap_path,
                "node_count": len(nodes),
                "edge_count": len(edges),
                "nodes": nodes,
                "edges": edges,
            }

        except Exception as e:
            return {"error": str(e), "nodes": [], "edges": []}

    @mcp.tool()
    def calculate_topology_metrics(
        topology_data: Annotated[dict, "Topology data from build_network_topology (must have 'nodes' and 'edges')"],
    ) -> dict:
        """Calculate network topology metrics.

        Computes centrality measures (degree, betweenness, closeness),
        clustering coefficients, and community detection.

        Helps identify critical nodes, potential bottlenecks, and network segments.
        """
        if not topology_data.get("nodes") or not topology_data.get("edges"):
            return {"error": "Invalid topology data. Must have 'nodes' and 'edges'.", "metrics": {}}

        try:
            import networkx as nx

            # Rebuild graph from data
            graph = nx.Graph()

            for node in topology_data["nodes"]:
                graph.add_node(node["id"], **{k: v for k, v in node.items() if k != "id"})

            for edge in topology_data["edges"]:
                graph.add_edge(
                    edge["source"],
                    edge["target"],
                    weight=edge.get("weight", 1),
                    protocol=edge.get("protocol"),
                )

            # Calculate metrics
            metrics = calculate_metrics(graph)

            return {
                "node_count": graph.number_of_nodes(),
                "edge_count": graph.number_of_edges(),
                "metrics": metrics.to_dict(),
            }

        except Exception as e:
            return {"error": str(e), "metrics": {}}

    @mcp.tool()
    def export_topology(
        topology_data: Annotated[dict, "Topology data from build_network_topology"],
        format: Annotated[str, "Export format: 'graphml', 'gexf', 'json', or 'png' (default: json)"] = "json",
        output_path: Annotated[str | None, "Output file path (auto-generated if not provided)"] = None,
    ) -> dict:
        """Export network topology to various formats.

        Supported formats:
        - graphml: For Gephi, yEd, Cytoscape
        - gexf: For Gephi (includes dynamics)
        - json: D3.js compatible JSON
        - png: Image visualization

        Returns the path to the exported file.
        """
        if not topology_data.get("nodes"):
            return {"error": "Invalid topology data. Must have 'nodes'.", "path": None}

        try:
            import networkx as nx

            # Rebuild graph
            graph = nx.Graph()

            for node in topology_data["nodes"]:
                graph.add_node(node["id"], **{k: v for k, v in node.items() if k != "id"})

            for edge in topology_data.get("edges", []):
                graph.add_edge(
                    edge["source"],
                    edge["target"],
                    weight=edge.get("weight", 1),
                )

            # Determine output path
            config = get_config()
            if output_path:
                path = Path(output_path)
            else:
                config.results_dir.mkdir(parents=True, exist_ok=True)
                path = config.results_dir / f"topology.{format}"

            # Export based on format
            if format == "graphml":
                nx.write_graphml(graph, str(path))
            elif format == "gexf":
                nx.write_gexf(graph, str(path))
            elif format == "json":
                data = {
                    "nodes": topology_data["nodes"],
                    "edges": topology_data.get("edges", []),
                }
                with open(path, "w") as f:
                    json.dump(data, f, indent=2)
            elif format == "png":
                visualize_topology(graph, output_file=str(path), show=False)
            else:
                return {"error": f"Unknown format: {format}. Use graphml, gexf, json, or png.", "path": None}

            return {
                "format": format,
                "path": str(path),
                "node_count": graph.number_of_nodes(),
                "edge_count": graph.number_of_edges(),
            }

        except Exception as e:
            return {"error": str(e), "path": None}
