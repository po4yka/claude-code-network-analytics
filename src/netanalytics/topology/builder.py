"""Network topology graph builder."""

from dataclasses import dataclass
from datetime import datetime

import networkx as nx

from ..core.exceptions import ScanError
from ..core.utils import validate_network, is_root
from ..discovery import arp_scan


@dataclass
class NodeInfo:
    """Information about a network node."""

    ip: str
    mac: str | None
    hostname: str | None
    vendor: str | None
    node_type: str  # "host", "gateway", "unknown"
    services: list[int]

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "node_type": self.node_type,
            "services": self.services,
        }


class TopologyBuilder:
    """Build network topology graphs."""

    def __init__(self):
        self.graph = nx.Graph()
        self.nodes: dict[str, NodeInfo] = {}

    def add_host(
        self,
        ip: str,
        mac: str | None = None,
        hostname: str | None = None,
        vendor: str | None = None,
        node_type: str = "host",
        services: list[int] | None = None,
    ) -> None:
        """Add a host to the topology."""
        self.nodes[ip] = NodeInfo(
            ip=ip,
            mac=mac,
            hostname=hostname,
            vendor=vendor,
            node_type=node_type,
            services=services or [],
        )

        self.graph.add_node(
            ip,
            mac=mac,
            hostname=hostname,
            vendor=vendor,
            node_type=node_type,
            services=services or [],
            label=hostname or ip,
        )

    def add_connection(
        self,
        src: str,
        dst: str,
        weight: float = 1.0,
        connection_type: str = "direct",
    ) -> None:
        """Add a connection between two hosts."""
        self.graph.add_edge(
            src,
            dst,
            weight=weight,
            connection_type=connection_type,
        )

    def discover_from_arp(self, network: str) -> None:
        """Discover hosts using ARP scan."""
        results = arp_scan(network)

        for host in results:
            self.add_host(
                ip=host.ip,
                mac=host.mac,
                hostname=host.hostname,
                vendor=host.vendor,
            )

    def discover_from_pcap(self, pcap_file: str) -> None:
        """Build topology from pcap file analysis."""
        from scapy.all import rdpcap, IP

        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            raise ScanError(f"Failed to read pcap: {pcap_file}", str(e))

        # Track connections
        connections: dict[tuple[str, str], int] = {}

        for packet in packets:
            if packet.haslayer(IP):
                ip = packet.getlayer(IP)
                src, dst = ip.src, ip.dst

                # Add hosts
                if src not in self.nodes:
                    self.add_host(src)
                if dst not in self.nodes:
                    self.add_host(dst)

                # Track connection
                key = tuple(sorted([src, dst]))
                connections[key] = connections.get(key, 0) + 1

        # Add connections with weight based on packet count
        for (src, dst), count in connections.items():
            self.add_connection(src, dst, weight=count)

    def infer_gateway(self) -> str | None:
        """Attempt to identify the gateway node."""
        if not self.graph.nodes():
            return None

        # Gateway is often the node with highest degree
        degrees = dict(self.graph.degree())
        if not degrees:
            return None

        gateway = max(degrees, key=degrees.get)

        # Update node type
        if gateway in self.nodes:
            self.nodes[gateway].node_type = "gateway"
            self.graph.nodes[gateway]["node_type"] = "gateway"

        return gateway

    def get_graph(self) -> nx.Graph:
        """Return the NetworkX graph."""
        return self.graph

    def to_dict(self) -> dict:
        """Export topology to dictionary."""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [
                {
                    "source": u,
                    "target": v,
                    "weight": d.get("weight", 1),
                    "type": d.get("connection_type", "direct"),
                }
                for u, v, d in self.graph.edges(data=True)
            ],
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
        }


def build_topology(
    network: str | None = None,
    pcap_file: str | None = None,
) -> nx.Graph:
    """
    Build network topology from discovery or pcap.

    Args:
        network: Network CIDR to scan (requires root)
        pcap_file: Pcap file to analyze

    Returns:
        NetworkX graph representing the topology
    """
    builder = TopologyBuilder()

    if network:
        if not is_root():
            from ..core.exceptions import PermissionError

            raise PermissionError("Topology discovery", "Requires root privileges for ARP scan")
        builder.discover_from_arp(network)

    if pcap_file:
        builder.discover_from_pcap(pcap_file)

    # Try to infer gateway
    builder.infer_gateway()

    return builder.get_graph()
