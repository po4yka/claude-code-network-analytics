"""Tests for topology module."""

import pytest
import networkx as nx

from netanalytics.topology.builder import TopologyBuilder, NodeInfo
from netanalytics.topology.metrics import (
    calculate_metrics,
    calculate_centrality,
    find_hub_nodes,
    TopologyMetrics,
)


class TestTopologyBuilder:
    """Test topology graph building."""

    def test_add_host(self):
        """Test adding a host to topology."""
        builder = TopologyBuilder()
        builder.add_host(
            ip="192.168.1.1",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="host1",
        )

        assert "192.168.1.1" in builder.nodes
        assert builder.graph.number_of_nodes() == 1

    def test_add_connection(self):
        """Test adding a connection."""
        builder = TopologyBuilder()
        builder.add_host("192.168.1.1")
        builder.add_host("192.168.1.2")
        builder.add_connection("192.168.1.1", "192.168.1.2")

        assert builder.graph.number_of_edges() == 1
        assert builder.graph.has_edge("192.168.1.1", "192.168.1.2")

    def test_to_dict(self):
        """Test topology export to dict."""
        builder = TopologyBuilder()
        builder.add_host("192.168.1.1", hostname="router")
        builder.add_host("192.168.1.2", hostname="server")
        builder.add_connection("192.168.1.1", "192.168.1.2")

        data = builder.to_dict()
        assert data["node_count"] == 2
        assert data["edge_count"] == 1
        assert len(data["nodes"]) == 2


class TestNodeInfo:
    """Test NodeInfo dataclass."""

    def test_node_info_creation(self):
        """Test creating NodeInfo."""
        node = NodeInfo(
            ip="192.168.1.1",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="test-host",
            vendor="Cisco",
            node_type="gateway",
            services=[22, 80, 443],
        )
        assert node.ip == "192.168.1.1"
        assert node.node_type == "gateway"

    def test_node_info_to_dict(self):
        """Test NodeInfo serialization."""
        node = NodeInfo(
            ip="10.0.0.1",
            mac=None,
            hostname=None,
            vendor=None,
            node_type="host",
            services=[],
        )
        data = node.to_dict()
        assert data["ip"] == "10.0.0.1"
        assert data["node_type"] == "host"


class TestTopologyMetrics:
    """Test topology metrics calculation."""

    def test_empty_graph(self):
        """Test metrics on empty graph."""
        graph = nx.Graph()
        metrics = calculate_metrics(graph)
        assert metrics.node_count == 0
        assert metrics.edge_count == 0

    def test_simple_graph(self):
        """Test metrics on simple graph."""
        graph = nx.Graph()
        graph.add_nodes_from(["A", "B", "C"])
        graph.add_edges_from([("A", "B"), ("B", "C")])

        metrics = calculate_metrics(graph)
        assert metrics.node_count == 3
        assert metrics.edge_count == 2
        assert metrics.connected_components == 1

    def test_centrality_calculation(self):
        """Test centrality measures."""
        graph = nx.star_graph(4)  # Star with center node 0
        centrality = calculate_centrality(graph)

        assert "degree" in centrality
        assert "betweenness" in centrality
        # Center node should have highest degree centrality
        assert centrality["degree"][0] > centrality["degree"][1]

    def test_hub_detection(self):
        """Test hub node detection."""
        graph = nx.star_graph(5)  # Node 0 is the hub
        hubs = find_hub_nodes(graph, top_n=1)
        assert 0 in hubs

    def test_metrics_to_dict(self):
        """Test metrics serialization."""
        graph = nx.path_graph(3)  # Simple path: 0-1-2
        metrics = calculate_metrics(graph)
        data = metrics.to_dict()

        assert "node_count" in data
        assert "edge_count" in data
        assert "density" in data
        assert "centrality" in data
