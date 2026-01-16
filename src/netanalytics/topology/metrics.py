"""Network topology metrics and analysis using NetworkX."""

from dataclasses import dataclass

import networkx as nx


@dataclass
class TopologyMetrics:
    """Network topology metrics."""

    node_count: int
    edge_count: int
    density: float
    average_degree: float
    clustering_coefficient: float
    connected_components: int
    diameter: int | None
    average_path_length: float | None
    centrality: dict[str, dict[str, float]]
    communities: list[set[str]]
    hub_nodes: list[str]
    bridge_nodes: list[str]

    def to_dict(self) -> dict:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "density": round(self.density, 4),
            "average_degree": round(self.average_degree, 2),
            "clustering_coefficient": round(self.clustering_coefficient, 4),
            "connected_components": self.connected_components,
            "diameter": self.diameter,
            "average_path_length": (
                round(self.average_path_length, 2) if self.average_path_length else None
            ),
            "centrality": {
                measure: {node: round(val, 4) for node, val in values.items()}
                for measure, values in self.centrality.items()
            },
            "communities": [list(c) for c in self.communities],
            "hub_nodes": self.hub_nodes,
            "bridge_nodes": self.bridge_nodes,
        }

    def __str__(self) -> str:
        lines = [
            f"Nodes: {self.node_count}",
            f"Edges: {self.edge_count}",
            f"Density: {self.density:.4f}",
            f"Average Degree: {self.average_degree:.2f}",
            f"Clustering Coefficient: {self.clustering_coefficient:.4f}",
            f"Connected Components: {self.connected_components}",
        ]

        if self.diameter:
            lines.append(f"Diameter: {self.diameter}")
        if self.average_path_length:
            lines.append(f"Average Path Length: {self.average_path_length:.2f}")

        if self.hub_nodes:
            lines.append(f"\nHub Nodes: {', '.join(self.hub_nodes[:5])}")

        if self.bridge_nodes:
            lines.append(f"Bridge Nodes: {', '.join(self.bridge_nodes[:5])}")

        if self.communities:
            lines.append(f"\nCommunities Detected: {len(self.communities)}")

        return "\n".join(lines)


def calculate_centrality(graph: nx.Graph) -> dict[str, dict[str, float]]:
    """Calculate various centrality measures."""
    centrality: dict[str, dict[str, float]] = {}

    if not graph.nodes():
        return centrality

    # Degree centrality
    centrality["degree"] = nx.degree_centrality(graph)

    # Betweenness centrality
    try:
        centrality["betweenness"] = nx.betweenness_centrality(graph)
    except Exception:
        centrality["betweenness"] = {}

    # Closeness centrality
    try:
        centrality["closeness"] = nx.closeness_centrality(graph)
    except Exception:
        centrality["closeness"] = {}

    # Eigenvector centrality (may fail for disconnected graphs)
    try:
        centrality["eigenvector"] = nx.eigenvector_centrality(graph, max_iter=1000)
    except Exception:
        centrality["eigenvector"] = {}

    # PageRank
    try:
        centrality["pagerank"] = nx.pagerank(graph)
    except Exception:
        centrality["pagerank"] = {}

    return centrality


def detect_communities(graph: nx.Graph) -> list[set[str]]:
    """Detect communities using various algorithms."""
    if not graph.nodes() or graph.number_of_nodes() < 2:
        return []

    communities = []

    # Try Louvain algorithm (if available)
    try:
        from networkx.algorithms.community import louvain_communities

        communities = list(louvain_communities(graph))
    except (ImportError, Exception):
        pass

    # Fallback to greedy modularity
    if not communities:
        try:
            from networkx.algorithms.community import greedy_modularity_communities

            communities = list(greedy_modularity_communities(graph))
        except Exception:
            pass

    # Final fallback: connected components
    if not communities:
        communities = [set(c) for c in nx.connected_components(graph)]

    return communities


def find_hub_nodes(graph: nx.Graph, top_n: int = 5) -> list[str]:
    """Find hub nodes (high degree centrality)."""
    if not graph.nodes():
        return []

    degree_cent = nx.degree_centrality(graph)
    sorted_nodes = sorted(degree_cent.items(), key=lambda x: -x[1])
    return [node for node, _ in sorted_nodes[:top_n]]


def find_bridge_nodes(graph: nx.Graph) -> list[str]:
    """Find bridge nodes (articulation points)."""
    if not graph.nodes():
        return []

    try:
        return list(nx.articulation_points(graph))
    except Exception:
        return []


def calculate_metrics(graph: nx.Graph) -> TopologyMetrics:
    """
    Calculate comprehensive topology metrics.

    Args:
        graph: NetworkX graph

    Returns:
        TopologyMetrics with all calculated metrics
    """
    if not graph.nodes():
        return TopologyMetrics(
            node_count=0,
            edge_count=0,
            density=0.0,
            average_degree=0.0,
            clustering_coefficient=0.0,
            connected_components=0,
            diameter=None,
            average_path_length=None,
            centrality={},
            communities=[],
            hub_nodes=[],
            bridge_nodes=[],
        )

    node_count = graph.number_of_nodes()
    edge_count = graph.number_of_edges()

    # Basic metrics
    density = nx.density(graph)
    average_degree = sum(dict(graph.degree()).values()) / node_count if node_count > 0 else 0

    # Clustering
    try:
        clustering = nx.average_clustering(graph)
    except Exception:
        clustering = 0.0

    # Connected components
    components = list(nx.connected_components(graph))
    num_components = len(components)

    # Diameter and average path length (only for connected graphs)
    diameter = None
    avg_path_length = None
    if num_components == 1 and node_count > 1:
        try:
            diameter = nx.diameter(graph)
            avg_path_length = nx.average_shortest_path_length(graph)
        except Exception:
            pass

    # Centrality measures
    centrality = calculate_centrality(graph)

    # Community detection
    communities = detect_communities(graph)

    # Hub and bridge nodes
    hub_nodes = find_hub_nodes(graph)
    bridge_nodes = find_bridge_nodes(graph)

    return TopologyMetrics(
        node_count=node_count,
        edge_count=edge_count,
        density=density,
        average_degree=average_degree,
        clustering_coefficient=clustering,
        connected_components=num_components,
        diameter=diameter,
        average_path_length=avg_path_length,
        centrality=centrality,
        communities=communities,
        hub_nodes=hub_nodes,
        bridge_nodes=bridge_nodes,
    )
