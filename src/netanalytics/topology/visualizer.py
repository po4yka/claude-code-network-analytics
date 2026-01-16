"""Network topology visualization using Matplotlib."""

from typing import Any, cast

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import networkx as nx

from ..core.config import get_config

# Color scheme for node types
NODE_COLORS = {
    "gateway": "#e74c3c",  # Red
    "host": "#3498db",  # Blue
    "server": "#2ecc71",  # Green
    "unknown": "#95a5a6",  # Gray
}


class TopologyVisualizer:
    """Visualize network topology graphs."""

    def __init__(self, graph: nx.Graph):
        self.graph = graph
        self.config = get_config().topology

    def _get_layout(self, layout: str) -> dict[Any, tuple[float, float]]:
        """Get node positions based on layout algorithm."""
        layout_result: Any
        if layout == "spring":
            layout_result = nx.spring_layout(self.graph, k=2, iterations=50)
        elif layout == "circular":
            layout_result = nx.circular_layout(self.graph)
        elif layout == "shell":
            layout_result = nx.shell_layout(self.graph)
        elif layout == "kamada_kawai":
            layout_result = nx.kamada_kawai_layout(self.graph)
        else:
            layout_result = nx.spring_layout(self.graph)
        return cast(dict[Any, tuple[float, float]], layout_result)

    def _get_node_colors(self) -> list[str]:
        """Get colors for each node based on type."""
        colors = []
        for node in self.graph.nodes():
            node_type = self.graph.nodes[node].get("node_type", "unknown")
            colors.append(NODE_COLORS.get(node_type, NODE_COLORS["unknown"]))
        return colors

    def _get_node_sizes(self) -> list[int]:
        """Get sizes for each node based on degree."""
        base_size = self.config.node_size
        sizes = []
        for node in self.graph.nodes():
            degree = self.graph.degree(node)
            # Scale size by degree
            size = base_size + (degree * 50)
            sizes.append(size)
        return sizes

    def _get_edge_weights(self) -> list[float]:
        """Get edge weights for line thickness."""
        weights = []
        for _u, _v, data in self.graph.edges(data=True):
            weight = data.get("weight", 1)
            # Normalize weight for visibility
            normalized = min(max(weight / 10, 0.5), 5)
            weights.append(normalized)
        return weights

    def draw(
        self,
        output_file: str | None = None,
        layout: str = "spring",
        show: bool = False,
        title: str = "Network Topology",
    ) -> None:
        """
        Draw the network topology.

        Args:
            output_file: Path to save the image
            layout: Layout algorithm (spring, circular, shell, kamada_kawai)
            show: Display interactive plot
            title: Plot title
        """
        if not self.graph.nodes():
            return

        fig, ax = plt.subplots(figsize=self.config.figure_size)

        pos = self._get_layout(layout)
        node_colors = self._get_node_colors()
        node_sizes = self._get_node_sizes()
        edge_weights = self._get_edge_weights() if self.graph.edges() else []

        # Draw edges
        if self.graph.edges():
            nx.draw_networkx_edges(
                self.graph,
                pos,
                ax=ax,
                width=edge_weights,
                alpha=0.6,
                edge_color="#7f8c8d",
            )

        # Draw nodes
        nx.draw_networkx_nodes(
            self.graph,
            pos,
            ax=ax,
            node_color=node_colors,
            node_size=node_sizes,
            alpha=0.9,
        )

        # Draw labels
        labels = {}
        for node in self.graph.nodes():
            label = self.graph.nodes[node].get("label", node)
            # Truncate long labels
            if len(label) > 15:
                label = label[:12] + "..."
            labels[node] = label

        nx.draw_networkx_labels(
            self.graph,
            pos,
            labels,
            ax=ax,
            font_size=self.config.font_size,
            font_color="black",
        )

        # Add legend
        legend_patches = [
            mpatches.Patch(color=color, label=node_type.capitalize())
            for node_type, color in NODE_COLORS.items()
        ]
        ax.legend(handles=legend_patches, loc="upper left")

        ax.set_title(title)
        ax.axis("off")

        plt.tight_layout()

        if output_file:
            from pathlib import Path
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            plt.savefig(output_file, dpi=150, bbox_inches="tight")

        if show:
            plt.show()

        plt.close(fig)

    def to_graphml(self, output_file: str) -> None:
        """Export topology to GraphML format."""
        from pathlib import Path
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        nx.write_graphml(self.graph, output_file)

    def to_gexf(self, output_file: str) -> None:
        """Export topology to GEXF format (Gephi)."""
        from pathlib import Path
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        nx.write_gexf(self.graph, output_file)

    def to_json(self) -> dict[str, Any]:
        """Export topology to JSON-compatible dict."""
        from networkx.readwrite import json_graph

        result: dict[str, Any] = json_graph.node_link_data(self.graph)
        return result


def visualize_topology(
    graph: nx.Graph,
    output_file: str | None = None,
    layout: str = "spring",
    show: bool = False,
    title: str = "Network Topology",
) -> None:
    """
    Visualize network topology.

    Args:
        graph: NetworkX graph
        output_file: Path to save the image
        layout: Layout algorithm
        show: Display interactive plot
        title: Plot title
    """
    visualizer = TopologyVisualizer(graph)
    visualizer.draw(output_file=output_file, layout=layout, show=show, title=title)
