# Topology Map Command

Generate and visualize network topology.

## Usage

```
/topology-map <network> [options]
```

## Arguments

- `network` (required): Network CIDR to map (e.g., `192.168.1.0/24`) or pcap file path

## Options

- `--layout`: Graph layout algorithm (`spring`, `circular`, `shell`, `kamada_kawai`)
- `--output, -o`: Output image file (PNG, SVG, PDF)
- `--show`: Display interactive graph window
- `--metrics`: Calculate and display network metrics
- `--export`: Export graph data (graphml, gexf, json)

## Examples

```bash
# Map local network
/topology-map 192.168.1.0/24

# Generate with specific layout
/topology-map 192.168.1.0/24 --layout circular --output network.png

# Build topology from pcap
/topology-map capture.pcap --metrics

# Export for Gephi
/topology-map 192.168.1.0/24 --export network.gexf
```

## What This Command Does

1. **Network Discovery**: Scans network using ARP to find active hosts
2. **Topology Building**: Constructs NetworkX graph with nodes and edges
3. **Gateway Detection**: Attempts to identify network gateway/router
4. **Visualization**: Generates visual graph with color-coded node types
5. **Metrics Calculation**: Computes centrality, clustering, communities

## Metrics Provided

- Node count and edge count
- Network density
- Average degree
- Clustering coefficient
- Connected components
- Hub nodes (highest connectivity)
- Bridge nodes (critical paths)
- Community detection

## Execution

When you invoke this command, I will:

1. Discover hosts on the network (requires root for ARP)
2. Build topology graph with node attributes
3. Calculate requested metrics
4. Generate visualization with legend
5. Save output files as specified

## Node Color Legend

- **Red**: Gateway/Router
- **Blue**: Host
- **Green**: Server (multiple services)
- **Gray**: Unknown

## Requirements

- Root/sudo for network discovery
- `matplotlib` for visualization
- `networkx` for graph analysis
