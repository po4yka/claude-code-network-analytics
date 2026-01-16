# Topology Analysis Skill

Guidance for network topology mapping and graph analysis.

## Topology Discovery

### ARP Discovery
```bash
# Discover local network
netanalytics discover 192.168.1.0/24 --method arp
```
- Most accurate for local subnet
- Reveals MAC addresses
- Identifies vendors via OUI

### ICMP Discovery
```bash
# Ping sweep
netanalytics discover 10.0.0.0/24 --method icmp
```
- Works across subnets
- May be blocked by firewalls
- Good for remote networks

### From Traffic
```bash
# Build from pcap
netanalytics topology --from-pcap capture.pcap
```
- Shows actual communication patterns
- Includes connection weights
- Reveals hidden relationships

## Graph Concepts

### Nodes
- Represent hosts/devices
- Attributes: IP, MAC, hostname, type
- Types: gateway, host, server, unknown

### Edges
- Represent connections
- Weight: connection strength/frequency
- Type: direct, inferred

### Node Types
- **Gateway**: High connectivity, routes traffic
- **Server**: Multiple services, many connections
- **Host**: Endpoint device
- **Unknown**: Unclassified

## Graph Metrics

### Centrality Measures

**Degree Centrality**
- Number of connections
- High = hub/important node
- Gateway detection

**Betweenness Centrality**
- Nodes on shortest paths
- High = bridge/bottleneck
- Critical path identification

**Closeness Centrality**
- Average distance to others
- High = central position
- Efficient communication

**Eigenvector Centrality**
- Connected to important nodes
- High = influential
- Authority identification

### Network Metrics

**Density**
- Ratio of edges to possible edges
- Range: 0 to 1
- High = well-connected network

**Clustering Coefficient**
- Degree of node clustering
- High = tight groups exist
- Community indicator

**Diameter**
- Longest shortest path
- Measures network span
- Routing efficiency indicator

**Connected Components**
- Isolated subnetworks
- Should typically be 1
- Multiple = segmentation

## Layout Algorithms

### Spring Layout (Default)
- Force-directed placement
- Good for general visualization
- Natural clustering visible

### Circular Layout
- Nodes in circle
- Good for comparing degrees
- Clear edge visibility

### Shell Layout
- Concentric circles
- Core-periphery visualization
- Hierarchical networks

### Kamada-Kawai
- Energy minimization
- Good edge length uniformity
- Better for larger graphs

## Community Detection

### Louvain Algorithm
- Modularity optimization
- Fast, scalable
- Best for large networks

### Greedy Modularity
- Hierarchical clustering
- Good quality communities
- Moderate complexity

### Label Propagation
- Simple, fast
- Semi-supervised possible
- May vary between runs

## Analysis Patterns

### Hub Identification
```python
# Find nodes with highest degree
hub_nodes = find_hub_nodes(graph, top_n=5)
```
- Central servers/routers
- Critical infrastructure
- Single points of failure

### Bridge Detection
```python
# Find articulation points
bridges = find_bridge_nodes(graph)
```
- Nodes whose removal disconnects
- Critical path dependencies
- Redundancy gaps

### Anomaly Detection
- Unexpected connections
- Isolated nodes
- Unusual centrality patterns

## Visualization Tips

1. **Color by type**: Differentiate node roles
2. **Size by importance**: Scale by centrality
3. **Weight edges**: Show connection strength
4. **Label key nodes**: Identify important devices
5. **Use layout wisely**: Match algorithm to data

## Export Formats

### GraphML
```bash
netanalytics topology <network> --export graph.graphml
```
- XML-based, widely supported
- Preserves attributes
- Gephi, yEd compatible

### GEXF
```bash
netanalytics topology <network> --export graph.gexf
```
- Gephi native format
- Dynamic graph support
- Rich attribute handling

### JSON
```bash
netanalytics topology <network> --export graph.json
```
- Web visualization (D3.js)
- API integration
- Programmatic access

## References

- [NetworkX Documentation](https://networkx.org/documentation/)
- [Graph Theory Basics](https://en.wikipedia.org/wiki/Graph_theory)
- [Network Visualization Best Practices](https://www.data-to-viz.com/graph/network.html)
