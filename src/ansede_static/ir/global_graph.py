from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple

@dataclass(frozen=True)
class NodeID:
    """A unique identifier for a symbol or AST node across the entire workspace."""
    file_path: str
    symbol_name: str
    
@dataclass
class TaintNode:
    """A node in the inter-procedural taint graph."""
    id: NodeID
    ast_type: str
    line_start: int
    is_source: bool = False
    is_sink: bool = False
    # For tracking module-level taint sources
    taint_source: Optional[str] = None
    # For tracking where taint originates from
    taint_trace: Tuple[str, ...] = field(default_factory=tuple)
    
@dataclass
class Edge:
    """A directional relationship between two nodes."""
    source: NodeID
    target: NodeID
    edge_type: str  # e.g., "CALLS", "IMPORTS", "DATA_FLOW"
    weight: int = 1
    metadata: Dict[str, str] = field(default_factory=dict)  # e.g., import alias

class GlobalGraph:
    """
    The central intelligence graph mapping inter-procedural reachability across files.
    Built during Pass 1 (Discovery) to enable Pass 2 (Deep Taint Evaluation).
    
    Key invariants:
    - Nodes are indexed by (file_path, symbol_name)
    - Edges model imports, function calls, and data flow
    - Taint can be queried transitively across file boundaries
    """
    def __init__(self):
        self.nodes: Dict[NodeID, TaintNode] = {}
        self.adjacency: Dict[NodeID, List[Edge]] = {}
        # Map (file_path, symbol_name) -> [(file_path, symbol_name)] for faster import lookup
        self.imports: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}
        # Track module-level tainted variables: (file, symbol) -> taint_source
        self.module_taint: Dict[Tuple[str, str], Tuple[str, Tuple[str, ...]]] = {}
        
    def add_node(self, node: TaintNode) -> None:
        self.nodes[node.id] = node
        if node.id not in self.adjacency:
            self.adjacency[node.id] = []
            
        # Track module-level taint
        if node.taint_source:
            key = (node.id.file_path, node.id.symbol_name)
            self.module_taint[key] = (node.taint_source, node.taint_trace)
            
    def add_edge(self, edge: Edge) -> None:
        if edge.edge_type == "IMPORTS":
            src_key = (edge.source.file_path, edge.source.symbol_name)
            tgt_key = (edge.target.file_path, edge.target.symbol_name)
            if src_key not in self.imports:
                self.imports[src_key] = []
            self.imports[src_key].append(tgt_key)

        # Only add edges between known nodes to maintain strict topology
        if edge.source in self.nodes and edge.target in self.nodes:
            self.adjacency[edge.source].append(edge)

    def resolve_cross_file_taint(self, file_path: str, symbol_name: str) -> Optional[Tuple[str, Tuple[str, ...]]]:
        """
        Resolve whether a symbol (potentially imported) is tainted.
        Returns (taint_source, trace) or None if not tainted.
        """
        
        # Check if directly tainted using fuzzy path match
        for (fp, sym), taint in self.module_taint.items():
            if sym == symbol_name and (file_path.endswith(fp) or fp.endswith(file_path)):
                return taint
        
        # Check imports
        for (fp, sym), targets in self.imports.items():
            if sym == symbol_name and (file_path.endswith(fp) or fp.endswith(file_path)):
                for target_fp, target_sym in targets:
                    imported_taint = self.resolve_cross_file_taint(target_fp, target_sym)
                    if imported_taint:
                        return imported_taint
        return None

    def find_all_paths(self, source_id: NodeID, sink_id: NodeID, max_depth=5) -> List[List[NodeID]]:
        """
        Traverses the global graph to find routes connecting an untrusted source to a sink.
        Uses a bounded DFS to prevent graph cycles from blowing up memory.
        """
        paths = []
        
        def dfs(current: NodeID, path: List[NodeID], visited: Set[NodeID]):
            if len(path) > max_depth:
                return
            if current == sink_id:
                paths.append(list(path))
                return
                
            for edge in self.adjacency.get(current, []):
                neighbor = edge.target
                if neighbor not in visited:
                    visited.add(neighbor)
                    path.append(neighbor)
                    dfs(neighbor, path, visited)
                    path.pop()
                    visited.remove(neighbor)
                    
        dfs(source_id, [source_id], {source_id})
        return paths
