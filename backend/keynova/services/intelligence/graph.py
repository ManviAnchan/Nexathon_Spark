from typing import List, Dict, Any

def build_dependency_graph(
    project_name: str,
    findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Constructs React Flow compatible nodes and directed edges
    mapping Application -> Files -> Libraries -> Cryptographic Algorithms.
    """
    nodes = []
    edges = []

    # 1. Root Application Node
    root_id = "app_root"
    nodes.append({
        "id": root_id,
        "type": "application",
        "data": {
            "label": project_name,
            "subtitle": "Service Boundary"
        },
        "position": {"x": 50, "y": 250}
    })

    file_nodes = set()
    lib_nodes = set()
    alg_nodes = set()

    file_y = 50
    lib_y = 50
    alg_y = 50

    for idx, f in enumerate(findings):
        # File Node
        fpath = f.get("file_path", "unknown")
        file_id = f"file_{hash(fpath) % 100000}"
        if file_id not in file_nodes:
            file_nodes.add(file_id)
            nodes.append({
                "id": file_id,
                "type": "file",
                "data": {
                    "label": fpath.split("/")[-1],
                    "full_path": fpath
                },
                "position": {"x": 300, "y": file_y}
            })
            file_y += 110
            edges.append({
                "id": f"e_root_{file_id}",
                "source": root_id,
                "target": file_id,
                "animated": False
            })

        # Library Node
        lib_name = f.get("library") or "builtin"
        lib_id = f"lib_{hash(lib_name) % 100000}"
        if lib_id not in lib_nodes:
            lib_nodes.add(lib_id)
            nodes.append({
                "id": lib_id,
                "type": "library",
                "data": {
                    "label": lib_name,
                    "kind": "Dependency"
                },
                "position": {"x": 550, "y": lib_y}
            })
            lib_y += 110

        # Link File to Library
        edge_fl = f"e_{file_id}_{lib_id}"
        if not any(e["id"] == edge_fl for e in edges):
            edges.append({
                "id": edge_fl,
                "source": file_id,
                "target": lib_id,
                "animated": True
            })

        # Algorithm Node
        alg = f.get("algorithm", "Unknown")
        sev = f.get("severity", "low")
        hndl = f.get("hndl", False)
        alg_id = f"alg_{f.get('id', idx)}"
        nodes.append({
            "id": alg_id,
            "type": "algorithm",
            "data": {
                "label": alg,
                "severity": sev,
                "hndl": hndl,
                "usage": f.get("usage", "crypto")
            },
            "position": {"x": 800, "y": alg_y}
        })
        alg_y += 90

        # Link Library to Algorithm
        edges.append({
            "id": f"e_{lib_id}_{alg_id}",
            "source": lib_id,
            "target": alg_id,
            "animated": hndl
        })

    return {
        "nodes": nodes,
        "edges": edges
    }
