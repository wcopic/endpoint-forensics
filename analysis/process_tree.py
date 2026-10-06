def _parent_for(process, process_map):
    """Resolve only plausible parents present in this snapshot."""
    parent_pid = process.get("parent_pid")
    if parent_pid in (None, 0, process["pid"]):
        return None
    parent = process_map.get(parent_pid)
    if parent is None:
        return None
    parent_created = parent.get("create_time")
    child_created = process.get("create_time")
    if parent_created is not None and child_created is not None:
        if parent_created > child_created:
            # The original parent exited and Windows reused its PID.
            return None
    return parent


def build_process_tree(processes):
    process_map = {process["pid"]: process for process in processes}
    children = {}
    for process in processes:
        parent = _parent_for(process, process_map)
        if parent is not None:
            children.setdefault(parent["pid"], []).append(process["pid"])
    return process_map, children


def print_process_tree(pid, process_map, children, level=0, visited=None):
    visited = set() if visited is None else visited
    process = process_map.get(pid)
    if process is None or pid in visited:
        return
    visited.add(pid)
    print(f"{'    ' * level}└── {process['name']} (PID: {pid})")
    for child_pid in children.get(pid, []):
        print_process_tree(child_pid, process_map, children, level + 1, visited)


def get_process_details(pid, process_map, children):
    process = process_map.get(pid)
    if process is None:
        return None
    return {
        "process": process,
        "parent": _parent_for(process, process_map),
        "children": [process_map[child] for child in children.get(pid, [])
                     if child in process_map],
    }


def get_process_ancestors(pid, process_map):
    """Return the selected process followed by its ancestors, once each."""
    ancestors = []
    visited = set()
    current = process_map.get(pid)
    while current is not None and current["pid"] not in visited:
        visited.add(current["pid"])
        ancestors.append(current)
        current = _parent_for(current, process_map)
    return ancestors
