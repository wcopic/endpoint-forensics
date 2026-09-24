def build_process_tree(processes):
    process_map = {
        process["pid"]: process
        for process in processes
    }

    children = {}

    for process in processes:
        pid = process["pid"]
        ppid = process["parent_pid"]

        if ppid not in children:
            children[ppid] = []

        children[ppid].append(pid)

    return process_map, children


def print_process_tree(pid, process_map, children, level=0):
    process = process_map.get(pid)

    if not process:
        return

    indent = "    " * level

    print(
        f"{indent}└── "
        f"{process['name']} "
        f"(PID: {process['pid']})"
    )

    for child_pid in children.get(pid, []):
        print_process_tree(
            child_pid,
            process_map,
            children,
            level + 1
        )

def get_process_details(pid, process_map, children):
    process = process_map.get(pid)

    if not process:
        return None

    parent = process_map.get(process["parent_pid"])

    child_processes = [
        process_map[child_pid]
        for child_pid in children.get(pid, [])
        if child_pid in process_map
    ]

    return {
        "process": process,
        "parent": parent,
        "children": child_processes
    }

def get_process_ancestors(pid, process_map):
    ancestors = []

    current = process_map.get(pid)

    while current:
        ancestors.append(current)

        parent_pid = current["parent_pid"]
        current = process_map.get(parent_pid)

    return ancestors