import psutil

def collect_processes():
    processes = []

    for process in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username", "create_time"]
    ):
        try:
            info = process.info

            processes.append({
                "pid": info["pid"],
                "parent_pid": info["ppid"],
                "name": info["name"],
                "path": info["exe"],
                "username": info["username"],
                "create_time": info["create_time"],
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes