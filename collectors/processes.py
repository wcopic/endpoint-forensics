import psutil
from datetime import datetime


def collect_processes(observed_at=None):
    processes = []

    if observed_at is None:
        observed_at = datetime.now().astimezone().isoformat()

    for process in psutil.process_iter(
        [
            "pid",
            "ppid",
            "name",
            "exe",
            "username",
            "create_time",
            "cmdline",
        ]
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
                "command_line": info["cmdline"],
                "observed_at": observed_at,
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes