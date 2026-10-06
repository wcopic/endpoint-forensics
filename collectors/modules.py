from datetime import datetime
from pathlib import Path

import psutil


def collect_loaded_modules(processes):
    """Collect mapped file paths, preserving failures and process identity."""
    modules_by_pid = {}
    for process in processes:
        pid = process.get("pid")
        if pid is None:
            continue
        record = {
            "pid": pid,
            "create_time": process.get("create_time"),
            "observed_at": datetime.now().astimezone().isoformat(),
            "collection_status": "collected",
            "error": None,
            "modules": [],
        }
        modules_by_pid[pid] = record
        if record["create_time"] is None:
            record.update(collection_status="identity_unverified",
                          error="Process creation time is unavailable; collection skipped.")
            continue
        try:
            live_process = psutil.Process(pid)
            if live_process.create_time() != record["create_time"]:
                record.update(collection_status="pid_reused",
                              error="PID now belongs to another process.")
                continue
            modules = []
            seen_paths = set()
            for mapping in live_process.memory_maps():
                path = getattr(mapping, "path", None)
                if not path or path.lower() in seen_paths:
                    continue
                seen_paths.add(path.lower())
                modules.append({"name": Path(path).name, "path": path})
            # A fresh handle catches exit/reuse while memory maps were read.
            if psutil.Process(pid).create_time() != record["create_time"]:
                record.update(collection_status="pid_reused",
                              error="Process identity changed during collection.")
            else:
                record["modules"] = modules
        except psutil.AccessDenied:
            record.update(collection_status="access_denied", error="Access denied.")
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            record.update(collection_status="process_exited", error="Process exited.")
        except (psutil.Error, OSError) as error:
            record.update(collection_status="error", error=str(error))
    return modules_by_pid
