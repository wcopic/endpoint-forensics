from pathlib import Path


PROCESS_FIELDS = {
    "ppid": "Parent process ID", "name": "Process name", "exe": "Executable path",
    "username": "Username", "create_time": "Process creation time", "cmdline": "Command line",
}


def collection_summary(processes, executables, modules):
    """Describe known missing data without counting a process more than once."""
    executable_map = {str(Path(item["path"])).lower(): item for item in executables}
    module_map = {(item["pid"], item.get("create_time")): item for item in modules}
    affected = []
    groups = {}

    for process in processes:
        missing = set()
        if process.get("collection_status") == "partial":
            missing.update(PROCESS_FIELDS.get(field, "Process details")
                           for field in process.get("unavailable_fields", []))
            if not missing:
                missing.add("Process details")
        path = process.get("path")
        executable = executable_map.get(str(Path(path)).lower()) if path else None
        if executable:
            status = executable.get("collection_status")
            if status in {"access_denied", "file_missing", "error"}:
                missing.add("Executable file metadata")
                missing.add("SHA-256 hash")
            elif status == "partial":
                missing.add("SHA-256 hash")
            if executable.get("pe_collection_status") == "unavailable":
                missing.add("PE headers")
            signature = executable.get("signature") or {}
            # NotSigned is a successful verification result, not a collection failure.
            if signature.get("collection_status") in {"error", "timeout", "unavailable"}:
                missing.add("Digital signature and certificate information")
        module = module_map.get((process["pid"], process.get("create_time")))
        if module and module.get("collection_status") in {
            "access_denied", "process_exited", "pid_reused", "identity_unverified", "error",
        }:
            missing.add("Memory-mapped file paths")
        if missing:
            labels = sorted(missing)
            affected.append({"pid": process["pid"], "name": process.get("name"), "missing": labels})
            for label in labels:
                groups[label] = groups.get(label, 0) + 1
    return {
        "total_processes": len(processes),
        "affected_process_count": len(affected),
        "issues": [{"label": label, "process_count": count} for label, count in sorted(groups.items())],
        "affected_processes": affected,
    }
