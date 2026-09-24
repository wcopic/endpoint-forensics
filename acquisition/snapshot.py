import json
from datetime import datetime
from pathlib import Path

from collectors.system import collect_system_info
from collectors.processes import collect_processes
from collectors.executables import collect_executables

from analysis.process_tree import build_process_tree
from analysis.pe import analyze_pe


def create_evidence_directory():
    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    path = Path("evidence") / timestamp

    path.mkdir(
        parents=True,
        exist_ok=True
    )

    return path


def save_json(path, data):
    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4
        )


def capture_snapshot(progress_callback=None):
    import time

    def progress(stage, percentage):
        if progress_callback:
            progress_callback(stage, percentage)

    total_start = time.perf_counter()

    evidence_path = create_evidence_directory()

    # System
    start = time.perf_counter()
    progress("Collecting system information", 5)
    system_info = collect_system_info()
    print(f"[TIMING] System: {time.perf_counter() - start:.3f}s")

    # Processes
    start = time.perf_counter()
    progress("Collecting running processes", 20)
    processes = collect_processes()

    captured_at = (
        processes[0].get("observed_at")
        if processes
        else datetime.now().astimezone().isoformat()
    )
    
    process_map, children = build_process_tree(processes)
    print(f"[TIMING] Processes: {time.perf_counter() - start:.3f}s")

    # Executables + SHA-256
    start = time.perf_counter()
    progress("Collecting executable metadata", 45)
    executables = collect_executables(processes)
    print(f"[TIMING] Executables + SHA-256: {time.perf_counter() - start:.3f}s")

    # PE analysis
    start = time.perf_counter()
    progress("Analyzing PE files", 70)

    for executable in executables:
        executable["pe"] = analyze_pe(executable["path"])

    print(f"[TIMING] PE analysis: {time.perf_counter() - start:.3f}s")

    # Saving
    start = time.perf_counter()
    progress("Saving evidence", 90)

    save_json(evidence_path / "system.json", system_info)
    save_json(evidence_path / "processes.json", processes)
    save_json(evidence_path / "executables.json", executables)

    print(f"[TIMING] Saving evidence: {time.perf_counter() - start:.3f}s")

    executable_map = {
        executable["path"].lower(): executable
        for executable in executables
    }

    progress("Analysis complete", 100)

    total_time = time.perf_counter() - total_start

    print(f"[TIMING] =============================")
    print(f"[TIMING] TOTAL: {total_time:.3f}s")
    print(f"[TIMING] =============================")

    return {
        "evidence_path": str(evidence_path),
        "captured_at": captured_at,
        "system": system_info,
        "processes": processes,
        "executables": executables,
        "process_map": process_map,
        "children": children,
        "executable_map": executable_map
    }

def load_snapshot(evidence_path):
    evidence_path = Path(evidence_path)

    system_path = evidence_path / "system.json"
    processes_path = evidence_path / "processes.json"
    executables_path = evidence_path / "executables.json"

    if not (
        system_path.exists()
        and processes_path.exists()
        and executables_path.exists()
    ):
        raise FileNotFoundError(
            "Invalid evidence directory"
        )

    with open(system_path, "r", encoding="utf-8") as file:
        system_info = json.load(file)

    with open(processes_path, "r", encoding="utf-8") as file:
        processes = json.load(file)

    captured_at = None

    if processes:
        captured_at = processes[0].get(
            "observed_at"
        )

    with open(executables_path, "r", encoding="utf-8") as file:
        executables = json.load(file)

    process_map, children = build_process_tree(processes)

    executable_map = {
        executable["path"].lower(): executable
        for executable in executables
    }

    return {
        "evidence_path": str(evidence_path),
        "captured_at": captured_at,
        "system": system_info,
        "processes": processes,
        "executables": executables,
        "process_map": process_map,
        "children": children,
        "executable_map": executable_map
    }