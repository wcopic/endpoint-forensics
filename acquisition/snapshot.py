import json
import math
import shutil
import tempfile
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from collectors.system import collect_system_info
from collectors.processes import collect_processes
from collectors.executables import collect_executables
from collectors.signatures import collect_signatures
from collectors.modules import collect_loaded_modules
from analysis.process_tree import build_process_tree
from analysis.pe import analyze_pe
from analysis.collection_summary import collection_summary


EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "evidence"
REQUIRED_FILES = ("system.json", "processes.json", "executables.json")


def now_iso():
    return datetime.now().astimezone().isoformat()


def save_json(path, data):
    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


def summarize(records):
    counts = dict(Counter(record.get("collection_status", "unknown") for record in records))
    return {"status": "partial" if any(key != "collected" for key in counts) else "collected",
            "counts": counts}


def _assemble(path, system, processes, executables, modules, metadata):
    process_map, children = build_process_tree(processes)
    return {
        "evidence_path": str(path),
        "captured_at": metadata.get("captured_at"),
        "metadata": metadata,
        "collection_summary": collection_summary(processes, executables, modules),
        "system": system, "processes": processes, "executables": executables,
        "process_map": process_map, "children": children,
        "executable_map": {item["path"].lower(): item for item in executables},
        "modules": modules,
        "module_map": {(item["pid"], item.get("create_time")): item for item in modules},
    }


def capture_snapshot(progress_callback=None, deep_analysis=False, evidence_dir=None):
    """Publish complete snapshot files together; report partial collector results."""
    def progress(stage, percentage):
        if progress_callback:
            progress_callback(stage, percentage)

    root = Path(evidence_dir) if evidence_dir is not None else EVIDENCE_DIR
    root.mkdir(parents=True, exist_ok=True)
    pending = Path(tempfile.mkdtemp(prefix=".pending-", dir=root))
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
    evidence_path = root / f"{timestamp}_{pending.name.removeprefix('.pending-')}"
    started_at = now_iso()
    total_start = time.perf_counter()
    timings = {}

    def timed(stage, percentage, action):
        progress(stage, percentage)
        start = time.perf_counter()
        result = action()
        timings[stage] = round(time.perf_counter() - start, 3)
        print(f"[TIMING] {stage}: {timings[stage]:.3f}s")
        return result

    try:
        system = timed("Collecting system information", 5, collect_system_info)
        captured_at = now_iso()
        processes = timed("Collecting running processes", 20,
                          lambda: collect_processes(observed_at=captured_at))
        executables = timed("Collecting executable metadata", 45,
                            lambda: collect_executables(processes))

        def collect_pe():
            for item in executables:
                item["pe"] = analyze_pe(item["path"])
                item["pe_collection_status"] = "collected" if item["pe"] is not None else "unavailable"
        timed("Analyzing PE headers", 70, collect_pe)
        collectors = {"processes": summarize(processes), "executables": summarize(executables),
                      "pe": summarize([{"collection_status": item["pe_collection_status"]}
                                       for item in executables])}
        modules = []
        if deep_analysis:
            signatures = timed("Collecting Authenticode signatures", 80,
                               lambda: collect_signatures(executables))
            for item in executables:
                item["signature"] = signatures[item["path"].lower()]
            collectors["signatures"] = summarize(list(signatures.values()))
            module_results = timed("Collecting memory-mapped file paths", 87,
                                   lambda: collect_loaded_modules(processes))
            modules = list(module_results.values())
            collectors["modules"] = summarize(modules)
        else:
            collectors.update(signatures={"status": "skipped", "counts": {}},
                              modules={"status": "skipped", "counts": {}})
        warnings = [f"{name}: incomplete collection; inspect record statuses."
                    for name, result in collectors.items() if result["status"] == "partial"]
        progress("Saving evidence", 90)
        save_json(pending / "system.json", system)
        save_json(pending / "processes.json", processes)
        save_json(pending / "executables.json", executables)
        if deep_analysis:
            save_json(pending / "modules.json", modules)
        metadata = {
            "schema_version": 1, "analysis_mode": "extended" if deep_analysis else "quick",
            "started_at": started_at, "captured_at": captured_at,
            "finished_at": now_iso(), "elapsed_seconds": round(time.perf_counter() - total_start, 3),
            "timings": timings, "collectors": collectors, "warnings": warnings,
        }
        save_json(pending / "metadata.json", metadata)
        pending.rename(evidence_path)
        print(f"[TIMING] TOTAL: {metadata['elapsed_seconds']:.3f}s")
        progress("Acquisition complete (partial evidence)" if warnings else "Acquisition complete", 100)
        return _assemble(evidence_path, system, processes, executables, modules, metadata)
    except Exception:
        shutil.rmtree(pending, ignore_errors=True)
        raise


def is_snapshot_directory(path):
    return (path.is_dir() and not path.name.startswith(".")
            and all((path / filename).is_file() for filename in REQUIRED_FILES))


def _read_json(path):
    with path.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


def _validate_records(processes, executables, modules):
    def pid(value):
        return type(value) is int and value >= 0

    def creation_time(value):
        return value is None or (type(value) in (int, float) and math.isfinite(value))

    if not all(isinstance(records, list) for records in (processes, executables, modules)):
        raise ValueError("Evidence records must be JSON arrays.")
    seen = set()
    for item in processes:
        if (not isinstance(item, dict) or not pid(item.get("pid"))
                or item["pid"] in seen
                or (item.get("parent_pid") is not None and not pid(item["parent_pid"]))
                or not creation_time(item.get("create_time"))):
            raise ValueError("Invalid or duplicate process identity.")
        seen.add(item["pid"])
        for field in ("name", "path", "username", "observed_at"):
            if item.get(field) is not None and not isinstance(item[field], str):
                raise ValueError(f"Invalid process field: {field}.")
        cmdline = item.get("command_line")
        if cmdline is not None and (not isinstance(cmdline, list)
                                   or not all(isinstance(value, str) for value in cmdline)):
            raise ValueError("Invalid command line.")
    for item in executables:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not item["path"]:
            raise ValueError("Invalid executable path.")
        for field in ("signature", "pe"):
            if item.get(field) is not None and not isinstance(item[field], dict):
                raise ValueError(f"Invalid executable {field}.")
    module_identities = set()
    for item in modules:
        if (not isinstance(item, dict) or not pid(item.get("pid"))
                or not creation_time(item.get("create_time"))
                or not isinstance(item.get("modules"), list)):
            raise ValueError("Invalid module record.")
        identity = (item["pid"], item.get("create_time"))
        if identity in module_identities:
            raise ValueError("Duplicate module identity.")
        module_identities.add(identity)
        for module in item["modules"]:
            if not isinstance(module, dict) or not isinstance(module.get("path"), str):
                raise ValueError("Invalid memory-mapped file path.")
        # Legacy [] did not distinguish errors from a successful empty result.
        item.setdefault("collection_status", "legacy_unknown")
        item.setdefault("error", None)


def load_snapshot(evidence_path):
    evidence_path = Path(evidence_path)
    if not is_snapshot_directory(evidence_path):
        raise FileNotFoundError("Invalid evidence directory: required JSON files are missing.")
    system = _read_json(evidence_path / "system.json")
    processes = _read_json(evidence_path / "processes.json")
    executables = _read_json(evidence_path / "executables.json")
    module_path = evidence_path / "modules.json"
    modules = _read_json(module_path) if module_path.is_file() else []
    if not isinstance(system, dict):
        raise ValueError("System evidence must be a JSON object.")
    _validate_records(processes, executables, modules)
    metadata_path = evidence_path / "metadata.json"
    if metadata_path.is_file():
        metadata = _read_json(metadata_path)
        if not isinstance(metadata, dict) or metadata.get("schema_version") != 1:
            raise ValueError("Unsupported snapshot metadata schema.")
        if not isinstance(metadata.get("warnings", []), list):
            raise ValueError("Snapshot warnings must be an array.")
    else:
        metadata = {
            "schema_version": 0, "analysis_mode": "legacy_unknown",
            "captured_at": processes[0].get("observed_at") if processes else None,
            "finished_at": None,
            "warnings": ["Legacy snapshot: acquisition mode and collection completeness are unknown."],
        }
    return _assemble(evidence_path, system, processes, executables, modules, metadata)
