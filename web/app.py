import re
from pathlib import Path
from threading import Lock, Thread

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from acquisition.snapshot import (
    EVIDENCE_DIR, capture_snapshot, is_snapshot_directory, load_snapshot, now_iso,
)
from analysis.process_tree import get_process_details, get_process_ancestors


class AnalysisRequest(BaseModel):
    deep_analysis: bool = False


app = FastAPI(title="Endpoint Forensics")
BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_PATH = BASE_DIR / "templates" / "index.html"
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
STATE = {
    "status": "idle", "stage": "Ready", "progress": 0, "error": None,
    "started_at": None, "finished_at": None, "warnings": [], "analysis_mode": None,
}
CURRENT_SNAPSHOT = None
STATE_LOCK = Lock()


def evidence_directories():
    if not EVIDENCE_DIR.exists():
        return []
    return sorted(
        (path for path in EVIDENCE_DIR.iterdir()
         if not path.is_symlink() and is_snapshot_directory(path)),
        key=lambda path: path.name, reverse=True,
    )


def set_snapshot_state(snapshot, stage):
    """Caller holds STATE_LOCK."""
    metadata = snapshot["metadata"]
    STATE.update(
        status="complete", stage=stage, progress=100, error=None,
        started_at=metadata.get("started_at"), finished_at=metadata.get("finished_at"),
        warnings=metadata.get("warnings", []), analysis_mode=metadata.get("analysis_mode"),
    )


@app.get("/", response_class=HTMLResponse)
def home():
    global CURRENT_SNAPSHOT
    with STATE_LOCK:
        if CURRENT_SNAPSHOT is None and STATE["status"] == "idle":
            # A malformed newest folder should not hide older valid evidence.
            for path in evidence_directories():
                try:
                    snapshot = load_snapshot(path)
                except (OSError, ValueError, KeyError, TypeError) as error:
                    print(f"Failed to load evidence {path.name}: {error}")
                    continue
                CURRENT_SNAPSHOT = snapshot
                set_snapshot_state(snapshot, "Evidence loaded")
                break
    return TEMPLATE_PATH.read_text(encoding="utf-8")


def update_progress(stage, progress):
    with STATE_LOCK:
        STATE.update(stage=stage, progress=progress)


def run_analysis(deep_analysis=False):
    global CURRENT_SNAPSHOT
    try:
        snapshot = capture_snapshot(
            progress_callback=update_progress, deep_analysis=deep_analysis,
            evidence_dir=EVIDENCE_DIR,
        )
        with STATE_LOCK:
            CURRENT_SNAPSHOT = snapshot
            stage = "Acquisition complete (partial evidence)" if snapshot["metadata"]["warnings"] else "Acquisition complete"
            set_snapshot_state(snapshot, stage)
    except Exception as error:
        with STATE_LOCK:
            STATE.update(status="error", stage="Acquisition failed", error=str(error),
                         finished_at=now_iso())


@app.post("/api/analyze")
def start_analysis(request: AnalysisRequest):
    with STATE_LOCK:
        if STATE["status"] == "running":
            raise HTTPException(status_code=409, detail="An acquisition is already running.")
        STATE.update(
            status="running", stage="Starting acquisition", progress=0, error=None,
            started_at=now_iso(), finished_at=None, warnings=[],
            analysis_mode="extended" if request.deep_analysis else "quick",
        )
    try:
        Thread(target=run_analysis, args=(request.deep_analysis,), daemon=True).start()
    except Exception as error:
        with STATE_LOCK:
            STATE.update(status="error", stage="Acquisition failed", error=str(error),
                         finished_at=now_iso())
        raise HTTPException(status_code=500, detail="Could not start acquisition.") from error
    return {"status": "started"}


@app.get("/api/status")
def get_status():
    with STATE_LOCK:
        return STATE.copy()


def current_snapshot():
    with STATE_LOCK:
        snapshot = CURRENT_SNAPSHOT
    if snapshot is None:
        raise HTTPException(status_code=404, detail="No evidence snapshot available.")
    return snapshot


@app.get("/api/processes")
def get_processes():
    snapshot = current_snapshot()
    return {
        "processes": snapshot["processes"], "executable_count": len(snapshot["executables"]),
        "captured_at": snapshot["captured_at"], "metadata": snapshot["metadata"],
    }


@app.get("/api/processes/{pid}")
def get_process(pid: int):
    snapshot = current_snapshot()
    details = get_process_details(pid, snapshot["process_map"], snapshot["children"])
    if details is None:
        raise HTTPException(status_code=404, detail="Process not found in this snapshot.")
    process = details["process"]
    path = process.get("path")
    return {
        **details,
        "ancestors": get_process_ancestors(pid, snapshot["process_map"]),
        "executable": snapshot["executable_map"].get(path.lower()) if path else None,
        "module_record": snapshot["module_map"].get((pid, process.get("create_time"))),
        "analysis_mode": snapshot["metadata"].get("analysis_mode"),
    }


@app.get("/api/evidence")
def get_evidence():
    return {"evidence": [{"name": path.name} for path in evidence_directories()]}


@app.post("/api/evidence/{snapshot_name}")
def import_evidence(snapshot_name: str):
    global CURRENT_SNAPSHOT
    # Keep selection within the evidence directory, including symlink resolution.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", snapshot_name):
        raise HTTPException(status_code=400, detail="Invalid snapshot name.")
    snapshot_path = EVIDENCE_DIR / snapshot_name
    if (snapshot_path.is_symlink()
            or snapshot_path.resolve().parent != EVIDENCE_DIR.resolve()):
        raise HTTPException(status_code=400, detail="Invalid snapshot path.")
    with STATE_LOCK:
        if STATE["status"] == "running":
            raise HTTPException(status_code=409, detail="Wait for the running acquisition before loading evidence.")
        if not is_snapshot_directory(snapshot_path):
            raise HTTPException(status_code=404, detail="Evidence snapshot not found or incomplete.")
        try:
            snapshot = load_snapshot(snapshot_path)
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise HTTPException(status_code=400, detail=f"Invalid evidence: {error}") from error
        CURRENT_SNAPSHOT = snapshot
        set_snapshot_state(snapshot, "Evidence loaded")
    return {"status": "loaded", "snapshot": snapshot_name}
