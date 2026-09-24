from pathlib import Path
from threading import Lock, Thread
from pydantic import BaseModel

from fastapi.staticfiles import StaticFiles
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from acquisition.snapshot import (
    capture_snapshot,
    load_snapshot
)

from analysis.process_tree import (
    get_process_details,
    get_process_ancestors
)


class AnalysisRequest(BaseModel):
    deep_analysis: bool = False

app = FastAPI(
    title="Endpoint Forensics"
)

BASE_DIR = Path(__file__).resolve().parent

TEMPLATE_PATH = (
    BASE_DIR /
    "templates" /
    "index.html"
)

STATIC_DIR = (
    BASE_DIR /
    "static"
)

app.mount(
    "/static",
    StaticFiles(
        directory=STATIC_DIR
    ),
    name="static"
)

STATE = {
    "status": "idle",
    "stage": "Ready",
    "progress": 0,
    "error": None,
    "started_at": None,
    "finished_at": None
}


CURRENT_SNAPSHOT = None

STATE_LOCK = Lock()

EVIDENCE_DIR = Path("evidence")


def get_latest_evidence():
    if not EVIDENCE_DIR.exists():
        return None

    snapshots = [
        path
        for path in EVIDENCE_DIR.iterdir()
        if path.is_dir()
    ]

    if not snapshots:
        return None

    return max(
        snapshots,
        key=lambda path: path.name
    )


@app.get("/", response_class=HTMLResponse)
def home():
    global CURRENT_SNAPSHOT

    if CURRENT_SNAPSHOT is None:
        latest = get_latest_evidence()

        if latest:
            try:
                CURRENT_SNAPSHOT = load_snapshot(latest)

                with STATE_LOCK:
                    STATE["status"] = "complete"
                    STATE["stage"] = "Evidence loaded"
                    STATE["progress"] = 100

            except Exception as error:
                print(
                    f"Failed to load evidence: {error}"
                )

    return TEMPLATE_PATH.read_text(
        encoding="utf-8"
    )
def update_progress(
    stage,
    progress
):

    with STATE_LOCK:

        STATE["stage"] = stage
        STATE["progress"] = progress


def run_analysis(deep_analysis=False):

    global CURRENT_SNAPSHOT

    try:

        snapshot = capture_snapshot(
            progress_callback=update_progress,
            deep_analysis=deep_analysis
        )


        with STATE_LOCK:

            CURRENT_SNAPSHOT = snapshot

            STATE["status"] = "complete"
            STATE["stage"] = "Analysis complete"
            STATE["progress"] = 100

            STATE["finished_at"] = (
                snapshot["captured_at"]
            )


    except Exception as error:

        with STATE_LOCK:

            STATE["status"] = "error"

            STATE["stage"] = "Analysis failed"

            STATE["error"] = str(error)


@app.post("/api/analyze")
def start_analysis(request: AnalysisRequest):

    global CURRENT_SNAPSHOT

    with STATE_LOCK:

        if STATE["status"] == "running":

            return {
                "status": "running"
            }


        CURRENT_SNAPSHOT = None


        STATE["status"] = "running"

        STATE["stage"] = "Starting analysis"

        STATE["progress"] = 0

        STATE["error"] = None

        STATE["started_at"] = (
            __import__("datetime")
            .datetime
            .now()
            .astimezone()
            .isoformat()
        )

        STATE["finished_at"] = None


    Thread(
        target=run_analysis,
        args=(
            request.deep_analysis,
        ),
        daemon=True
    ).start()

    return {
        "status": "started"
    }


@app.get("/api/status")
def get_status():

    with STATE_LOCK:

        return STATE.copy()


@app.get("/api/processes")
def get_processes():

    if CURRENT_SNAPSHOT is None:

        raise HTTPException(
            status_code=404,
            detail="No analysis available"
        )


    return {
        "processes":
            CURRENT_SNAPSHOT["processes"],

        "executable_count":
            len(
                CURRENT_SNAPSHOT[
                    "executables"
                ]
            ),
        "captured_at":
            CURRENT_SNAPSHOT.get(
                "captured_at"
            )
    }

@app.get("/api/processes/{pid}")
def get_process(pid: int):
    import time

    total_start = time.perf_counter()

    process_map = CURRENT_SNAPSHOT["process_map"]
    children = CURRENT_SNAPSHOT["children"]

    start = time.perf_counter()

    details = get_process_details(
        pid,
        process_map,
        children
    )

    print(f"get_process_details: {time.perf_counter() - start:.4f}s")

    if not details:
        raise HTTPException(
            status_code=404,
            detail="Process not found"
        )

    start = time.perf_counter()

    ancestors = get_process_ancestors(
        pid,
        process_map
    )

    print(f"get_process_ancestors: {time.perf_counter() - start:.4f}s")

    process = details["process"]

    start = time.perf_counter()

    executable = None
    process_path = process.get("path")

    if process_path:
        executable = (
            CURRENT_SNAPSHOT["executable_map"]
            .get(process_path.lower())
        )

    print(f"executable lookup: {time.perf_counter() - start:.4f}s")

    print(
        f"TOTAL: {time.perf_counter() - total_start:.4f}s"
    )

    return {
        "process": process,
        "parent": details["parent"],
        "children": details["children"],
        "ancestors": ancestors,
        "executable": executable
    }

@app.get("/api/evidence")
def get_evidence():

    if not EVIDENCE_DIR.exists():
        return {"evidence": []}

    snapshots = [
        path
        for path in EVIDENCE_DIR.iterdir()
        if path.is_dir()
    ]

    snapshots.sort(
        key=lambda path: path.name,
        reverse=True
    )

    return {
        "evidence": [
            {
                "name": snapshot.name
            }
            for snapshot in snapshots
        ]
    }

@app.post("/api/evidence/{snapshot_name}")
def import_evidence(snapshot_name: str):

    global CURRENT_SNAPSHOT

    snapshot_path = EVIDENCE_DIR / snapshot_name

    if not snapshot_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Evidence snapshot not found"
        )

    try:

        snapshot = load_snapshot(
            snapshot_path
        )

        CURRENT_SNAPSHOT = snapshot

        with STATE_LOCK:

            STATE["status"] = "complete"
            STATE["stage"] = "Evidence loaded"
            STATE["progress"] = 100
            STATE["error"] = None

        return {
            "status": "loaded",
            "snapshot": snapshot_name
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )