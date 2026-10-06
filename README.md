# Endpoint Forensics

A local Windows endpoint evidence collection and investigation project built with Python, FastAPI, and a localhost dashboard.

The current implementation captures snapshots of processes and executable files. Extended acquisition adds Authenticode results and memory-mapped file paths. **It does not detect malware, assign severity, or correlate behavioral events yet.**

## Requirements

- Windows for supported endpoint acquisition
- Python **3.10 or later**; current regression tests were run with Python 3.12
- Git to clone the repository
- Windows PowerShell available as **`powershell.exe`** for Authenticode collection

PowerShell 7 (`pwsh`) can be used as your terminal, but the signature collector explicitly invokes Windows PowerShell. CMD is also supported.

Acquisition is best effort. Running from an elevated terminal can improve access to process metadata and memory maps; protected or terminated processes can remain unavailable. Elevation is not required to launch the dashboard.

## Installation and execution — PowerShell

Run these commands from the directory where you want the repository:

```powershell
git clone https://github.com/wcopic/endpoint-forensics.git
cd endpoint-forensics
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m uvicorn web.app:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. Stop the server with `Ctrl+C`. These commands use the environment's interpreter directly, so script activation and execution-policy changes are unnecessary. If `python` is unavailable but the Windows Python launcher is installed, use `py -3 -m venv venv` to create the environment.

### Optional virtual environment activation

In PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn web.app:app --host 127.0.0.1 --port 8000
```

If activation is blocked by script execution policy, use the direct-interpreter commands above. Alternatively, where permitted, change policy for the current terminal session and then install dependencies:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Organization-managed policies may take precedence. A new terminal needs activation again if you use the activation workflow.

In CMD, after creating the environment:

```bat
venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python -m uvicorn web.app:app --host 127.0.0.1 --port 8000
```

### Development server

```powershell
.\venv\Scripts\python.exe -m uvicorn web.app:app --host 127.0.0.1 --port 8000 --reload
```

Use `--reload` only while developing. A reload or server shutdown can interrupt an acquisition. The server stores the active view and progress in memory; persisted snapshots can be loaded again. Use one server worker. Acquisition and evidence selection operate on the Windows machine running Python, not on another device visiting the page.

## Acquisition modes

| Evidence | Quick (checkbox unchecked) | Extended (checkbox checked) |
| --- | --- | --- |
| System information | Yes | Yes |
| Processes: PID, PPID, name, path, username, creation time, command line, observation time | Yes, where accessible | Yes, where accessible |
| Unique executable paths: file size, timestamps, SHA-256 | Yes, where accessible | Yes, where accessible |
| Basic PE headers: machine code, subsystem, entry-point RVA, image base | Yes, where parseable | Yes, where parseable |
| Authenticode status, signature type and signer certificate fields | Not requested | Best effort |
| Process memory-mapped file paths | Not requested | Best effort, with process identity checks |

The API retains the parameter name `deep_analysis` for compatibility. Extended acquisition replaces the earlier “Full Endpoint Analysis” label. It does not collect network traffic, registry activity, Windows events, or malware indicators.

PE parsing uses `fast_load=True` and closes the PE object after reading headers. The architecture value is a hexadecimal PE machine identifier, not a human-readable CPU label. The entry point is an RVA, not an absolute virtual address.

No reproducible Windows benchmark is currently published. Duration varies with process count, file access, file sizes, and Windows signature verification. Signature collection has a **120-second subprocess timeout**; the total acquisition can take longer. New snapshots include stage timings and elapsed time in `metadata.json`.

## Dashboard

1. Click **Analyze Endpoint** and choose Quick or Extended acquisition.
2. Wait for completion; progress percentages represent stages, not an estimate of remaining time.
3. Select a recorded process to inspect executable metadata, signatures and mapped files.
4. Follow parent/child links within that snapshot.
5. Review the completion popup. When data is unavailable, it lists the missing fields, affected process counts, and expandable per-process details. The generic collection warnings are no longer displayed in the header. Per-record statuses remain available in the process details and JSON evidence.

The popup appears once when a new acquisition completes (including after reconnecting to an acquisition that is still running). Opening an already completed snapshot or importing old evidence does not display it again.

The process list describes the saved observation, not a live-updating process monitor. Importing evidence is blocked while an acquisition is running. Reloading the page reconnects to a running acquisition on the same server.

### Load existing evidence

Each successful acquisition publishes a directory under the repository's `evidence/` folder, independent of the terminal's working directory:

```text
evidence/<local-timestamp-with-microseconds>_<unique-id>/
    system.json
    processes.json
    executables.json
    metadata.json
    modules.json       # Extended acquisition only
```

Signature records are embedded in `executables.json`; there is no separate signatures file. `metadata.json` includes the schema version, requested mode, acquisition start, process observation time, collection finish, timings, collector summaries and warnings. It is not an evidence integrity manifest.

Use **Import Evidence** to select a directory already inside `evidence/`. This is a local folder selection, not a file-upload feature. To bring a snapshot from another installation, copy its entire directory into `evidence/` first. Use a folder name containing letters, digits, underscores, hyphens or dots, starting with a letter or digit.

Older snapshots without `metadata.json` or `modules.json` remain loadable. Missing legacy metadata is shown as unknown, rather than assumed complete. At startup, the dashboard attempts to load the most recent valid snapshot by folder name. Hidden acquisition staging folders and folders missing required files are excluded from selection. Failed acquisitions do not publish a new snapshot.

### Interpret missing data correctly

- `collection_status` distinguishes successful collection from partial results, access denial, terminated processes, reused PIDs, missing files, timeout and collector errors.
- Authenticode `status` is a separate Windows verification result. `NotSigned` is an observed result; an unavailable or failed check is **not** evidence that a file is unsigned.
- `Valid` is not a declaration that software is safe. Certificate dates describe the signer certificate, not a complete independent trust assessment.
- An empty mapped-file list after a failed collection does not establish absence of loaded files.
- Mapped paths can include executable images, DLLs and other mapped files. They are not restricted to DLLs; hashes, PE metadata and signatures for those paths are not collected yet.
- Files and processes can change during acquisition. A snapshot is collected over an interval, not an atomic image of the operating system. Executable metadata, hashes and signatures are separate reads of the file on disk, not of the running image in memory.

## Process relationships and identity

Process lookups use a PID map within one snapshot. Parent-child links use PID/PPID, excluding PID 0 as a parent, self-parent links, and candidate parents created after the child. Ancestry traversal detects cycles.

These checks reject obvious PID reuse but do not prove a historical parent relationship when timestamps are unavailable. Historical ancestry and lifecycle correlation remain planned. Module acquisition compares the live process creation time with the recorded creation time both before and after reading memory maps. Unverifiable or changed identities are reported and their mapped paths are discarded.

## CLI

The CLI uses the same acquisition and persistence code as the dashboard:

```powershell
.\venv\Scripts\python.exe main.py
.\venv\Scripts\python.exe main.py --deep-analysis
.\venv\Scripts\python.exe main.py --load .\evidence\<snapshot-folder>
```

`--deep-analysis` and `--load` are mutually exclusive. The interactive CLI displays the process tree and process details. Use the dashboard or JSON evidence files to inspect executable signatures and mapped-file records.

## Architecture

| Directory | Responsibility |
| --- | --- |
| `collectors/` | System, processes, executable files, Authenticode and memory-map collection |
| `acquisition/` | Snapshot orchestration, persistence, loading and collector summaries |
| `analysis/` | Snapshot process relationships and basic PE header parsing |
| `web/` | FastAPI routes, dashboard and static assets |
| `cli/` and `main.py` | Interactive CLI backed by shared acquisition |
| `evidence/` | Local snapshots; evidence contents are excluded from Git tracking |
| `tests/` | Regression tests and optional native Windows collector checks |

## Validation

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\venv\Scripts\python.exe -m unittest discover -s tests -v
```

If Node.js is installed, also run `node tests/test_frontend.js` to check rendering, escaping, connection failure handling and page-reload recovery.

Most regression tests isolate operating-system calls with mocks. Native Windows tests additionally exercise Windows PowerShell signatures and the current process's memory maps; they are skipped on other systems. Passing mocked tests does not establish native Windows coverage or collection performance.

## Roadmap and analysis philosophy

See [ROADMAP.md](ROADMAP.md) for implemented and planned features. Future analysis should correlate evidence with context and confidence. An unsigned file alone is not proof of malware. Network/registry/event acquisition, findings, timelines and ML are future work.

## Privacy, use and licensing

The application binds to localhost in the documented commands and contains no cloud analysis API integration. Windows handles Authenticode verification using its configured trust mechanisms. The dashboard has no authentication and is intended for local use.

Snapshots contain sensitive process paths, usernames and command lines. Collect only on systems you own or are explicitly authorized to investigate. The tool is intended for education, defensive research and endpoint investigation; it does not currently provide forensic chain-of-custody guarantees.

A redistribution license has not yet been selected; the repository does not currently contain a `LICENSE` file.
