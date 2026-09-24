# Endpoint Forensics

A local-first Windows endpoint investigation and forensic collection tool designed to capture, inspect, and correlate process and executable evidence through a lightweight web interface.

The project focuses on building a transparent DFIR-style workflow: **collect evidence first, analyze context second, and avoid treating individual indicators as definitive proof of malicious activity.**

---

## Overview

Endpoint Forensics collects information from a Windows system and organizes it into reusable evidence snapshots.

The application currently supports two acquisition modes:

### Quick Analysis

Designed for fast endpoint inspection.

Collects:

- System information
- Running processes
- PID / PPID relationships
- Process ancestry
- Process creation timestamps
- Command-line arguments
- Executable paths
- File metadata
- SHA-256 hashes
- Basic PE information

Typical execution time on the development system: **~4–5 seconds**.

### Full Endpoint Analysis

Extends the normal snapshot with additional security-related evidence.

Currently collects:

- Everything included in Quick Analysis
- Authenticode digital signature status
- Signer certificate information
- Certificate issuer
- Certificate thumbprint
- Certificate validity period
- Loaded modules / DLLs per process

Typical execution time on the development system: **~10–15 seconds**.

Additional behavioral indicators and correlation capabilities are planned for future versions.

---

## Web Interface

Endpoint Forensics includes a local FastAPI-based dashboard that allows the investigator to:

- Start a new endpoint analysis
- Choose between Quick and Full analysis modes
- Import previous evidence snapshots
- Browse running processes
- Inspect executable metadata
- Navigate parent and child process relationships
- Review command-line execution
- Inspect PE metadata
- Review digital signature and certificate information

The interface runs entirely on:

```text
localhost
```

No endpoint information is intentionally transmitted to an external service.

---

## Evidence Collection

Each analysis creates a timestamped evidence directory:

```text
evidence/
└── YYYY-MM-DD_HH-MM-SS/
    ├── system.json
    ├── processes.json
    ├── executables.json
    └── modules.json
```

`modules.json` is generated only during Full Endpoint Analysis.

Evidence snapshots can later be reloaded directly from the web interface.

---

## Process Relationships

Processes are indexed using in-memory mappings for fast lookup.

The application maintains structures similar to:

```text
PID → Process

Parent PID → Child Processes
```

This allows near constant-time lookup of processes and efficient traversal of:

```text
Process
├── Parent
│   └── Grandparent
│       └── ...
│
└── Children
    └── Descendants
```

For evidence that may span longer periods of time, process identity is also associated with creation timestamps because Windows may reuse process IDs.

---

## Executable Intelligence

For unique executables discovered during acquisition, Endpoint Forensics currently collects:

```text
Executable
├── Path
├── File name
├── File size
├── Creation time
├── Modification time
├── Access time
├── SHA-256
│
├── PE Metadata
│   ├── Architecture
│   ├── Subsystem
│   ├── Entry Point
│   └── Image Base
│
└── Digital Signature
    ├── Status
    ├── Signature Type
    ├── Subject
    ├── Issuer
    ├── Thumbprint
    ├── Valid From
    └── Valid Until
```

PE parsing uses lightweight header analysis during acquisition to reduce collection time while preserving the metadata currently required by the project.

---

## Loaded Modules

Full Endpoint Analysis also collects memory-mapped modules for running processes.

Example:

```text
Process
└── Loaded Modules
    ├── ntdll.dll
    ├── kernel32.dll
    ├── kernelbase.dll
    └── ...
```

Module evidence is associated with the process PID and creation time.

This will later allow the analysis layer to identify contextual signals such as modules loaded from unusual or user-writable locations.

---

## Architecture

The project separates evidence collection from analysis logic.

```text
endpoint-forensics/
│
├── acquisition/
│   └── Snapshot orchestration and evidence persistence
│
├── collectors/
│   ├── System information
│   ├── Processes
│   ├── Executables
│   ├── Digital signatures
│   └── Loaded modules
│
├── analysis/
│   ├── Process relationships
│   └── PE analysis
│
├── web/
│   ├── FastAPI backend
│   ├── Web interface
│   └── Static assets
│
├── evidence/
│   └── Local evidence snapshots
│
└── main.py
```

The general design principle is:

```text
Collectors
    ↓
Raw Evidence
    ↓
Analysis
    ↓
Indicators
    ↓
Correlation
    ↓
Findings
```

An individual indicator should not automatically be treated as evidence of malware.

---

## Installation

### Requirements

- Windows
- Python 3
- PowerShell

Clone the repository:

```bash
git clone https://github.com/wcopic/endpoint-forensics.git
cd endpoint-forensics
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Running the Application

Start the FastAPI server:

```bash
uvicorn web.app:app --reload
```

Then open:

```text
http://127.0.0.1:8000
```

From the dashboard you can either create a new endpoint analysis or load previously collected evidence.

---

## Current Technology

The project currently uses:

- Python
- FastAPI
- Uvicorn
- psutil
- pefile
- PowerShell
- HTML
- CSS
- JavaScript

---

## Roadmap

Planned areas of development include:

- Network connection collection
- Process-to-network correlation
- Deeper PE analysis
- DLL and module intelligence
- Digital signature analysis improvements
- Registry persistence
- Startup locations
- Windows services
- Scheduled tasks
- Windows Event Logs
- Sysmon integration
- Process lifecycle tracking
- Timeline generation
- Behavioral indicators
- LOLBin detection
- Suspicious command-line analysis
- Evidence correlation
- Severity and confidence-based findings
- Local investigation dashboard improvements

The long-term goal is to move from simple endpoint enumeration toward an evidence-driven local investigation tool capable of explaining **why** activity may deserve further investigation.

---

## Analysis Philosophy

Endpoint Forensics does not aim to classify software as malicious based on a single signal.

For example:

```text
Unsigned executable
        +
Execution from a user-writable directory
        +
Suspicious parent process
        +
Encoded PowerShell command
        +
Unexpected outbound connection
```

is significantly more useful than treating:

```text
Unsigned executable
```

alone as malware.

Future detection logic will therefore emphasize **correlation, confidence, context, and explainable findings**.

---

## Project Status

Endpoint Forensics is currently under active development.

The current versions primarily focus on building the acquisition layer and establishing the evidence model required for future behavioral analysis and timeline correlation.

Expect significant changes as additional collectors and analysis modules are introduced.

---

## Disclaimer

This project is intended for:

- Cybersecurity education
- Defensive security research
- Digital forensics experimentation
- Endpoint investigation
- Controlled laboratory environments

Use the tool only on systems that you own or are explicitly authorized to analyze.

---

## Author

Developed as a cybersecurity and systems engineering project focused on Windows endpoint forensics, DFIR concepts, and defensive security engineering.
