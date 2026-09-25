# Endpoint Forensics

Endpoint Forensics is an open-source, local-first Windows security auditing and DFIR tool designed to collect, correlate, and visualize endpoint activity.

The goal is to provide detailed information about processes, files, network connections, Windows Registry changes, security events, and other endpoint activity through a simple local interface.

The project should remain:

* **Free and open source**
* **Local-first** — no cloud or external services required
* **Privacy-conscious** — endpoint evidence stays on the user's machine
* **Modular** — collectors and analysis components remain separated
* **Usable** — eventually accessible through a localhost web interface

---

## Roadmap

### v0.0.1 — Initial Process Collection ✅

* System information collection
* Running process collection
* Process tree
* Parent/child relationships
* Basic process investigation
* JSON evidence snapshots
* CLI interface

### v0.0.2 — Process Intelligence ✅

* Process ancestry
* Better timestamps and process lifetime
* Command-line arguments
* Process sessions and security context
* More detailed process metadata

### v0.0.3 — Executable Analysis ✅

* File size and timestamps
* SHA-256 hashes
* PE metadata
* Digital signatures
* Certificate and publisher information
* Loaded modules / DLLs

### v0.0.4 — Network & File Activity

* Active TCP/UDP connections
* Local and remote endpoints
* DNS activity
* File creation/modification/deletion
* Process-to-network correlation
* Process-to-file correlation

### v0.0.5 — Windows Registry & Persistence

* Registry changes
* Registry Run keys
* Startup folders
* Services
* Scheduled tasks
* Process-to-registry correlation

### v0.0.6 — Windows Security Events

* Windows Event Log collection
* Process creation events
* Logon events
* Failed logons
* Security-related events
* Event/process correlation

### v0.0.7 — Sysmon Integration

* Process creation
* Network connections
* Image/DLL loading
* Process access
* Registry activity
* File activity
* DNS activity
* Other relevant Sysmon telemetry

### v0.0.8 — Timeline & Correlation

* Unified endpoint timeline
* Cross-source event correlation
* Process ancestry + network + file + registry relationships
* Investigation context
* Evidence-based findings

### v0.1.0 — Complete Local Web Dashboard 🚀

* Localhost web interface
* Process explorer
* Search and filtering
* Process investigation pages
* Interactive process trees
* Network activity visualization
* Registry/file activity
* Timeline
* Findings and investigation summaries

### v0.2.0 — Machine Learning Model 

* (Long term goal - TBD)
  
---

## Long-Term Goal

Build a lightweight, open-source Windows endpoint investigation platform that helps users understand **what happened on a machine, which processes were involved, what they interacted with, and when those events occurred** — without requiring cloud infrastructure or paid services.
