# Endpoint Forensics Roadmap

Endpoint Forensics currently collects and displays local Windows process and executable evidence. The milestones below describe feature scope, not published release guarantees. Checked items are implemented; collection remains best effort.

## v0.0.1 — Initial Process Collection

- [x] System information and running process collection
- [x] Snapshot process tree and parent/child navigation
- [x] JSON evidence persistence
- [x] Interactive CLI

## v0.0.2 — Process Context (partially implemented)

- [x] Snapshot ancestry traversal with cycle protection
- [x] Process creation and snapshot observation timestamps
- [x] Command-line arguments, executable path and username
- [x] Reject candidate parents created after the child
- [ ] Process session IDs
- [ ] Security token, integrity level and elevation context
- [ ] Process termination events and lifetime tracking
- [ ] Historical ancestry across observations, with verified process identities

## v0.0.3 — Executable and Extended Acquisition

- [x] File size, timestamps and SHA-256; report inaccessible/missing files
- [x] Basic PE header metadata with lightweight parsing
- [x] Extended-mode Authenticode status and signer certificate fields
- [x] Extended-mode process memory-mapped file paths
- [x] Verify process creation time before and after memory-map collection
- [x] Persist collector statuses and acquisition metadata
- [x] Display signature and mapped-file evidence in the dashboard
- [x] Shared CLI/web acquisition, including Extended mode and snapshot loading
- [ ] Identify image/DLL mappings separately from other mapped files
- [ ] Hash, signature and PE analysis of mapped files
- [ ] Stronger executable identity consistency across file metadata/hash/signature reads
- [ ] Evidence integrity manifest and chain-of-custody support
- [ ] Reproducible Windows benchmarks and broader native Windows validation

## v0.0.4 — Network and File Activity

- [ ] Active TCP/UDP connections and local/remote endpoints
- [ ] Process-to-network correlation
- [ ] DNS activity from a defined telemetry source
- [ ] File creation/modification/deletion events
- [ ] Process-to-file correlation

Connection snapshots and file/DNS event monitoring need separate collectors and explicit coverage limits.

## v0.0.5 — Windows Registry and Persistence

- [ ] Registry Run keys and startup folders
- [ ] Windows services and scheduled tasks
- [ ] Registry change telemetry
- [ ] Process-to-registry correlation

## v0.0.6 — Windows Security Events

- [ ] Event Log collection with documented audit prerequisites
- [ ] Process creation, logon, failed-logon and security events
- [ ] Event/process correlation

## v0.0.7 — Sysmon Integration

- [ ] Optional Sysmon telemetry import with configuration prerequisites
- [ ] Process creation and image/DLL loading
- [ ] Network, DNS, file, registry and process-access events

## v0.0.8 — Timeline and Correlation

- [ ] Unified timeline with source-specific timestamps
- [ ] Cross-source process, file, network and registry relationships
- [ ] Explainable behavioral indicators
- [ ] Findings with severity, confidence and supporting evidence
- [ ] Suspicious command-line and LOLBin analysis with contextual checks

## v0.1.0 — Expanded Local Dashboard

- [x] Localhost dashboard and process explorer
- [x] Snapshot selection and parent/child navigation
- [x] Executable, certificate and mapped-file views
- [x] Partial-collection warnings and progress recovery after page reload
- [ ] Search and filtering
- [ ] Interactive tree visualization
- [ ] Network, registry and file activity views
- [ ] Timeline, findings and investigation summaries

## v0.2.0 — Machine Learning Research (long term, scope TBD)

- [ ] Define a task that benefits from a model and a baseline to compare against
- [ ] Establish representative, labeled data and evaluation criteria
- [ ] Assess false positives, explanations and local resource requirements

The goal is an accessible local investigation tool that helps explain endpoint activity through evidence and context. Malware classification is not a current capability. A repository license remains to be selected by the author.
