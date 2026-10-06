import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import psutil
from fastapi.testclient import TestClient

from acquisition import snapshot as snapshots
from analysis.collection_summary import collection_summary
from analysis.process_tree import build_process_tree, get_process_ancestors, get_process_details, print_process_tree
from collectors.executables import collect_file_metadata
from collectors.modules import collect_loaded_modules
from collectors.signatures import collect_signatures
from web import app as backend


def process(pid=10, parent=0, created=100.0):
    return {"pid": pid, "parent_pid": parent, "name": "process.exe",
            "path": "C:\\example.exe", "username": "user", "create_time": created,
            "command_line": ["process.exe"], "observed_at": "2026-10-06T12:00:00-05:00",
            "collection_status": "collected"}


def fixture(path, processes=None, modules=None, metadata=None):
    path.mkdir(parents=True, exist_ok=True)
    snapshots.save_json(path / "system.json", {"hostname": "test", "operating_system": "Windows"})
    snapshots.save_json(path / "processes.json", [process()] if processes is None else processes)
    snapshots.save_json(path / "executables.json", [{"path": "C:\\example.exe", "pe": None}])
    if modules is not None:
        snapshots.save_json(path / "modules.json", modules)
    if metadata is not None:
        snapshots.save_json(path / "metadata.json", metadata)
    return path


class CollectionNoticeTests(unittest.TestCase):
    def test_shared_executable_failures_count_each_process_once(self):
        processes = [process(10), process(11)]
        executables = [{"path": "C:\\example.exe", "collection_status": "access_denied",
                        "pe_collection_status": "unavailable",
                        "signature": {"collection_status": "timeout", "status": None}}]
        result = collection_summary(processes, executables, [])
        self.assertEqual(result["affected_process_count"], 2)
        self.assertTrue(all(issue["process_count"] == 2 for issue in result["issues"]))
        self.assertEqual(len(result["affected_processes"][0]["missing"]), 4)

    def test_exact_missing_process_fields_are_reported(self):
        item = process()
        item.update(collection_status="partial", unavailable_fields=["username", "cmdline"])
        result = collection_summary([item], [], [])
        self.assertEqual(result["affected_processes"][0]["missing"], ["Command line", "Username"])

    def test_unsigned_and_successful_empty_modules_do_not_warn(self):
        executable = {"path": "C:\\example.exe", "collection_status": "collected",
                      "pe_collection_status": "collected",
                      "signature": {"collection_status": "collected", "status": "NotSigned"}}
        module = {"pid": 10, "create_time": 100.0, "collection_status": "collected", "modules": []}
        self.assertEqual(collection_summary([process()], [executable], [module])["affected_process_count"], 0)

    def test_unrequested_and_legacy_unknown_data_do_not_create_failures(self):
        self.assertEqual(collection_summary([process()], [{"path": "C:\\example.exe"}], [])[
            "affected_process_count"], 0)

    def test_module_failure_matches_process_identity(self):
        module = {"pid": 10, "create_time": 100.0, "collection_status": "pid_reused", "modules": []}
        result = collection_summary([process()], [], [module])
        self.assertEqual(result["issues"], [{"label": "Memory-mapped file paths", "process_count": 1}])
        self.assertEqual(collection_summary([process(created=200.0)], [], [module])["affected_process_count"], 0)


class RelationshipTests(unittest.TestCase):
    def test_ancestry_and_children(self):
        data = [process(1, 0, 1), process(2, 1, 2), process(3, 2, 3)]
        mapping, children = build_process_tree(data)
        self.assertEqual([p["pid"] for p in get_process_ancestors(3, mapping)], [3, 2, 1])
        self.assertEqual(get_process_details(2, mapping, children)["children"], [data[2]])

    def test_reused_parent_pid_is_not_linked(self):
        mapping, children = build_process_tree([process(1, 0, 20), process(2, 1, 10)])
        self.assertIsNone(get_process_details(2, mapping, children)["parent"])
        self.assertEqual(children, {})

    def test_system_idle_and_self_parent_do_not_loop(self):
        mapping, children = build_process_tree([process(0, 0, 0), process(1, 1, 1)])
        self.assertEqual(children, {})
        self.assertEqual(len(get_process_ancestors(0, mapping)), 1)

    def test_cyclic_legacy_ancestry_and_tree_terminate(self):
        mapping, children = build_process_tree([process(1, 2, None), process(2, 1, None)])
        self.assertEqual(len(get_process_ancestors(1, mapping)), 2)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            print_process_tree(1, mapping, children)
        self.assertEqual(output.getvalue().count("PID:"), 2)


class ModuleTests(unittest.TestCase):
    def live(self, created=100.0):
        live = MagicMock()
        live.create_time.return_value = created
        live.memory_maps.return_value = [SimpleNamespace(path="C:\\A.dll"),
                                         SimpleNamespace(path="c:\\a.DLL"),
                                         SimpleNamespace(path="C:\\mapped.dat")]
        return live

    def test_mappings_are_deduplicated_and_data_files_retained(self):
        with patch("collectors.modules.psutil.Process", return_value=self.live()):
            record = collect_loaded_modules([process()])[10]
        self.assertEqual(record["collection_status"], "collected")
        self.assertEqual(len(record["modules"]), 2)

    def test_access_denied_is_not_successful_empty_collection(self):
        with patch("collectors.modules.psutil.Process", side_effect=psutil.AccessDenied(10)):
            record = collect_loaded_modules([process()])[10]
        self.assertEqual(record["collection_status"], "access_denied")
        self.assertEqual(record["modules"], [])

    def test_exit_is_reported(self):
        with patch("collectors.modules.psutil.Process", side_effect=psutil.NoSuchProcess(10)):
            self.assertEqual(collect_loaded_modules([process()])[10]["collection_status"], "process_exited")

    def test_reused_pid_before_collection_is_skipped(self):
        live = self.live(created=200)
        with patch("collectors.modules.psutil.Process", return_value=live):
            record = collect_loaded_modules([process()])[10]
        self.assertEqual(record["collection_status"], "pid_reused")
        live.memory_maps.assert_not_called()

    def test_reused_pid_during_collection_discards_paths(self):
        with patch("collectors.modules.psutil.Process", side_effect=[self.live(), self.live(200)]):
            record = collect_loaded_modules([process()])[10]
        self.assertEqual(record["collection_status"], "pid_reused")
        self.assertEqual(record["modules"], [])

    def test_unavailable_creation_time_skips_live_lookup(self):
        with patch("collectors.modules.psutil.Process") as lookup:
            record = collect_loaded_modules([process(created=None)])[10]
        lookup.assert_not_called()
        self.assertEqual(record["collection_status"], "identity_unverified")


class SignatureTests(unittest.TestCase):
    def collect(self):
        return collect_signatures([{"path": "C:\\José\\a.exe"}])["c:\\josé\\a.exe"]

    def test_timeout_is_not_unsigned(self):
        with patch("collectors.signatures.subprocess.run", side_effect=subprocess.TimeoutExpired("powershell", 120)):
            record = self.collect()
        self.assertEqual(record["collection_status"], "timeout")
        self.assertIsNone(record["status"])

    def test_missing_windows_powershell(self):
        with patch("collectors.signatures.subprocess.run", side_effect=FileNotFoundError()):
            self.assertEqual(self.collect()["collection_status"], "unavailable")

    def test_nonzero_exit_is_reported(self):
        with patch("collectors.signatures.subprocess.run", return_value=SimpleNamespace(returncode=1, stderr="failure", stdout="")):
            record = self.collect()
        self.assertEqual(record["error"], "failure")
        self.assertIsNone(record["status"])

    def test_utf8_output_and_ascii_json_input(self):
        data = {"path": "C:\\José\\a.exe", "subject": "CN=José", "status": "NotSigned",
                "collection_status": "collected", "error": None}
        with patch("collectors.signatures.subprocess.run", return_value=SimpleNamespace(
                returncode=0, stderr="", stdout=json.dumps(data, ensure_ascii=False))) as run:
            record = self.collect()
        self.assertEqual(record["subject"], "CN=José")
        self.assertEqual(run.call_args.kwargs["encoding"], "utf-8")
        run.call_args.kwargs["input"].encode("ascii")
        self.assertEqual(record["status"], "NotSigned")

    def test_malformed_or_missing_results_are_errors(self):
        for output in ("not json", "null", "[]", '[{"path":"C:\\\\José\\\\a.exe"}]'):
            with self.subTest(output=output), patch("collectors.signatures.subprocess.run", return_value=SimpleNamespace(
                    returncode=0, stderr="", stdout=output)):
                self.assertEqual(self.collect()["collection_status"], "error")

    def test_no_paths_does_not_start_subprocess(self):
        with patch("collectors.signatures.subprocess.run") as run:
            self.assertEqual(collect_signatures([]), {})
        run.assert_not_called()


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def capture(self, deep=False, processes=None):
        p = process()
        executable = {"path": p["path"], "collection_status": "collected"}
        signature = {"path": p["path"], "collection_status": "timeout", "status": None, "error": "Timeout"}
        module = {"pid": p["pid"], "create_time": p["create_time"], "modules": [],
                  "collection_status": "access_denied", "error": "Access denied"}
        with patch.multiple(snapshots,
                            collect_system_info=MagicMock(return_value={"hostname": "test"}),
                            collect_processes=MagicMock(return_value=[p] if processes is None else processes),
                            collect_executables=MagicMock(return_value=[executable]),
                            analyze_pe=MagicMock(return_value={"architecture": "0x8664"}),
                            collect_signatures=MagicMock(return_value={p["path"].lower(): signature}),
                            collect_loaded_modules=MagicMock(return_value={p["pid"]: module})), contextlib.redirect_stdout(io.StringIO()):
            return snapshots.capture_snapshot(deep_analysis=deep, evidence_dir=self.root)

    def test_extended_roundtrip_preserves_failures_and_timestamps(self):
        result = self.capture(deep=True)
        loaded = snapshots.load_snapshot(result["evidence_path"])
        self.assertEqual(loaded["metadata"], result["metadata"])
        self.assertEqual(loaded["module_map"][(10, 100.0)]["collection_status"], "access_denied")
        self.assertEqual(loaded["metadata"]["collectors"]["signatures"]["status"], "partial")
        self.assertEqual(len(loaded["metadata"]["warnings"]), 2)
        self.assertGreaterEqual(loaded["metadata"]["finished_at"], loaded["metadata"]["captured_at"])

    def test_quick_mode_skips_extended_files(self):
        result = self.capture()
        directory = Path(result["evidence_path"])
        self.assertFalse((directory / "modules.json").exists())
        self.assertNotIn("signature", result["executables"][0])
        self.assertEqual(result["metadata"]["collectors"]["modules"]["status"], "skipped")

    def test_empty_process_snapshot_keeps_capture_time(self):
        result = self.capture(processes=[])
        self.assertEqual(snapshots.load_snapshot(result["evidence_path"])["captured_at"], result["captured_at"])

    def test_failed_capture_does_not_publish_or_leave_pending_folder(self):
        with patch.object(snapshots, "collect_system_info", side_effect=RuntimeError("failure")):
            with self.assertRaises(RuntimeError):
                snapshots.capture_snapshot(evidence_dir=self.root)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_repeated_captures_do_not_overwrite(self):
        first, second = self.capture(), self.capture()
        self.assertNotEqual(first["evidence_path"], second["evidence_path"])
        self.assertEqual(len(list(self.root.iterdir())), 2)

    def test_legacy_evidence_does_not_claim_verified_modules(self):
        path = fixture(self.root / "old", modules=[{"pid": 10, "create_time": 100.0, "modules": []}])
        loaded = snapshots.load_snapshot(path)
        self.assertEqual(loaded["metadata"]["analysis_mode"], "legacy_unknown")
        self.assertEqual(loaded["module_map"][(10, 100.0)]["collection_status"], "legacy_unknown")

    def test_invalid_process_identity_is_rejected(self):
        for invalid in ("<script>", -1, True):
            with self.subTest(pid=invalid):
                path = fixture(self.root / "invalid", processes=[process(pid=invalid)])
                with self.assertRaises(ValueError):
                    snapshots.load_snapshot(path)

    def test_missing_executable_file_has_explicit_status(self):
        result = collect_file_metadata(self.root / "absent.exe")
        self.assertEqual(result["collection_status"], "file_missing")
        self.assertIsNone(result["sha256"])

    def test_file_hash_and_size(self):
        file = self.root / "file.exe"
        file.write_bytes(b"abc")
        result = collect_file_metadata(file)
        self.assertEqual(result["size"], 3)
        self.assertEqual(result["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.evidence_patch = patch.object(backend, "EVIDENCE_DIR", self.root)
        self.evidence_patch.start()
        self.old_snapshot = backend.CURRENT_SNAPSHOT
        self.old_state = backend.STATE.copy()
        backend.CURRENT_SNAPSHOT = None
        backend.STATE.update(status="idle", error=None, warnings=[], started_at=None, finished_at=None)
        self.client = TestClient(backend.app)

    def tearDown(self):
        backend.CURRENT_SNAPSHOT = self.old_snapshot
        backend.STATE.clear()
        backend.STATE.update(self.old_state)
        self.evidence_patch.stop()
        self.client.close()
        self.temp.cleanup()

    def test_details_without_snapshot_returns_404(self):
        self.assertEqual(self.client.get("/api/processes/10").status_code, 404)

    def test_modules_reach_process_details_api(self):
        fixture(self.root / "snapshot", modules=[{"pid": 10, "create_time": 100.0,
                "modules": [{"path": "C:\\A.dll"}], "collection_status": "collected"}])
        self.assertEqual(self.client.post("/api/evidence/snapshot").status_code, 200)
        result = self.client.get("/api/processes/10").json()
        self.assertEqual(result["module_record"]["modules"][0]["path"], "C:\\A.dll")
        self.assertEqual(self.client.get("/api/processes/99").status_code, 404)

    def test_import_and_duplicate_start_are_blocked_while_running(self):
        fixture(self.root / "snapshot")
        backend.STATE["status"] = "running"
        self.assertEqual(self.client.post("/api/evidence/snapshot").status_code, 409)
        self.assertEqual(self.client.post("/api/analyze", json={}).status_code, 409)

    def test_home_does_not_load_old_evidence_during_capture(self):
        fixture(self.root / "snapshot")
        backend.STATE["status"] = "running"
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertIsNone(backend.CURRENT_SNAPSHOT)
        self.assertEqual(backend.STATE["status"], "running")

    def test_pending_and_incomplete_directories_are_hidden(self):
        fixture(self.root / "valid")
        fixture(self.root / ".pending-test")
        (self.root / "incomplete").mkdir()
        self.assertEqual(self.client.get("/api/evidence").json(), {"evidence": [{"name": "valid"}]})

    def test_corrupt_newest_snapshot_does_not_hide_valid_older(self):
        fixture(self.root / "a-valid")
        fixture(self.root / "z-invalid", processes=[process(pid="bad")])
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertTrue(backend.CURRENT_SNAPSHOT["evidence_path"].endswith("a-valid"))

    def test_invalid_json_import_returns_400_and_keeps_old_snapshot(self):
        old = snapshots.load_snapshot(fixture(self.root / "valid"))
        backend.CURRENT_SNAPSHOT = old
        path = fixture(self.root / "invalid")
        (path / "processes.json").write_text("not json")
        self.assertEqual(self.client.post("/api/evidence/invalid").status_code, 400)
        self.assertIs(backend.CURRENT_SNAPSHOT, old)

    def test_snapshot_name_and_symlink_are_restricted(self):
        self.assertEqual(self.client.post("/api/evidence/bad%20name").status_code, 400)
        with tempfile.TemporaryDirectory() as external:
            target = fixture(Path(external) / "outside")
            try:
                (self.root / "linked").symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("Symlinks unavailable on this host.")
            self.assertEqual(self.client.post("/api/evidence/linked").status_code, 400)
            self.assertEqual(self.client.get("/api/evidence").json()["evidence"], [])

    def test_default_request_starts_quick_acquisition(self):
        with patch.object(backend, "Thread") as thread:
            self.assertEqual(self.client.post("/api/analyze", json={}).status_code, 200)
        self.assertEqual(thread.call_args.kwargs["args"], (False,))
        self.assertEqual(backend.STATE["analysis_mode"], "quick")

    def test_finish_time_comes_from_completion_not_capture(self):
        snapshot = snapshots.load_snapshot(fixture(self.root / "finished", metadata={
            "schema_version": 1, "analysis_mode": "quick", "warnings": [],
            "started_at": "2026-10-06T12:00:00-05:00", "captured_at": "2026-10-06T12:00:01-05:00",
            "finished_at": "2026-10-06T12:00:10-05:00"}))
        with patch.object(backend, "capture_snapshot", return_value=snapshot):
            backend.run_analysis()
        self.assertEqual(backend.STATE["finished_at"], "2026-10-06T12:00:10-05:00")


@unittest.skipUnless(os.name == "nt", "Native Windows collector validation requires Windows.")
class NativeWindowsTests(unittest.TestCase):
    def test_unsigned_script_unicode_path_and_missing_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "prueba_á_日.ps1"
            path.write_text("Write-Output 'test'", encoding="utf-8")
            absent = Path(root) / "missing.ps1"
            records = collect_signatures([{"path": str(path)}, {"path": str(absent)}])
            self.assertEqual(records[str(path).lower()]["collection_status"], "collected")
            self.assertEqual(records[str(path).lower()]["status"], "NotSigned")
            self.assertEqual(records[str(absent).lower()]["collection_status"], "error")

    def test_current_process_memory_maps(self):
        live = psutil.Process()
        record = collect_loaded_modules([{"pid": live.pid, "create_time": live.create_time()}])[live.pid]
        self.assertEqual(record["collection_status"], "collected")
        self.assertTrue(record["modules"])


if __name__ == "__main__":
    unittest.main()
