"""Loopback lab boundary/restart tests. No actual proof, wallet or network."""
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import subprocess

import browser_feasibility as lab


class LabBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zolana-browser-lab-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in lab.WASM_NAMES:
            (self.root / name).write_bytes(b"synthetic fixture only")
        self.checker = self.root / "native-checker"
        self.checker.write_text("unit fixture only")
        self.start()

    def start(self):
        self.server = lab.LabServer(("127.0.0.1", 0), self.root, self.checker)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(2)
            self.server = None

    def request(self, method, path, body=None, headers=None):
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        self.addCleanup(client.close)
        client.request(method, path, body=body, headers=headers or {})
        response = client.getresponse()
        return response.status, dict(response.getheaders()), response.read()

    def post(self, payload, **headers):
        values = {"Origin": self.server.origin, "Content-Type": "application/json"}
        values.update(headers)
        return self.request("POST", "/api/verify", json.dumps(payload), values)

    def fixture(self):
        return {"format": "zolana-browser-synthetic-fixture-v1", "fixture_only": True, "network_hex": "ab" * 32,
                "funding_payload_hex": "aabb", "payment_payload_hex": "ccdd", "envelope_hex": "eeff",
                "timings_ms": {"funding_proof": 1.0, "payment_proof": 1.0, "local_verify": 1.0}}

    def test_static_config_and_no_arbitrary_files_or_query_paths(self):
        status, headers, content = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"synthetic", content)
        self.assertIn("'wasm-unsafe-eval'", headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(headers["Cache-Control"], "no-store")
        status, _, content = self.request("GET", "/api/config")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(content), {"test_only": True, "wasm_ready": True, "parallel_ready": False, "native_checker_ready": True})
        for path in ("/../Cargo.toml", "/wallet", "/api/config?any=thing", "/wasm/../Cargo.toml"):
            self.assertEqual(self.request("GET", path)[0], 404)

    def test_remote_host_origin_and_cross_site_are_refused_before_checker(self):
        with patch.object(lab, "verify_native") as verify:
            for headers in ({"Origin": "https://hostile.example"}, {"Host": "hostile.example"}, {"Sec-Fetch-Site": "cross-site"}):
                self.assertEqual(self.post(self.fixture(), **headers)[0], 403)
            self.assertEqual(self.request("POST", "/api/verify", "{}", {"Content-Type": "application/json"})[0], 403)
            verify.assert_not_called()
        with self.assertRaisesRegex(ValueError, "only"):
            lab.LabServer(("0.0.0.0", 0), self.root)

    def test_schema_secret_fields_bad_hex_and_content_type_fail_closed(self):
        with patch.object(lab, "verify_native") as verify:
            for payload in ([], {}, {**self.fixture(), "password": "must never reach checker"},
                            {**self.fixture(), "payment_payload_hex": "AA"}, {**self.fixture(), "network_hex": "wrong"},
                            {**self.fixture(), "timings_ms": {"funding_proof": float('nan'), "payment_proof": 1, "local_verify": 1}}):
                self.assertEqual(self.post(payload)[0], 400)
            self.assertEqual(self.post(self.fixture(), **{"Content-Type": "text/plain"})[0], 415)
            self.assertEqual(self.post(self.fixture(), **{"Content-Length": str(lab.MAX_FIXTURE_BYTES + 1)})[0], 413)
            verify.assert_not_called()

    def test_native_failure_and_busy_check_do_not_retry_and_restart_stays_usable(self):
        with patch.object(lab, "verify_native", side_effect=ValueError("fixture rejection")) as verify:
            self.assertEqual(self.post(self.fixture())[0], 400)
            self.assertEqual(verify.call_count, 1)
        self.server.verify_slot.acquire()
        try:
            self.assertEqual(self.post(self.fixture())[0], 429)
        finally:
            self.server.verify_slot.release()
        self.stop()
        self.start()
        with patch.object(lab, "verify_native", return_value={"ok": True, "checks": ["Native fixture verified"]}) as verify:
            status, _, content = self.post(self.fixture())
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(content)["ok"])
            self.assertEqual(verify.call_count, 1)

    def test_missing_wasm_and_checker_are_reported_without_fallback(self):
        (self.root / lab.WASM_NAMES[1]).unlink()
        self.checker.unlink()
        _, _, content = self.request("GET", "/api/config")
        self.assertFalse(json.loads(content)["wasm_ready"])
        self.assertFalse(json.loads(content)["native_checker_ready"])
        self.assertEqual(self.post(self.fixture())[0], 503)

    def test_native_checker_uses_exact_stdin_contract_and_rejects_false_success(self):
        response = {"ok": True, "format": "zolana-browser-native-parity-v1", "fixture_only": True,
                    "backing_after": 97, "commitments": 4, "checks": ["Fixture verified"]}
        def completed(value):
            return subprocess.CompletedProcess([str(self.checker)], 0, json.dumps(value).encode(), b"")
        with patch.object(lab.subprocess, "run", return_value=completed(response)) as run:
            self.assertTrue(lab.verify_native(self.checker, self.fixture())["ok"])
            self.assertEqual(run.call_args.args[0], [str(self.checker)])
            self.assertEqual(json.loads(run.call_args.kwargs["input"]), self.fixture())
            self.assertNotIn("shell", run.call_args.kwargs)
        for changed in ({"ok": True}, {**response, "fixture_only": False}, {**response, "backing_after": 100}, {**response, "checks": []}):
            with patch.object(lab.subprocess, "run", return_value=completed(changed)), self.assertRaises(ValueError):
                lab.verify_native(self.checker, self.fixture())

    def test_parallel_snippet_is_explicit_and_blob_policy_is_opt_in(self):
        _, headers, _ = self.request("GET", "/")
        self.assertNotIn("blob:", headers["Content-Security-Policy"])
        self.stop()
        snippet = "snippets/wasm-bindgen-rayon-aabbcc/src/workerHelpers.no-bundler.js"
        target = self.root / snippet
        target.parent.mkdir(parents=True)
        target.write_text("// explicit unit fixture helper")
        self.server = lab.LabServer(("127.0.0.1", 0), self.root, self.checker, self.root, [snippet])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        _, headers, content = self.request("GET", "/api/config")
        self.assertTrue(json.loads(content)["parallel_ready"])
        self.assertIn("worker-src 'self' blob:", headers["Content-Security-Policy"])
        self.assertEqual(self.request("GET", "/wasm-parallel/" + snippet)[0], 200)
        self.assertEqual(self.request("GET", "/wasm-parallel/snippets/other.js")[0], 404)
        for path in ("../outside.js", "snippets/arbitrary/helper.js"):
            with self.assertRaisesRegex(ValueError, "explicit"):
                lab.LabServer(("127.0.0.1", 0), self.root, self.checker, self.root, [path])
        with self.assertRaisesRegex(ValueError, "Explicit"):
            lab.LabServer(("127.0.0.1", 0), self.root, self.checker, self.root, [])


if __name__ == "__main__":
    unittest.main()
