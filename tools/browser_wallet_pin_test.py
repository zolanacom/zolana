"""Network pin of a browser wallet bundle: rendering, strict reading and stamping.

Synthetic public network identities only; no chain, wallet or gateway process.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import browser_gateway as gateway
import browser_wallet_pin as pin

LOCAL = {"network": [7] * 32, "genesis_hash": "1" * 32}
OTHER = {"network": [9] * 32, "genesis_hash": "2" * 32}


def profile(network):
    return dict(format="native-wallet-profile-v1", key_mode="user-wallet-v1",
                network=network["network"], genesis_hash=network["genesis_hash"],
                label="Disposable pin test", invite_required=True, program="7" * 32, pool="8" * 32,
                pool_format="NPOOL004", private_send_transport="native-inline-v1",
                rpc=dict(transport="https", url="https://rpc.fixture.invalid/"),
                faucet=dict(transport="https", url="https://admission.fixture.invalid/"))


class RenderingTests(unittest.TestCase):
    def test_rendering_is_deterministic_and_reads_back_exactly(self):
        raw = pin.render(LOCAL, "testnet")
        self.assertEqual(raw, pin.render(dict(reversed(list(LOCAL.items()))), "testnet"))
        self.assertEqual(pin.parse(raw), {"environment": "testnet", "network": LOCAL})
        self.assertNotEqual(raw, pin.render(OTHER, "testnet"))
        self.assertNotEqual(raw, pin.render(LOCAL, "mainnet"))
        self.assertTrue(raw.endswith(b");\n"))
        self.assertLess(len(raw), 512)

    def test_invalid_identities_and_environments_are_refused(self):
        for value in (None, [], {"network": [7] * 32}, dict(LOCAL, extra=1),
                      dict(LOCAL, network=[7] * 31), dict(LOCAL, network=[0] * 32),
                      dict(LOCAL, network=[7] * 31 + [256]), dict(LOCAL, network=[7] * 31 + [True]),
                      dict(LOCAL, genesis_hash="0" * 32), dict(LOCAL, genesis_hash="1" * 31),
                      dict(LOCAL, genesis_hash="1" * 45), dict(LOCAL, genesis_hash=7)):
            with self.assertRaises(ValueError):
                pin.render(value, "testnet")
        for environment in ("devnet", "", None, "Testnet"):
            with self.assertRaises(ValueError):
                pin.render(LOCAL, environment)

    def test_only_the_generated_form_is_read(self):
        raw = pin.render(LOCAL, "testnet")
        body = json.dumps({"format": pin.PIN_FORMAT, "environment": "testnet", "network": LOCAL},
                          separators=(",", ":"))
        for changed in (raw + b"\n", raw[:-1], raw.replace(b"Object.freeze", b"Object.assign"),
                        raw.replace(b"// Network pin", b"// network pin"),
                        raw + b"export const extra = 1;\n", b"\xff" + raw,
                        raw.replace(b'"testnet"', b'"devnet"'),
                        raw.replace(b'"genesis_hash"', b'"genesis_hash":"' + b"2" * 32 + b'","genesis_hash"'),
                        (pin.HEADER + f"export default Object.freeze({body});\n").encode()):
            with self.assertRaises(ValueError):
                pin.parse(changed)

    def test_profile_states_the_network(self):
        self.assertEqual(pin.profile_network(profile(OTHER)), OTHER)
        for value in (None, {}, dict(profile(LOCAL), format="native-wallet-profile-v0"),
                      {k: v for k, v in profile(LOCAL).items() if k != "genesis_hash"}):
            with self.assertRaises(ValueError):
                pin.profile_network(value)


class StampTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "bundle"
        self.root.mkdir()
        (self.root / "index.html").write_bytes(b"reviewed")
        self.manifest = self.root.parent / "assets.json"
        item = dict(path="index.html", sha256=hashlib.sha256(b"reviewed").hexdigest())
        self.manifest.write_bytes(json.dumps(dict(format="zolana-browser-assets-v1", assets={"/": item})).encode())

    def bundle(self):
        raw = self.manifest.read_bytes()
        return gateway.assets(self.root, raw, hashlib.sha256(raw).hexdigest())

    def test_stamped_bundle_is_served_only_for_its_network(self):
        result = pin.stamp(self.root, pin.render(LOCAL, "testnet"), self.manifest)
        self.assertEqual(result["pin_sha256"], hashlib.sha256((self.root / "network-pin.js").read_bytes()).hexdigest())
        self.assertEqual(result["assets_sha256"], hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        bundle = self.bundle()
        self.assertEqual(bundle["/network-pin.js"], (pin.render(LOCAL, "testnet"), "text/javascript; charset=utf-8"))
        self.assertEqual(bundle["/"][0], b"reviewed")
        app = gateway.BrowserGateway(profile(LOCAL), bundle)
        try:
            self.assertEqual(app.config()["network"], LOCAL)
            self.assertEqual(app.config()["environment"], "testnet")
        finally:
            app.close()
        with self.assertRaisesRegex(ValueError, "pinned to a different network"):
            gateway.BrowserGateway(profile(OTHER), bundle)
        for network in (dict(LOCAL, genesis_hash=OTHER["genesis_hash"]), dict(LOCAL, network=OTHER["network"])):
            with self.assertRaisesRegex(ValueError, "pinned to a different network"):
                gateway.BrowserGateway(profile(network), bundle)

    def test_a_mainnet_or_hand_edited_pin_is_not_served_by_this_gateway(self):
        for raw in (pin.render(LOCAL, "mainnet"), pin.render(LOCAL, "testnet") + b"// edited\n"):
            pin.stamp(self.root, raw, self.manifest)
            with self.assertRaisesRegex(ValueError, "pinned to a different network"):
                gateway.BrowserGateway(profile(LOCAL), self.bundle())

    def test_a_bundle_without_a_pin_is_still_served(self):
        app = gateway.BrowserGateway(profile(LOCAL), self.bundle())
        app.close()

    def test_restamping_replaces_the_pin_and_changes_the_manifest_digest(self):
        first = pin.stamp(self.root, pin.render(LOCAL, "testnet"), self.manifest)
        again = pin.stamp(self.root, pin.render(LOCAL, "testnet"), self.manifest)
        self.assertEqual(first, again)
        second = pin.stamp(self.root, pin.render(OTHER, "testnet"), self.manifest)
        self.assertNotEqual(first["assets_sha256"], second["assets_sha256"])
        self.assertEqual(pin.parse(self.bundle()["/network-pin.js"][0])["network"], OTHER)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["index.html", "network-pin.js"])

    def test_stamp_refuses_unsafe_targets_and_foreign_manifests_without_writing(self):
        raw = pin.render(LOCAL, "testnet")
        with self.assertRaises(ValueError):
            pin.stamp(self.root / "missing", raw)
        self.manifest.write_bytes(b'{"format":"other","assets":{}}')
        with self.assertRaises(ValueError):
            pin.stamp(self.root, raw, self.manifest)
        self.assertFalse((self.root / "network-pin.js").exists())
        (self.root / "network-pin.js").symlink_to(self.root / "index.html")
        with self.assertRaises(ValueError):
            pin.stamp(self.root, raw)
        self.assertEqual((self.root / "index.html").read_bytes(), b"reviewed")

    def test_command_requires_the_reviewed_profile_digest_and_an_explicit_environment(self):
        path = self.root.parent / "profile.json"
        path.write_bytes(json.dumps(profile(LOCAL)).encode())
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        command = [sys.executable, "-B", str(Path(pin.__file__).resolve()), "--profile", str(path),
                   "--assets-root", str(self.root), "--assets-manifest", str(self.manifest)]
        refused = subprocess.run(command + ["--profile-sha256", "0" * 64, "--environment", "testnet"],
                                 capture_output=True, text=True, timeout=30)
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse((self.root / "network-pin.js").exists())
        missing = subprocess.run(command + ["--profile-sha256", digest], capture_output=True, text=True, timeout=30)
        self.assertNotEqual(missing.returncode, 0)
        done = subprocess.run(command + ["--profile-sha256", digest, "--environment", "testnet"],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        report = json.loads(done.stdout)
        self.assertEqual(report["genesis_hash"], LOCAL["genesis_hash"])
        self.assertEqual(report["assets_sha256"], hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        self.assertEqual((self.root / "network-pin.js").read_bytes(), pin.render(LOCAL, "testnet"))


if __name__ == "__main__":
    unittest.main()
