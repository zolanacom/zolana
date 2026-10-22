import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from package_wallet import archive, main, public_profile
from wallet_launch import verify
from wallet_ui import WalletApp


class TesterPackageTests(unittest.TestCase):
    def config(self):
        return {"format": "native-wallet-profile-v1", "label": "Test network", "key_mode": "user-wallet-v1",
                "network": [7] * 32, "genesis_hash": "1" * 32, "program": "public-program", "pool": "public-pool",
                "pool_format": "NPOOL003", "recipient_withdrawals": True,
                "rpc": {"transport": "loopback-http", "url": "http://127.0.0.1:18899"}}

    def validated(self, config=None):
        return type("Completed", (), {"returncode": 0, "stdout": json.dumps(config or self.config())})()

    def test_public_export_is_an_allowlist_and_never_exports_operator_fields(self):
        config = {**self.config(), "roles": {"treasury": "private-role"}, "secret": "secret-value", "fixture_keys_are_public": False}
        exported = public_profile(config, "Invite", "https://rpc.example.invalid", "https")
        self.assertNotIn("private-role", json.dumps(exported))
        self.assertNotIn("secret-value", json.dumps(exported))
        self.assertNotIn("fixture_keys_are_public", exported)

    def test_native_export_preserves_explicit_modes_without_exporting_endpoint_or_authority(self):
        config = {**self.config(), "pool_format": "NPOOL004",
                  "private_send_transport": "native-inline-v1", "retained_history_format": "compact-v2",
                  "relay": {"password_file": "operator-secret"}, "invite_required": True,
                  "faucet": {"url": "https://old-endpoint.invalid"}, "local_tls_ca_pem": "not-selected"}
        exported = public_profile(config, "Native testnet", "https://new-endpoint.invalid", "https")
        self.assertEqual(exported['private_send_transport'], 'native-inline-v1')
        self.assertEqual(exported['retained_history_format'], 'compact-v2')
        self.assertEqual(exported['rpc']['url'], 'https://new-endpoint.invalid')
        for key in ('relay', 'faucet', 'local_tls_ca_pem', 'invite_required'):
            self.assertNotIn(key, exported)  # Deployment selection remains explicit CLI input.

    def test_legacy_export_does_not_invent_native_modes(self):
        for config in (self.config(), {**self.config(), 'private_send_transport': None,
                                      'retained_history_format': None}):
            exported = public_profile(config, "Legacy", "https://rpc.example.invalid", "https")
            self.assertNotIn('private_send_transport', exported)
            self.assertNotIn('retained_history_format', exported)
            self.assertNotIn('access_audiences', exported)

    def test_public_export_preserves_explicit_network_bound_access_audiences(self):
        config = self.config()
        aliases = dict(format='native-access-audiences-v1', network=config['network'],
                       genesis_hash=config['genesis_hash'], rpc='https://127.0.0.1:39443',
                       faucet='https://127.0.0.1:39444')
        exported = public_profile({**config, 'access_audiences': aliases},
                                  'Public pilot', 'https://pilot.example.invalid', 'https')
        self.assertEqual(exported['access_audiences'], aliases)
        self.assertEqual(exported['rpc']['url'], 'https://pilot.example.invalid')
        self.assertEqual(config['rpc']['url'], 'http://127.0.0.1:18899')

    def test_public_export_rejects_null_partial_or_private_alias_fields(self):
        for aliases in (None, {}, {'rpc': 'https://127.0.0.1:39443'},
                        dict(format='native-access-audiences-v1', network=[7]*32,
                             genesis_hash='1'*32, rpc='https://127.0.0.1:39443',
                             faucet='https://127.0.0.1:39444', password='must-not-export')):
            with self.subTest(aliases=aliases), self.assertRaises(ValueError):
                public_profile({**self.config(), 'access_audiences': aliases},
                               'Public pilot', 'https://pilot.example.invalid', 'https')

    def test_standalone_storage_is_private_and_bound_to_profile_without_overwrite(self):
        with tempfile.TemporaryDirectory() as name, patch("wallet_ui.subprocess.run", return_value=self.validated()):
            root = Path(name) / "state"
            app = WalletApp.from_profile(Path("profile.json"), root)
            pending = Path(str(app.wallet) + ".pending.json")
            pending.write_text("preserved journal")
            again = WalletApp.from_profile(Path("profile.json"), root)
            self.assertEqual(again.status()["network"], "Test network")
            self.assertFalse(again.status()["operator_sponsor_available"])
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(app.network_file.stat().st_mode & 0o777, 0o600)
            changed = self.config()
            changed["rpc"]["url"] = "http://127.0.0.1:19899"
            with patch("wallet_ui.subprocess.run", return_value=self.validated(changed)):
                with self.assertRaisesRegex(ValueError, "different profile"):
                    WalletApp.from_profile(Path("other.json"), root)
            self.assertEqual(pending.read_text(), "preserved journal")

    def test_standalone_refuses_symlinks_and_shared_storage(self):
        with tempfile.TemporaryDirectory() as name, patch("wallet_ui.subprocess.run", return_value=self.validated()):
            root = Path(name) / "state"
            root.mkdir(mode=0o755)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                WalletApp.from_profile(Path("profile.json"), root)
            link = Path(name) / "link"
            link.symlink_to(root)
            with self.assertRaisesRegex(ValueError, "symlink"):
                WalletApp.from_profile(Path("profile.json"), link)
            root.chmod(0o700)
            (root / "network.json").symlink_to(Path(name) / "external")
            with self.assertRaises(OSError):
                WalletApp.from_profile(Path("profile.json"), root)

    def test_standalone_cannot_redirect_rpc_or_use_operator_sponsorship(self):
        with tempfile.TemporaryDirectory() as name, patch("wallet_ui.subprocess.run", return_value=self.validated()):
            app = WalletApp.from_profile(Path("profile.json"), Path(name) / "state")
            app.ack.touch()
            with self.assertRaisesRegex(ValueError, "Operator sponsorship"):
                app.action({"action": "fund"})
            self.assertTrue(app.status()["user_paid_sends"])
            with patch.object(app,"cli",return_value={}) as cli:
                app.action({"action":"send","password":"test-password-long","amount":1,"recipient":"npriv1example","fee_mode":"user","max_fee_debit":150000000})
                self.assertEqual(cli.call_args.args[0],"send")
                self.assertNotIn("--sponsor",cli.call_args.args[2])
            with patch("wallet_ui.subprocess.run", return_value=self.validated()) as run:
                app.cli("address", "test-password-long")
                self.assertNotIn("--rpc", run.call_args.args[0])
                self.assertEqual(run.call_args.kwargs["input"], "test-password-long")

    def bundle(self, root):
        (root / "asset").write_bytes(b"content")
        manifest = {"format": "native-wallet-bundle-v1", "platform": f"{platform.system().lower()}-{platform.machine().lower()}",
                    "files": {"asset": {"size": 7, "sha256": hashlib.sha256(b"content").hexdigest()}}}
        (root / "MANIFEST.json").write_text(json.dumps(manifest))

    def test_integrity_rejects_modified_added_and_symlinked_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.bundle(root)
            verify(root)
            (root / "asset").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "integrity"):
                verify(root)
            (root / "asset").write_bytes(b"content")
            (root / "extra").touch()
            with self.assertRaisesRegex(ValueError, "inventory"):
                verify(root)
            (root / "extra").unlink()
            (root / "extra").symlink_to(root / "asset")
            with self.assertRaisesRegex(ValueError, "symlink"):
                verify(root)

    def test_archive_bytes_are_deterministic_regardless_of_input_order(self):
        self.assertEqual(archive({"a": b"one", "b": b"two"}, {}), archive({"b": b"two", "a": b"one"}, {}))


@unittest.skipUnless(os.environ.get('WALLET_PACKAGE_TEST_BINARY') and os.environ.get('WALLET_PACKAGE_TEST_PROFILE'),
                     'set explicit pinned wallet binary/public profile for offline canonical-parser acceptance')
class NativePackageAcceptanceTests(unittest.TestCase):
    """Actual wallet parser, archive and launcher integrity; no RPC or wallet seeds."""

    def setUp(self):
        self.binary = Path(os.environ['WALLET_PACKAGE_TEST_BINARY']).resolve(strict=True)
        self.profile = json.loads(Path(os.environ['WALLET_PACKAGE_TEST_PROFILE']).read_text())
        self.assertEqual(self.profile['private_send_transport'], 'native-inline-v1')
        self.assertEqual(self.profile['retained_history_format'], 'compact-v2')

    def package_args(self, root, config):
        network = root / 'network.json'
        network.write_text(json.dumps(config))
        ca = root / 'test-ca.pem'
        ca.write_text(config['local_tls_ca_pem'])
        return ['package_wallet', '--network', str(network), '--label', 'Native package acceptance',
                '--rpc', config['rpc']['url'], '--transport', 'https', '--invite-only',
                '--faucet', config['faucet']['url'], '--local-tls-ca', str(ca),
                '--binary', str(self.binary), '--output', str(root / 'wallet.tgz')]

    def test_real_native_archive_round_trip_and_legacy_profile(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            args = self.package_args(root, {**self.profile, 'operator_secret': 'NEVER EXPORT THIS'})
            # Dependency notice enumeration is independent of profile handling;
            # real binary, parser, UI assets, manifest and archive remain in use.
            with patch('sys.argv', args), patch('package_wallet.dependencies', return_value={}), contextlib.redirect_stdout(io.StringIO()):
                main()
            with tarfile.open(root / 'wallet.tgz', 'r:gz') as bundle:
                exported = json.load(bundle.extractfile('native-wallet/wallet-profile.json'))
                self.assertNotIn('operator_secret', exported)
                for key in ('private_send_transport', 'retained_history_format', 'pool_format'):
                    self.assertEqual(exported[key], self.profile[key])
                bundle.extractall(root / 'extracted', filter='data')
            directory = root / 'extracted/native-wallet'
            verify(directory)
            parsed = subprocess.run([str(directory / 'bin/native-wallet'), 'profile', '--network',
                                     str(directory / 'wallet-profile.json')], check=True, capture_output=True, text=True, timeout=20)
            self.assertEqual(json.loads(parsed.stdout), exported)
            self.assertFalse((directory / 'wallet-ui').exists())
            legacy = {**exported, 'pool_format': 'NPOOL003'}
            for key in ('private_send_transport', 'retained_history_format'):
                legacy.pop(key)
            path = root / 'legacy.json'
            path.write_text(json.dumps(legacy))
            subprocess.run([str(self.binary), 'profile', '--network', str(path)], check=True, capture_output=True, timeout=20)

    def test_invalid_modes_fail_before_archive_output_instead_of_downgrading(self):
        cases = [('unknown-send-mode', {'private_send_transport': 'future-native-v9'}),
                 ('unknown-history-mode', {'retained_history_format': 'compact-v9'}),
                 ('old-pool-native', {'pool_format': 'NPOOL003'})]
        with tempfile.TemporaryDirectory() as name:
            for label, change in cases:
                with self.subTest(label=label):
                    root = Path(name) / label
                    root.mkdir()
                    args = self.package_args(root, {**self.profile, **change})
                    with patch('sys.argv', args), self.assertRaises(subprocess.CalledProcessError):
                        main()
                    self.assertFalse((root / 'wallet.tgz').exists())
                    self.assertFalse((root / 'wallet.tgz.sha256').exists())


if __name__ == "__main__":
    unittest.main()
