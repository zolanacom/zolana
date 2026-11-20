"""The cohort gateway is built with bulk authorization; no listener is opened."""
import os
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

import native_cohort_service as service


class BulkAuthorization(unittest.TestCase):
    def test_gateway_is_constructed_with_authorize_many_and_nothing_else_new(self):
        service.select_mode(False)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(service.select_mode, False)
        root = Path(temp.name).resolve() / "cohort"
        root.mkdir(mode=0o700)
        stop, seen = threading.Event(), []

        class Parent:
            def __init__(self, faucet_root, password, binary):
                self.stop, self.child_lock, self.child = threading.Event(), threading.Lock(), None
                self.arguments = (faucet_root, password, binary)
            def close(self):
                self.stop.set()

        class Gateway:
            def __init__(self, faucet, *args, **kwargs):
                seen.append((faucet.arguments, args, kwargs))
                self.relay = types.SimpleNamespace(native_ingress="127.0.0.1:1", close=lambda: None)
                stop.set()  # leave before any activation, listener or worker

        base = types.SimpleNamespace(
            sandbox=lambda config, role: 1, stop_event=lambda: stop, real_directory=lambda *a: None,
            read_ready=lambda *a: dict(generation=1, peers=[dict(rpc="127.0.0.1:1", native_ingress="127.0.0.1:2")]),
            GWROOT=root.parent)
        ingress = types.SimpleNamespace(activated_sockets=lambda: {})
        modules = dict(test_faucet=types.SimpleNamespace(Faucet=Parent, Handler=object),
                       testnet_gateway=types.SimpleNamespace(Gateway=Gateway, Handler=object),
                       service_tls=types.SimpleNamespace(listener=None))
        plan = dict(cohort_size=200, network={})
        with mock.patch.object(service, "ROOT", root), mock.patch.dict(sys.modules, modules), \
                mock.patch.object(service, "load_binding", return_value=({}, plan, {})), \
                mock.patch.object(service, "authority", return_value=dict(claims=[])), \
                mock.patch.object(service, "prepare", return_value=(None, "http://127.0.0.1:1")), \
                mock.patch.object(service, "activate") as activate:
            service.gateway(base, dict(gateway_uid=os.getuid(), test_mode=False), "d" * 64, ingress)
        activate.assert_not_called()
        self.assertEqual(len(seen), 1)
        arguments, positional, keywords = seen[0]
        self.assertEqual(arguments, (root / "faucet", root / "password", service.PREFIX / "bin/native-faucet"))
        self.assertEqual(positional, ())
        self.assertEqual(keywords, dict(relay_root=root / "relay", authorize_many=True))
        self.assertIs(keywords["authorize_many"], True)


if __name__ == "__main__":
    unittest.main()
