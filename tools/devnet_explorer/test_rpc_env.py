import json
import os
import tempfile
import unittest

import rpc_env


class RpcUrl(unittest.TestCase):
    def test_first_peer_loopback_port(self):
        ready = {"peers": [{"rpc": "127.0.0.1:49643"}, {"rpc": "127.0.0.1:50001"}]}
        self.assertEqual(rpc_env.rpc_url(ready), "http://127.0.0.1:49643")

    def test_rejects_anything_that_is_not_a_loopback_port(self):
        for ready in (
            None, [], {}, {"peers": []}, {"peers": ["127.0.0.1:1"]}, {"peers": [{}]},
            {"peers": [{"rpc": 4113}]}, {"peers": [{"rpc": "127.0.0.1"}]},
            {"peers": [{"rpc": "10.0.0.5:4113"}]}, {"peers": [{"rpc": "localhost:4113"}]},
            {"peers": [{"rpc": "127.0.0.1:0"}]}, {"peers": [{"rpc": "127.0.0.1:65536"}]},
            {"peers": [{"rpc": "127.0.0.1:41x3"}]}, {"peers": [{"rpc": "127.0.0.1:4113/x"}]},
            {"peers": [{"rpc": "127.0.0.1:4113:1"}]}, {"peers": [{"rpc": "127.0.0.1:٤"}]},
        ):
            with self.assertRaises(ValueError, msg=repr(ready)):
                rpc_env.rpc_url(ready)


class Main(unittest.TestCase):
    def test_writes_environment_file_and_replaces_stale_port(self):
        with tempfile.TemporaryDirectory() as folder:
            ready, env = os.path.join(folder, "ready.json"), os.path.join(folder, "feed.env")
            for port in ("4113", "49643"):
                with open(ready, "w", encoding="utf-8") as handle:
                    json.dump({"peers": [{"rpc": "127.0.0.1:" + port}]}, handle)
                self.assertEqual(rpc_env.main(["rpc_env.py", ready, env]), 0)
                with open(env, encoding="utf-8") as handle:
                    self.assertEqual(handle.read(), "RPC_URL=http://127.0.0.1:" + port + "\n")
            self.assertEqual(sorted(os.listdir(folder)), ["feed.env", "ready.json"])

    def test_missing_or_malformed_readiness_file_fails_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as folder:
            ready, env = os.path.join(folder, "ready.json"), os.path.join(folder, "feed.env")
            self.assertEqual(rpc_env.main(["rpc_env.py", ready, env]), 1)
            with open(ready, "w", encoding="utf-8") as handle:
                handle.write("{not json")
            self.assertEqual(rpc_env.main(["rpc_env.py", ready, env]), 1)
            self.assertFalse(os.path.exists(env))
            self.assertEqual(rpc_env.main(["rpc_env.py", ready]), 2)


if __name__ == "__main__":
    unittest.main()
