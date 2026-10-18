import json
from pathlib import Path
import tempfile
import unittest

from private_send_localnet import load_checkpoint


class PreservedCheckpointTests(unittest.TestCase):
    def test_resume_never_overwrites_running_completed_or_wrong_checkpoint_evidence(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            file=root/"private-send-result.json"
            for status in ["running","passed","failed"]:
                content=json.dumps({"status":status,"events":[],"error":"a different failure"}).encode()
                file.write_bytes(content)
                for kind in ["setup","upload"]:
                    with self.assertRaises(ValueError): load_checkpoint(root,kind)
                    self.assertEqual(file.read_bytes(),content)
            setup={"status":"failed","events":[],"error":"Wallet error: missing --rpc\n"}
            file.write_text(json.dumps(setup))
            self.assertEqual(load_checkpoint(root,"setup"),setup)
            with self.assertRaises(ValueError): load_checkpoint(root,"upload")
            upload={"status":"failed","error":"expected 'never accepts operator': earlier guard","events":[{"kind":"browser_unfunded"},{"kind":"browser_funded"}]}
            file.write_text(json.dumps(upload))
            self.assertEqual(load_checkpoint(root,"upload"),upload)
            with self.assertRaises(ValueError): load_checkpoint(root,"setup")
