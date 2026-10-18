import json
from pathlib import Path
import tempfile
import unittest
from faucet_localnet import checkpoint


class FaucetCheckpointTests(unittest.TestCase):
    def test_only_exact_failed_checkpoints_can_resume_and_evidence_is_not_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); path=root/'faucet-result.json'
            allowed=dict(status='failed',events=[dict(kind=k) for k in ['signed_claim_reserved_once','gas_acknowledgement_lost','private_upload_crash']],error='Faucet error: secret file exceeds its size bound\n')
            path.write_text(json.dumps(allowed)); original=path.read_bytes()
            self.assertEqual(checkpoint(root,'upload'),allowed)
            self.assertEqual(path.read_bytes(),original)
            for value in [{**allowed,'status':'passed'},{**allowed,'status':'running'},{**allowed,'error':'different failure'},{**allowed,'events':[]}]:
                path.write_text(json.dumps(value)); before=path.read_bytes()
                with self.assertRaises(ValueError): checkpoint(root,'upload')
                self.assertEqual(path.read_bytes(),before)
            path.write_text(json.dumps(allowed))
            with self.assertRaises(ValueError): checkpoint(root,'pregas')


if __name__=='__main__': unittest.main()
