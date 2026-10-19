import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from replay_localnet import plan, prepare, shared_checkpoint


def state(tail=None, frozen=None):
    return {"complete_tail_replay_slot": tail, "frozen_hashes": frozen or {"8": "old-bank"},
            "shred_digests": {"9/data/0": "retained-shred"}, "slot": 8}


class OfflineReplayTests(unittest.TestCase):
    def test_epoch_horizon_requires_same_frozen_checkpoint_from_both_original_identities(self):
        config={'key_mode':'local-testnet-rehearsal-v1','genesis_hash':'genesis','identities':['a','b']}
        descriptor={'bank_hash':'same','epoch':49,'leader_schedule_epoch':50}
        first={'slot':6399,'bank_hash':'same','genesis_hash':'genesis','identity':'a','root_epoch':48,'root_leader_schedule_epoch':49,'restart_ancestors':{'6399':descriptor}}
        second={**first,'identity':'b'}
        self.assertEqual(shared_checkpoint(config,[first,second]),{'slot':6399,'bank_hash':'same','genesis_hash':'genesis'})
        for change in [{'slot':6398},{'bank_hash':'other'},{'identity':'a'},{'genesis_hash':'other'}]:
            self.assertIsNone(shared_checkpoint(config,[first,{**second,**change}]))
        self.assertIsNone(shared_checkpoint({**config,'key_mode':'fixture'},[first,second]))

    def test_epoch_anchor_survives_an_early_future_epoch_crash_with_different_tips(self):
        config={'key_mode':'local-testnet-rehearsal-v1','genesis_hash':'genesis','identities':['a','b']}
        anchor={'bank_hash':'ancestor','epoch':49,'leader_schedule_epoch':50}
        first={'slot':6400,'bank_hash':'new','genesis_hash':'genesis','identity':'a','root_epoch':48,'root_leader_schedule_epoch':49,
            'restart_ancestors':{'6400':{'bank_hash':'new','epoch':50,'leader_schedule_epoch':51},'6321':anchor}}
        second={**first,'slot':6399,'bank_hash':'old','identity':'b','restart_ancestors':{'6399':{'bank_hash':'old','epoch':49,'leader_schedule_epoch':50},'6321':anchor}}
        self.assertEqual(shared_checkpoint(config,[first,second]),{'slot':6321,'bank_hash':'ancestor','genesis_hash':'genesis'})
        changed={**second,'restart_ancestors':{**second['restart_ancestors'],'6321':{**anchor,'bank_hash':'other'}}}
        self.assertIsNone(shared_checkpoint(config,[first,changed]))
    def test_no_replay_is_started_when_both_tips_are_frozen(self):
        with patch("replay_localnet.load", return_value={}), patch("replay_localnet.plan", side_effect=[state(), state()]), patch("replay_localnet.subprocess.Popen") as launch:
            self.assertEqual(prepare(Path("unused")), {"replayed": False})
            launch.assert_not_called()

    def test_live_primary_blockstore_failure_never_starts_replay(self):
        with patch("replay_localnet.load", return_value={}), patch("replay_localnet.plan", side_effect=subprocess.CalledProcessError(1, "primary-lock")), patch("replay_localnet.subprocess.Popen") as launch:
            with self.assertRaises(subprocess.CalledProcessError):
                prepare(Path("unused"))
            launch.assert_not_called()

    def test_multiple_unfrozen_children_are_retained_without_offline_execution(self):
        with patch("replay_localnet.load", return_value={}), patch("replay_localnet.plan", side_effect=[state(9), state(9)]), patch("replay_localnet.subprocess.Popen") as launch:
            result=prepare(Path("unused"));self.assertTrue(result['native_restart_checkpoint_required'])
            self.assertEqual(result['retained_complete_children'],[9,9])
            launch.assert_not_called()

    def test_uncorroborated_child_is_never_executed_automatically(self):
        with patch("replay_localnet.load", return_value={}), patch("replay_localnet.plan", side_effect=[state(), state(9)]), patch("replay_localnet.subprocess.Popen") as launch:
            result=prepare(Path("unused"));self.assertTrue(result['native_restart_checkpoint_required'])
            self.assertEqual(result['retained_complete_children'],[9])
            launch.assert_not_called()

    def test_complete_descendant_chain_requires_native_checkpoint_without_offline_guess(self):
        descendant={**state(), 'retained_complete_slots':[9,10]}
        with patch("replay_localnet.load", return_value={}), patch("replay_localnet.plan", side_effect=[descendant,state()]), patch("replay_localnet.subprocess.Popen") as launch:
            result=prepare(Path('unused'))
            self.assertEqual(result,{'replayed':False,'retained_complete_children':[9,10],'native_restart_checkpoint_required':True})
            launch.assert_not_called()

    def test_plan_authenticates_genesis_and_validator_identity(self):
        config = {"genesis_hash": "expected", "identities": ["identity-0", "identity-1"]}
        response = Mock(stdout=json.dumps({"genesis_hash": "wrong", "identity": "identity-1"}))
        with patch("replay_localnet.load", return_value=config), patch("replay_localnet.ledger", return_value=Path("ledger-1")), patch("replay_localnet.subprocess.run", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "identity/genesis"):
                plan(Path("unused"), 1)

    def test_only_halted_no_voting_child_runs_and_bank_mismatch_fails_closed(self):
        for mismatch,isolation in [(False,False),(True,False),(False,True),(True,True)]:
            with self.subTest(mismatch=mismatch,isolation=isolation), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                for index in [0, 1]:
                    (root / f"ledger-{index}").mkdir()
                config = {"key_mode": "local-testnet-rehearsal-v1", "vote_accounts": ["vote-0", "vote-1"], "genesis_hash": "expected"}
                if isolation:config["raw_rpc_isolation"]=True
                before = [state(frozen={"8": "old-bank", "9": "peer-bank"}), state(9)]
                after = [before[0], {**state(frozen={"8": "old-bank", "9": "wrong-bank" if mismatch else "peer-bank"}), "slot": 9}]
                child = Mock()
                child.poll.return_value = None
                def launch(args, **options):
                    for flag in ["--no-voting", "--require-tower", "--process-ledger-before-services", "--dev-halt-at-slot"]:
                        self.assertIn(flag, args)
                    self.assertNotIn("--wait-for-supermajority", args)
                    self.assertNotIn("--entrypoint", args)
                    self.assertEqual(args[args.index("--dev-halt-at-slot") + 1], "9")
                    self.assertEqual(args[args.index("--rpc-bind-address") + 1], "127.0.0.1")
                    self.assertNotIn(args[args.index("--rpc-port") + 1], ["18899", "19899"])
                    if isolation:
                        self.assertEqual(args[args.index("--native-rpc-access-file")+1],str(root/"rpc-access.key"))
                    else:self.assertNotIn("--native-rpc-access-file",args)
                    self.assertEqual(json.loads((Path(args[args.index("--log")+1]).parent/"command.json").read_text()),args)
                    Path(args[args.index("--log") + 1]).write_text("Validator halted")
                    return child
                with patch("replay_localnet.load", return_value=config), patch("replay_localnet.ledger", side_effect=lambda r,i:r/f"ledger-{i}"), patch("replay_localnet.plan", side_effect=before), patch("replay_localnet.restart_state", side_effect=after), patch("replay_localnet.subprocess.Popen", side_effect=launch):
                    if mismatch:
                        with self.assertRaisesRegex(RuntimeError, "bank hash differs"):
                            prepare(root)
                    else:
                        result = prepare(root)
                        self.assertTrue(result["signed_towers_unchanged"])
                        self.assertTrue(result["inspection_rpc_never_used_for_payments"])
                    child.kill.assert_called_once()
                    child.wait.assert_called_once()
