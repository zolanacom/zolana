from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from staging_localnet import StagingExperiment


class WalletCrashGuardTests(unittest.TestCase):
    def test_only_owned_live_wallet_children_can_be_signaled(self):
        trial = StagingExperiment(Path("unused-test-root"))
        child = Mock()
        child.poll.return_value = None
        with self.assertRaisesRegex(RuntimeError, "owned live child"):
            trial.kill_wallet(child)
        child.kill.assert_not_called()
        trial.wallet_children.append(child)
        child.poll.return_value = 0
        with self.assertRaisesRegex(RuntimeError, "owned live child"):
            trial.kill_wallet(child)
        child.kill.assert_not_called()

    def test_wrong_rpc_network_prevents_wallet_crash_injection(self):
        trial = StagingExperiment(Path("unused-test-root"))
        child = Mock()
        child.poll.return_value = None
        trial.wallet_children.append(child)
        with patch("staging_localnet.wait_rpc", side_effect=RuntimeError("wrong genesis")):
            with self.assertRaisesRegex(RuntimeError, "wrong genesis"):
                trial.kill_wallet(child)
        child.kill.assert_not_called()
