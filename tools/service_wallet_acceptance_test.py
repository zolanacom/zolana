import unittest
from unittest.mock import Mock,patch
from types import SimpleNamespace
from service_wallet_acceptance import Acceptance,validate_ca_refresh


class DesktopAcceptanceGuards(unittest.TestCase):
    def test_lost_send_response_cannot_trigger_a_replacement_payment(self):
        run=object.__new__(Acceptance);run.state={'phase':'funded'};run.save=Mock()
        run.user=Mock(side_effect=[{'maximum_gross_debit':123},{'address':'npriv1recipient'},TimeoutError('response lost')])
        with self.assertRaises(TimeoutError):run.payment()
        self.assertEqual(run.state['phase'],'send_started')
        run.save.assert_called_once();run.user.reset_mock()
        with self.assertRaisesRegex(ValueError,'never repeat a started payment'):run.payment()
        run.user.assert_not_called()

    def test_restart_verification_refuses_changed_original_wallet_before_rpc(self):
        run=object.__new__(Acceptance);run.state={'phase':'checkpoint','fingerprints':{'wallet':'original'}}
        run.fingerprints=Mock(return_value={'wallet':'replaced'});run.balances=Mock()
        with self.assertRaisesRegex(ValueError,'original desktop wallet'):run.verify()
        run.balances.assert_not_called()

    def test_ca_certificate_refresh_cannot_change_network_or_trusted_public_key(self):
        original={'genesis_hash':'original genesis','rpc':{'url':'https://127.0.0.1:23898'},'local_tls_ca_pem':'-----BEGIN CERTIFICATE-----\noriginal\n-----END CERTIFICATE-----'}
        replacement={**original,'local_tls_ca_pem':'-----BEGIN CERTIFICATE-----\nsame key with identifiers\n-----END CERTIFICATE-----'}
        with patch('service_wallet_acceptance.subprocess.run',return_value=SimpleNamespace(stdout='original public key')):
            validate_ca_refresh(original,replacement)
        with patch('service_wallet_acceptance.subprocess.run',side_effect=[SimpleNamespace(stdout='original key'),SimpleNamespace(stdout='different key')]):
            with self.assertRaisesRegex(ValueError,'original trusted CA'):validate_ca_refresh(original,replacement)
        with patch('service_wallet_acceptance.subprocess.run') as run:
            with self.assertRaisesRegex(ValueError,'cannot change genesis'):validate_ca_refresh(original,{**replacement,'genesis_hash':'other genesis'})
            run.assert_not_called()
        with self.assertRaisesRegex(ValueError,'additional trust anchors forbidden'):
            validate_ca_refresh(original,{**replacement,'local_tls_ca_pem':replacement['local_tls_ca_pem']*2})


if __name__=='__main__':unittest.main()
