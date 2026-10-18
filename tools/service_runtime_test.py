"""Exercise the sealed runtime's actual lifecycle function without starting nodes."""
import ast
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


class RuntimeRetentionTests(unittest.TestCase):
    def exercise(self, failure=None, waits=(True,), close_failure=False, expired_after_start=False, terminate_during_start=False, archival=False):
        events = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); root = base / '.data/s20'; root.mkdir(parents=True)
            (base / '.data/setup.complete').write_text('existing')
            (root / 'ingress-setup.json').write_text('{"phase":"ready"}')
            shutdown = Mock(); shutdown.wait.side_effect = waits
            shutdown.is_set.return_value = False
            shutdown.set.side_effect = lambda:setattr(shutdown.is_set, 'return_value', True)
            handlers = {}
            children = [Mock(pid=100), Mock(pid=101)]
            for child in children: child.poll.return_value = None
            def stop(_, index): events.append('stop'+str(index)); children[index].poll.return_value = 0
            retention = Mock(); retention.healthy.return_value = failure != 'background'
            def begin():
                events.append('retention-start')
                if terminate_during_start:handlers[15]()
                if failure == 'initial': raise RuntimeError('collection failed')
            retention.start.side_effect = begin
            def close():
                events.append('retention-close')
                if close_failure: raise RuntimeError('worker close failed')
            retention.close.side_effect = close
            ingress = Mock(); ingress.healthy.return_value = True
            ingress.close.side_effect = lambda: events.append('ingress-close')
            def opening(**_): events.append('ingress-open'); return ingress
            namespace = dict(BASE=base, ROOT=root, WALLET=base/'wallet', load=Mock(),
                start=lambda _, index, **kw: children[index], stop=stop, wait_rpc=Mock(), quiet=Mock(), save=Mock(),
                rpc=Mock(), prepare=Mock(), print=Mock(),
                os=SimpleNamespace(nice=Mock(),getpid=lambda:1,getpgid=lambda p:p,getuid=lambda:450,getgid=lambda:450),
                threading=SimpleNamespace(Event=lambda:shutdown), signal=SimpleNamespace(SIGTERM=15,SIGINT=2,signal=lambda number,callback:handlers.update({number:callback})),
                shutil=SimpleNamespace(disk_usage=lambda _:SimpleNamespace(free=4*1024**3)),
                time=SimpleNamespace(time=Mock(side_effect=[100,100,100,700]) if expired_after_start else lambda:100), json=json, math=__import__('math'))
            source = ast.parse(Path(__file__).with_name('service_runtime.py').read_text())
            function = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == 'supervise')
            exec(compile(ast.Module(body=[function],type_ignores=[]),'service_runtime.py','exec'), namespace)
            modules = {'history_retention': SimpleNamespace(Retention=Mock(return_value=retention)),
                       'service_ingress': SimpleNamespace(Ingress=opening),
                       'service_tls': SimpleNamespace(private_bytes=lambda *args:json.dumps({'format':'local-canonical-archive-test-v1' if archival else 'local-history-retention-test-v1','expires_at':600}).encode())}
            with patch.dict('sys.modules', modules):
                if close_failure:
                    with self.assertRaisesRegex(RuntimeError,'cleanup failed'):namespace['supervise']()
                else: namespace['supervise'](retention_test=expired_after_start and not archival,archival_test=archival)
        return events

    def test_verified_initial_mirror_precedes_ingress_and_normal_shutdown_stops_everything(self):
        self.assertEqual(self.exercise(),['retention-start','ingress-open','ingress-close','retention-close','stop1','stop0'])

    def test_initial_failure_never_opens_ingress_or_restarts_nodes(self):
        self.assertEqual(self.exercise(failure='initial'),['retention-start','retention-close','stop1','stop0'])

    def test_background_failure_closes_ingress_and_parks_both_nodes(self):
        self.assertEqual(self.exercise(failure='background',waits=(False,True)),
                         ['retention-start','ingress-open','ingress-close','retention-close','stop1','stop0'])

    def test_cleanup_exception_still_stops_both_validators(self):
        self.assertEqual(self.exercise(close_failure=True),['retention-start','ingress-open','ingress-close','retention-close','stop1','stop0'])

    def test_shutdown_during_initial_collection_requests_stop_and_never_opens_ingress(self):
        self.assertEqual(self.exercise(terminate_during_start=True),['retention-start','retention-close','stop1','stop0'])

    def test_expiry_during_initial_collection_never_opens_ingress(self):
        self.assertEqual(self.exercise(expired_after_start=True),['retention-start','retention-close','stop1','stop0'])

    def test_archival_rehearsal_has_its_own_finite_session_and_cleans_both_validators(self):
        self.assertEqual(self.exercise(archival=True),['retention-start','ingress-open','ingress-close','retention-close','stop1','stop0'])
        self.assertEqual(self.exercise(archival=True,expired_after_start=True),['retention-start','retention-close','stop1','stop0'])


if __name__ == '__main__': unittest.main()
