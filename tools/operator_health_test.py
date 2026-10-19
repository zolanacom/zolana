import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import operator_health as health
from operator_monitor import Journal, Monitor


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.public=self.root/'health'; self.public.mkdir(mode=0o755)
        self.path=self.public/'heartbeat.json'; self.clock=100.
        self.publisher=health.Publisher(self.path,interval=100,clock=lambda:self.clock).start()
        self.journal=Journal(self.root/'monitor')
        self.job={'loaded':True,'pid':os.getpid()}
        self.monitor=Monitor(self.journal,self.path,os.getuid(),probe=lambda:self.job,grace=0)

    def tearDown(self):
        try:self.publisher.close()
        except (OSError,ValueError):pass
        self.journal.close();self.temp.cleanup()

    def ready(self,slot=8):
        self.publisher.observe(slot,validator_count=2,ingress_ready=True)
        self.publisher.update('ready')

    def codes(self):return [e['code'] for e in self.journal.state['events']]

    def test_private_fields_and_arbitrary_reasons_cannot_be_published(self):
        for metrics in ({'wallet':'CANARY_SECRET'}, {'rpc_access':'CANARY_SECRET'}):
            with self.assertRaises(ValueError):self.publisher.update(**metrics)
        data=health.read(self.path,os.getuid())
        for key,value in [('reason','CANARY_SECRET'),('validator_count',True),('published_at',float('nan')),('finalized_slot',True),('phase',[]),('instance','Z'*32)]:
            altered=dict(data);altered[key]=value
            with self.assertRaises(ValueError):health.validate(altered)
        self.assertNotIn('CANARY_SECRET',self.path.read_text())
        self.assertEqual(self.path.stat().st_mode&0o777,0o644)

    def test_ownership_modes_symlinks_and_oversize_are_rejected(self):
        with self.assertRaises(ValueError):health.read(self.path,os.getuid()+1)
        self.path.chmod(0o666)
        self.assertEqual(self.monitor.sample(100)['code'],'heartbeat_invalid')
        self.path.chmod(0o644);saved=self.public/'saved';self.path.rename(saved);self.path.symlink_to(saved)
        self.assertEqual(self.monitor.sample(100)['code'],'heartbeat_invalid')
        self.path.unlink();self.path.write_bytes(b'x'*4097);self.path.chmod(0o644)
        self.assertEqual(self.monitor.sample(100)['code'],'heartbeat_invalid')
        self.public.chmod(0o777)
        with self.assertRaises(ValueError):health.read(self.path,os.getuid())
        self.public.chmod(0o755)

    def test_unloaded_service_is_quiet_even_with_stale_or_missing_status(self):
        self.job={'loaded':False,'pid':None};self.path.unlink()
        self.assertEqual(self.monitor.sample(900)['state'],'paused')
        self.assertEqual(self.journal.state['events'],[])

    def test_loaded_missing_and_bad_status_are_distinct(self):
        self.path.unlink();self.assertEqual(self.monitor.sample(100)['code'],'heartbeat_missing')
        self.path.write_text('{bad');self.path.chmod(0o644)
        self.assertEqual(self.monitor.sample(100)['code'],'heartbeat_invalid')

    def test_startup_grace_does_not_resolve_incident_or_hide_invalid_input(self):
        self.publisher.update('blocked','retention_failed');self.monitor.sample(100)
        self.clock=101;self.publisher.update('starting');self.monitor.grace=30
        self.job={'loaded':True,'pid':os.getpid()+1}
        self.assertIsNone(self.monitor.sample(101)['code'])
        self.assertEqual(self.journal.state['incident']['code'],'retention_failed')
        self.path.write_text('[]')
        self.assertEqual(self.monitor.sample(102)['code'],'heartbeat_invalid')

    def test_fresh_heartbeat_with_stalled_finality_alerts_and_deduplicates(self):
        self.ready();self.monitor.sample(100)
        self.clock=170;self.publisher.observe(8)
        self.assertEqual(self.monitor.sample(170)['code'],'finality_stalled')
        self.monitor.sample(171);self.assertEqual(self.codes(),['finality_stalled'])
        self.clock=172;self.publisher.observe(9);self.assertEqual(self.monitor.sample(172)['state'],'healthy')
        self.assertEqual([e['kind'] for e in self.journal.state['events']],['incident','recovered'])
        with self.assertRaisesRegex(ValueError,'regressed'):self.publisher.observe(8)

    def test_stale_samples_alert_even_if_heartbeat_and_phase_are_fresh(self):
        self.ready();self.clock=117;self.publisher.update()
        self.assertEqual(self.monitor.sample(117)['code'],'finality_stalled')

    def test_stale_publisher_and_mismatched_pid(self):
        self.ready();self.assertEqual(self.monitor.sample(116)['code'],'heartbeat_stale')
        self.job={'loaded':True,'pid':os.getpid()+1}
        self.assertEqual(self.monitor.sample(117)['code'],'publisher_mismatch')

    def test_healthy_publisher_does_not_get_new_grace_when_it_stalls(self):
        self.monitor.grace=30;self.ready();self.monitor.sample(100)
        self.assertEqual(self.monitor.sample(116)['code'],'heartbeat_stale')
        self.monitor.sample(117)
        self.assertEqual(self.codes(),['heartbeat_stale'])

    def test_only_first_restart_after_actual_health_gets_fresh_grace(self):
        self.monitor.grace=30;self.ready();self.monitor.sample(100)
        self.job={'loaded':True,'pid':123456}
        self.assertIsNone(self.monitor.sample(200)['code'])
        self.job={'loaded':True,'pid':123457}
        self.assertEqual(self.monitor.sample(231)['code'],'publisher_mismatch')

    def test_startup_stall_and_failed_phase_keep_static_cause(self):
        self.clock=290;self.publisher.update()
        self.assertEqual(self.monitor.sample(290)['code'],'startup_stalled')
        self.publisher.update('blocked','retention_failed');self.publisher.close()
        self.assertEqual(health.read(self.path,os.getuid())['phase'],'blocked')
        self.assertEqual(self.monitor.sample(290)['code'],'retention_failed')

    def test_repeated_crashes_cannot_renew_startup_grace_forever(self):
        self.monitor.grace=30
        for now in (100,110,120):
            self.job={'loaded':True,'pid':int(now)}
            self.assertIsNone(self.monitor.sample(now)['code'])
        self.job={'loaded':True,'pid':999}
        self.assertEqual(self.monitor.sample(131)['code'],'publisher_mismatch')
        self.clock=300;self.publisher.update('syncing');self.job={'loaded':True,'pid':os.getpid()}
        self.assertEqual(self.monitor.sample(300)['code'],'startup_stalled')

    def test_clock_rollback_future_and_probe_errors_fail_visibly(self):
        self.ready();self.monitor.sample(100)
        self.assertEqual(self.monitor.sample(95)['code'],'clock_invalid')
        self.clock=200;self.publisher.update()
        self.assertEqual(self.monitor.sample(110)['code'],'clock_invalid')
        self.monitor.probe=lambda:(_ for _ in ()).throw(OSError('CANARY_SECRET'))
        self.assertEqual(self.monitor.sample(200)['code'],'monitor_probe_failed')
        self.assertNotIn('CANARY_SECRET',(self.root/'monitor/state.json').read_text())

    def test_operator_pause_resolves_separately_from_ready_recovery(self):
        self.publisher.update('failed','validator_exited');self.monitor.sample(100)
        self.job={'loaded':False,'pid':None};self.monitor.sample(101);self.monitor.sample(102)
        self.assertEqual([e['kind'] for e in self.journal.state['events']],['incident','operator_paused'])

    def test_restart_keeps_incident_and_delivered_event_is_not_replayed(self):
        self.publisher.update('failed','startup_failed');self.monitor.sample(100)
        output=io.StringIO();self.journal.deliver(output);self.journal.close()
        self.journal=Journal(self.root/'monitor');self.monitor.journal=self.journal
        replay=io.StringIO();self.journal.deliver(replay);self.monitor.sample(101)
        self.assertEqual(replay.getvalue(),'');self.assertEqual(len(self.journal.state['events']),1)
        self.clock=102;self.publisher.update('starting');self.monitor.sample(102)
        self.assertEqual(self.journal.state['incident']['code'],'startup_failed')
        self.ready();self.monitor.sample(102)
        self.assertEqual(self.journal.state['events'][-1]['kind'],'recovered')

    def test_failed_stdout_is_durable_and_same_id_is_replayed(self):
        self.publisher.update('failed','startup_failed');self.monitor.sample(100)
        class Broken:
            def write(self,_):raise BrokenPipeError()
        with self.assertRaises(BrokenPipeError):self.journal.deliver(Broken())
        identifier=self.journal.state['events'][0]['id'];self.journal.close()
        self.journal=Journal(self.root/'monitor');out=io.StringIO();self.journal.deliver(out)
        self.assertEqual(json.loads(out.getvalue())['id'],identifier)

    def test_corrupt_or_deleted_state_and_concurrent_observer_never_reset(self):
        with self.assertRaises(BlockingIOError):Journal(self.root/'monitor')
        self.journal.close();path=self.root/'monitor/state.json';original=path.read_bytes()
        path.write_bytes(b'{corrupt')
        with self.assertRaises(ValueError):Journal(self.root/'monitor')
        self.assertEqual(path.read_bytes(),b'{corrupt')
        path.unlink()
        with self.assertRaises(FileNotFoundError):Journal(self.root/'monitor')
        path.write_bytes(original);path.chmod(0o600);self.journal=Journal(self.root/'monitor')

    def test_pending_outbox_capacity_fails_without_discarding_evidence(self):
        for index in range(128):self.journal.event('incident','startup_failed',100+index)
        self.journal.save();original=(self.root/'monitor/state.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'outbox full'):self.journal.event('incident','disk_low',300)
        self.assertEqual((self.root/'monitor/state.json').read_bytes(),original)

    def test_failed_background_publication_is_detected_and_thread_stops(self):
        self.publisher.close();self.publisher=health.Publisher(self.path,interval=.01,clock=lambda:self.clock)
        self.publisher.start()
        with patch.object(health,'atomic',side_effect=OSError('disk failed')):
            deadline=time.monotonic()+2
            while self.publisher.healthy() and time.monotonic()<deadline:time.sleep(.01)
        self.assertFalse(self.publisher.healthy())

    def test_real_publisher_sigkill_detected_then_new_instance_recovers(self):
        tools=str(Path(__file__).resolve().parent)
        code='import sys,time;sys.path.insert(0,sys.argv[1]);from operator_health import Publisher;p=Publisher(sys.argv[2],interval=.05).start();p.observe(9,validator_count=2,ingress_ready=True);p.update("ready");print("ready",flush=True);time.sleep(30)'
        child=subprocess.Popen([sys.executable,'-B','-c',code,tools,str(self.path)],stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),'ready')
            self.job={'loaded':True,'pid':child.pid};self.assertEqual(self.monitor.sample()['state'],'healthy')
            child.kill();child.wait(timeout=3)
            self.assertEqual(self.monitor.sample(time.time()+16)['code'],'heartbeat_stale')
            # Fresh process identity alone leaves the incident open.
            self.clock=time.time()+17;self.publisher.update('starting');self.job={'loaded':True,'pid':os.getpid()}
            self.monitor.sample(self.clock);self.assertIsNotNone(self.journal.state['incident'])
            self.ready(10);self.assertEqual(self.monitor.sample(self.clock)['state'],'healthy')
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=3)
            child.stdout.close()

    def test_real_monitor_sigkill_after_stdout_before_ack_replays_same_id(self):
        tools=str(Path(__file__).resolve().parent);journal=self.root/'crash-monitor'
        code='''import sys,os,signal
sys.path.insert(0,sys.argv[1])
from operator_monitor import Journal
j=Journal(sys.argv[2]);j.event('incident','startup_failed',100);j.save()
class Crash:
 def write(self,text):sys.stdout.write(text)
 def flush(self):sys.stdout.flush();os.kill(os.getpid(),signal.SIGKILL)
j.deliver(Crash())
'''
        child=subprocess.run([sys.executable,'-B','-c',code,tools,str(journal)],capture_output=True,text=True,timeout=5)
        self.assertEqual(child.returncode,-signal.SIGKILL);event=json.loads(child.stdout)
        recovered=Journal(journal)
        try:
            out=io.StringIO();recovered.deliver(out)
            self.assertEqual(json.loads(out.getvalue())['id'],event['id'])
            again=io.StringIO();recovered.deliver(again);self.assertEqual(again.getvalue(),'')
        finally:recovered.close()


if __name__=='__main__':unittest.main()
