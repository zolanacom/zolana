#!/usr/bin/env python3
"""Pure LOCAL-058 policy/FD guards; no services, validators or listeners started."""
import copy
import errno
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

import native_linux_service as service
import service_tls


def key(number):return service.b58(bytes([number])*32)


def config():
    identities=[key(i) for i in (1,2,3)]
    return dict(format='zolana-native-linux-service-v1',manifest_sha256='a'*64,
        validator_uid=995,validator_gid=986,gateway_uid=994,gateway_gid=985,link_gid=983,
        network=dict(network=[67]*32,genesis_hash=key(4)),validator_identities=identities,
        relay_public_key=key(5),test_mode=True,host_namespace_inode=12345,
        validator_layout=[dict(identity=identity,voter=key(10+i),ledger='ledgers/node-'+str(i),
            identity_file='identity-'+str(i)+'.json',voter_file='voter-'+str(i)+'.json')
            for i,identity in enumerate(identities)])


def ready():
    value=config()
    peers=[dict(identity=identity,rpc='127.0.0.1:'+str(20000+i),native_ingress='127.0.0.1:'+str(21000+i))
           for i,identity in enumerate(value['validator_identities'])]
    return dict(network=value['network'],pool_format='NPOOL004',peers=peers,
        mac_relay=value['relay_public_key'],ingress=[p['native_ingress'] for p in peers],
        hold_seconds=0,shared_private_smoke_skipped=True,operator_private_keys_exported=False,service_mode=True)


class FakeSocket:
    family=socket.AF_INET
    def __init__(self,port=38443,kind=socket.SOCK_STREAM,listening=1,address='127.0.0.1',fileno=3):
        self.port,self.kind,self.listening,self.address,self.fd=port,kind,listening,address,fileno
        self.closed=False
    def getsockopt(self,level,name):
        return self.kind if name==socket.SO_TYPE else self.listening
    def getsockname(self):return (self.address,self.port)
    def fileno(self):return self.fd
    def close(self):self.closed=True


class ConfigGuards(unittest.TestCase):
    def test_exact_original_layout_and_separate_roles(self):
        self.assertIs(service.validate_config(config())['test_mode'],True)
        cases=[]
        for name,replacement in [('gateway_uid',995),('link_gid',986),('validator_uid',0),
                                 ('test_mode',1),('host_namespace_inode',0),('manifest_sha256','bad')]:
            value=config();value[name]=replacement;cases.append(value)
        value=config();value['unreviewed_command']='/bin/sh';cases.append(value)
        value=config();value['validator_identities'][1]=value['validator_identities'][0];cases.append(value)
        value=config();value['network']['network'][0]=True;cases.append(value)
        value=config();value['network']['genesis_hash']='1'*31;cases.append(value)
        for value in cases:
            with self.subTest(value=value),self.assertRaises(ValueError):service.validate_config(value)

    def test_no_absolute_parent_or_aliased_original_paths(self):
        for field,value in [('ledger','/old/ledger'),('ledger','ledgers/../original'),
                            ('ledger','ledgers//node'),('ledger','not-ledgers/node'),
                            ('identity_file','nested/identity.json'),('voter_file','..')]:
            candidate=config();candidate['validator_layout'][0][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):service.validate_config(candidate)
        candidate=config();candidate['validator_layout'][1]['ledger']=candidate['validator_layout'][0]['ledger']
        with self.assertRaises(ValueError):service.validate_config(candidate)

    def test_service_ready_pins_identity_profile_and_all_six_endpoints(self):
        self.assertEqual(service.validate_ready(ready(),config())['network'],config()['network'])
        for field,value in [('network',dict(network=[66]*32,genesis_hash=key(4))),('pool_format','NPOOL003'),
                            ('mac_relay',key(6)),('operator_private_keys_exported',True),
                            ('hold_seconds',600),('service_mode',False)]:
            candidate=ready();candidate[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):service.validate_ready(candidate,config())
        candidate=ready();candidate['peers'][0]['identity']=key(8)
        with self.assertRaises(ValueError):service.validate_ready(candidate,config())
        candidate=ready();candidate['peers'][0]['rpc']=candidate['peers'][0]['native_ingress']
        with self.assertRaises(ValueError):service.validate_ready(candidate,config())
        for address in ['127.0.0.1:0123','localhost:123','127.0.0.1:0','127.0.0.1:65536',
                        '127.0.0.1:123@outside','http://127.0.0.1:123','127.0.0.1:123/path']:
            with self.subTest(address=address),self.assertRaises(ValueError):service.endpoint(address)

    def test_endpoint_repin_preserves_policy_and_all_other_profile_fields(self):
        template=dict(rpc=dict(url='http://127.0.0.1:100',transport='loopback-http'),pool_format='NPOOL004',budget=123)
        current=copy.deepcopy(template);current['rpc']['url']='http://127.0.0.1:200'
        updated=service.endpoint_update(current,template,{'rpc.url':'http://127.0.0.1:300'})
        self.assertEqual(updated,dict(template,rpc=dict(url='http://127.0.0.1:300',transport='loopback-http')))
        self.assertEqual(current['rpc']['url'],'http://127.0.0.1:200')
        current['budget']=124
        with self.assertRaises(ValueError):service.endpoint_update(current,template,{'rpc.url':'http://127.0.0.1:300'})
        relay=dict(rpc='http://127.0.0.1:100',native_ingress=['127.0.0.1:200'],fee=3000000,binary='/sealed/bin')
        changed=service.endpoint_update(relay,relay,{'rpc':'http://127.0.0.1:300','native_ingress':['127.0.0.1:400']})
        self.assertEqual(changed['fee'],relay['fee']);self.assertEqual(changed['binary'],relay['binary'])
        compromised=dict(relay,binary='/mutable/bin')
        with self.assertRaises(ValueError):service.endpoint_update(compromised,relay,{'rpc':'http://127.0.0.1:300'})

    def test_sandbox_requires_mount_denial_not_only_permissions(self):
        status='NoNewPrivs:\t1\n'+''.join(k+':\t00000000\n' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
        account=mock.Mock(pw_uid=995,pw_gid=986,pw_shell='/usr/sbin/nologin')
        with mock.patch.object(service.pwd,'getpwnam',return_value=account),\
             mock.patch.object(service.os,'geteuid',return_value=995),\
             mock.patch.object(service.os,'getegid',return_value=986),\
             mock.patch.object(service.Path,'read_text',return_value=status),\
             mock.patch.object(service.Path,'stat',return_value=mock.Mock(st_ino=999)),\
             mock.patch.object(service,'real_directory'),\
             mock.patch.object(service.os,'open',side_effect=OSError(errno.EROFS,'read-only')):
            self.assertEqual(service.sandbox(config(),'validator'),999)
        with mock.patch.object(service.pwd,'getpwnam',return_value=account),\
             mock.patch.object(service.os,'geteuid',return_value=995),\
             mock.patch.object(service.os,'getegid',return_value=986),\
             mock.patch.object(service.Path,'read_text',return_value=status),\
             mock.patch.object(service.Path,'stat',return_value=mock.Mock(st_ino=999)),\
             mock.patch.object(service,'real_directory'),\
             mock.patch.object(service.os,'open',side_effect=PermissionError(errno.EACCES,'denied')):
            with self.assertRaisesRegex(ValueError,'mount denial'):service.sandbox(config(),'validator')


class InheritedFDGuards(unittest.TestCase):
    def environment(self,names='rpc:faucet'):
        return dict(LISTEN_PID=str(os.getpid()),LISTEN_FDS='2',LISTEN_FDNAMES=names)

    def test_exact_two_named_pid_bound_descriptors_and_pinned_socket_metadata(self):
        for names in ('rpc:faucet','faucet:rpc'):
            records={3:FakeSocket(service.PORTS[names.split(':')[0]],fileno=3),
                     4:FakeSocket(service.PORTS[names.split(':')[1]],fileno=4)}
            with mock.patch.object(service.os,'set_inheritable') as inherited:
                result=service.activated_sockets(self.environment(names),lambda fileno:records[fileno])
            self.assertEqual(set(result),{'rpc','faucet'});self.assertEqual(inherited.call_count,2)
        for changes in [dict(LISTEN_PID='1'),dict(LISTEN_FDS='1'),dict(LISTEN_FDNAMES='rpc:rpc'),
                        dict(LISTEN_FDNAMES='rpc:other'),dict(LISTEN_FDNAMES='rpc:faucet:extra')]:
            env=self.environment();env.update(changes);factory=mock.Mock()
            with self.subTest(changes=changes),self.assertRaises(ValueError):service.activated_sockets(env,factory)
            factory.assert_not_called()

    def test_wrong_family_datagram_unbound_or_wildcard_cannot_be_adopted(self):
        cases=[FakeSocket(kind=socket.SOCK_DGRAM),FakeSocket(listening=0),FakeSocket(address='0.0.0.0'),FakeSocket(port=38444)]
        ipv6=FakeSocket();ipv6.family=socket.AF_INET6;cases.append(ipv6)
        for stream in cases:
            with self.subTest(stream=stream),self.assertRaises(ValueError):service_tls.check_activated_socket(stream,38443)
        service_tls.check_activated_socket(FakeSocket(),38443)

    def test_failed_second_descriptor_closes_all_adopted_handles(self):
        first,second=FakeSocket(),FakeSocket(38444,address='0.0.0.0',fileno=4)
        with mock.patch.object(service.os,'set_inheritable'),self.assertRaises(ValueError):
            service.activated_sockets(self.environment(),lambda fileno:first if fileno==3 else second)
        self.assertTrue(first.closed);self.assertTrue(second.closed)

    def test_inherited_http_and_direct_policy_bypass_rejected(self):
        stream=FakeSocket()
        with self.assertRaisesRegex(ValueError,'require TLS'):
            service_tls.listener('http://127.0.0.1:38443',38443,None,None,activated_socket=stream)
        with self.assertRaisesRegex(ValueError,'both reviewed'):
            service_tls.listener('https://127.0.0.1:38443',38443,None,None,
                                 listener_config='config',activated_socket=stream)


class UnitGuards(unittest.TestCase):
    def test_each_service_has_private_shm_without_mutating_host_allocator(self):
        for role in ('validator','gateway'):
            unit=service.units()[service.UNITS[role]]
            self.assertIn('PrivateIPC=yes\n',unit)
            self.assertIn('TemporaryFileSystem=/dev/shm:rw,nodev,nosuid,mode=1777\n',unit)
            self.assertNotIn('shared_port_allocator',unit)
            self.assertNotIn('chmod ',unit)
            self.assertNotIn('ExecStartPre=',unit)

    def test_only_host_tls_sockets_and_separate_joined_service_roles(self):
        units=service.units();self.assertEqual(len(units),4)
        for role in ('validator','gateway'):
            unit=units[service.UNITS[role]]
            for required in ['Type=notify','Restart=on-failure','RestartSec=10s','PrivateNetwork=yes',
                             'NoNewPrivileges=yes','CapabilityBoundingSet=\n','ProtectSystem=strict',
                             'KillMode=control-group','/usr/bin/python3 -I -B']:
                self.assertIn(required,unit)
        edge=units[service.UNITS['gateway']]
        for dependency in ('After','Requires','BindsTo','PartOf','JoinsNamespaceOf'):
            self.assertIn(dependency+'='+service.UNITS['validator'],edge)
        self.assertIn('User=zolana058g',edge);self.assertIn('ReadWritePaths='+str(service.GWROOT),edge)
        self.assertNotIn('ReadWritePaths='+str(service.STATE/'validator'),edge)
        self.assertNotIn('ReadWritePaths='+str(service.RUN),edge)
        for name,port in service.PORTS.items():
            unit=units['zolana-native-058-'+name+'.socket']
            self.assertIn('ListenStream=127.0.0.1:'+str(port),unit)
            self.assertIn('FileDescriptorName='+name,unit)
            self.assertIn('Service='+service.UNITS['gateway'],unit)
            self.assertNotIn('0.0.0.0',unit)


class FinalizedHistoryReadiness(unittest.TestCase):
    class StopClock:
        def __init__(self):self.now=0;self.stopped=False
        def is_set(self):return self.stopped
        def wait(self,seconds):self.now+=seconds;return self.stopped
        def clock(self):return self.now

    def block(self):
        return dict(parentSlot=649,blockHeight=500,blockhash=key(21),previousBlockhash=key(20))

    def test_replayed_slot_fallback_alone_cannot_make_service_ready(self):
        stop=self.StopClock();child=mock.Mock();child.poll.return_value=None
        with mock.patch.object(service,'finalized_slot',return_value=650),mock.patch.object(service,'read_rpc') as history:
            with self.assertRaises(TimeoutError):
                service.wait_finalized_history(ready()['peers'],child,stop,.4,stop.clock)
        history.assert_not_called()

    def test_progress_without_finalized_history_on_one_peer_never_satisfies_all_peer_gate(self):
        stop=self.StopClock();child=mock.Mock();child.poll.return_value=None;calls={}
        peers=ready()['peers']
        def slot(address,timeout):
            calls[address]=calls.get(address,0)+1
            return 650 if calls[address]==1 else 651
        def history(address,method,params,timeout):
            self.assertEqual(method,'getBlock');self.assertEqual(params[0],650)
            self.assertEqual(params[1],dict(encoding='base64',transactionDetails='none',rewards=False,
                commitment='finalized',maxSupportedTransactionVersion=0))
            self.assertGreater(timeout,0);self.assertLessEqual(timeout,2)
            return None if address==peers[2]['rpc'] else self.block()
        with mock.patch.object(service,'finalized_slot',side_effect=slot),mock.patch.object(service,'read_rpc',side_effect=history):
            with self.assertRaises(TimeoutError):service.wait_finalized_history(peers,child,stop,.5,stop.clock)
        self.assertGreater(calls[peers[2]['rpc']],calls[peers[0]['rpc']])

    def test_all_peers_require_real_history_and_advanced_roots_and_emit_pinned_receipt(self):
        stop=self.StopClock();child=mock.Mock();child.poll.return_value=None;slots={};reads={};peers=ready()['peers']
        def slot(address,timeout):
            slots[address]=slots.get(address,0)+1
            return 650 if slots[address]==1 else 650+slots[address]
        def history(address,method,params,timeout):
            reads[address]=reads.get(address,0)+1
            if address==peers[2]['rpc'] and reads[address]<3:return None
            return self.block()
        with mock.patch.object(service,'finalized_slot',side_effect=slot),mock.patch.object(service,'read_rpc',side_effect=history):
            result=service.wait_finalized_history(peers,child,stop,1,stop.clock)
        self.assertEqual(result['format'],'zolana-native-finality-readiness-v1')
        self.assertEqual([p['identity'] for p in result['peers']],[p['identity'] for p in peers])
        self.assertEqual([reads[p['rpc']] for p in peers],[1,1,3])
        for proof in result['peers']:
            self.assertEqual(proof['startup_root'],650);self.assertGreater(proof['advanced_root'],650)
            self.assertEqual(proof['finalized_block_slot'],650);self.assertEqual(proof['finalized_blockhash'],key(21))

    def test_stopped_or_dead_child_cannot_publish_finalized_history_readiness(self):
        stop=self.StopClock();stop.stopped=True;child=mock.Mock();child.poll.return_value=None
        with mock.patch.object(service,'finalized_slot') as slot:
            self.assertIsNone(service.wait_finalized_history(ready()['peers'],child,stop,1,stop.clock))
        slot.assert_not_called();stop.stopped=False;child.poll.return_value=1
        with self.assertRaises(RuntimeError):service.wait_finalized_history(ready()['peers'],child,stop,1,stop.clock)
        with self.assertRaises(ValueError):service.finalized_block(dict(self.block(),parentSlot=650),650)
        with self.assertRaises(ValueError):service.finalized_block(dict(self.block(),blockhash='bad'),650)

    def test_stop_arriving_during_final_history_rpc_prevents_ready_receipt(self):
        stop=self.StopClock();child=mock.Mock();child.poll.return_value=None;slots={};peers=ready()['peers']
        def slot(address,timeout):
            slots[address]=slots.get(address,0)+1
            return 650 if slots[address]==1 else 651
        def history(address,*args,**kwargs):
            if address==peers[-1]['rpc']:stop.stopped=True
            return self.block()
        with mock.patch.object(service,'finalized_slot',side_effect=slot),mock.patch.object(service,'read_rpc',side_effect=history):
            self.assertIsNone(service.wait_finalized_history(peers,child,stop,1,stop.clock))


if __name__=='__main__':unittest.main()
