"""LOCAL-063 immutable-overlay, import-order and fixed-service guards. No listeners."""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import native_cohort_service as original_cohort
import native_history_candidate as candidate


def raw(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def entry(data):return dict(sha256=candidate.digest(data),size=len(data),mode=0o444)


class CandidateGuards(unittest.TestCase):
    def setUp(self):
        self.data={candidate.PREFIX/name:name.encode() for name in candidate.FILES}
        self.manifest=dict(format='zolana-native-history-candidate-bundle-v1',
            files={name:entry(self.data[candidate.PREFIX/name]) for name in candidate.FILES})
        self.old_modules={name:name.encode() for name in ('tools/native_cohort_service.py','tools/native_linux_service.py')}
        old_manifest=raw(dict(format='zolana-native-service-bundle-v1',files={k:entry(v) for k,v in self.old_modules.items()}))
        self.old_config=dict(manifest_sha256=candidate.digest(old_manifest));old_raw=raw(self.old_config)
        self.base_sha=candidate.digest(old_raw);binding=b'{"retained_original_binding":true}\n'
        self.config=dict(format='zolana-native-history-candidate-v1',manifest_sha256=candidate.digest(raw(self.manifest)),
            base_config_sha256=self.base_sha,rehearsal_binding_sha256=candidate.digest(binding))
        self.data.update({candidate.PREFIX/'MANIFEST.json':raw(self.manifest),candidate.CONFIG:raw(self.config),
                          candidate.OLD_CONFIG:old_raw,candidate.OLD_PREFIX/'MANIFEST.json':old_manifest,candidate.OLD_BINDING:binding})
        self.data.update({candidate.OLD_PREFIX/k:v for k,v in self.old_modules.items()})
        self.expected=candidate.digest(self.data[candidate.CONFIG]);self.events=[];self.base=object()
        self.cohort=SimpleNamespace(ROOT=Path('/var/lib/zolana-native-058/gateway/cohort-060-rehearsal'),
            PORTS={'rpc':40443,'faucet':40444},select_mode=mock.Mock(),load_binding=mock.Mock(),gateway=mock.Mock())
        def load_base():
            self.events.append('load-base')
            self.assertNotEqual(sys.path[0],str(candidate.PREFIX/'tools'))
            sys.path.insert(0,str(candidate.OLD_PREFIX/'tools'))
            return self.base,self.old_config,self.base_sha
        self.cohort.load_base=load_base
        def import_overlay(name):
            self.events.append(name);self.assertEqual(sys.path[0],str(candidate.PREFIX/'tools'))
            self.assertIs(sys.modules['native_linux_service'],self.base)
            return SimpleNamespace(__file__=str(candidate.PREFIX/'tools'/(name+'.py')))
        self.import_overlay=import_overlay

    def context(self):
        stack=ExitStack();self.addCleanup(stack.close)
        stack.enter_context(mock.patch.dict(sys.modules))
        for name in ('testnet_gateway','native_cohort_fault','native_linux_service'):sys.modules.pop(name,None)
        stack.enter_context(mock.patch.object(sys,'path',list(sys.path)))
        stack.enter_context(mock.patch.object(candidate.sys,'platform','linux'))
        stack.enter_context(mock.patch.object(candidate,'BASE_SHA',self.base_sha))
        stack.enter_context(mock.patch.object(candidate,'__file__',str(candidate.PREFIX/'tools/native_history_candidate.py')))
        stack.enter_context(mock.patch.object(candidate,'sealed',side_effect=lambda path,*args:self.data[path]))
        stack.enter_context(mock.patch.object(candidate,'root_ancestors'))
        stack.enter_context(mock.patch.object(Path,'iterdir',return_value=[candidate.PREFIX/name for name in candidate.FILES]))
        self.loader=stack.enter_context(mock.patch.object(candidate,'load_module',return_value=self.cohort))
        stack.enter_context(mock.patch.object(candidate.importlib,'import_module',side_effect=self.import_overlay))
        return stack

    def test_original_seals_precede_overlay_import_and_no_activation_or_service_is_started(self):
        self.context();cohort,base,config,digest,evidence=candidate.load_runtime(self.expected)
        self.assertEqual(self.events,['load-base','testnet_gateway','native_cohort_fault'])
        self.assertIs(cohort,self.cohort);self.assertIs(base,self.base);self.assertEqual(digest,self.base_sha)
        self.loader.assert_called_once_with('zolana_history_original_cohort',candidate.OLD_PREFIX/'tools/native_cohort_service.py')
        self.cohort.select_mode.assert_called_once_with(True)
        self.cohort.load_binding.assert_called_once_with(self.base,self.old_config,self.base_sha)
        self.cohort.gateway.assert_not_called();self.assertEqual(evidence['services_started'],0)
        self.assertEqual(evidence['original_audiences'],{'rpc':40443,'faucet':40444})
        self.assertEqual(evidence['rehearsal_binding_sha256'],candidate.digest(self.data[candidate.OLD_BINDING]))

    def test_changed_original_config_binding_or_bootstrap_module_never_executes_original_code(self):
        self.context()
        for path in (candidate.OLD_CONFIG,candidate.OLD_BINDING,candidate.OLD_PREFIX/'tools/native_cohort_service.py',
                     candidate.OLD_PREFIX/'tools/native_linux_service.py'):
            saved=self.data[path];self.data[path]=saved+b'changed'
            with self.subTest(path=path),self.assertRaises(ValueError):candidate.load_runtime(self.expected)
            self.loader.assert_not_called();self.data[path]=saved

    def test_candidate_config_manifest_and_exact_module_contents_are_pinned(self):
        self.context()
        for path in (candidate.CONFIG,candidate.PREFIX/'MANIFEST.json',candidate.PREFIX/'tools/testnet_gateway.py',
                     candidate.PREFIX/'tools/native_cohort_fault.py',candidate.PREFIX/'tools/native_history_candidate.py'):
            saved=self.data[path];self.data[path]=saved+b'changed'
            with self.subTest(path=path),self.assertRaises(ValueError):candidate.load_runtime(self.expected)
            self.loader.assert_not_called();self.data[path]=saved
        for bad in ('',None,'a'*63,'a'*64+'\n'):
            with self.assertRaises(ValueError):candidate.load_runtime(bad)

    def test_unmanifested_modules_missing_modules_and_bytecode_cache_are_rejected(self):
        self.context()
        for extra in ('unexpected.py','__pycache__','package'):
            with mock.patch.object(Path,'iterdir',return_value=[*(candidate.PREFIX/name for name in candidate.FILES),candidate.PREFIX/'tools'/extra]):
                with self.subTest(extra=extra),self.assertRaises(ValueError):candidate.verify_candidate(self.config)
        for files in ({},dict(self.manifest['files'],**{'tools/extra.py':entry(b'extra')})):
            manifest=raw(dict(self.manifest,files=files));self.data[candidate.PREFIX/'MANIFEST.json']=manifest
            with self.assertRaises(ValueError):candidate.verify_candidate(dict(self.config,manifest_sha256=candidate.digest(manifest)))

    def test_preloaded_or_substituted_overlays_fail_closed(self):
        self.context()
        for name in ('testnet_gateway','native_cohort_fault','native_linux_service'):
            sys.modules[name]=object()
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'imported before'):candidate.load_runtime(self.expected)
            self.loader.assert_not_called();sys.modules.pop(name)
        with mock.patch.object(candidate.importlib,'import_module',return_value=SimpleNamespace(__file__='/tmp/testnet_gateway.py')):
            with self.assertRaisesRegex(ValueError,'outside'):candidate.load_runtime(self.expected)

    def test_invalid_config_artifact_metadata_and_duplicate_json_are_rejected(self):
        with mock.patch.object(candidate,'BASE_SHA',self.base_sha):
            self.assertEqual(candidate.validate_config(self.config),self.config)
            for key,bad in [('format','old'),('base_config_sha256','a'*64),('manifest_sha256',True),('rehearsal_binding_sha256','x')]:
                with self.subTest(key=key),self.assertRaises(ValueError):candidate.validate_config(dict(self.config,**{key:bad}))
            with self.assertRaises(ValueError):candidate.validate_config(dict(self.config,extra=True))
        data=b'unchanged module'
        for key,bad in [('sha256','a'*64),('size',len(data)+1),('size',True),('mode',0o644),('mode',True)]:
            with self.subTest(key=key),self.assertRaises(ValueError):candidate.check_entry(dict(entry(data),**{key:bad}),data)
        for text in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.assertRaises(ValueError):candidate.decode(text)

    def test_render_preserves_hardening_old_authority_and_conflicts_all_previous_releases(self):
        original=original_cohort.units(True);units=candidate.units(original_cohort,'e'*64)
        self.assertEqual(set(units),{candidate.UNIT,*candidate.SOCKETS.values()})
        service=units[candidate.UNIT]
        for line in ('User=zolana058g','Group=zolana058g','SupplementaryGroups=zolana058link','ProtectSystem=strict',
                     'PrivateNetwork=yes','NoNewPrivileges=yes','KillMode=control-group','CapabilityBoundingSet=',
                     'TemporaryFileSystem=/dev/shm:rw,nodev,nosuid,mode=1777','RestartSec=10s',
                     'JoinsNamespaceOf=zolana-native-058-validator.service',
                     'ReadWritePaths=/var/lib/zolana-native-058/gateway/cohort-060-rehearsal'):
            self.assertIn(line+'\n',service)
        self.assertIn('ExecStart=/usr/bin/python3 -I -B /opt/zolana-native-063/tools/native_history_candidate.py gateway --config-sha256 '+'e'*64,service)
        conflicts=candidate.OLD_UNITS+candidate.PREVIOUS_UNITS
        for text in units.values():
            self.assertIn('Conflicts='+' '.join(conflicts)+'\n',text)
            self.assertIn('After='+' '.join(conflicts)+'\n',text)
            for release in ('060-rehearsal','061','062'):
                for suffix in ('gateway.service','rpc.socket','faucet.socket'):
                    self.assertIn('zolana-native-'+release+'-'+suffix,conflicts)
        self.assertIn('ListenStream=127.0.0.1:40443',units[candidate.SOCKETS['rpc']])
        self.assertIn('ListenStream=127.0.0.1:40444',units[candidate.SOCKETS['faucet']])
        self.assertEqual(original,original_cohort.units(True))
        broken={k:v.replace('gateway --rehearsal','something-else') for k,v in original.items()}
        with mock.patch.object(original_cohort,'units',return_value=broken),self.assertRaises(ValueError):candidate.units(original_cohort,'e'*64)

    def test_new_release_keeps_original_seals_and_explicit_old_unit_mapping(self):
        self.assertEqual(candidate.PREFIX,Path('/opt/zolana-native-063'))
        self.assertEqual(candidate.CONFIG,Path('/etc/zolana-native-063/config.json'))
        self.assertEqual(candidate.OLD_PREFIX,Path('/opt/zolana-native-058'))
        self.assertEqual(candidate.OLD_CONFIG,Path('/etc/zolana-native-058/config.json'))
        self.assertEqual(candidate.OLD_BINDING,Path('/etc/zolana-native-058/cohort-060-rehearsal/binding.json'))
        self.assertEqual(candidate.BASE_SHA,'b043578eb7e8128bd79785100b0df68351fe36948633786a12a4dfdb8ee31397')
        self.assertEqual(candidate.OLD_UNITS,('zolana-native-060-rehearsal-gateway.service',
            'zolana-native-060-rehearsal-rpc.socket','zolana-native-060-rehearsal-faucet.socket'))
        self.assertEqual(candidate.PREVIOUS_UNITS,('zolana-native-061-gateway.service',
            'zolana-native-061-rpc.socket','zolana-native-061-faucet.socket','zolana-native-062-gateway.service',
            'zolana-native-062-rpc.socket','zolana-native-062-faucet.socket'))
        self.assertEqual(candidate.UNIT,'zolana-native-063-gateway.service')
        self.assertEqual(candidate.SOCKETS,dict(rpc='zolana-native-063-rpc.socket',faucet='zolana-native-063-faucet.socket'))

    def test_sealed_reader_checks_actual_modes_size_and_no_follow(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'module.py';path.write_bytes(b'root controlled module');path.chmod(0o444)
            real_fstat=os.fstat
            def root_stat(fd):
                actual=real_fstat(fd)
                return SimpleNamespace(st_mode=actual.st_mode,st_uid=0,st_size=actual.st_size)
            with mock.patch.object(candidate,'root_ancestors'),mock.patch.object(candidate.os,'fstat',side_effect=root_stat):
                self.assertEqual(candidate.sealed(path),path.read_bytes())
                path.chmod(0o644)
                with self.assertRaises(ValueError):candidate.sealed(path)
                path.chmod(0o444)
                with self.assertRaises(ValueError):candidate.sealed(path,3)
                link=path.with_name('link.py');link.symlink_to(path)
                with self.assertRaises(OSError):candidate.sealed(link)

    def test_ancestor_guard_rejects_mutable_or_nonroot_directories(self):
        for uid,mode in ((0,0o755),(1,0o755),(0,0o775)):
            meta=SimpleNamespace(st_mode=stat.S_IFDIR|mode,st_uid=uid)
            with mock.patch.object(Path,'lstat',return_value=meta):
                if uid==0 and mode==0o755:candidate.root_ancestors(Path('/opt/zolana-native-063/tools/module.py'))
                else:
                    with self.assertRaises(ValueError):candidate.root_ancestors(Path('/opt/zolana-native-063/tools/module.py'))
        with self.assertRaises(ValueError):candidate.root_ancestors(Path('relative.py'))


if __name__=='__main__':unittest.main()
