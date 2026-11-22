"""The deployment description: the built-in one changes nothing, a second one changes everything.

No service, validator, listener or account is created. Units are rendered into
temporary directories; nothing is installed.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import deployment
import native_linux_service as accepted
import native_linux_service_test as accepted_tests

TOOLS = Path(__file__).resolve().parent
SECOND_FILE = TOOLS / 'fixtures/deployment_second_v1.json'
SETTINGS = (deployment.SETTING, deployment.DIGEST_SETTING)

# SHA-256 of every unit the tools rendered before they read a description.
ACCEPTED_UNITS = {
    'service': {
        'zolana-native-058-faucet.socket': '8644d84471070ac6d9cf9abec1905f33a70e42938536c1b9625c008cd336101f',
        'zolana-native-058-gateway.service': '531c930596b4a8029cb267a75e39ea0138e07b6c241eaa7ee9089a17875c173e',
        'zolana-native-058-rpc.socket': '200eb46c3c258475ab0f2149047087d06289589a7d7e0ea0c814943b36bbda65',
        'zolana-native-058-validator.service': 'b477bf5efc83663a17ab004c002d65316aa00b38a3e6cab40266569ab20a2e9e',
    },
    'cohort': {
        'zolana-native-060-faucet.socket': 'e9f01643f33378f638c3ee1b2b34804f7ce6e2bd3cd3f7b0fefe6d19dfb1c281',
        'zolana-native-060-gateway.service': 'c5a803d621358c26f5de7abea7c41e234520e942ca637955e89046ee627cf0e1',
        'zolana-native-060-rpc.socket': 'bd6f76e4853836064d479ec09d4960c33a8b17792888f324ae37565ecce1bf10',
    },
    'rehearsal': {
        'zolana-native-060-rehearsal-faucet.socket': '41bbd011b874d3bb8e73ed871c250e96faa565597999437fa6c0350b06f0aafe',
        'zolana-native-060-rehearsal-gateway.service': '5f28cad26f2df9ded49271464a5d854f899dbeed5dd4e907acb4f2f4284e94b8',
        'zolana-native-060-rehearsal-rpc.socket': 'cde84620938e309907adedaf81ed80c0f8ba3e660bacfbdf39a39e83f7b77219',
    },
    'history_candidate': {
        'zolana-native-063-faucet.socket': '62d17ca0d0849b3d4c1fdb6bb97219a282bf363e3e9302f5e5676e0fb2e707b9',
        'zolana-native-063-gateway.service': '124998897aa88563c00e07dd656813869ce5306d90d1b7e0a3c28a089d7b0bf3',
        'zolana-native-063-rpc.socket': 'c864ca7618a1249618fde3763727a31c1b3e7a7dfe4828834bc2eab086fbf680',
    },
}
ACCEPTED_PILOT_UNIT = '0bcf2f906e045e736d6877646148b745196c7b55ff6778d5972e8057752ee2f4'
SECOND_UNITS = {
    'service': {'zolana-second-validator.service', 'zolana-second-gateway.service',
                'zolana-second-rpc.socket', 'zolana-second-faucet.socket'},
    'cohort': {'zolana-second-cohort-gateway.service', 'zolana-second-cohort-rpc.socket',
               'zolana-second-cohort-faucet.socket'},
    'rehearsal': {'zolana-second-cohort-rehearsal-gateway.service', 'zolana-second-cohort-rehearsal-rpc.socket',
                  'zolana-second-cohort-rehearsal-faucet.socket'},
}


def digests(units):
    return {name: hashlib.sha256(text if isinstance(text, bytes) else text.encode()).hexdigest()
            for name, text in units.items()}


def second():
    return deployment.read(SECOND_FILE)


def described(file=None):
    """The process environment with exactly this description selected."""
    values = {} if file is None else {deployment.SETTING: str(file)}
    cleared = {name: value for name, value in os.environ.items() if name not in SETTINGS}
    return mock.patch.dict(os.environ, {**cleared, **values}, clear=True)


def load(module, file=None):
    """A private copy of a tool, imported while a description is selected."""
    with described(file):
        spec = importlib.util.spec_from_file_location(module + '_for_description', TOOLS / (module + '.py'))
        loaded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded)
    return loaded


def render(tool, file, output, *flags):
    """Start a sealed entry point the way its unit does: isolated, with no bytecode."""
    environment = {name: value for name, value in os.environ.items() if name not in SETTINGS}
    if file is not None:
        environment[deployment.SETTING] = str(file)
    return subprocess.Popen([sys.executable, '-I', '-B', str(TOOLS / tool), 'render', '--output', str(output), *flags],
                            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def rendered(directory):
    return {path.name: path.read_text() for path in sorted(Path(directory).iterdir())}


def service_config(count, network=None):
    value = accepted_tests.config()
    identities = value['validator_identities'][:count]
    value.update(validator_identities=identities, validator_layout=value['validator_layout'][:count])
    if network is not None:
        value['network'] = network
    return value


class BuiltInDescription(unittest.TestCase):
    def test_it_is_valid_and_is_what_an_unset_environment_selects(self):
        self.assertEqual(deployment.validate(deployment.default()), deployment.DEFAULT)
        self.assertEqual(deployment.active({}), deployment.DEFAULT)
        self.assertIsNot(deployment.active({}), deployment.DEFAULT)
        self.assertEqual(deployment.unit_environment({}), '')
        with self.assertRaisesRegex(ValueError, 'without'):
            deployment.active({deployment.DIGEST_SETTING: 'a' * 64})

    def test_the_tools_render_the_units_they_rendered_before(self):
        import native_cohort_service as cohort
        import native_history_candidate as candidate
        import pilot_linux
        self.assertEqual(digests(accepted.units()), ACCEPTED_UNITS['service'])
        self.assertEqual(digests(cohort.units(False)), ACCEPTED_UNITS['cohort'])
        self.assertEqual(digests(cohort.units(True)), ACCEPTED_UNITS['rehearsal'])
        self.assertEqual(digests(candidate.units(cohort, 'c' * 64)), ACCEPTED_UNITS['history_candidate'])
        self.assertEqual(hashlib.sha256(pilot_linux.unit('a' * 64, 'b' * 64)).hexdigest(), ACCEPTED_PILOT_UNIT)

    def test_the_values_kept_in_tools_that_are_installed_alone_equal_the_description(self):
        import native_history_candidate as candidate
        import native_snapshot_startup as snapshot
        import native_validator_startup as startup
        import pilot_linux
        value = deployment.DEFAULT
        service, cohort = value['service'], value['cohort']
        base = Path(service['prefix']) / 'tools' / service['module']
        self.assertEqual((startup.INSTALLED_PATH, startup.BASE_PATH, startup.BASE_SHA256),
                         (Path(value['startup']['validator']['installed_path']), base, service['module_sha256']))
        self.assertEqual((snapshot.INSTALLED_PATH, snapshot.RUNNER_PATH, snapshot.BASE_PATH, snapshot.BASE_SHA256),
                         (Path(value['startup']['snapshot']['installed_path']),
                          Path(value['startup']['snapshot']['runner_path']), base, service['module_sha256']))
        chosen = value['history_candidate']
        stem = cohort['rehearsal']['unit_stem']
        self.assertEqual(
            (candidate.PREFIX, candidate.CONFIG, candidate.OLD_PREFIX, candidate.OLD_CONFIG, candidate.OLD_BINDING,
             candidate.BASE_SHA, candidate.UNIT, candidate.SOCKETS, candidate.OLD_UNITS, candidate.PREVIOUS_UNITS,
             candidate.BASE_MODULE),
            (Path(chosen['prefix']), Path(chosen['config']), Path(service['prefix']),
             Path(service['etc']) / 'config.json',
             Path(service['etc']) / cohort['rehearsal']['directory'] / 'binding.json',
             chosen['base_config_sha256'], chosen['unit'], chosen['sockets'],
             (stem + '-gateway.service', stem + '-rpc.socket', stem + '-faucet.socket'),
             tuple(chosen['previous_units']), service['module']))
        self.assertEqual((pilot_linux.PREFIX, pilot_linux.ACCOUNT, pilot_linux.APPROVAL, pilot_linux.UNIT_ENVIRONMENT),
                         (Path(value['pilot']['prefix']), value['pilot']['account'],
                          Path(value['pilot']['approval']), ''))

    def test_the_accepted_service_source_is_the_one_the_description_binds(self):
        raw = (TOOLS / deployment.DEFAULT['service']['module']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), deployment.DEFAULT['service']['module_sha256'])

    def test_the_described_service_is_the_accepted_service(self):
        bound = load('native_network_service')
        self.assertEqual(bound.units(), accepted.units())
        for name in ('PREFIX', 'ETC', 'STATE', 'RUN', 'VALROOT', 'GWROOT', 'READY', 'PORTS', 'UNITS',
                     'CONFIG_KEYS', 'REQUIRED_BINS'):
            self.assertEqual(getattr(bound, name), getattr(accepted, name), name)
        # Every guard test written for the accepted service passes unchanged against it.
        suite = unittest.defaultTestLoader.loadTestsFromModule(accepted_tests)
        result = unittest.TestResult()
        with mock.patch.object(accepted_tests, 'service', bound):
            suite.run(result)
        self.assertEqual((result.errors, result.failures), ([], []))
        self.assertGreaterEqual(result.testsRun, 16)

    def test_a_changed_accepted_source_or_a_stale_replacement_stops_the_described_service(self):
        bound = load('native_network_service')
        with mock.patch.object(bound, 'ACCEPTED_SOURCE', 'deployment.py'):
            with self.assertRaisesRegex(ValueError, 'differs from its SHA-256'):
                bound.accepted_source()
        with mock.patch.object(bound, 'REPLACEMENTS', (("PORTS = {'rpc':1}", 'PORTS = {}', 1),)):
            with self.assertRaisesRegex(ValueError, 'no longer matches'):
                bound.accepted_source()
        self.assertEqual(len({old for old, _, _ in bound.REPLACEMENTS}), len(bound.REPLACEMENTS))


class Validation(unittest.TestCase):
    def refused(self, change):
        value = deployment.default()
        change(value)
        with self.assertRaises(ValueError):
            deployment.validate(value)

    def test_every_field_is_required_and_bounded(self):
        def setter(path, replacement):
            def change(value):
                for key in path[:-1]:
                    value = value[key]
                value[path[-1]] = replacement
            return change
        for path, replacement in [
                (('format',), 'zolana-deployment-v2'), (('name',), 'Zolana'), (('name',), 'a/b'),
                (('validators',), 0), (('validators',), 4), (('validators',), True), (('validators',), '3'),
                (('network', 'genesis_hash'), 'not-base58'), (('network', 'domain'), [0] * 32),
                (('network', 'domain'), [1] * 31), (('network', 'upstream_commit'), 'abc'),
                (('service', 'prefix'), 'opt/relative'), (('service', 'prefix'), '/opt/../etc/x'),
                (('service', 'prefix'), '/'), (('service', 'prefix'), '/opt'), (('service', 'etc'), '/etc/a b'),
                (('service', 'module'), '../evil.py'), (('service', 'module_sha256'), 'A' * 64),
                (('service', 'users', 'gateway'), 'zolana058v'), (('service', 'users', 'tester'), 'Root'),
                (('service', 'link_group'), 'zolana058g'), (('service', 'ports', 'rpc'), 0),
                (('service', 'ports', 'rpc'), 65536), (('service', 'ports', 'faucet'), 38443),
                (('service', 'ports', 'rpc'), 39443), (('service', 'units', 'gateway'), 'gateway'),
                (('service', 'units', 'gateway'), 'zolana-native-058-validator.service'),
                (('service', 'sockets', 'rpc'), 'zolana-native-058-rpc.service'),
                (('cohort', 'pilot', 'directory'), 'a/b'), (('cohort', 'pilot', 'directory'), 'cohort-rehearsal'),
                (('cohort', 'rehearsal', 'directory'), 'practice'),
                (('cohort', 'rehearsal', 'unit_stem'), 'zolana-native-060'),
                (('history', 'binary'), 'native-wallet'), (('history_candidate', 'base_config_sha256'), 'z' * 64),
                (('history_candidate', 'previous_units'), 'zolana-native-061-gateway.service'),
                (('startup', 'snapshot', 'runner_path'), '~/runner'),
                (('public_tls', 'service_uid'), 0), (('public_tls', 'minimum_validity_seconds'), -1),
                (('public_tls', 'lifetime_days'), 0), (('public_tls', 'lifetime_days'), 826),
                (('pilot', 'account'), 'a b'), (('pilot', 'approval'), 'activation.json')]:
            with self.subTest(path=path, replacement=replacement):
                self.refused(setter(path, replacement))
        self.refused(lambda value: value.pop('pilot'))
        self.refused(lambda value: value.update(extra=1))
        self.refused(lambda value: value['service'].pop('run'))
        self.refused(lambda value: value['service']['users'].update(operator='root'))
        self.refused(lambda value: value['cohort'].pop('rehearsal'))
        for bad in (None, [], 'default', 3):
            with self.assertRaises(ValueError):
                deployment.validate(bad)
        accepted_days = deployment.default()
        accepted_days['public_tls']['lifetime_days'] = 365
        deployment.validate(accepted_days)

    def test_a_named_file_is_read_exactly_or_refused_and_never_replaced_by_the_default(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder).resolve()
            good = folder / 'second.json'
            raw = SECOND_FILE.read_bytes()
            good.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            self.assertEqual(deployment.active({deployment.SETTING: str(good)}), second())
            self.assertEqual(deployment.active({deployment.SETTING: str(good), deployment.DIGEST_SETTING: digest}),
                             second())
            self.assertEqual(deployment.unit_environment({deployment.SETTING: str(good)}),
                             'Environment=ZOLANA_DEPLOYMENT=' + str(good) + '\n'
                             'Environment=ZOLANA_DEPLOYMENT_SHA256=' + digest + '\n')
            for wrong in ('0' * 64, 'short', digest.upper()):
                with self.assertRaises(ValueError):
                    deployment.active({deployment.SETTING: str(good), deployment.DIGEST_SETTING: wrong})
            with self.assertRaises(OSError):
                deployment.active({deployment.SETTING: str(folder / 'missing.json')})
            with self.assertRaises(ValueError):
                deployment.active({deployment.SETTING: 'second.json'})
            # A sealed read needs root ownership; this file is ours.
            with self.assertRaises(ValueError):
                deployment.active({deployment.SETTING: str(good)}, sealed=True)
            link = folder / 'link.json'
            link.symlink_to(good)
            with self.assertRaises((OSError, ValueError)):
                deployment.active({deployment.SETTING: str(link)})
            writable = folder / 'writable.json'
            writable.write_bytes(raw)
            writable.chmod(0o666)
            with self.assertRaises(ValueError):
                deployment.active({deployment.SETTING: str(writable)})
            for text in (b'', b'{', b'[]', raw.replace(b'"validators": 2', b'"validators": 2, "validators": 3'),
                         raw.replace(b'"validators": 2', b'"validators": NaN'), b' ' * (deployment.MAXIMUM + 1)):
                bad = folder / 'bad.json'
                bad.write_bytes(text)
                with self.assertRaises(ValueError):
                    deployment.active({deployment.SETTING: str(bad)})
            spaced = folder / 'two words.json'
            spaced.write_bytes(raw)
            with self.assertRaises(ValueError):
                deployment.unit_environment({deployment.SETTING: str(spaced)})

    def test_a_description_that_names_a_network_refuses_another(self):
        chosen = second()
        network = dict(network=chosen['network']['domain'], genesis_hash=chosen['network']['genesis_hash'])
        deployment.check_network(chosen, network)
        for wrong in (dict(network, genesis_hash=accepted.b58(bytes([2]) * 32)), dict(network, network=[8] * 32), {}):
            with self.assertRaises(ValueError):
                deployment.check_network(chosen, wrong)
        deployment.check_network(deployment.DEFAULT, dict(network=[67] * 32, genesis_hash=accepted.b58(bytes([4]) * 32)))


class SecondDescription(unittest.TestCase):
    def test_it_shares_nothing_with_the_built_in_description(self):
        self.assertEqual(deployment.collisions(deployment.default(), second()), [])
        self.assertTrue(deployment.collisions(deployment.default(), deployment.default()))
        for change, word in [
                (lambda v: v['service']['ports'].update(rpc=38443), 'port 38443'),
                (lambda v: v['cohort']['rehearsal']['ports'].update(faucet=39444), 'port 39444'),
                (lambda v: v['service']['users'].update(gateway='zolana058g'), 'zolana058g'),
                (lambda v: v['service'].update(state='/var/lib/zolana-native-058/second'), 'overlaps'),
                (lambda v: v['service'].update(etc='/etc/zolana-native-058'), 'overlaps'),
                (lambda v: v['service']['units'].update(validator='zolana-native-058-validator.service'), 'unit'),
                (lambda v: v['cohort']['pilot'].update(unit_stem='zolana-native-060'), 'unit'),
                (lambda v: v['public_tls'].update(service_uid=994), 'user number 994'),
                (lambda v: v['pilot'].update(account='zolanapilot'), 'zolanapilot'),
                (lambda v: v.update(name='zolana-native-058'), 'named')]:
            value = second()
            change(value)
            found = deployment.collisions(deployment.default(), value)
            self.assertTrue(any(word in line for line in found), (word, found))

    def test_two_deployments_render_side_by_side_from_one_checkout(self):
        jobs = [('service', 'native_network_service.py', ()), ('cohort', 'native_cohort_service.py', ()),
                ('rehearsal', 'native_cohort_service.py', ('--rehearsal',))]
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder).resolve()
            running = []
            # All six start before any is waited for: the two descriptions run at once.
            for kind, tool, flags in jobs:
                for label, file in (('built-in', None), ('second', SECOND_FILE)):
                    output = folder / (kind + '-' + label)
                    running.append((kind, label, output, render(tool, file, output, *flags)))
            results = {}
            for kind, label, output, process in running:
                out, error = process.communicate(timeout=60)
                self.assertEqual(process.returncode, 0, error.decode())
                results[kind, label] = rendered(output)
        ours, theirs = set(), set()
        for kind, _, _ in jobs:
            self.assertEqual(digests(results[kind, 'built-in']), ACCEPTED_UNITS[kind])
            self.assertEqual(set(results[kind, 'second']), SECOND_UNITS[kind])
            for text in results[kind, 'built-in'].values():
                ours |= deployment.pins_in(text)
            for name, text in results[kind, 'second'].items():
                theirs |= deployment.pins_in(text)
                if name.endswith('.service'):
                    self.assertIn('Environment=ZOLANA_DEPLOYMENT=' + str(SECOND_FILE) + '\n', text)
                    self.assertIn('Environment=ZOLANA_DEPLOYMENT_SHA256=' +
                                  hashlib.sha256(SECOND_FILE.read_bytes()).hexdigest() + '\n', text)
        self.assertTrue(ours and theirs)
        self.assertEqual(ours & theirs, set())
        gateway = results['service', 'second']['zolana-second-gateway.service']
        for line in ('User=zsecondg', 'Group=zsecondg', 'SupplementaryGroups=zsecondlink',
                     'WorkingDirectory=/opt/zolana-second', 'ReadWritePaths=/var/lib/zolana-second/gateway',
                     'ExecStart=/usr/bin/python3 -I -B /opt/zolana-second/tools/native_network_service.py gateway',
                     'Sockets=zolana-second-rpc.socket zolana-second-faucet.socket',
                     'JoinsNamespaceOf=zolana-second-validator.service', 'Description=Zolana second network gateway'):
            self.assertIn(line + '\n', gateway)
        self.assertIn('ListenStream=127.0.0.1:48443\n', results['service', 'second']['zolana-second-rpc.socket'])
        cohort = results['rehearsal', 'second']['zolana-second-cohort-rehearsal-gateway.service']
        for line in ('User=zsecondg', 'BindsTo=zolana-second-validator.service',
                     'ReadWritePaths=/var/lib/zolana-second/gateway/cohort-rehearsal',
                     'ExecStart=/usr/bin/python3 -I -B /opt/zolana-second/tools/native_cohort_service.py gateway --rehearsal'):
            self.assertIn(line + '\n', cohort)
        self.assertIn('ListenStream=127.0.0.1:50444\n',
                      results['rehearsal', 'second']['zolana-second-cohort-rehearsal-faucet.socket'])

    def test_the_described_service_enforces_the_second_description(self):
        bound = load('native_network_service', SECOND_FILE)
        self.assertEqual((bound.PREFIX, bound.ETC, bound.STATE, bound.RUN),
                         tuple(Path('/' + top + '/zolana-second') for top in ('opt', 'etc', 'var/lib', 'run')))
        self.assertEqual(bound.PORTS, {'rpc': 48443, 'faucet': 48444})
        self.assertEqual(bound.READY, Path('/run/zolana-second/ready.json'))
        self.assertIs(bound.validate_config(service_config(2))['test_mode'], True)
        for count in (1, 3):
            with self.assertRaises(ValueError):
                bound.validate_config(service_config(count))
        with self.assertRaises(ValueError):
            accepted.validate_config(service_config(2))
        ready = accepted_tests.ready()
        ready.update(peers=ready['peers'][:2], ingress=ready['ingress'][:2])
        self.assertEqual(len(bound.validate_ready(dict(ready), service_config(2))['peers']), 2)
        with self.assertRaises(ValueError):
            bound.validate_ready(accepted_tests.ready(), service_config(2))
        account = mock.Mock(pw_uid=1, pw_gid=1, pw_shell='/bin/sh')
        for role, name in (('validator', 'zsecondv'), ('gateway', 'zsecondg')):
            with mock.patch.object(bound.pwd, 'getpwnam', return_value=account) as lookup:
                with self.assertRaises(ValueError):
                    bound.sandbox(service_config(2), role)
            lookup.assert_called_once_with(name)
        for names in ('rpc:faucet', 'faucet:rpc'):
            first, last = names.split(':')
            records = {3: accepted_tests.FakeSocket(bound.PORTS[first], fileno=3),
                       4: accepted_tests.FakeSocket(bound.PORTS[last], fileno=4)}
            environment = dict(LISTEN_PID=str(os.getpid()), LISTEN_FDS='2', LISTEN_FDNAMES=names)
            with mock.patch.object(bound.os, 'set_inheritable'):
                self.assertEqual(set(bound.activated_sockets(environment, lambda fileno: records[fileno])),
                                 {'rpc', 'faucet'})
            records[3] = accepted_tests.FakeSocket(accepted.PORTS[first], fileno=3)
            with mock.patch.object(bound.os, 'set_inheritable'), self.assertRaises(ValueError):
                bound.activated_sockets(environment, lambda fileno: records[fileno])

    def test_the_described_service_refuses_an_unsealed_description_and_another_network(self):
        bound = load('native_network_service', SECOND_FILE)
        chosen = second()
        network = dict(network=chosen['network']['domain'], genesis_hash=chosen['network']['genesis_hash'])
        with described(SECOND_FILE), mock.patch.object(bound, 'sealed', return_value=json.dumps(service_config(2)).encode()):
            # Another network is refused before the description's seal is looked at.
            with self.assertRaisesRegex(ValueError, 'another network'):
                bound.load_config()
        raw = json.dumps(service_config(2, network)).encode()
        with described(SECOND_FILE), mock.patch.object(bound, 'sealed', return_value=raw), \
                mock.patch.object(bound, 'verify_bundle') as bundle:
            # The fixture is not a root-owned mode 0444 file under root-owned directories.
            with self.assertRaisesRegex(ValueError, 'deployment description'):
                bound.load_config()
            bundle.assert_not_called()
            with mock.patch.object(bound.description, 'active', return_value=second()):
                config, digest = bound.load_config()
            bundle.assert_called_once_with(config)
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

    def test_every_tool_takes_its_names_from_the_second_description(self):
        program = '''
import json, sys
import native_cohort_service as cohort, native_pilot_cohort as planner, native_cohort_fault as fault
import compact_history_collector as collector, public_tls_certificate as tls, public_pilot_ingress as ingress
import native_service_acceptance as acceptance
print(json.dumps(dict(
    cohort=[str(cohort.PREFIX), str(cohort.ROOT), str(cohort.ETC), cohort.PORTS, cohort.UNIT, cohort.SOCKETS, cohort.VALUNIT],
    rehearsal=[str(cohort.fixed_mode(True)[k]) for k in ('root', 'etc', 'unit')],
    planner=[str(planner.PREFIX), str(planner.BASE_CONFIG), str(planner.ROOT), str(planner.ETC),
             str(planner.FAUCET), str(planner.WALLET), planner.MODES],
    fault=[str(fault.root_for(False)), str(fault.root_for(True))],
    collector=[str(collector.ROOT), str(collector.BINARY), str(collector.OPERATOR)],
    tls=[tls.SERVICE_UID, str(tls.TLS_ROOT), str(tls.LETSENCRYPT), tls.GATEWAY, tls.MINIMUM_VALIDITY,
         tls.verified_context.__defaults__[0]],
    ingress=[str(ingress.CONFIG), str(ingress.MANIFEST), str(ingress.BUNDLES), ingress.LOCAL_PORTS, ingress.PUBLIC_PORTS],
    acceptance=[str(acceptance.PREFIX), str(acceptance.CONFIG), str(acceptance.TESTER_PROFILE), str(acceptance.STATE),
                str(acceptance.READY), str(acceptance.GATE), list(acceptance.ACCOUNTS), acceptance.LINK_GROUP,
                acceptance.UNITS, list(acceptance.SOCKET_UNITS), list(acceptance.TLS_PORTS)])))
'''
        environment = {name: value for name, value in os.environ.items() if name not in SETTINGS}
        environment[deployment.SETTING] = str(SECOND_FILE)
        result = subprocess.run([sys.executable, '-B', '-c', program], cwd=TOOLS, env=environment,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        still_typed = {pin for pins in deployment.scan(TOOLS.parent).values() for pin in pins}
        self.assertEqual(deployment.pins_in(result.stdout) & still_typed, set())
        self.assertEqual(json.loads(result.stdout), dict(
            cohort=['/opt/zolana-second', '/var/lib/zolana-second/gateway/cohort', '/etc/zolana-second/cohort',
                    {'rpc': 49443, 'faucet': 49444}, 'zolana-second-cohort-gateway.service',
                    {'rpc': 'zolana-second-cohort-rpc.socket', 'faucet': 'zolana-second-cohort-faucet.socket'},
                    'zolana-second-validator.service'],
            rehearsal=['/var/lib/zolana-second/gateway/cohort-rehearsal', '/etc/zolana-second/cohort-rehearsal',
                       'zolana-second-cohort-rehearsal-gateway.service'],
            planner=['/opt/zolana-second', '/etc/zolana-second/config.json', '/var/lib/zolana-second/gateway/cohort',
                     '/etc/zolana-second/cohort', '/opt/zolana-second/bin/native-faucet',
                     '/opt/zolana-second/bin/native-wallet',
                     {'cohort': [49443, 49444], 'cohort-rehearsal': [50443, 50444]}],
            fault=['/var/lib/zolana-second/gateway/cohort', '/var/lib/zolana-second/gateway/cohort-rehearsal'],
            collector=['/var/lib/zolana-second/gateway/history', '/opt/zolana-second/bin/native-wallet',
                       '/etc/zolana-second/operator.json'],
            tls=[993, '/etc/zolana-second-public/tls', '/etc/letsencrypt', 'zolana-second-cohort-gateway.service',
                 7200, 7200],
            ingress=['/etc/zolana-second-public/public-ingress.json', '/etc/zolana-second-public/tls/current.json',
                     '/etc/zolana-second-public/tls/bundles', {'rpc': 49443, 'faucet': 49444},
                     {'rpc': 8443, 'faucet': 8445}],
            acceptance=['/opt/zolana-second', '/etc/zolana-second/config.json', '/etc/zolana-second/public-profile.json',
                        '/var/lib/zolana-second', '/run/zolana-second/ready.json',
                        '/var/lib/zolana-second/gateway/acceptance-gate', ['zsecondv', 'zsecondg', 'zsecondt'],
                        'zsecondlink', {'validator': 'zolana-second-validator.service',
                                        'gateway': 'zolana-second-gateway.service'},
                        ['zolana-second-rpc.socket', 'zolana-second-faucet.socket'], [48443, 48444]]))

    def test_the_cohort_service_follows_a_description_and_loads_its_service_module(self):
        cohort = load('native_cohort_service', SECOND_FILE)
        self.assertEqual(cohort.DEPLOYMENT, second())
        self.assertEqual(cohort.audience('rpc'), 'https://127.0.0.1:49443')
        cohort.select_mode(True)
        self.assertEqual((cohort.ROOT.name, cohort.audience('faucet')), ('cohort-rehearsal', 'https://127.0.0.1:50444'))
        cohort.configure(deployment.default())
        self.assertEqual((str(cohort.PREFIX), cohort.PORTS, cohort.UNIT),
                         ('/opt/zolana-native-058', {'rpc': 39443, 'faucet': 39444}, 'zolana-native-060-gateway.service'))
        with self.assertRaises(ValueError):
            cohort.configure(dict(deployment.default(), validators=9))
        # Started for the second description but not sealed: refused before any base code is loaded.
        cohort.configure(second())
        with described(SECOND_FILE), mock.patch.object(cohort.importlib.util, 'spec_from_file_location') as spec:
            with self.assertRaisesRegex(ValueError, 'deployment description'):
                cohort.load_base()
            spec.assert_not_called()
        # Sealed: it loads the service module the description names, and holds it to the described network.
        chosen = second()
        network = dict(network=chosen['network']['domain'], genesis_hash=chosen['network']['genesis_hash'])
        loaded = mock.Mock()

        def metadata(path):
            return mock.Mock(st_mode=0o100444 if path.suffix == '.py' else 0o040755, st_uid=0)
        with mock.patch.object(cohort.description, 'active', return_value=second()), \
                mock.patch.object(cohort.Path, 'lstat', metadata), \
                mock.patch.object(cohort.Path, 'resolve', lambda path: path), \
                mock.patch.object(cohort.importlib.util, 'spec_from_file_location') as spec, \
                mock.patch.object(cohort.importlib.util, 'module_from_spec', return_value=loaded), \
                mock.patch.object(cohort.sys, 'path', list(sys.path)):
            loaded.load_config.return_value = (service_config(2, network), 'f' * 64)
            self.assertEqual(cohort.load_base(), (loaded, service_config(2, network), 'f' * 64))
            spec.assert_called_once_with('zolana_sealed_base', Path('/opt/zolana-second/tools/native_network_service.py'))
            self.assertEqual(cohort.sys.path[0], '/opt/zolana-second/tools')
            loaded.load_config.return_value = (service_config(2), 'f' * 64)
            with self.assertRaisesRegex(ValueError, 'another network'):
                cohort.load_base()

    def test_tools_installed_alone_read_their_own_fields(self):
        import native_history_candidate as candidate
        import native_snapshot_startup as snapshot
        import native_validator_startup as startup
        import pilot_linux
        raw = SECOND_FILE.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        chosen = {deployment.SETTING: str(SECOND_FILE), deployment.DIGEST_SETTING: digest}
        base = Path('/opt/zolana-second/tools/native_network_service.py')

        def kept(module, *names):
            return mock.patch.multiple(module, **{name: getattr(module, name) for name in names})

        for module, names in ((startup, ('INSTALLED_PATH', 'BASE_PATH', 'BASE_SHA256')),
                              (snapshot, ('INSTALLED_PATH', 'RUNNER_PATH', 'BASE_PATH', 'BASE_SHA256'))):
            before = tuple(getattr(module, name) for name in names)
            with kept(module, *names):
                self.assertIs(module.described({}), False)
                self.assertEqual(tuple(getattr(module, name) for name in names), before)
                for partial in ({deployment.SETTING: str(SECOND_FILE)}, {deployment.DIGEST_SETTING: digest},
                                dict(chosen, **{deployment.SETTING: 'relative.json'})):
                    with self.assertRaises(ValueError):
                        module.described(partial)
                # Not root-owned and sealed, so the real reader refuses it.
                with self.assertRaises(ValueError):
                    module.described(chosen)
                with mock.patch.object(module, 'sealed_source', return_value=raw) as sealed:
                    self.assertIs(module.described(chosen), True)
                sealed.assert_called_once_with(SECOND_FILE, digest)
                self.assertEqual((module.BASE_PATH, module.BASE_SHA256), (base, 'e' * 64))
                for wrong in (b'{}', raw.replace(b'"/opt/zolana-second"', b'"opt"'),
                              raw.replace(b'native_network_service.py', b'../x.py')):
                    with mock.patch.object(module, 'sealed_source', return_value=wrong):
                        with self.assertRaises((ValueError, KeyError)):
                            module.described(chosen)
            self.assertEqual(tuple(getattr(module, name) for name in names), before)
        with kept(startup, 'INSTALLED_PATH', 'BASE_PATH', 'BASE_SHA256'), \
                mock.patch.object(startup, 'sealed_source', return_value=raw):
            startup.described(chosen)
            self.assertEqual(startup.INSTALLED_PATH, Path('/etc/zolana-second-startup/validator-startup.py'))
        with kept(snapshot, 'INSTALLED_PATH', 'RUNNER_PATH', 'BASE_PATH', 'BASE_SHA256'), \
                mock.patch.object(snapshot, 'sealed_source', return_value=raw):
            snapshot.described(chosen)
            self.assertEqual((snapshot.INSTALLED_PATH, snapshot.RUNNER_PATH),
                             (Path('/etc/zolana-second-snapshot/validator-startup.py'),
                              Path('/opt/zolana-second-snapshot/bin/zolana-fast-check')))

        names = ('PREFIX', 'CONFIG', 'OLD_PREFIX', 'OLD_CONFIG', 'OLD_BINDING', 'BASE_SHA', 'UNIT', 'SOCKETS',
                 'OLD_UNITS', 'PREVIOUS_UNITS', 'BASE_MODULE')
        with kept(candidate, *names):
            self.assertIs(candidate.described({}), False)
            with self.assertRaises(ValueError):
                candidate.described({deployment.SETTING: str(SECOND_FILE)})
            with mock.patch.object(candidate, 'sealed', return_value=raw):
                with self.assertRaises(ValueError):
                    candidate.described(dict(chosen, **{deployment.DIGEST_SETTING: '0' * 64}))
                self.assertIs(candidate.described(chosen), True)
            self.assertEqual(
                (candidate.PREFIX, candidate.CONFIG, candidate.OLD_PREFIX, candidate.OLD_CONFIG, candidate.OLD_BINDING,
                 candidate.BASE_SHA, candidate.UNIT, candidate.OLD_UNITS, candidate.PREVIOUS_UNITS, candidate.BASE_MODULE),
                (Path('/opt/zolana-second-history'), Path('/etc/zolana-second-history/config.json'),
                 Path('/opt/zolana-second'), Path('/etc/zolana-second/config.json'),
                 Path('/etc/zolana-second/cohort-rehearsal/binding.json'), 'd' * 64,
                 'zolana-second-history-gateway.service',
                 ('zolana-second-cohort-rehearsal-gateway.service', 'zolana-second-cohort-rehearsal-rpc.socket',
                  'zolana-second-cohort-rehearsal-faucet.socket'), (), 'native_network_service.py'))
            # The overlay rewrites the units the described cohort service renders.
            cohort = load('native_cohort_service', SECOND_FILE)
            with described(SECOND_FILE):
                units = candidate.units(cohort, 'c' * 64)
            self.assertEqual(set(units), {'zolana-second-history-gateway.service', 'zolana-second-history-rpc.socket',
                                          'zolana-second-history-faucet.socket'})
            gateway = units['zolana-second-history-gateway.service']
            self.assertIn('ExecStart=/usr/bin/python3 -I -B /opt/zolana-second-history/tools/native_history_candidate.py'
                          ' gateway --config-sha256 ' + 'c' * 64 + '\n', gateway)
            self.assertIn('WorkingDirectory=/opt/zolana-second-history\n', gateway)
            self.assertIn('Environment=ZOLANA_DEPLOYMENT=' + str(SECOND_FILE) + '\n', gateway)
            self.assertNotIn('zolana-native', ''.join(units.values()))
        self.assertEqual(candidate.UNIT, 'zolana-native-063-gateway.service')

        with kept(pilot_linux, 'PREFIX', 'ACCOUNT', 'APPROVAL', 'UNIT_ENVIRONMENT'):
            self.assertIs(pilot_linux.described({}), False)
            for wrong in ({deployment.DIGEST_SETTING: digest}, dict(chosen, **{deployment.DIGEST_SETTING: '0' * 64}),
                          {deployment.SETTING: 'relative.json'}):
                with self.assertRaises(ValueError):
                    pilot_linux.described(wrong)
            self.assertIs(pilot_linux.described(chosen), True)
            self.assertEqual((pilot_linux.PREFIX, pilot_linux.ACCOUNT, pilot_linux.APPROVAL),
                             (Path('/opt/zolana-second-pilot'), 'zsecondpilot',
                              Path('/etc/zolana-second-pilot/activation.json')))
            unit = pilot_linux.unit('a' * 64, 'b' * 64).decode()
            for line in ('User=zsecondpilot', 'WorkingDirectory=/opt/zolana-second-pilot',
                         'ConditionPathExists=/etc/zolana-second-pilot/activation.json',
                         'Environment=ZOLANA_DEPLOYMENT=' + str(SECOND_FILE),
                         'Environment=ZOLANA_DEPLOYMENT_SHA256=' + digest):
                self.assertIn(line + '\n', unit)
            self.assertNotIn('/opt/zolana/', unit)
        self.assertEqual(hashlib.sha256(pilot_linux.unit('a' * 64, 'b' * 64)).hexdigest(), ACCEPTED_PILOT_UNIT)


class Lint(unittest.TestCase):
    def test_the_tools_type_nothing_that_is_not_recorded(self):
        self.assertEqual(deployment.lint(TOOLS.parent), [])
        recorded = deployment.load_pins(TOOLS.parent)['files']
        for converted in ('native_cohort_service.py', 'native_pilot_cohort.py', 'native_cohort_fault.py',
                          'compact_history_collector.py', 'public_tls_certificate.py', 'public_pilot_ingress.py',
                          'native_service_acceptance.py'):
            self.assertNotIn('tools/' + converted, recorded)

    def test_it_finds_stems_hashes_and_addresses_and_leaves_ordinary_code_alone(self):
        for text, expected in [
                ("ROOT = Path('/var/lib/zolana-third/gateway')", {'/var/lib/zolana-third/gateway'}),
                ("UNIT='zolana-third-gateway.service'", {'zolana-third-gateway.service'}),
                ("user='zolana123v'", {'zolana123v'}),
                ('PIN = "' + 'ab' * 32 + '"', {'ab' * 32}),
                ("COMMIT='" + '0123456789' * 4 + "'", {'0123456789' * 4}),
                ("GENESIS='" + accepted.b58(bytes(range(7, 39))) + "'", {accepted.b58(bytes(range(7, 39)))}),
                ("HOST='198.18.0.1'", {'198.18.0.1'}),
                ("stream=socket.socket();value=args.service;path='/usr/bin/openssl';x='/etc/ssl/certs'", set()),
                ("HOSTS=('127.0.0.1','0.0.0.0','192.0.2.7','203.0.113.10','::1')", set()),
                ("format='zolana-native-058-ack-arm-v1';other='zolana-example-record-v12'", set()),
                ("name='" + 'word' * 10 + "';version='1.2.3'", set()),
                ("f'/etc/{name}/config.json'", set())]:
            with self.subTest(text=text):
                self.assertEqual(deployment.pins_in(text), expected)

    def test_a_new_pin_and_a_stale_record_both_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / 'tools/fixtures').mkdir(parents=True)

            def record(files):
                reasons = {'kept': 'a reason'}
                (root / deployment.PINS_FILE).write_text(json.dumps(dict(
                    format=deployment.PINS_FORMAT, reasons=reasons,
                    files={name: dict(reason='kept', pins=pins) for name, pins in files.items()})))
            record({})
            (root / 'tools/clean.py').write_text("import socket\nPORT=8080\n")
            (root / 'tools/thing_test.py').write_text("ROOT='/opt/zolana-test-only'\n")
            (root / 'tools/fixtures/sample.json').write_text('{"root": "/opt/zolana-fixture"}\n')
            (root / 'tools/deployment.py').write_text("ROOT='/opt/zolana-described'\n")
            self.assertEqual(deployment.lint(root), [])
            (root / 'tools/new_tool.py').write_text("ROOT='/opt/zolana-typed'\nUNIT='zolana-typed-node.service'\n")
            problems = deployment.lint(root)
            self.assertEqual(len(problems), 2)
            self.assertTrue(all(line.startswith('tools/new_tool.py: types ') for line in problems))
            record({'tools/new_tool.py': ['/opt/zolana-typed', 'zolana-typed-node.service']})
            self.assertEqual(deployment.lint(root), [])
            (root / 'tools/new_tool.py').write_text("ROOT='/opt/zolana-typed'\n")
            self.assertEqual(deployment.lint(root),
                             ['tools/new_tool.py: no longer types zolana-typed-node.service (remove it from ' +
                              deployment.PINS_FILE + ')'])
            (root / 'tools/new_tool.py').unlink()
            self.assertEqual(len(deployment.lint(root)), 2)
            for bad in (dict(format='other', reasons={}, files={}),
                        dict(format=deployment.PINS_FORMAT, reasons={}, files={'tools/x.py': dict(reason='kept', pins=['a'])}),
                        dict(format=deployment.PINS_FORMAT, reasons={'kept': 'r'},
                             files={'tools/x.py': dict(reason='kept', pins=['b', 'a'])}),
                        dict(format=deployment.PINS_FORMAT, reasons={'kept': 'r'},
                             files={'tools/x.py': dict(reason='kept', pins=[])})):
                (root / deployment.PINS_FILE).write_text(json.dumps(bad))
                with self.assertRaises(ValueError):
                    deployment.lint(root)

    def test_the_command_line(self):
        def run(*arguments, file=None):
            environment = {name: value for name, value in os.environ.items() if name not in SETTINGS}
            if file is not None:
                environment[deployment.SETTING] = str(file)
            return subprocess.run([sys.executable, '-I', '-B', str(TOOLS / 'deployment.py'), *arguments],
                                  env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(json.loads(run('show').stdout), deployment.DEFAULT)
        self.assertEqual(json.loads(run('show', file=SECOND_FILE).stdout), second())
        self.assertEqual(run('check', str(SECOND_FILE)).returncode, 0)
        self.assertEqual(run('compare', 'default', str(SECOND_FILE)).returncode, 0)
        clash = run('compare', 'default', 'default')
        self.assertEqual(clash.returncode, 1)
        self.assertIn('both are named', clash.stdout)
        self.assertEqual(run('lint').returncode, 0)


if __name__ == '__main__':
    unittest.main()
