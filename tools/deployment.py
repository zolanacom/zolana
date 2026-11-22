#!/usr/bin/env python3
"""The deployment description: one file that names a network's installation.

A deployment is the set of values that tell one installed network from another on
the same host: its name, its paths, its service accounts, its loopback ports, its
unit names, how many validators it runs and which hashes it is bound to. The tools
used to carry these as typed constants. They now read them from here.

DEFAULT is the description the tools have always used; with ZOLANA_DEPLOYMENT unset
every tool behaves exactly as before. Set ZOLANA_DEPLOYMENT to the absolute path of
a JSON file with the same shape to run the tools for another deployment, and
ZOLANA_DEPLOYMENT_SHA256 to bind that file's exact bytes. See
docs/deployment-description.md.

Standard library only, and no imports of sibling tools: sealed service entry points
load this file by path before any other module.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

FORMAT = 'zolana-deployment-v1'
SETTING = 'ZOLANA_DEPLOYMENT'
DIGEST_SETTING = 'ZOLANA_DEPLOYMENT_SHA256'
MAXIMUM = 65536
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# Every value below was a typed constant in the tool named beside it.
DEFAULT = {
    'format': FORMAT,
    'name': 'zolana-native-058',
    'network': {
        # None means the tools take the value from the sealed service
        # configuration, as they always have. A value here is compared with it.
        'genesis_hash': None,
        'domain': None,
        'upstream_commit': 'a203300045b405f86c9c84308b2eae76af69ac3b',
    },
    # The runner starts and resumes clusters of one to three validators.
    'validators': 3,
    'service': {  # native_linux_service.py, native_service_acceptance.py
        'label': 'LOCAL-058',
        'module': 'native_linux_service.py',
        'module_sha256': '5f102297516b40ff8299def02e6a993e4277e3f80bc6ed958102b5781b106a7a',
        'prefix': '/opt/zolana-native-058',
        'etc': '/etc/zolana-native-058',
        'state': '/var/lib/zolana-native-058',
        'run': '/run/zolana-native-058',
        'users': {'validator': 'zolana058v', 'gateway': 'zolana058g', 'tester': 'zolana058t'},
        'link_group': 'zolana058link',
        'ports': {'rpc': 38443, 'faucet': 38444},
        'units': {'validator': 'zolana-native-058-validator.service',
                  'gateway': 'zolana-native-058-gateway.service'},
        'sockets': {'rpc': 'zolana-native-058-rpc.socket', 'faucet': 'zolana-native-058-faucet.socket'},
    },
    'cohort': {  # native_cohort_service.py, native_pilot_cohort.py, native_cohort_fault.py
        'label': 'LOCAL-060',
        'pilot': {'directory': 'cohort-060', 'unit_stem': 'zolana-native-060',
                  'ports': {'rpc': 39443, 'faucet': 39444}},
        'rehearsal': {'directory': 'cohort-060-rehearsal', 'unit_stem': 'zolana-native-060-rehearsal',
                      'ports': {'rpc': 40443, 'faucet': 40444}},
    },
    'history': {  # compact_history_collector.py
        'root': '/var/lib/zolana-native-058/gateway/history-065',
        'binary': '/opt/zolana-native-065/bin/native-wallet',
        'operator_profile': '/etc/zolana-native-064/mac-live/operator.json',
    },
    'history_candidate': {  # native_history_candidate.py
        'prefix': '/opt/zolana-native-063',
        'config': '/etc/zolana-native-063/config.json',
        'base_config_sha256': 'b043578eb7e8128bd79785100b0df68351fe36948633786a12a4dfdb8ee31397',
        'unit': 'zolana-native-063-gateway.service',
        'sockets': {'rpc': 'zolana-native-063-rpc.socket', 'faucet': 'zolana-native-063-faucet.socket'},
        'previous_units': ['zolana-native-061-gateway.service', 'zolana-native-061-rpc.socket',
                           'zolana-native-061-faucet.socket', 'zolana-native-062-gateway.service',
                           'zolana-native-062-rpc.socket', 'zolana-native-062-faucet.socket'],
    },
    'startup': {  # native_validator_startup.py, native_snapshot_startup.py
        'validator': {'installed_path': '/etc/zolana-native-065/validator-startup.py'},
        'snapshot': {'installed_path': '/etc/zolana-native-072/validator-startup.py',
                     'runner_path': '/opt/zolana-native-072/bin/zolana-fast-check'},
    },
    'public_tls': {  # public_tls_certificate.py, public_pilot_ingress.py
        'root': '/etc/zolana-native-074/tls',
        'ingress_config': '/etc/zolana-native-074/public-ingress.json',
        'certificate_source': '/etc/letsencrypt',
        'service_uid': 994,
        'ports': {'rpc': 443, 'faucet': 8444},
        # Seconds of validity a certificate must still have when it is deployed or loaded.
        'minimum_validity_seconds': 3600,
        # Days an installer issues the loopback certificate for. No tool in this
        # repository issues it, so no tool reads this field: it is here so that
        # the installers have one place to take it from.
        'lifetime_days': None,
    },
    'pilot': {  # pilot_linux.py
        'prefix': '/opt/zolana',
        'account': 'zolanapilot',
        'approval': '/etc/zolana-pilot/activation.json',
    },
}

NAME = re.compile(r'[a-z][a-z0-9-]{2,47}\Z')
LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}\Z')
ACCOUNT = re.compile(r'[a-z_][a-z0-9_-]{0,31}\Z')
UNIT_STEM = re.compile(r'[a-z][a-z0-9-]{2,63}\Z')
UNIT = re.compile(r'[a-z][a-z0-9-]{2,63}\.(service|socket)\Z')
MODULE = re.compile(r'[a-z][a-z0-9_]{2,63}\.py\Z')
SEGMENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')
HEX64 = re.compile(r'[a-f0-9]{64}\Z')
HEX40 = re.compile(r'[a-f0-9]{40}\Z')


def default():
    """A private copy of the built-in description."""
    return copy.deepcopy(DEFAULT)


def _keys(value, expected, where):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError('deployment description: ' + where + ' must have exactly the fields ' +
                         ', '.join(sorted(expected)))


def _text(value, pattern, where):
    if not isinstance(value, str) or pattern.match(value) is None:
        raise ValueError('deployment description: ' + where + ' is not an accepted value')
    return value


def _path(value, where):
    if (not isinstance(value, str) or not value.startswith('/') or value != str(PurePosixPath(value))
            or len(value) > 255 or len(PurePosixPath(value).parts) < 3
            or any(SEGMENT.match(part) is None or part in ('.', '..') for part in PurePosixPath(value).parts[1:])):
        raise ValueError('deployment description: ' + where +
                         ' must be a normal absolute path below a top-level directory')
    return value


def _port(value, where):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError('deployment description: ' + where + ' must be a port number')
    return value


def _ports(value, where):
    _keys(value, ('rpc', 'faucet'), where)
    for name in ('rpc', 'faucet'):
        _port(value[name], where + '.' + name)
    if value['rpc'] == value['faucet']:
        raise ValueError('deployment description: ' + where + ' must name two different ports')


def public_key(value):
    """Canonical base58 text of exactly 32 bytes."""
    if not isinstance(value, str) or not 32 <= len(value) <= 44 or any(c not in B58 for c in value):
        return False
    number = 0
    for character in value:
        number = number * 58 + B58.index(character)
    return (number.bit_length() + 7) // 8 + len(value) - len(value.lstrip('1')) == 32


def validate(value):
    """Check the complete description; partial descriptions are refused."""
    _keys(value, DEFAULT, 'the description')
    if value['format'] != FORMAT:
        raise ValueError('deployment description: unsupported format')
    _text(value['name'], NAME, 'name')

    network = value['network']
    _keys(network, DEFAULT['network'], 'network')
    if network['genesis_hash'] is not None and not public_key(network['genesis_hash']):
        raise ValueError('deployment description: network.genesis_hash must be base58 of 32 bytes or null')
    domain = network['domain']
    if domain is not None and (not isinstance(domain, list) or len(domain) != 32 or domain == [0] * 32
                               or any(type(item) is not int or not 0 <= item <= 255 for item in domain)):
        raise ValueError('deployment description: network.domain must be 32 bytes, not all zero, or null')
    _text(network['upstream_commit'], HEX40, 'network.upstream_commit')

    if type(value['validators']) is not int or not 1 <= value['validators'] <= 3:
        raise ValueError('deployment description: validators must be one, two or three')

    service = value['service']
    _keys(service, DEFAULT['service'], 'service')
    _text(service['label'], LABEL, 'service.label')
    _text(service['module'], MODULE, 'service.module')
    _text(service['module_sha256'], HEX64, 'service.module_sha256')
    for name in ('prefix', 'etc', 'state', 'run'):
        _path(service[name], 'service.' + name)
    _keys(service['users'], ('validator', 'gateway', 'tester'), 'service.users')
    accounts = [_text(service['users'][role], ACCOUNT, 'service.users.' + role)
                for role in ('validator', 'gateway', 'tester')]
    accounts.append(_text(service['link_group'], ACCOUNT, 'service.link_group'))
    if len(set(accounts)) != 4:
        raise ValueError('deployment description: the three service accounts and the link group must differ')
    _ports(service['ports'], 'service.ports')
    _keys(service['units'], ('validator', 'gateway'), 'service.units')
    _keys(service['sockets'], ('rpc', 'faucet'), 'service.sockets')
    for role, unit in service['units'].items():
        if not _text(unit, UNIT, 'service.units.' + role).endswith('.service'):
            raise ValueError('deployment description: service.units must name services')
    for role, unit in service['sockets'].items():
        if not _text(unit, UNIT, 'service.sockets.' + role).endswith('.socket'):
            raise ValueError('deployment description: service.sockets must name sockets')

    cohort = value['cohort']
    _keys(cohort, DEFAULT['cohort'], 'cohort')
    _text(cohort['label'], LABEL, 'cohort.label')
    for mode in ('pilot', 'rehearsal'):
        _keys(cohort[mode], DEFAULT['cohort'][mode], 'cohort.' + mode)
        _text(cohort[mode]['directory'], SEGMENT, 'cohort.' + mode + '.directory')
        _text(cohort[mode]['unit_stem'], UNIT_STEM, 'cohort.' + mode + '.unit_stem')
        _ports(cohort[mode]['ports'], 'cohort.' + mode + '.ports')
    if (cohort['pilot']['directory'] == cohort['rehearsal']['directory']
            or cohort['pilot']['unit_stem'] == cohort['rehearsal']['unit_stem']
            # The tools tell the two modes apart by this suffix.
            or cohort['pilot']['directory'].endswith('-rehearsal')
            or not cohort['rehearsal']['directory'].endswith('-rehearsal')):
        raise ValueError('deployment description: the pilot and rehearsal cohorts must be separate, '
                         'and only the rehearsal directory may end in -rehearsal')

    history = value['history']
    _keys(history, DEFAULT['history'], 'history')
    for name in DEFAULT['history']:
        _path(history[name], 'history.' + name)

    candidate = value['history_candidate']
    _keys(candidate, DEFAULT['history_candidate'], 'history_candidate')
    _path(candidate['prefix'], 'history_candidate.prefix')
    _path(candidate['config'], 'history_candidate.config')
    _text(candidate['base_config_sha256'], HEX64, 'history_candidate.base_config_sha256')
    _text(candidate['unit'], UNIT, 'history_candidate.unit')
    _keys(candidate['sockets'], ('rpc', 'faucet'), 'history_candidate.sockets')
    for role, unit in candidate['sockets'].items():
        _text(unit, UNIT, 'history_candidate.sockets.' + role)
    if not isinstance(candidate['previous_units'], list) or len(candidate['previous_units']) > 16:
        raise ValueError('deployment description: history_candidate.previous_units must be a short list')
    for unit in candidate['previous_units']:
        _text(unit, UNIT, 'history_candidate.previous_units')

    startup = value['startup']
    _keys(startup, DEFAULT['startup'], 'startup')
    _keys(startup['validator'], DEFAULT['startup']['validator'], 'startup.validator')
    _keys(startup['snapshot'], DEFAULT['startup']['snapshot'], 'startup.snapshot')
    _path(startup['validator']['installed_path'], 'startup.validator.installed_path')
    _path(startup['snapshot']['installed_path'], 'startup.snapshot.installed_path')
    _path(startup['snapshot']['runner_path'], 'startup.snapshot.runner_path')

    tls = value['public_tls']
    _keys(tls, DEFAULT['public_tls'], 'public_tls')
    for name in ('root', 'ingress_config', 'certificate_source'):
        _path(tls[name], 'public_tls.' + name)
    if type(tls['service_uid']) is not int or not 1 <= tls['service_uid'] < 65534:
        raise ValueError('deployment description: public_tls.service_uid must be an unprivileged user number')
    _ports(tls['ports'], 'public_tls.ports')
    if type(tls['minimum_validity_seconds']) is not int or not 0 <= tls['minimum_validity_seconds'] <= 2147483647:
        raise ValueError('deployment description: public_tls.minimum_validity_seconds out of range')
    if tls['lifetime_days'] is not None and (type(tls['lifetime_days']) is not int
                                             or not 1 <= tls['lifetime_days'] <= 825):
        raise ValueError('deployment description: public_tls.lifetime_days must be 1 to 825 or null')

    pilot = value['pilot']
    _keys(pilot, DEFAULT['pilot'], 'pilot')
    _path(pilot['prefix'], 'pilot.prefix')
    _text(pilot['account'], ACCOUNT, 'pilot.account')
    _path(pilot['approval'], 'pilot.approval')

    loopback = [service['ports'][n] for n in ('rpc', 'faucet')]
    loopback += [cohort[mode]['ports'][n] for mode in ('pilot', 'rehearsal') for n in ('rpc', 'faucet')]
    if len(set(loopback)) != len(loopback):
        raise ValueError('deployment description: the six loopback ports must all differ')
    names = unit_names(value)
    if len(set(names)) != len(names):
        raise ValueError('deployment description: every unit name must be different')
    return value


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('deployment description: duplicate field ' + key)
            value[key] = item
        return value

    def refuse(_):
        raise ValueError('deployment description: non-finite number')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=refuse)


def read(path, digest=None, sealed=False):
    """Read and validate a description file.

    sealed=True is for installed services: the file must be root-owned, mode
    0444, and every directory above it root-owned and not writable by others.
    """
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError('deployment description: an absolute real path is required')
    if digest is not None and (not isinstance(digest, str) or HEX64.match(digest) is None):
        raise ValueError('deployment description: the expected SHA-256 is not 64 lower-case hex digits')
    if sealed:
        for parent in path.parents:
            meta = parent.lstat()
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
                raise ValueError('deployment description: a sealed file needs immutable root-owned directories above it')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        meta = os.fstat(source.fileno())
        if not stat.S_ISREG(meta.st_mode) or not 1 <= meta.st_size <= MAXIMUM or meta.st_mode & 0o022:
            raise ValueError('deployment description: a bounded regular file that others cannot write is required')
        if sealed and (meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) != 0o444):
            raise ValueError('deployment description: a sealed file must be root-owned with mode 0444')
        raw = source.read(MAXIMUM + 1)
    if len(raw) != meta.st_size:
        raise ValueError('deployment description: the file changed while it was read')
    if digest is not None and hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('deployment description: the file differs from its expected SHA-256')
    return validate(decode(raw))


def selected(environment=None):
    """(path, digest) of the description file the environment names, or None for the built-in one."""
    environment = os.environ if environment is None else environment
    path = environment.get(SETTING)
    digest = environment.get(DIGEST_SETTING)
    if path is None:
        if digest is not None:
            raise ValueError('deployment description: ' + DIGEST_SETTING + ' is set without ' + SETTING)
        return None
    return path, digest


def active(environment=None, sealed=False):
    """The description this process runs for.

    An unset ZOLANA_DEPLOYMENT is the built-in description. A set one is never
    replaced by the built-in description on any error: the error is raised.
    """
    choice = selected(environment)
    if choice is None:
        return default()
    return read(choice[0], choice[1], sealed=sealed)


def check_network(value, network):
    """Refuse a sealed service configuration for a network the description does not name.

    network is the {'network': 32 bytes, 'genesis_hash': base58} object of the
    sealed configuration. A description that names neither accepts any.
    """
    expected = value['network']
    if ((expected['genesis_hash'] is not None and network.get('genesis_hash') != expected['genesis_hash'])
            or (expected['domain'] is not None and network.get('network') != expected['domain'])):
        raise ValueError('sealed service configuration is for another network than the deployment description')


def unit_environment(environment=None):
    """Lines for a rendered unit so that the service reads the same description.

    Empty for the built-in description, so units rendered for it do not change.
    """
    choice = selected(environment)
    if choice is None:
        return ''
    path, digest = choice
    if any(character.isspace() or not character.isprintable() for character in path):
        raise ValueError('deployment description: a path without spaces is required in a unit')
    raw = Path(path).read_bytes()
    read(path, digest)
    return ('Environment=' + SETTING + '=' + path + '\n' +
            'Environment=' + DIGEST_SETTING + '=' + hashlib.sha256(raw).hexdigest() + '\n')


def cohort_mode(value, rehearsal=False):
    """Paths, ports and unit names of one of the two cohort modes."""
    if type(rehearsal) is not bool:
        raise ValueError('only the two fixed cohort modes are allowed')
    chosen = value['cohort']['rehearsal' if rehearsal else 'pilot']
    stem = chosen['unit_stem']
    ports = dict(chosen['ports'])
    return dict(root=Path(value['service']['state']) / 'gateway' / chosen['directory'],
                etc=Path(value['service']['etc']) / chosen['directory'], ports=ports,
                unit=stem + '-gateway.service',
                sockets={role: stem + '-' + role + '.socket' for role in ports})


def unit_names(value):
    names = list(value['service']['units'].values()) + list(value['service']['sockets'].values())
    for rehearsal in (False, True):
        mode = cohort_mode(value, rehearsal)
        names.append(mode['unit'])
        names.extend(mode['sockets'].values())
    names.append(value['history_candidate']['unit'])
    names.extend(value['history_candidate']['sockets'].values())
    return names


def roots(value):
    """Every directory or file a deployment owns outright."""
    service = value['service']
    return {
        'service.prefix': service['prefix'], 'service.etc': service['etc'],
        'service.state': service['state'], 'service.run': service['run'],
        'history.root': value['history']['root'], 'history.binary': value['history']['binary'],
        'history.operator_profile': value['history']['operator_profile'],
        'history_candidate.prefix': value['history_candidate']['prefix'],
        'history_candidate.config': value['history_candidate']['config'],
        'startup.validator.installed_path': value['startup']['validator']['installed_path'],
        'startup.snapshot.installed_path': value['startup']['snapshot']['installed_path'],
        'startup.snapshot.runner_path': value['startup']['snapshot']['runner_path'],
        'public_tls.root': value['public_tls']['root'],
        'public_tls.ingress_config': value['public_tls']['ingress_config'],
        'pilot.prefix': value['pilot']['prefix'], 'pilot.approval': value['pilot']['approval'],
    }


def _overlap(first, second):
    first, second = PurePosixPath(first), PurePosixPath(second)
    return first == second or first in second.parents or second in first.parents


def collisions(first, second):
    """Why two descriptions cannot be installed on one host; empty when they can."""
    validate(first)
    validate(second)
    found = []
    if first['name'] == second['name']:
        found.append('both are named ' + first['name'])
    theirs = roots(second)
    for name, path in roots(first).items():
        for other, candidate in theirs.items():
            if _overlap(path, candidate):
                found.append(name + ' ' + path + ' overlaps ' + other + ' ' + candidate)

    def accounts(value):
        service = value['service']
        return set(service['users'].values()) | {service['link_group'], value['pilot']['account']}
    for account in sorted(accounts(first) & accounts(second)):
        found.append('both use the account or group ' + account)

    def ports(value):
        result = set(value['service']['ports'].values()) | set(value['public_tls']['ports'].values())
        for mode in ('pilot', 'rehearsal'):
            result |= set(value['cohort'][mode]['ports'].values())
        return result
    for port in sorted(ports(first) & ports(second)):
        found.append('both use port ' + str(port))
    for unit in sorted(set(unit_names(first)) & set(unit_names(second))):
        found.append('both name the unit ' + unit)
    if first['public_tls']['service_uid'] == second['public_tls']['service_uid']:
        found.append('both give the public TLS files to user number ' + str(first['public_tls']['service_uid']))
    return found


# ---- The lint: no typed stem, hash or address outside this file and the tests ----

PINS_FILE = 'tools/deployment_pins.json'
PINS_FORMAT = 'zolana-deployment-pins-v1'
STEM_PATTERNS = (
    # Absolute paths under the directories that hold installed software and its state.
    re.compile(r'''(?<![A-Za-z0-9_.{}/-])/(?:opt|etc|srv|run|var/lib|var/log|Library|home|root)/[A-Za-z0-9_.@/-]*[A-Za-z0-9_]'''),
    # systemd unit names (a hyphen tells them from attribute access in code).
    re.compile(r'''(?<![A-Za-z0-9_.{}/-])[A-Za-z][A-Za-z0-9_.@]*-[A-Za-z0-9_.@-]*\.(?:service|socket|timer)(?![A-Za-z0-9_])'''),
    # Names that carry a three-digit generation number, and the project's account names.
    re.compile(r'''(?<![A-Za-z0-9_/-])(?:zolana|cohort|history)[a-z-]*[0-9]{3}[a-z0-9-]*'''),
    re.compile(r'''(?<![A-Za-z0-9/])_?(?:zolanapilot|zolana-pilot|nativepay)(?![A-Za-z0-9-])'''),
)
# A name that ends in a version, such as zolana-example-record-v1, names a file
# or message format. Formats are the same in every deployment.
FORMAT_NAME = re.compile(r'-v[0-9]+\Z')
HASH_PATTERNS = (
    re.compile(r'(?<![0-9A-Fa-f])[0-9a-f]{64}(?![0-9A-Fa-f])'),
    re.compile(r'(?<![0-9A-Fa-f])[0-9a-f]{40}(?![0-9A-Fa-f])'),
)
BASE58_PATTERN = re.compile(r'(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![1-9A-HJ-NP-Za-km-z])')
IPV4_PATTERN = re.compile(r'(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])')
# Places every host has; naming them does not tie a tool to one deployment.
SYSTEM_PATHS = ('/etc/ssl/certs', '/etc/passwd', '/etc/group', '/etc/hosts', '/etc/os-release',
                '/etc/machine-id', '/etc/systemd/system', '/run/systemd', '/run/credentials',
                '/Library/LaunchDaemons', '/Library/Keychains', '/Library/Developer')
DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(n) for n in
                               ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'))
TEXT_SUFFIXES = ('.py', '.sh', '.cjs', '.mjs', '.js', '.json', '.service', '.socket', '.timer', '.toml', '.txt', '')


def is_test(path):
    """Tests and their fixtures may type any value."""
    name = path.name
    return ('fixtures' in path.parts or name.endswith(('_test.py', '_test.cjs')) or '.test.' in name
            # The explorer's tests are named the other way round; test_faucet.py is a tool.
            or (path.parent.name == 'devnet_explorer' and name.startswith('test_')))


def pins_in(text):
    """Typed stems, hashes and addresses in one file's text."""
    found = set()
    for pattern in STEM_PATTERNS:
        for match in pattern.finditer(text):
            token = match.group(0)
            if ((token.startswith('/') or FORMAT_NAME.search(token) is None)
                    and not any(token == path or token.startswith(path + '/') for path in SYSTEM_PATHS)):
                found.add(token)
    for pattern in HASH_PATTERNS:
        found.update(match.group(0) for match in pattern.finditer(text))
    for match in BASE58_PATTERN.finditer(text):
        token = match.group(0)
        # An address decodes to 32 bytes and mixes digits with both cases;
        # a long identifier or word does not.
        if (public_key(token) and any(c.isdigit() for c in token)
                and any(c.isupper() for c in token) and any(c.islower() for c in token)):
            found.add(token)
    for match in IPV4_PATTERN.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if not (address.is_loopback or address.is_unspecified
                or any(address in network for network in DOCUMENTATION_NETWORKS)
                or int(address) == 2 ** 32 - 1):
            found.add(match.group(0))
    return found


def scan(root):
    """{'tools/name': sorted pins} for every tool that types one."""
    root = Path(root)
    result = {}
    for path in sorted((root / 'tools').rglob('*')):
        relative = path.relative_to(root)
        if (not path.is_file() or path.is_symlink() or '__pycache__' in path.parts
                or path.suffix not in TEXT_SUFFIXES or is_test(relative)
                or relative.as_posix() in ('tools/deployment.py', PINS_FILE)):
            continue
        try:
            text = path.read_text(encoding='utf-8')
        except (UnicodeDecodeError, OSError):
            continue
        pins = pins_in(text)
        if pins:
            result[relative.as_posix()] = sorted(pins)
    return result


def load_pins(root):
    value = decode((Path(root) / PINS_FILE).read_bytes())
    _keys(value, ('format', 'reasons', 'files'), 'the recorded pins')
    if (value['format'] != PINS_FORMAT or not isinstance(value['reasons'], dict)
            or not isinstance(value['files'], dict)):
        raise ValueError('recorded pins: unsupported format')
    for name, entry in value['files'].items():
        _keys(entry, ('reason', 'pins'), 'recorded pins for ' + name)
        if (entry['reason'] not in value['reasons'] or not isinstance(entry['pins'], list) or not entry['pins']
                or entry['pins'] != sorted(set(entry['pins']))
                or any(not isinstance(pin, str) for pin in entry['pins'])):
            raise ValueError('recorded pins for ' + name + ': a known reason and a sorted list are required')
    return value


def lint(root):
    """Problems, as lines of text; empty when the tools type nothing new.

    A tool may type a stem, hash or address only if tools/deployment_pins.json
    records it with a reason. The record can only shrink: an entry that no
    longer matches the file is itself a problem.
    """
    recorded = load_pins(root)['files']
    found = scan(root)
    problems = []
    for name in sorted(set(found) | set(recorded)):
        present = set(found.get(name, ()))
        allowed = set(recorded[name]['pins']) if name in recorded else set()
        for pin in sorted(present - allowed):
            problems.append(name + ': types ' + pin +
                            ' (take it from the deployment description, or record why it must stay)')
        for pin in sorted(allowed - present):
            problems.append(name + ': no longer types ' + pin + ' (remove it from ' + PINS_FILE + ')')
    return problems


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('show', help='print the description in use')
    check = commands.add_parser('check', help='validate a description file')
    check.add_argument('file', type=Path)
    compare = commands.add_parser('compare', help='say whether two descriptions can share a host')
    compare.add_argument('first')
    compare.add_argument('second')
    commands.add_parser('lint', help='fail on a typed stem, hash or address outside this file and the tests')
    args = parser.parse_args(arguments)
    if args.command == 'show':
        print(json.dumps(active(), indent=2, sort_keys=True))
    elif args.command == 'check':
        read(args.file.resolve())
        print('valid deployment description: ' + str(args.file))
    elif args.command == 'compare':
        pair = [default() if name == 'default' else read(Path(name).resolve()) for name in (args.first, args.second)]
        found = collisions(*pair)
        for line in found:
            print(line)
        if found:
            return 1
        print('the two deployments share no name, path, account, port or unit')
    else:
        problems = lint(Path(__file__).resolve().parents[1])
        for line in problems:
            print(line, file=sys.stderr)
        if problems:
            return 1
        print('no typed deployment stem, hash or address outside the description and the recorded pins')
    return 0


if __name__ == '__main__':
    sys.exit(main())
