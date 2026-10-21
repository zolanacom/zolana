"""Fixed LOCAL065 public-history collector; no wallet or payment authority."""
import json
import os
from pathlib import Path
import urllib.request

from history_retention import Retention, atomic, directory, read

ROOT = Path('/var/lib/zolana-native-058/gateway/history-065')
BINARY = Path('/opt/zolana-native-065/bin/native-wallet')
OPERATOR = Path('/etc/zolana-native-064/mac-live/operator.json')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def query(rpc, method, params):
    allowed = {'getSlot': [{'commitment': 'finalized'}], 'getFirstAvailableBlock': []}
    if method not in allowed or params != allowed[method]:
        raise ValueError('only fixed public collector checkpoint reads allowed')
    request = urllib.request.Request(rpc,
        json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params)).encode(),
        {'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=2) as response:
        if response.status != 200:
            raise ValueError('collector checkpoint HTTP failure')
        raw = response.read(4097)
        if len(raw) > 4096:
            raise ValueError('collector checkpoint response exceeds bound')
    value = json.loads(raw)
    if (not isinstance(value, dict) or set(value) != {'jsonrpc', 'id', 'result'}
            or value['jsonrpc'] != '2.0' or type(value['id']) is not int or value['id'] != 1
            or type(value['result']) is not int or not 0 <= value['result'] <= 2**64 - 1):
        raise ValueError('invalid collector checkpoint response')
    return value['result']


def make_collector(base, config, ready, history_root, binary):
    """The sealed runtime verifies the binary manifest before invoking this."""
    if Path(history_root) != ROOT or Path(binary) != BINARY or os.geteuid() != config['gateway_uid']:
        raise ValueError('fixed owned collector paths and service identity required')
    base.real_directory(ROOT, config['gateway_uid'], 0o700)
    directory(ROOT)
    if ready.get('network') != config['network'] or ready.get('pool_format') != 'NPOOL004':
        raise ValueError('collector cannot change the retained chain')
    rpc = 'http://' + base.endpoint(ready['peers'][0]['rpc'])
    # This is a public operator profile, already byte-pinned by LOCAL064.
    # Never copy a seed, password, ledger, signer or RPC credential into history.
    raw = base.sealed(OPERATOR, 32768)
    profile = json.loads(raw)
    if ({key: profile.get(key) for key in ('network', 'genesis_hash')} != config['network']
            or profile.get('pool_format') != 'NPOOL004' or profile.get('invite_required', False)
            or profile.get('key_mode') == 'user-wallet-v1'):
        raise ValueError('unchanged non-invited public operator profile required')
    path = ROOT / 'network.json'
    if os.path.lexists(path):
        if read(path, 32768) != raw:
            raise ValueError('original collector profile changed; preserve it')
    else:
        atomic(path, raw)
    return Retention(ROOT, BINARY, rpc, lambda method, params: query(rpc, method, params), interval=60,
        primary=ROOT / 'recovery-history', mirror=ROOT / 'recovery-history-mirror')
