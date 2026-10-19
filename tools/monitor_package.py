"""Prepare a reproducible, secret-free standalone monitoring bundle locally."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import zipfile

RUNTIME=('operator_health.py','operator_monitor.py','monitor_transport.py','offhost_monitor.py')
README='''# Independent monitoring bundle

This bundle uses Python 3.9+ and its standard library on macOS/Linux. It contains
no service, wallet, RPC, TLS private keys or monitoring capabilities. Verify the
reviewed MANIFEST.json SHA-256 outside this bundle before use. run.py verifies
the fixed file inventory and every digest before importing application code;
this is integrity checking, not release signing or a security audit.

Run with: python3 -I /absolute/bundle/run.py ACTION --config /private/config.json
Actions: export, receive, watch, check. The exporter reads the sanitized heartbeat
and fixed macOS launchd job. Run it as an unprivileged desktop operator, not as
the validator/key account. The observer and alert inbox run independently on
macOS or Linux and need no validator installation or raw RPC access.

Copy example configurations OUTSIDE the bundle, replace the deployment identity,
origins, pinned CA digests and private file paths, and chmod each config/CA/key to
0600. Use distinct health-read and alert-write keys. Create each with:
python3 -I /absolute/bundle/run.py keygen --deployment HEX32 --role health-read --output NEW_PRIVATE_FILE
Use alert-write for the separate delivery capability. Provision these files over
a separately reviewed secure channel. Never substitute wallet or RPC keys.

Local executions permit only 127.0.0.1 endpoints/listeners and expire after sixty
seconds by default; --duration N accepts 1..600. No service or OS trust is installed.
Actual off-host use requires reviewed origins/certificates and --allow-network.
Only that explicit mode permits --duration 0 (foreground until terminated) and
--bind 0.0.0.0. Place the observer on a different host; do not colocate every role.
The code does not configure firewalls, DNS, supervision, backups or notifications.

Fresh challenged health observations distinguish an intentional pause from loss
of the entire source/exporter. Even a previously paused source alerts when its
HTTPS endpoint disappears. Source/observer clocks must agree within ten seconds.
Production examples set expect_running=true so a reachable exporter with an
unloaded validator job also alerts. Set false only for an explicitly paused
rehearsal; that policy is bound to the journal and cannot silently change later.
TLS validates hostname and the pinned CA; redirects/proxies are not used.
Authentication, request schemas, responses and socket reads are bounded.
OS DNS resolution follows the host resolver's own timeout policy.

The observer persists events before delivery. It retries with the same event ID
until a matching durable receipt arrives from the HTTPS alert inbox. Sampling
continues during delivery outages with bounded exponential retry backoff. The
inbox stores at most 1024 deduplicated events and rejects changed-content retries.
The observer retains at most 128 recent/pending events. Full/corrupt journals fail
visibly and preserve evidence; do not replace them to silence a failure.
Keep the original route, deployment and CA pins for a pending journal. Changing
them requires an explicit reviewed migration, not silent redirection.

The receiver's owner-only inbox.json is the remote machine-delivery destination.
Connecting it to human paging, email, Telegram, Slack or another webhook service
is a separate operator choice; no accounts/messages or human notifications are
created here. A durable machine receipt is not proof that a person was notified.
Keep an independent watchdog for the observer/delivery channel itself.

Local tests do not establish real separate-host availability, power-loss safety,
release signing or independent security review. No public deployment is implied.
'''


def templates():
    deployment='0'*32
    peer=lambda host,role:{'origin':'https://'+host+'.example.invalid','capability_file':role+'.json','ca_file':host+'-ca.crt','ca_sha256':'REVIEWED_CA_SHA256'}
    return {
        'exporter.example.json':dict(format='native-health-exporter-v1',deployment=deployment,origin='https://health.example.invalid',
            capability_file='health-read.json',certificate_file='health.crt',key_file='health.key',heartbeat_file='/Library/NativePayLocal/health/heartbeat.json',heartbeat_owner=450),
        'receiver.example.json':dict(format='native-alert-receiver-v1',deployment=deployment,origin='https://alerts.example.invalid',
            capability_file='alert-write.json',certificate_file='alerts.crt',key_file='alerts.key',root='private-alert-inbox'),
        'observer.example.json':dict(format='native-offhost-monitor-v1',deployment=deployment,source=peer('health','health-read'),alerts=peer('alerts','alert-write'),journal='private-observer-journal',interval_seconds=2,expect_running=True),
    }


def prepare(output):
    output=Path(output).absolute();archive=output.with_name(output.name+'.zip')
    if os.path.lexists(output) or os.path.lexists(archive):raise ValueError('use new bundle/archive paths')
    payload={name:(Path(__file__).parent/name).read_bytes() for name in RUNTIME}
    for name in ('LICENSE','THIRD_PARTY.md'):payload[name]=(Path(__file__).parents[1]/name).read_bytes()
    payload['README.md']=README.encode()
    payload.update({name:(json.dumps(value,sort_keys=True,indent=2)+'\n').encode() for name,value in templates().items()})
    names=tuple(sorted([*payload,'run.py']))
    entry='''import hashlib,json,os,stat,sys
from pathlib import Path
root=Path(__file__).resolve().parent
names=NAMES
for path in (root,*root.parents):
 meta=path.lstat()
 if not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0,os.getuid()) or (meta.st_mode&0o022 and not (meta.st_uid==0 and meta.st_mode&stat.S_ISVTX)):raise ValueError('unsafe monitoring bundle directory')
def checked(path):
 meta=path.lstat()
 if not stat.S_ISREG(meta.st_mode) or meta.st_uid not in (0,os.getuid()) or meta.st_mode&0o022:raise ValueError('unsafe monitoring bundle file')
 return path.read_bytes()
manifest=json.loads(checked(root/'MANIFEST.json'))
if set(manifest)!={'format','files'} or manifest['format']!='native-monitor-bundle-v1' or set(manifest['files'])!=set(names) or set(p.name for p in root.iterdir())!=set(names)|{'MANIFEST.json'}:raise ValueError('unexpected monitoring inventory')
for name in names:
 raw=checked(root/name)
 if manifest['files'][name]!={'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}:raise ValueError('monitoring bundle changed')
sys.dont_write_bytecode=True
sys.path.insert(0,str(root))
from offhost_monitor import main
try:main()
except Exception:
 print('monitoring_failed; original evidence retained',file=sys.stderr);sys.exit(1)
'''.replace('NAMES',repr(names))
    payload['run.py']=entry.encode()
    manifest={'format':'native-monitor-bundle-v1','files':{name:{'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for name,raw in sorted(payload.items())}}
    payload['MANIFEST.json']=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
    output.mkdir(mode=0o755)
    for name,raw in payload.items():
        with (output/name).open('xb') as stream:stream.write(raw)
        (output/name).chmod(0o444)
    with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED) as zipped:
        for name,raw in sorted(payload.items()):
            info=zipfile.ZipInfo(output.name+'/'+name,date_time=(2020,1,1,0,0,0));info.create_system=3
            info.external_attr=(stat.S_IFREG|0o444)<<16;info.compress_type=zipfile.ZIP_DEFLATED
            zipped.writestr(info,raw)
    # Archive top-level name is deliberately fixed by the selected output name;
    # repeated builds with that same name in different parents are identical.
    return {'format':manifest['format'],'files':len(payload),'bundle':str(output),'archive':str(archive),
            'manifest_sha256':hashlib.sha256(payload['MANIFEST.json']).hexdigest(),'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
            'contains_credentials':False,'installed':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    print(json.dumps(prepare(parser.parse_args().output),sort_keys=True))
