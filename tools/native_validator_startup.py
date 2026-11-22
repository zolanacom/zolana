#!/usr/bin/env python3
"""LOCAL-065 original-ledger supervisor with a bounded 600 second startup budget.

The original sealed bundle/configuration remain unchanged. Every readiness,
identity, history, finality, health and preservation check is retained verbatim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
import types

INSTALLED_PATH = Path('/etc/zolana-native-065/validator-startup.py')
BASE_PATH = Path('/opt/zolana-native-058/tools/native_linux_service.py')
BASE_SHA256 = '5f102297516b40ff8299def02e6a993e4277e3f80bc6ed958102b5781b106a7a'
MAX_SOURCE_BYTES = 128 * 1024
ORIGINAL_EXPORTS = ('sandbox', 'verify_original', 'RUN', 'real_directory',
    'stop_event', 'STATE', 'PREFIX', 'VALROOT', 'validate_ready',
    'wait_finalized_history', 'atomic', 'READY', 'notify', 'owned', 'fsync_dir',
    'finalized_slot')


def root_ancestors(path):
    for parent in (path.parent, *path.parent.parents):
        meta = parent.lstat()
        if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0
                or meta.st_mode & 0o022 or parent.resolve() != parent):
            raise ValueError('startup source requires immutable root-owned ancestors')


def sealed_source(path, expected, owner=0):
    if not isinstance(expected, str) or re.fullmatch('[a-f0-9]{64}', expected) is None:
        raise ValueError('exact startup source digest required')
    root_ancestors(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        meta = os.fstat(source.fileno())
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != owner
                or stat.S_IMODE(meta.st_mode) != 0o444
                or not 1 <= meta.st_size <= MAX_SOURCE_BYTES):
            raise ValueError('bounded root-owned mode444 startup source required')
        raw = source.read(MAX_SOURCE_BYTES + 1)
    if len(raw) > MAX_SOURCE_BYTES or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('startup source content differs from its pin')
    return raw


def described(environment=None):
    """This file is installed alone, so it reads the deployment description itself.

    With ZOLANA_DEPLOYMENT unset the built-in paths and pin stand. Otherwise the
    description must be a sealed file whose SHA-256 is ZOLANA_DEPLOYMENT_SHA256.
    """
    global INSTALLED_PATH, BASE_PATH, BASE_SHA256
    environment = os.environ if environment is None else environment
    path, expected = (environment.get(name) for name in ('ZOLANA_DEPLOYMENT', 'ZOLANA_DEPLOYMENT_SHA256'))
    if path is None and expected is None:
        return False
    if path is None or expected is None or not Path(path).is_absolute():
        raise ValueError('a deployment description needs its absolute path and its SHA-256')
    value = json.loads(sealed_source(Path(path), expected))
    service, startup = value['service'], value['startup']['validator']
    paths = (startup['installed_path'], service['prefix'])
    if (any(not isinstance(item, str) or not Path(item).is_absolute() for item in paths)
            or not isinstance(service['module'], str)
            or re.fullmatch(r'[a-z][a-z0-9_]{2,63}\.py', service['module']) is None
            or not isinstance(service['module_sha256'], str)
            or re.fullmatch('[a-f0-9]{64}', service['module_sha256']) is None):
        raise ValueError('deployment description does not name this startup wrapper and its base')
    INSTALLED_PATH = Path(paths[0])
    BASE_PATH = Path(paths[1])/'tools'/service['module']
    BASE_SHA256 = service['module_sha256']
    return True


def load_original():
    raw = sealed_source(BASE_PATH, BASE_SHA256)
    module = types.ModuleType('zolana_native_065_verified_base')
    module.__file__ = str(BASE_PATH)
    exec(compile(raw, str(BASE_PATH), 'exec'), module.__dict__)
    # Explicit original helper/constant imports; never mutate the base module.
    globals().update({name: getattr(module, name) for name in ORIGINAL_EXPORTS})
    return module


def validator(config,digest):
    inode=sandbox(config,'validator');verify_original(config)
    real_directory(RUN,config['validator_uid'],0o750,config['link_gid'])
    stop=stop_event();events=queue.Queue(maxsize=64);generation=secrets.token_hex(32)
    env={'PATH':'/usr/bin:/bin','HOME':str(STATE/'validator'),'RAYON_NUM_THREADS':'4','SOLANA_RAYON_THREADS':'4','RUST_BACKTRACE':'0'}
    logfd=os.open(STATE/'validator/runner.stderr',os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
    child=None;published=False;last_slot=-1;last_progress=0;next_probe=0;health_endpoint=None
    try:
        with os.fdopen(logfd,'ab',buffering=0) as log:
            if stat.S_IMODE(os.fstat(log.fileno()).st_mode)!=0o600:raise ValueError('private runner log required')
            child=subprocess.Popen([str(PREFIX/'bin/zolana-fast-check'),'--resume-root',str(VALROOT),'--service'],
                                   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=log,env=env,close_fds=True)
            def read_events():
                try:
                    while True:
                        raw=child.stdout.readline(131073)
                        if not raw:break
                        if len(raw)>131072:raise ValueError('managed runner stdout record exceeds bound')
                        try:value=json.loads(raw)
                        except (ValueError,UnicodeError):continue
                        if isinstance(value,dict) and value.get('event')=='external_mac_fixture_ready':
                            events.put(value.get('data'),timeout=1)
                except BaseException as error:
                    try:events.put(error,timeout=1)
                    except queue.Full:pass
            reader=threading.Thread(target=read_events,daemon=True);reader.start()
            deadline=time.monotonic()+600
            while not stop.wait(.1):
                if child.poll() is not None:raise RuntimeError('managed original-ledger runner exited')
                if not published:
                    if time.monotonic()>deadline:raise TimeoutError('original-ledger service readiness timed out')
                    try:value=events.get_nowait()
                    except queue.Empty:continue
                    if isinstance(value,BaseException):raise value
                    value=validate_ready(value,config)
                    readiness=wait_finalized_history(value['peers'],child,stop,deadline)
                    if readiness is None:break
                    value['finality_readiness']=readiness
                    health_endpoint=value['peers'][0]['rpc']
                    last_slot=readiness['peers'][0]['advanced_root'];last_progress=time.monotonic();next_probe=last_progress+5
                    if stop.is_set():break
                    if child.poll() is not None:raise RuntimeError('managed runner exited before readiness publication')
                    if last_progress>=deadline:raise TimeoutError('original-ledger service readiness timed out')
                    value.update(format='zolana-native-service-ready-v1',config_sha256=digest,generation=generation,
                                 namespace_inode=inode,supervisor_pid=os.getpid(),child_pid=child.pid,ready_at=int(time.time()))
                    atomic(READY,value,0o640,config['link_gid']);published=True
                    notify('READY=1\nSTATUS=Original three-validator private network restored')
                elif not reader.is_alive():raise RuntimeError('managed runner event reader stopped')
                if published and time.monotonic()>=next_probe:
                    next_probe=time.monotonic()+5
                    try:slot=finalized_slot(health_endpoint)
                    except (OSError,ValueError):slot=last_slot
                    if slot<last_slot:raise RuntimeError('managed finalized root regressed')
                    if slot>last_slot:last_slot=slot;last_progress=time.monotonic()
                    if time.monotonic()-last_progress>=60:raise RuntimeError('managed finalized root stalled for sixty seconds')
    finally:
        if published:
            try:
                if json.loads(owned(READY,config['validator_uid'],mode=0o640)).get('generation')==generation:
                    READY.unlink();fsync_dir(RUN)
            except FileNotFoundError:pass
        if child is not None and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=80)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
        if child is not None and child.stdout is not None:child.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    described()
    if Path(__file__) != INSTALLED_PATH or Path(__file__).resolve() != INSTALLED_PATH:
        raise ValueError('startup wrapper must use its fixed sealed installation path')
    sealed_source(INSTALLED_PATH, args.sha256)
    if sys.platform != 'linux':
        raise ValueError('LOCAL-065 validator startup requires Linux')
    base = load_original()
    config, digest = base.load_config()
    sys.path.insert(0, str(base.PREFIX/'tools'))
    validator(config, digest)


if __name__ == '__main__':
    main()
