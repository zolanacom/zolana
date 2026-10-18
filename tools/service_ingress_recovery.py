#!/usr/bin/env python3
"""Administrator-reviewed crash check for the existing funded local ingress."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    base=Path('/Library/NativePayLocal');sys.path.insert(0,str(base/'tools'))
    import service_account as service
    service.require_root();config=service.verify_install();root=base/'.data/s20'
    report=base/'INGRESS-RECOVERY.json';started=base/'INGRESS-RECOVERY.started.json'
    if report.exists() or started.exists():raise ValueError('recovery acceptance already started; preserve its original checkpoint')
    def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
    def state_hash(value):return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()
    def status():return json.loads(service.as_service('status',config).stdout)
    def files():
        paths=[root/'rpc-access.key',root/'faucet/admission.json',root/'faucet/claims.json',root/'faucet/wallet.enc.json',root/'client-profile.json']
        paths+=list(root.glob('*.keypair.json'))
        paths+=[root/name for name in ['sponsor.enc.json','sponsor-policy.json','sponsor-policy.json.reservations.json']]
        return {str(p.relative_to(root)):digest(p) for p in paths}
    setup=json.loads((root/'ingress-setup.json').read_text())
    if setup.get('phase')!='ready':raise ValueError('original ingress setup not ready')
    if any(digest(root/name)!=value for name,value in setup['setup_sponsor_sha256'].items()):raise ValueError('setup sponsor used after reservoir funding')
    claims=json.loads((root/'faucet/claims.json').read_text())['claims']
    if len(claims)!=2:raise ValueError('expected exactly two original grants')
    for path in (root/'faucet').glob('*.json'):
        if len(path.stem)==64:
            progress=json.loads(path.read_text())
            if not progress.get('private_done') or not progress.get('gas_done'):raise ValueError('original grant not complete')
    for suffix in ('.pending.json','.staging.json'):
        if Path(str(root/'faucet/wallet.enc.json')+suffix).exists():raise ValueError('original source journal still needs cleanup')
    before=status();instance=json.loads((root/'service-instance.json').read_text())
    if len(before['native_state'])!=13:raise ValueError('expected original pool plus twelve permanent nullifiers')
    checkpoint={'native_state_sha256':state_hash(before['native_state']),'slots':before['slots'],'instance':instance,'files':files()}
    started.write_text(json.dumps(checkpoint,sort_keys=True));started.chmod(0o400)
    denied_before=service.probe_identity(config,config['desktop_uid'],__import__('pwd').getpwuid(config['desktop_uid']).pw_gid)
    service.command(['/bin/launchctl','kill','SIGKILL','system/'+service.LABEL],timeout=30)
    deadline=time.monotonic()+240
    while time.monotonic()<deadline:
        try:
            after=status();replacement=json.loads((root/'service-instance.json').read_text())
        except (subprocess.CalledProcessError,ValueError,FileNotFoundError):time.sleep(2)
        else:
            if replacement['supervisor']==instance['supervisor'] or set(replacement['validators'])&set(instance['validators']) or min(after['slots'])<=max(before['slots'])+8:
                time.sleep(2);continue
            if state_hash(after['native_state'])!=checkpoint['native_state_sha256']:raise ValueError('original pool or nullifiers changed')
            if files()!=checkpoint['files']:raise ValueError('original service keys, profile, admission, claims or sponsor budget changed')
            if set(replacement['process_groups'])!={os.getpgid(replacement['supervisor'])}:raise ValueError('child escaped original service process group')
            break
    else:raise RuntimeError('original isolated ingress did not recover before deadline; retain checkpoint')
    denied_after=service.probe_identity(config,config['desktop_uid'],__import__('pwd').getpwuid(config['desktop_uid']).pw_gid)
    result={'status':'passed','native_accounts':len(after['native_state']),'permanent_nullifiers':12,
        'original_pool_keys_capability_admission_claims_and_sponsor_budget_unchanged':True,
        'supervisor_and_both_validators_replaced':True,'new_finalized_slots':after['slots'],
        'desktop_denied_before':denied_before,'desktop_denied_after':denied_after,'pending_payment_ack_loss_exercised':False}
    report.write_text(json.dumps(result,sort_keys=True,indent=2));report.chmod(0o444)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
