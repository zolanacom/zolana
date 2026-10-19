"""Finite, read-only payment-state acceptance on the preserved local service."""
import hashlib,json,os,plistlib,signal,subprocess,sys,time
from pathlib import Path

BASE=Path('/Library/NativePayLocal')
ROOT=BASE/'.data/s20'
sys.path.insert(0,str(BASE/'tools'))
import service_account as service

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path,value,owner=None,mode=0o600):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
        if owner is not None:os.fchown(stream.fileno(),*owner)

def main():
    service.require_root();config=service.verify_install();owner=(config['uid'],config['gid'])
    os.nice(15)
    recheck=sys.argv[1:] in [['--recheck-after-crash'],*(['--recheck-after-crash',str(i)] for i in range(2,16))]
    if sys.argv[1:] and not recheck:raise ValueError('unexpected acceptance arguments')
    attempt=sys.argv[2] if len(sys.argv)==3 else '1'
    suffix='-RECHECK'+attempt if recheck else ''
    marker=BASE/('RESTART-TAIL-029'+suffix+'.started.json');report=BASE/('RESTART-TAIL-029'+suffix+'.json')
    def progress(value):
        path=BASE/('RESTART-TAIL-029'+suffix+'.progress.json');temporary=path.with_name(path.name+'.tmp')
        write(temporary,value,mode=0o444);os.replace(temporary,path)
    def log_tail():
        logs=[]
        for i in [0,1]:
            p=ROOT/('validator-'+str(i)+'.log')
            if not p.exists():continue
            with p.open('rb') as stream:stream.seek(max(0,p.stat().st_size-65536));raw=stream.read()
            lines=raw.decode(errors='replace').splitlines()
            logs.append([line for line in lines if any(s in line for s in ['replay_stage','consensus','ERROR','panic'])][-25:])
        return logs
    if marker.exists() or report.exists():raise ValueError('preserve existing test evidence')
    original=service.PLIST.read_bytes();plist=plistlib.loads(original)
    def unloaded():return subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True).returncode==113
    if not unloaded() or plist['ProgramArguments'][-1]!='run':raise ValueError('normal service must be paused')
    if subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode!=1:raise ValueError('validators must be stopped')
    copy=json.loads((ROOT/('restart-copy-029d' if recheck else 'restart-copy-029b')/'validated-copy-029.json').read_text())
    expected_checkpoint=6270 if recheck else 6174
    if copy['checkpoint']!=expected_checkpoint or not all(copy[k] for k in ['retained_shreds_and_frozen_hashes_unchanged','signed_towers_unchanged','original_private_files_unchanged']):raise ValueError('preserved copy replay must pass first')
    if recheck and json.loads((BASE/'RESTART-TAIL-029.json').read_text())['status']!='failed':raise ValueError('recheck requires preserved first crash failure')
    previous=json.loads((BASE/'CANONICAL-ARCHIVE-028.started.json').read_text())
    for name,value in previous['private_file_digests'].items():
        if digest(ROOT/name)!=value:raise ValueError('original state differs before test: '+name)
    names=set(previous['private_file_digests'])|{'faucet/admission.json','raw-rpc-required.json'}
    names.update(str(p.relative_to(ROOT)) for p in ROOT.glob('*.wallet.json*') if p.is_file())
    def fixed():return {name:digest(ROOT/name) for name in sorted(names)}
    before_files=fixed()
    evidence=ROOT/('restart-evidence-029'+suffix);evidence.mkdir(mode=0o700);os.chown(evidence,*owner)
    def drop():os.setgroups([]);os.setgid(config['gid']);os.setuid(config['uid']);os.umask(0o077);os.nice(15)
    def run(args,timeout=90):
        child=subprocess.run([str(a) for a in args],cwd=BASE,env={'PATH':'/usr/bin:/bin','RAYON_NUM_THREADS':'2','SOLANA_METRICS_CONFIG':''},
            preexec_fn=drop,capture_output=True,text=True,timeout=timeout)
        if child.returncode:raise RuntimeError('native check failed: '+child.stderr[-1500:])
        return json.loads(child.stdout)
    def inventory(label):
        if not unloaded():raise ValueError('inventory requires stopped ledgers')
        values=[run([BASE/'target/debug/native-localnet','replay-plan',ROOT,i,'ledger-'+str(i)]) for i in [0,1]]
        write(evidence/(label+'.json'),values,owner)
        return values
    def preserve(first,last):
        for a,b in zip(first,last):
            for field in ['frozen_hashes','shred_digests']:
                if any(b[field].get(k)!=v for k,v in a[field].items()):raise ValueError('retained '+field+' changed')
            for field in ['dead_slots','duplicate_slots']:
                if not set(a[field]).issubset(b[field]):raise ValueError('retained '+field+' cleared')
            if a['identity']!=b['identity'] or a['genesis_hash']!=b['genesis_hash'] or b['tower_root']<a['tower_root'] or b['last_vote']<a['last_vote']:raise ValueError('signed identity/tower continuity failed')
    initial=inventory('before')
    if recheck and attempt!='1':
        if any(v['slot']<expected_checkpoint for v in initial):raise ValueError('restart checkpoint moved behind verified crash ancestor')
        if attempt=='7' and (initial[0]['slot']!=initial[1]['slot'] or initial[0]['bank_hash']!=initial[1]['bank_hash']):raise ValueError('epoch-boundary acceptance requires a shared frozen checkpoint')
    elif [v['slot'] for v in initial]!=[expected_checkpoint,expected_checkpoint] or initial[0]['bank_hash']!=initial[1]['bank_hash']:raise ValueError('original frozen checkpoint changed')
    original_inventory=json.loads((ROOT/'restart-evidence-029/before.json').read_text()) if recheck else initial
    preserve(original_inventory,initial)
    if recheck and attempt=='1':
        if initial[0]['last_vote']!=6271 or initial[0]['retained_future_tower_vote']!=6271:raise ValueError('crash future vote was not retained')
    elif not recheck and (initial[0]['retained_partial_slots']!=[6175,6179] or initial[0]['retained_competing_slots']!=[6176] or initial[0]['retained_rejected_slots']!=[6156]):raise ValueError('original tail no longer matches diagnosis')
    write(marker,{'private_file_digests':before_files,'original_plist_sha256':hashlib.sha256(original).hexdigest(),'checkpoint':6174},mode=0o400)
    wallets=evidence/'wallets';wallets.mkdir(mode=0o700);os.chown(wallets,*owner)
    for who in ['alice','bob']:
        path=wallets/(who+'.wallet.json');path.write_bytes((ROOT/(who+'.wallet.json')).read_bytes());path.chmod(0o600);os.chown(path,*owner)
    def balances():
        result={who:run([BASE/'target/debug/native-wallet','balance','--network',ROOT/'network.json','--wallet',wallets/(who+'.wallet.json'),
            '--password-file',BASE/'.data/operators/wallet.password','--rpc','http://127.0.0.1:23899','--rpc-access-file',ROOT/'rpc-access.key'],120)['balance'] for who in ['alice','bob']}
        if result!={'alice':90,'bob':10}:raise ValueError('original wallet balances differ')
        return result
    def desktop_balances():
        # The desktop runner stays in its original macOS authorization context.
        # setuid from a root AppleScript child does not inherit Documents access.
        import stat
        receipt=Path('/private/tmp/native-tail-029-g3xxx4ft')/('desktop-recheck'+attempt)/'result.json'
        admission=json.loads((ROOT/'faucet/admission.json').read_text())
        def members(value):
            value=json.loads(json.dumps(value))
            for invitation in value['invitations']:
                if invitation.get('member'):invitation['member'].pop('rpc',None)
            return value
        token=os.urandom(24).hex()
        progress({'phase':'desktop_wallet_check_ready','token':token})
        deadline=time.monotonic()+150
        while not receipt.exists():
            if time.monotonic()>=deadline:raise TimeoutError('normal-user desktop wallet check deadline')
            time.sleep(.25)
        fd=os.open(receipt,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=config['desktop_uid'] or info.st_nlink!=1 or info.st_size>8192:raise ValueError('invalid desktop check receipt')
            value=json.loads(stream.read())
        if value.get('token')!=token or value.get('status')!='passed' or value.get('original_wallets_unchanged') is not True:raise ValueError('desktop wallet check failed: '+str(value.get('error','invalid receipt')))
        result=value['balances']
        if result!={'alice':895000,'bob':1105000}:raise ValueError('existing invited desktop balances differ')
        if members(admission)!=members(json.loads((ROOT/'faucet/admission.json').read_text())):raise ValueError('wallet reads changed invitation identity or faucet usage')
        return result
    def archive():
        value=json.loads(service.as_service('archival-check',config).stdout)
        if not 1<=value['blocks']<=16 or not 1<=value['next_blocks']<=16 or not value['same_anchor'] or not value['private_unix_transport']:raise ValueError('canonical history continuation failed')
        return {k:value[k] for k in ['blocks','next_blocks','same_anchor','private_unix_transport']}
    def wait(after,replaced=None):
        deadline=time.monotonic()+220;last_sample=0
        while time.monotonic()<deadline:
            health=ROOT/'history-retention.json'
            if health.exists() and health.stat().st_mtime>=started_at:
                info=json.loads(health.read_text())
                if info['error'] and info['phase'] in ['blocked','paused']:raise RuntimeError('retention startup failed: '+info['error'])
            try:
                value=json.loads(service.as_service('status',config).stdout);instance=json.loads((ROOT/'service-instance.json').read_text())
                if time.monotonic()-last_sample>15:
                    progress({'phase':'waiting_for_finality_and_history','slots':value['slots'],'native_accounts':len(value['native_state']),
                        'history_phase':value['history_retention']['phase'],'logs':log_tail()});last_sample=time.monotonic()
                if value['history_retention']['phase']=='ready' and min(value['slots'])>after and abs(value['slots'][0]-value['slots'][1])<=12 and (replaced is None or instance['supervisor']!=replaced):return value,instance
            except (subprocess.CalledProcessError,OSError,ValueError):pass
            time.sleep(1)
        raise TimeoutError('fresh finalized convergence deadline')
    def stop():
        if not unloaded():service.command(['/bin/launchctl','bootout','system',str(service.PLIST)],timeout=100)
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode==1:return
            time.sleep(.3)
        raise RuntimeError('validators did not pause')
    started_at=time.time()
    def start():
        nonlocal started_at
        started_at=time.time();service.command(['/bin/launchctl','bootstrap','system',str(service.PLIST)],timeout=60)
    result={'status':'failed'}
    try:
        session=ROOT/'restart-tail-session-029.json'
        if session.exists():
            if not recheck:raise ValueError('unexpected prior test session')
            write(evidence/'prior-session.json',json.loads(session.read_text()),owner)
            replacement=session.with_name('restart-tail-session-029.recheck'+attempt+'.json')
            write(replacement,{'format':'local-restart-tail-test-v1','expires_at':time.time()+585},owner);os.replace(replacement,session)
        else:write(session,{'format':'local-restart-tail-test-v1','expires_at':time.time()+585},owner)
        plist['ProgramArguments'][-1]='run-tail-test';service.PLIST.write_bytes(plistlib.dumps(plist))
        start();baseline,instance=wait(max(v['highest_stored_slot'] for v in initial)+8)
        if len(baseline['native_state'])!=21:raise ValueError('pool/twenty-nullifier inventory differs')
        first_balance=balances();pages=[archive()]
        progress({'phase':'baseline_wallets_recovered','slots':baseline['slots'],'balances':first_balance,'native_accounts':21})
        write(evidence/'baseline-live.json',dict(baseline,balances=first_balance,archival_page=pages[-1]),owner)
        if fixed()!=before_files:raise ValueError('read-only startup changed private state')
        print(json.dumps({'phase':'original_service_resumed','finalized_slots':baseline['slots'],'native_accounts':21,'balances':first_balance}),flush=True)
        # Validate every exact owned process before any signal. No broad pkill.
        targets=[*instance['validators'],instance['supervisor']]
        for index,pid in enumerate(targets):
            command=subprocess.run(['/bin/ps','-p',str(pid),'-o','uid=,command='],capture_output=True,text=True,check=True).stdout.strip()
            needle=str(BASE/'target/debug/agave-validator') if index<2 else str(BASE/'tools/service_runtime.py')
            if not command.startswith(str(config['uid'])+' ') or needle not in command:raise ValueError('crash target identity differs')
            if index<2 and str(ROOT/('ledger-'+str(index))) not in command:raise ValueError('crash target ledger differs')
            if index==2 and 'run-tail-test' not in command:raise ValueError('supervisor test identity differs')
        for pid in targets:os.kill(pid,signal.SIGKILL)
        progress({'phase':'both_validators_and_supervisor_sigkilled'})
        recovered,replacement=wait(max(baseline['slots'])+8,instance['supervisor'])
        write(evidence/'post-crash-live.json',recovered,owner)
        if set(targets)&set([*replacement['validators'],replacement['supervisor']]):raise ValueError('crashed processes not replaced')
        if recovered['native_state']!=baseline['native_state'] or fixed()!=before_files:raise ValueError('crash changed payment/authority state')
        balances();pages.append(archive());stop();crash=inventory('after-crash');preserve(initial,crash)
        if not all(v['last_vote_data_complete'] and v['last_vote_ancestry_complete'] for v in crash):raise ValueError('new signed vote outran its complete local ledger ancestry')
        progress({'phase':'crash_recovery_verified','slots':recovered['slots'],'native_accounts':21})
        print(json.dumps({'phase':'both_validators_and_supervisor_sigkill_recovered','finalized_slots':recovered['slots'],'original_shreds_and_hashes_preserved':True}),flush=True)
        start();orderly,_=wait(max(v['highest_stored_slot'] for v in crash)+8)
        if orderly['native_state']!=baseline['native_state'] or fixed()!=before_files:raise ValueError('repeated restart changed payment state')
        balances();pages.append(archive())
        if fixed()!=before_files:raise ValueError('restarts changed original private state')
        desktop=desktop_balances() if recheck and int(attempt)>=5 else None
        stop();final=inventory('after-orderly-restart');preserve(crash,final);preserve(initial,final);preserve(original_inventory,final)
        final_files=fixed()
        if any(final_files[name]!=value for name,value in before_files.items() if name!='faucet/admission.json' or desktop is None):raise ValueError('final private state changed')
        result={'status':'passed','original_checkpoint':6174,'recheck_checkpoint':expected_checkpoint,'future_signed_vote_retained':recheck,'initial_finalized_slots':baseline['slots'],'post_sigkill_finalized_slots':recovered['slots'],
            'post_orderly_restart_finalized_slots':orderly['slots'],'original_native_accounts':21,'permanent_nullifiers':20,'balances':first_balance,
            'broadcast_commands':0,'both_validators_and_supervisor_sigkill':True,'repeated_orderly_restart':True,
            'new_signed_votes_and_ancestry_complete_after_sigkill':True,
            'all_original_shreds_frozen_hashes_dead_and_duplicate_flags_preserved':True,'signed_tower_identity_and_monotonicity_preserved':True,
            'original_keys_wallets_journals_sponsor_and_claims_unchanged':True,'admission_bytes_unchanged_through_crash_and_orderly_restarts':True,
            'existing_invited_desktop_balances_after_restarts':desktop,'desktop_reads_preserved_membership_and_faucet_usage':desktop is not None,'canonical_archival_pages':pages,
            'retained_initial_shreds':[len(v['shred_digests']) for v in initial],'retained_initial_frozen_banks':[len(v['frozen_hashes']) for v in initial]}
    except BaseException as error:
        result['error']=type(error).__name__+': '+str(error)[:500];result['validator_log_tail']=log_tail();raise
    finally:
        try:stop()
        finally:
            service.PLIST.write_bytes(original)
            result.update(validators_paused_after_test=unloaded(),normal_plist_restored=service.PLIST.read_bytes()==original)
            write(report,result,mode=0o444)
    print(json.dumps(result),flush=True)

if __name__=='__main__':main()
