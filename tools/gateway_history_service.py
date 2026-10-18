"""Reviewed fixed-scope local service rehearsal; never exports private material."""
import hashlib,json,os,plistlib,pwd,signal,subprocess,sys,time
from pathlib import Path
BASE=Path('/Library/NativePayLocal')
sys.path.insert(0,str(BASE/'tools'))
import service_account as service

def digest(raw):return hashlib.sha256(raw).hexdigest()
def atomic(path,value,owner=None,mode=0o600):
 raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();temporary=path.with_name(path.name+'.027.tmp')
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:
  f.write(raw);f.flush();os.fsync(f.fileno())
  if owner is not None:os.fchown(f.fileno(),*owner)
 os.replace(temporary,path)
 fd=os.open(path.parent,os.O_RDONLY)
 try:os.fsync(fd)
 finally:os.close(fd)

def main():
 service.require_root();config=service.verify_install();root=BASE/'.data/s20'
 marker=BASE/'GATEWAY-HISTORY-027.started.json';report=BASE/'GATEWAY-HISTORY-027.json'
 if marker.exists() or report.exists():raise ValueError('rehearsal already started; preserve original evidence')
 original=service.PLIST.read_bytes();plist=plistlib.loads(original)
 if plist['ProgramArguments'][-1]!='run' or subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True).returncode!=113:raise ValueError('original normal service must be paused')
 if json.loads((BASE/'HISTORY-026.json').read_text())['status']!='passed':raise ValueError('prior original-state verification required')
 names=['network.json','rpc-access.key','client-profile.json','faucet/claims.json','faucet/wallet.enc.json','sponsor.enc.json','sponsor-policy.json','sponsor-policy.json.reservations.json']
 names += [p.name for p in root.glob('*.keypair.json')]+[p.name for p in root.glob('*.wallet.json')]
 names += [p.name for p in root.glob('*ack*025.json')]+[p.name for p in root.glob('*ack*024.json')]+[p.name for p in root.glob('*ack*022.json')]
 def fixed():return {name:digest((root/name).read_bytes()) for name in sorted(set(names))}
 def admission_identity():
  value=json.loads((root/'faucet/admission.json').read_text());invitations=value['invitations']
  for invitation in invitations:
   member=invitation.get('member')
   if member:member.pop('rpc',None);member.pop('faucet',None)
  return {'policy':value['policy'],'invitations':invitations}
 before=fixed();identity=admission_identity();atomic(marker,{'original_plist_sha256':digest(original),'private_file_digests':before},mode=0o400)
 def state():return json.loads(service.as_service('status',config).stdout)
 def wait(after=None,replaced=None):
  deadline=time.monotonic()+150
  while time.monotonic()<deadline:
   try:
    value=state();instance=json.loads((root/'service-instance.json').read_text())
    if value['history_retention']['phase']=='ready' and (after is None or min(value['slots'])>after) and (replaced is None or instance['supervisor']!=replaced):return value,instance
   except (subprocess.CalledProcessError,ValueError,OSError):pass
   time.sleep(.5)
  raise TimeoutError('bounded retention readiness/finalization deadline')
 def prefix():
  from history_retention import manifest
  network=json.loads((root/'network.json').read_text());network={k:network[k] for k in ['network','genesis_hash']}
  # Root intentionally reads the owned service ciphertexts, never wallet seeds.
  source=root/'recovery-history';mirror=root/'recovery-history-mirror'
  from history_retention import capture
  # Do not run capture as root: use the native service's committed copies only.
  raw,files,tip=manifest(mirror,network,owner=config['uid'])
  if raw!=(source/'manifest.json').read_bytes():raise ValueError('captured service manifests differ')
  for name,descriptor in files:
   data=(mirror/name).read_bytes()
   if hashlib.blake2b(data,digest_size=32,person=b'NPayArchiveV1').hexdigest()!=descriptor['digest'] or data!=(source/name).read_bytes():raise ValueError('service backup payload differs')
  return {'tip':tip,'segments':len(files),'manifest_sha256':digest(raw),'files':{name:digest((mirror/name).read_bytes()) for name,_ in files}}
 result={'status':'failed'}
 try:
  atomic(root/'gateway-history-session-027.json',{'format':'local-gateway-history-test-v1','expires_at':time.time()+540},owner=(config['uid'],config['gid']))
  plist['ProgramArguments'][-1]='run-history-test';service.PLIST.write_bytes(plistlib.dumps(plist))
  service.command(['/bin/launchctl','bootstrap','system',str(service.PLIST)],timeout=60)
  baseline,instance=wait();first=prefix()
  if len(baseline['native_state'])!=21:raise ValueError('expected original pool and twenty permanent nullifiers')
  if fixed()!=before:raise ValueError('retention changed original keys/wallets/grants/quotas')
  page=json.loads(service.as_service('history-check',config).stdout)
  if not 1<=page['blocks']<=16:raise ValueError('sealed gateway did not read retained mirror')
  import ssl,urllib.request,urllib.error
  profile=json.loads((root/'client-profile.json').read_text())
  request=urllib.request.Request(profile['rpc']['url'],json.dumps({'jsonrpc':'2.0','id':1,'method':'getWalletRetainedHistory','params':[0,2**64-1,None]}).encode(),{'Content-Type':'application/json'})
  try:
   urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cadata=profile['local_tls_ca_pem']))).open(request,timeout=15)
  except urllib.error.HTTPError as error:
   if error.code!=403:raise
  else:raise ValueError('uninvited TLS retained history request was accepted')
  quota_before=digest((root/'faucet/admission.json').read_bytes())
  # Signal only the exact launchd-owned supervisor after verifying its identity.
  command=subprocess.run(['/bin/ps','-p',str(instance['supervisor']),'-o','uid=,command='],capture_output=True,text=True,check=True).stdout.strip()
  if not command.startswith(str(config['uid'])+' ') or str(BASE/'tools/service_runtime.py') not in command or 'run-history-test' not in command:raise ValueError('supervisor crash target differs')
  os.kill(instance['supervisor'],signal.SIGKILL)
  restarted,replacement=wait(max(baseline['slots'])+8,instance['supervisor']);second=prefix()
  if set(instance['validators'])&set(replacement['validators']):raise ValueError('both validator processes were not replaced')
  if second['tip']<=first['tip'] or second['segments']<first['segments']:raise ValueError('retention did not extend after restart')
  mirror=root/'recovery-history-mirror'
  if any(digest((mirror/name).read_bytes())!=value for name,value in first['files'].items()):raise ValueError('restart changed committed immutable backup prefix')
  if restarted['native_state']!=baseline['native_state'] or fixed()!=before:raise ValueError('restart altered original native/authority/admission state')
  if digest((root/'faucet/admission.json').read_bytes())!=quota_before or admission_identity()!=identity:raise ValueError('restart changed original admission identity or durable quota usage')
  page_after=json.loads(service.as_service('history-check',config).stdout)
  if not 1<=page_after['blocks']<=16:raise ValueError('gateway mirror unavailable after restart')
  isolation=service.probe_identity(config,config['desktop_uid'],pwd.getpwuid(config['desktop_uid']).pw_gid)
  result={'status':'passed','native_accounts':21,'permanent_nullifiers':20,'broadcast_commands':0,
   'original_keys_wallets_claims_sponsor_quotas_and_prior_evidence_unchanged':True,
   'actual_supervisor_sigkill_and_both_validators_replaced':True,'committed_prefix_unchanged':True,'gateway_retained_page_blocks':[page['blocks'],page_after['blocks']],
   'uninvited_tls_history_denied':True,'exact_admission_usage_persisted_across_restart':True,
   'initial_history':{k:v for k,v in first.items() if k!='files'},'restarted_history':{k:v for k,v in second.items() if k!='files'},
   'finalized_slots':restarted['slots'],'desktop_isolation':isolation}
 except BaseException as error:
  result.update(error=type(error).__name__+': '+str(error)[:500]);raise
 finally:
  try:
   if subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True).returncode==0:service.command(['/bin/launchctl','bootout','system',str(service.PLIST)],timeout=100)
  finally:
   service.PLIST.write_bytes(original)
   paused=subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True).returncode==113
   result.update(validators_paused_after_test=paused,normal_plist_restored=service.PLIST.read_bytes()==original)
   atomic(report,result,mode=0o444)
 print(json.dumps(result))

if __name__=='__main__':main()
