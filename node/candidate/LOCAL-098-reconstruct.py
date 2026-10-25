"""Source-only ten-leaf reconstruction. No native tests, installation or host access."""
from pathlib import Path
import hashlib,json,subprocess,tempfile
R=Path(__file__).resolve().parents[2]
C=R/'node/candidate'
PREP=R/'.local/durable-pruning-098/native-r1/preparation.json'
SOURCE=PREP.parent/'source'
PATCH=C/'agave-4.3.2-LOCAL-098.patch'
REPORT=C/'LOCAL-098-reconstruction.json'
PREP_SHA='f217ec09f20fba8d4f87d29cecd0115b8516e896bc37a5c46e19d976f069318a'
PATCH_SHA='225faa3cf4286744879bc072311e67d0fdec3fae39a8f781ba4ed948beb79776'
BEFORE={'zolana-fast-check/src/main.rs': '.local/archive-scale-094/offline-native-r1/source/zolana-fast-check/src/main.rs', 'zolana-fast-check/src/resume.rs': '.local/restart-scale-095/native-r2/source/zolana-fast-check/src/resume.rs', 'ledger/src/blockstore.rs': '.local/storage-recovery-092/actual-inventory-r1/source/ledger/src/blockstore.rs', 'ledger/src/blockstore_db.rs': '.local/archive-scale-094/source-inventory/ledger/src/blockstore_db.rs'}
def digest(b):return hashlib.sha256(b).hexdigest()
def check(v,m):
 if not v:raise ValueError(m)
raw=PREP.read_bytes();check(digest(raw)==PREP_SHA,'frozen098 native preparation')
p=json.loads(raw);check(len(p['source_changes'])==10 and len(p['existing_before'])==4,'exact ten-leaf scope')
check(digest(PATCH.read_bytes())==PATCH_SHA,'frozen098 patch')
check(not REPORT.exists(),'exclusive new reconstruction receipt; do not overwrite')
commands=[]
with tempfile.TemporaryDirectory(prefix='zolana098-code-only-')as directory:
 t=Path(directory)
 for rel,source in BEFORE.items():
  b=(R/source).read_bytes();spec=p['existing_before'][rel]
  check(len(b)==spec['bytes']and digest(b)==spec['sha256'],'exact095 baseline code leaf')
  target=t/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b)
 for extra in [True,False]:
  argv=['git','apply']+(['--check']if extra else[])+[str(PATCH)]
  result=subprocess.run(argv,cwd=t,capture_output=True,check=True)
  commands.append({'argv':['git','apply']+(['--check']if extra else[])+['<absolute LOCAL098 patch>'],'exit_code':result.returncode,'stdout_sha256':digest(result.stdout),'stderr_sha256':digest(result.stderr)})
 actual={str(x.relative_to(t)):{'bytes':len(x.read_bytes()),'sha256':digest(x.read_bytes())}for x in t.rglob('*')if x.is_file()}
 check(actual==p['source_changes'],'all ten reconstructed after pins; no extra files')
 report={'format':'zolana098-ten-leaf-source-reconstruction-v1','status':'passed','patch_sha256':PATCH_SHA,'native_preparation_sha256':PREP_SHA,'commands':commands,'after':actual,'native_test_build_install_or_host_actions':0,'qualification':'Only the four-baseline/six-new-file code delta is reconstructed, not the full workspace or a runtime installation.'}
 with REPORT.open('x')as f:f.write(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({'status':'passed','report':str(REPORT),'sha256':digest(REPORT.read_bytes())}))
