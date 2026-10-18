#!/usr/bin/env python3
"""Reviewed one-time local certificate identifier repair; never generates keys."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    base=Path('/Library/NativePayLocal');sys.path.insert(0,str(base/'tools'))
    from service_account import verify_install
    config=verify_install()
    if os.getuid()!=config['uid'] or os.geteuid()!=config['uid']:raise PermissionError('requires original service UID, never root')
    from service_ingress import check_ready,public_profile,ROOT,TLS,PROFILE,STATE
    from service_runtime import private,save,load
    state=check_ready();before_keys={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in TLS.glob('*.key')}
    directory=TLS/'identifier-repair-021';directory.mkdir(mode=0o700)
    def run(*args):
        result=subprocess.run(['/usr/bin/openssl',*map(str,args)],capture_output=True,text=True,check=True,timeout=30)
        return result.stdout
    original_key=run('x509','-in',TLS/'ca.crt','-pubkey','-noout')
    original_subject=run('x509','-in',TLS/'ca.crt','-subject','-nameopt','RFC2253','-noout')
    for name in ['ca','server','rotated','wrong-host']:private(directory/(name+'.before.crt'),(TLS/(name+'.crt')).read_bytes())
    private(directory/'profile.before.json',PROFILE.read_bytes());private(directory/'state.before.json',STATE.read_bytes())
    extension=directory/'ca.cnf'
    extension.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Local test access CA\n[ca]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
    run('req','-new','-x509','-key',TLS/'ca.key','-out',directory/'ca.crt','-days','3','-sha256','-config',extension)
    if run('x509','-in',directory/'ca.crt','-pubkey','-noout')!=original_key or run('x509','-in',directory/'ca.crt','-subject','-nameopt','RFC2253','-noout')!=original_subject:
        raise ValueError('original CA public key or subject changed')
    for serial,(name,ip) in enumerate([('server','127.0.0.1'),('rotated','127.0.0.1'),('wrong-host','127.0.0.2')],21):
        extension=directory/(name+'.cnf');extension.write_text('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:'+ip+'\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
        run('x509','-req','-in',TLS/(name+'.csr'),'-CA',directory/'ca.crt','-CAkey',TLS/'ca.key','-set_serial',str(serial),'-out',directory/(name+'.crt'),'-days','2','-sha256','-extfile',extension)
        if run('x509','-in',directory/(name+'.crt'),'-pubkey','-noout')!=run('x509','-in',TLS/(name+'.crt'),'-pubkey','-noout'):
            raise ValueError('original TLS leaf public key changed')
    for name in ['ca','server','rotated','wrong-host']:os.replace(directory/(name+'.crt'),TLS/(name+'.crt'))
    save(PROFILE,public_profile(load(ROOT),(TLS/'ca.crt').read_text()))
    state['profile_sha256']=hashlib.sha256(PROFILE.read_bytes()).hexdigest();save(STATE,state)
    if before_keys!={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in TLS.glob('*.key')}:raise ValueError('original TLS private keys changed')
    check_ready()
    print(json.dumps({'certificate_identifiers_repaired':True,'original_ca_and_leaf_keys_unchanged':True,'client_profile_ca_certificate_refresh_required':True,'funding_not_repeated':True}))


if __name__=='__main__':main()
