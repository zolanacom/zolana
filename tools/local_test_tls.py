#!/usr/bin/env python3
"""Create an isolated short-lived test CA and server leaves; never install OS trust."""
import argparse
import json
from pathlib import Path
import subprocess
from wallet_localnet import private_new


def create(directory):
    directory=directory.resolve();directory.mkdir(mode=0o700,parents=True,exist_ok=False)
    def run(*args):
        result=subprocess.run(['openssl',*map(str,args)],capture_output=True,text=True,timeout=30)
        if result.returncode: raise ValueError('local test certificate generation failed: '+result.stderr)
    def key(name):
        path=directory/(name+'.key');private_new(path,b'');run('genrsa','-out',path,'2048');return path
    ca_key=key('ca'); ca=directory/'ca.crt'
    root=directory/'ca-ext.cnf';root.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Local test access CA\n[ca]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
    run('req','-new','-x509','-key',ca_key,'-out',ca,'-days','3','-sha256','-config',root)
    for number,(name,ip) in enumerate([('server','127.0.0.1'),('rotated','127.0.0.1'),('wrong-host','127.0.0.2')],1):
        secret=key(name);csr=directory/(name+'.csr');cert=directory/(name+'.crt');ext=directory/(name+'.cnf')
        ext.write_text('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:'+ip+'\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
        run('req','-new','-key',secret,'-out',csr,'-subj','/CN=Local test endpoint')
        run('x509','-req','-in',csr,'-CA',ca,'-CAkey',ca_key,'-set_serial',str(number),'-out',cert,'-days','2','-sha256','-extfile',ext)
    # Explicit historical validity; neither the system nor wallet clock changes.
    private_new(directory/'index.txt',b'');private_new(directory/'serial',b'10\n')
    config=directory/'expired-ca.cnf'
    config.write_text('[ca]\ndefault_ca=local\n[local]\ndatabase='+str(directory/'index.txt')+'\nserial='+str(directory/'serial')+'\nnew_certs_dir='+str(directory)+'\ncertificate='+str(ca)+'\nprivate_key='+str(ca_key)+'\ndefault_md=sha256\npolicy=names\nx509_extensions=server\n[names]\ncommonName=supplied\n[server]\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
    run('ca','-batch','-config',config,'-in',directory/'server.csr','-out',directory/'expired.crt','-startdate','20000101000000Z','-enddate','20010101000000Z','-notext')
    return {'ca':str(ca),'certificate':str(directory/'server.crt'),'private_key':str(directory/'server.key'),'installed_in_system_trust':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args();print(json.dumps(create(args.directory)))


if __name__=='__main__':main()
