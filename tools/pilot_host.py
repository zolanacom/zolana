#!/usr/bin/env python3
"""Secret-free pilot host review packet. No installer, SSH or service activation."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import platform
import urllib.parse

import pilot_cohort as cohort
from wallet_release import create,decode,encode,fsync_dir,read,sha

FILES=('cohort-plan.json','host-plan.json','funding-budget.json','SETUP.txt')


def external_profile(profile):
    for name in ('rpc','faucet'):
        item=profile[name];url=urllib.parse.urlsplit(item['url']);hostname=url.hostname
        if item['transport']!='https' or not hostname or hostname=='localhost' or hostname.endswith(('.invalid','.localhost')):
            return False
        try:
            if not ipaddress.ip_address(hostname).is_global:return False
        except ValueError:pass
    return 'local_tls_ca_pem' not in profile


def host_plan(value):
    cohort.validate(value)
    return dict(format='zolana-pilot-host-plan-v1',phase='local-preparation',cohort_plan_sha256=sha(encode(value)),
                hosts=[dict(id='primary-1',roles=['validator-pair','invited-ingress','faucet','history-collector'],
                            failure_domain='primary',runtime='darwin-arm64',service_identity='_nativepay',
                            placement_verified=False),
                       dict(id='recovery-1',roles=['history-receiver','canonical-archive-required'],
                            failure_domain='independent-recovery',runtime='python3-posix',service_identity='zolana_history',
                            placement_verified=False),
                       dict(id='observer-1',roles=['monitor','pager','watchdog'],failure_domain='independent-observer',
                            runtime='python3-posix',service_identity='zolana_watch',placement_verified=False)],
                consensus=dict(validators=2,placement='same-primary-host',independent_validator_hosts=False),
                network=dict(raw_rpc='private-unix-only',validator_peers='loopback-only-rehearsal',
                             tester_rpc=value['tester_profile']['rpc'],tester_faucet=value['tester_profile']['faucet'],
                             external_profile_ready=external_profile(value['tester_profile'])),
                activation=dict(enabled=False,installer_included=False,credentials_included=False,
                                host_connections_attempted=False,required_adapters=['reviewed-cohort-service-binding','external-tls-audience-routing']),
                required_evidence=['dedicated-service-uid-and-raw-rpc-denial','host-runtime-and-network-identity',
                                   'independent-history-and-canonical-recovery','authorized-human-alert-receipt',
                                   'fresh-funding-check-and-key-backup','external-device-invite-payment-restart'])


SETUP='''Zolana pilot host preparation — REVIEW ONLY

No host, DNS record, firewall, service account or listener is created by this packet.
The tested validator supervisor is macOS-specific and runs both development validators
on one primary host. This is one consensus failure domain, not independent validator
hosting. Linux validator binaries, a portable supervisor and split-host peer operation
are not validated by the current local service. Do not install Darwin executables on Linux.

1. Assign actual primary, recovery and observer hosts and independent failure domains.
   No cloud provider or hardware purchase is selected here. Decide whether this limited
   co-located-validator pilot is acceptable or implement/review a portable peer runtime.
2. Build/review the runtime for the selected OS. Use immutable root-owned code, a
   dedicated no-login service identity and owner-only persistent state. Run the existing
   private Unix RPC transport; expose neither raw RPC nor validator keys to desktop apps.
3. Generate a NEW pilot genesis/key ceremony as the intended service identity, or
   explicitly review preservation of a selected existing network. Never reinitialize
   funded keys, ledgers, towers, admission quotas or old user wallets. Keep cold treasury
   and encrypted recovery custody outside the hot service. Verify off-host backups.
4. Prepare the separately reviewed cohort with its original RPC Unix capability. The
   currently installed two-client rehearsal runtime is not a cohort deployment adapter.
   Implement/review that binding before loading a new service; do not edit its fixed
   rehearsal setup or claim that this packet supplies an operational installer.
5. Configure real TLS tester endpoints and exact public audience/Host routing. Existing
   service_tls listeners accept only loopback audiences. External proxy routing, trusted
   peer-IP attribution and denial of direct bypass require implementation and validation;
   merely forwarding a public domain to the old loopback listener is not sufficient.
6. On the separate recovery host, deploy the existing pinned TLS history receiver and
   validate source loss/restore. Provide full canonical archival RPC as well; ciphertext
   history alone cannot resolve old ambiguous payments. On the observer host deploy
   monitor/pager/watchdog with scoped credentials and an authorized human recipient.
7. Create a funding intent using pilot_funding.py against the prepared cohort. Review
   its exact genesis, shielded reservoir address, gas authority and conservative budget.
   Fund test units via the existing operator ceremony with permanent request IDs and
   original journals. The new funding checker never signs or broadcasts a transfer.
8. Stop grant workers/admission while verifying initial funding. A native verified scan,
   finalized public gas read and stable canonical header must meet the complete budget.
   A successful receipt is valid for five minutes, belongs only to that unused cohort,
   and is not a continuing guarantee of future balances or an activation command.
9. Rehearse invite, backup, grants, user-paid send/withdrawal, old-payment recovery and
   host loss from an actual external supported device; verify raw RPC/key denial and
   independent history/human alerts. Review unresolved privacy/consensus limits.
10. Only an explicitly authorized, reviewed deployment may activate those real services.
    This packet remains disabled and contains no credentials or commands that contact hosts.
'''


def prepare(value,output):
    value=cohort.validate(value);output=Path(output).absolute()
    output.mkdir(mode=0o700)
    files={'cohort-plan.json':encode(value),'host-plan.json':encode(host_plan(value)),
           'funding-budget.json':encode(dict(format='zolana-pilot-host-funding-v1',cohort_plan_sha256=sha(encode(value)),
                                            budget=value['budget'],recipients_bound=False,funding_verified=False)),
           'SETUP.txt':SETUP.encode()}
    for name,raw in files.items():create(output/name,raw)
    manifest=dict(format='zolana-pilot-host-packet-v1',files={name:dict(size=len(raw),sha256=sha(raw)) for name,raw in sorted(files.items())})
    create(output/'MANIFEST.json',encode(manifest));fsync_dir(output);fsync_dir(output.parent)
    return dict(manifest_sha256=sha(encode(manifest)),activation_enabled=False,hosts_contacted=0)


def verify(output,expected):
    output=Path(output).absolute();cohort.directory(output)
    raw=read(output/'MANIFEST.json',16384)
    if sha(raw)!=expected:raise ValueError('reviewed host packet digest changed')
    manifest=decode(raw)
    if set(manifest)!={'format','files'} or manifest['format']!='zolana-pilot-host-packet-v1' or set(manifest['files'])!=set(FILES):
        raise ValueError('unexpected host packet inventory')
    if {p.name for p in output.iterdir()}!={*FILES,'MANIFEST.json'}:raise ValueError('unexpected host packet file')
    for name,item in manifest['files'].items():
        data=read(output/name,65536)
        if item!=dict(size=len(data),sha256=sha(data)):raise ValueError('host packet content changed')
    value=cohort.validate(decode(read(output/'cohort-plan.json',32768)))
    if decode(read(output/'host-plan.json',16384))!=host_plan(value):raise ValueError('host plan differs from reviewed contract')
    budget=dict(format='zolana-pilot-host-funding-v1',cohort_plan_sha256=sha(encode(value)),budget=value['budget'],recipients_bound=False,funding_verified=False)
    if decode(read(output/'funding-budget.json',16384))!=budget:raise ValueError('host funding budget differs')
    if read(output/'SETUP.txt',32768)!=SETUP.encode():raise ValueError('host setup instructions changed')
    return value


def check(output,expected):
    value=verify(output,expected);plan=host_plan(value)
    actual=platform.system().lower()+'-'+platform.machine().lower()
    blockers=['actual-host-placement-unverified','pilot-cohort-service-adapter-required','external-tls-audience-adapter-required',
              'independent-recovery-not-deployed','human-paging-not-confirmed','fresh-funding-receipt-required','external-device-acceptance-required']
    if not plan['network']['external_profile_ready']:blockers.append('profile-is-local-rehearsal-only')
    if actual!='darwin-arm64':blockers.append('current-primary-runtime-platform-incompatible')
    return dict(packet_verified=True,local_platform=actual,activation_allowed=False,ready_for_external_testers=False,
                blockers=blockers,hosts_contacted=0,services_started=0)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('prepare','check'))
    parser.add_argument('--plan',type=Path);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--manifest-sha256')
    args=parser.parse_args()
    if args.action=='prepare':
        if args.plan is None:raise ValueError('reviewed cohort plan required')
        result=prepare(decode(read(args.plan,32768)),args.output)
    else:result=check(args.output,args.manifest_sha256)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError):raise SystemExit('Host preparation failed closed; no hosts were contacted or services started.')
