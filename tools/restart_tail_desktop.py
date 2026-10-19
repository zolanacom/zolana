"""Read existing invited wallets in the desktop session during finite acceptance."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    attempt = int(sys.argv[1])
    if not 9 <= attempt <= 15 or os.getuid() != 501:
        raise ValueError('expected desktop user and fresh acceptance attempt')
    project = Path(__file__).resolve().parent.parent
    source = project / '.local/service-wallet-acceptance-021'
    destination = project / ('.local/restart-desktop-wallets-029-RECHECK' + str(attempt))
    output = Path('/private/tmp/native-tail-029-g3xxx4ft') / ('desktop-recheck' + str(attempt))
    output.mkdir(mode=0o700)
    progress = Path('/Library/NativePayLocal') / ('RESTART-TAIL-029-RECHECK' + str(attempt) + '.progress.json')
    deadline = time.monotonic() + 900
    while True:
        try:
            value = json.loads(progress.read_text())
            if value.get('phase') == 'desktop_wallet_check_ready':
                break
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        if time.monotonic() >= deadline:
            raise TimeoutError('desktop check readiness deadline')
        time.sleep(.5)
    result = {'token': value['token'], 'status': 'failed'}
    try:
        destination.mkdir(mode=0o700)
        originals = {}
        balances = {}
        for who in ['alice', 'bob']:
            wallet = source / (who + '-client/wallet-ui/wallet.json')
            originals[who] = hashlib.sha256(wallet.read_bytes()).hexdigest()
            copied = destination / (who + '.wallet.json')
            copied.write_bytes(wallet.read_bytes())
            copied.chmod(0o600)
            profile = destination / (who + '.profile.json')
            profile.write_bytes((source / (who + '-client/network.json')).read_bytes())
            profile.chmod(0o600)
            child = subprocess.run([
                '/Library/NativePayLocal/target/debug/native-wallet', 'balance',
                '--network', str(profile), '--wallet', str(copied),
                '--password-file', str(source / 'password')],
                capture_output=True, text=True, timeout=120,
                env={'PATH': '/usr/bin:/bin', 'RAYON_NUM_THREADS': '2'})
            if child.returncode:
                raise RuntimeError('wallet balance failed: ' + child.stderr[-1000:])
            balances[who] = json.loads(child.stdout)['balance']
        if balances != {'alice': 895000, 'bob': 1105000}:
            raise ValueError('existing invited balances differ')
        if any(hashlib.sha256((source / (who + '-client/wallet-ui/wallet.json')).read_bytes()).hexdigest() != digest
               for who, digest in originals.items()):
            raise ValueError('original encrypted wallet changed')
        result.update(status='passed', balances=balances, original_wallets_unchanged=True)
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    temporary = output / 'result.tmp'
    temporary.write_text(json.dumps(result))
    temporary.chmod(0o600)
    os.replace(temporary, output / 'result.json')
    print(json.dumps(result))
    if result['status'] != 'passed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
