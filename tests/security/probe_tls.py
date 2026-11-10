"""Check this interpreter and OpenSSL CLI separately. Installs nothing."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('OPENSSL_CONF', str(ROOT / 'configs' / 'pqc_openssl.cnf'))

import re
import shutil
import ssl
import subprocess


def main():
    print(f'Python: {sys.version}\nExecutable: {sys.executable}')
    print(f'Python ssl: {ssl.OPENSSL_VERSION}\nOPENSSL_CONF: {os.environ["OPENSSL_CONF"]}')
    cli = shutil.which('openssl')
    if cli:
        for args in (['version', '-a'], ['list', '-kem-algorithms'], ['list', '-tls-groups']):
            result = subprocess.run([cli, *args], capture_output=True, text=True, timeout=10)
            print(f'\n$ {cli} {" ".join(args)}\n{result.stdout}{result.stderr}')
            if args == ['list', '-kem-algorithms']:
                supported = bool(re.search(r'\bML[-_]?KEM[-_]?768\b', result.stdout, re.I))
                print('ML-KEM-768 (CLI): ' + ('SUPPORTED' if supported else
                      'NOT LISTED' if result.returncode == 0 else 'UNKNOWN (command unavailable)'))
    else:
        print('OpenSSL CLI: NOT FOUND; ML-KEM-768 CLI capability UNKNOWN')
    try:
        from blockchain.network.tls_helper import TLSManager
        server = TLSManager.create_server_ssl_context(require_pqc=True)
        client = TLSManager.create_client_ssl_context(require_pqc=True)
        result = TLSManager.verify_policy(server, client)
    except Exception as exc:
        print(f'X25519MLKEM768 (Python project policy): NOT VERIFIED / UNAVAILABLE: {exc}')
        print('PQC_REQUIRED must not start. Classical demo requires explicit REQUIRE_PQC=0.')
        return 1
    print(f'X25519MLKEM768 (Python): SUPPORTED — real in-memory handshake: {result}')
    print('Classical X25519 and P-256 controls rejected. No TCP capture created by this test.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
