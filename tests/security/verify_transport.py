"""One real TLS/WebSocket stream. Use --classical for the negative policy control."""
import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('port', nargs='?', type=int, default=6000)
    parser.add_argument('--classical', action='store_true')
    args = parser.parse_args()
    if not args.classical:
        os.environ.setdefault('OPENSSL_CONF', str(ROOT / 'configs' / 'pqc_openssl.cnf'))
    # Imports after environment configuration are intentional.
    from blockchain.network.tls_helper import TLSManager, connection_evidence
    from websockets.sync.client import connect
    ctx = TLSManager.create_client_ssl_context(require_pqc=not args.classical)
    try:
        with connect(f'wss://127.0.0.1:{args.port}', ssl=ctx, open_timeout=5, close_timeout=2) as ws:
            evidence = connection_evidence(ws)
            response = ws.response
            print(f'HTTP/1.1 {response.status_code} {response.reason_phrase}')
            print(f'Upgrade: {response.headers.get("Upgrade")}\n{evidence}')
            payload = os.urandom(12)
            if not ws.ping(payload).wait(timeout=3):
                print('Pong NOT received')
                return 1
            print(f'WebSocket Pong received | ping payload hex={payload.hex()} | {evidence}')
            print('All observations above belong to this one TCP connection.')
            return 0
    except Exception as exc:
        print(f'TLS/WebSocket NOT established: {exc}')
        print('Correlate with Node audit; a client failure alone does not prove an attack.')
        return 1


if __name__ == '__main__':
    sys.exit(main())
