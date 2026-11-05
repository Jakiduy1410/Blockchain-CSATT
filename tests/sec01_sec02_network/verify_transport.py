import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("OPENSSL_CONF", str(ROOT / "configs/pqc_openssl.cnf"))

from blockchain.network.tls_helper import TLSManager
from websockets.sync.client import connect

parser = argparse.ArgumentParser()
parser.add_argument("port", nargs="?", type=int, default=6000)
parser.add_argument("--classical", action="store_true")
args = parser.parse_args()

mode = "ecdhe" if args.classical else "hybrid"
ctx = TLSManager.create_client_ssl_context(mode=mode, verify_peer=False)
if args.classical:
    ctx.set_ecdh_curve("X25519")

try:
    with connect(
        f"wss://127.0.0.1:{args.port}",
        ssl=ctx, open_timeout=5, close_timeout=2
    ) as ws:
        assert ws.socket.version() == "TLSv1.3", "Wrong TLS version"
        assert ws.response.status_code == 101, "Upgrade failed"

        print("TLS:", ws.socket.version())
        print("Cipher:", ws.socket.cipher())
        print(f"HTTP/1.1 {ws.response.status_code} {ws.response.reason_phrase}")
        print("Upgrade:", ws.response.headers.get("Upgrade"))

        if not ws.ping(b"sec0102-transport-check").wait(timeout=3):
            raise TimeoutError("Pong not received")

        print("PASS: WebSocket Pong received on this same connection")
        print("Check selected group in captured ServerHello.")
except Exception as exc:
    print(f"TLS/WebSocket NOT established or check failed: {exc}")
    sys.exit(1)
