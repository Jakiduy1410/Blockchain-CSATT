"""
Node Server Bootstrapper
Trách nhiệm:
- Ghép nối các module: Core Ledger, P2P Network, Consensus Miner, API Controller
- Khởi chạy Flask Server với chế độ đa luồng (threaded=True) để chống nghẽn
"""

import os
import sys
from flask import Flask
from flask_cors import CORS

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

try:
    from .config import NodeConfig
    from .core.ledger import BlockchainLedger
    from .network.p2p import P2PNetwork
    from .consensus.miner import Miner
    from .api.routes import create_api_blueprint
except ImportError:
    from config import NodeConfig
    from core.ledger import BlockchainLedger
    from network.p2p import P2PNetwork
    from consensus.miner import Miner
    from api.routes import create_api_blueprint


def create_app(config: NodeConfig = None) -> tuple[Flask, BlockchainLedger, P2PNetwork, Miner]:
    if config is None:
        config = NodeConfig.load()

    # 1. Khởi tạo Ledger
    ledger = BlockchainLedger(difficulty=config.difficulty)

    # 2. Khởi tạo P2P Network
    my_address = f"{config.host}:{config.port}"
    network = P2PNetwork(ledger=ledger, my_address=my_address, use_tls=config.use_tls)
    if config.peers:
        network.register_peers_bulk(config.peers)

    # 3. Khởi tạo Consensus Miner
    miner = Miner(ledger=ledger, network=network, auto_mine=config.is_miner, check_interval=config.auto_mine_interval)
    if config.is_miner:
        print(f"[*] Node {my_address} khoi chay voi vai tro: ACTIVE AUTO-MINER [MINER]")
        miner.start_auto_miner()
    else:
        print(f"[*] Node {my_address} khoi chay voi vai tro: RELAY & VALIDATOR NODE")

    # 4. Khởi tạo Web API App
    current_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(current_dir, 'templates')
    static_dir = os.path.join(current_dir, 'static')

    app = Flask(__name__, template_folder=templates_dir, static_folder=static_dir)
    CORS(app)

    # Gắn API Blueprint
    api_blueprint = create_api_blueprint(ledger, network, miner, config.port)
    app.register_blueprint(api_blueprint)

    return app, ledger, network, miner


def main():
    config = NodeConfig.load()
    app, ledger, network, miner = create_app(config)
    protocol = "https" if config.use_tls else "http"
    print(f"[+] Blockchain Node dang lang nghe tai: {protocol}://{config.host}:{config.port}")
    if config.use_tls:
        print(f"[*] Che do bao mat: TLS/HTTPS (Cert: {config.ssl_cert})")
    if config.peers:
        print(f"[+] Da ket noi voi cac Peers: {config.peers}")

    if config.use_tls:
        if not os.path.exists(config.ssl_cert) or not os.path.exists(config.ssl_key):
            raise FileNotFoundError(
                f"Khong tim thay file chung chi TLS: '{config.ssl_cert}' hoac '{config.ssl_key}'. "
                f"Vui long kiem tra thu muc certs/."
            )
        ssl_ctx = (config.ssl_cert, config.ssl_key)
        app.run(host=config.host, port=config.port, ssl_context=ssl_ctx, threaded=True)
    else:
        app.run(host=config.host, port=config.port, threaded=True)


if __name__ == '__main__':
    main()
