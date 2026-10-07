"""
Configuration Manager
Trách nhiệm:
- Quản lý cấu hình linh hoạt qua Command-Line Arguments (CLI) và Config File
- Tuyệt đối không hardcode cổng, danh sách peers hay vai trò miner
"""

import argparse
import json
import os
from typing import List


class NodeConfig:
    def __init__(self):
        self.host: str = "127.0.0.1"
        self.port: int = 5000
        self.peers: List[str] = []
        self.is_miner: bool = False
        self.difficulty: int = 2
        self.auto_mine_interval: float = 2.0
        self.use_tls: bool = False
        self.ssl_cert: str = ""
        self.ssl_key: str = ""

    @classmethod
    def load(cls) -> 'NodeConfig':
        config = cls()

        parser = argparse.ArgumentParser(description="Blockchain P2P Node Engine")
        parser.add_argument('-p', '--port', default=5000, type=int, help='Cổng lắng nghe của Node (mặc định: 5000)')
        parser.add_argument('--host', default="127.0.0.1", type=str, help='Địa chỉ IP / Host (mặc định: 127.0.0.1)')
        parser.add_argument('--peers', default="", type=str, help='Danh sách Peers ban đầu, cách nhau bằng dấu phẩy (vd: 127.0.0.1:5001,127.0.0.1:5002)')
        parser.add_argument('--miner', action='store_true', help='Kích hoạt chế độ Auto-Miner cho Node này')
        parser.add_argument('--difficulty', default=2, type=int, help='Độ khó Proof of Work (mặc định: 2)')
        parser.add_argument('--tls', action='store_true', help='Kích hoạt bảo mật mã hóa đường truyền TLS/HTTPS')
        parser.add_argument('--ssl-cert', default="", type=str, help='Đường dẫn file chứng chỉ SSL (.crt/.pem)')
        parser.add_argument('--ssl-key', default="", type=str, help='Đường dẫn file khóa bí mật SSL (.key/.pem)')
        parser.add_argument('-c', '--config', default="", type=str, help='Đường dẫn tới file cấu hình JSON')

        args, _ = parser.parse_known_args()

        # 1. Đọc từ file JSON nếu có
        if args.config and os.path.exists(args.config):
            try:
                with open(args.config, 'r', encoding='utf-8') as f:
                    file_data = json.load(f)
                    config.host = file_data.get('host', config.host)
                    config.port = file_data.get('port', config.port)
                    config.peers = file_data.get('peers', config.peers)
                    config.is_miner = file_data.get('is_miner', config.is_miner)
                    config.difficulty = file_data.get('difficulty', config.difficulty)
                    config.use_tls = file_data.get('use_tls', config.use_tls)
                    config.ssl_cert = file_data.get('ssl_cert', config.ssl_cert)
                    config.ssl_key = file_data.get('ssl_key', config.ssl_key)
            except Exception as e:
                print(f"[CẢNH BÁO] Không thể đọc file config: {e}")

        # 2. CLI arguments có độ ưu tiên ghi đè cao hơn
        config.port = args.port
        config.host = args.host
        if args.peers:
            config.peers = [p.strip() for p in args.peers.split(',') if p.strip()]
        if args.miner:
            config.is_miner = True
        config.difficulty = args.difficulty

        if args.tls:
            config.use_tls = True

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        default_cert = os.path.join(project_root, 'certs', 'server.crt')
        default_key = os.path.join(project_root, 'certs', 'server.key')

        if args.ssl_cert:
            config.ssl_cert = args.ssl_cert
        elif not config.ssl_cert and config.use_tls:
            config.ssl_cert = default_cert

        if args.ssl_key:
            config.ssl_key = args.ssl_key
        elif not config.ssl_key and config.use_tls:
            config.ssl_key = default_key

        return config
