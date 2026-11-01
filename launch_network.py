"""
Detached Background Network Launcher
Chạy toàn bộ 6 Node P2P và 1 Client 8080 ngầm độc lập với file log riêng cho từng tiến trình
Hỗ trợ tham số cấu hình: --tls, --sig, --miner
"""

import argparse
import json
import os
import subprocess
import sys

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

base_dir = os.path.dirname(os.path.abspath(__file__))
py = sys.executable

parser = argparse.ArgumentParser(description="Detached Background Network Launcher")
parser.add_argument('--tls', type=str, default=os.environ.get("BLOCKCHAIN_TLS_MODE", "ecdhe"),
                    choices=['ecdhe', 'hybrid', 'none', 'plaintext'], help="Cơ chế TLS: ecdhe, hybrid, none")
parser.add_argument('--sig', type=str, default=os.environ.get("BLOCKCHAIN_SIG_MODE", "all"),
                    choices=['ecdsa', 'mldsa44', 'mldsa87', 'all'], help="Thuật toán chữ ký: ecdsa, mldsa44, mldsa87, all")
parser.add_argument('--auto-mine', action='store_true', help="Tự động đào cho Node 2")
args, _ = parser.parse_known_args()

tls_mode = args.tls.lower()
sig_mode = args.sig.lower()

config_path = os.path.join(base_dir, 'configs', 'network_6nodes.json')
if not os.path.exists(config_path):
    config_path = os.path.join(base_dir, 'network_6nodes.json')

with open(config_path, 'r', encoding='utf-8') as f:
    net_cfg = json.load(f)

log_dir = os.path.join(base_dir, 'logs')
os.makedirs(log_dir, exist_ok=True)

# Cờ tạo tiến trình tách biệt hoàn toàn trên Windows
DETACHED_PROCESS = 0x00000008 if sys.platform == 'win32' else 0

env = os.environ.copy()
env["BLOCKCHAIN_TLS_MODE"] = tls_mode
env["BLOCKCHAIN_SIG_MODE"] = sig_mode

print(f"[*] Khoi chay 6 Blockchain Nodes (TLS: {tls_mode}, Signature: {sig_mode})...")
for node in net_cfg['nodes']:
    cmd = [py, 'blockchain/blockchain.py', '-p', str(node['port']), '--tls', tls_mode, '--sig', sig_mode]
    if args.auto_mine and node.get('is_miner'):
        cmd.append('--miner')
    if node['peers']:
        cmd.extend(['--peers', ','.join(node['peers'])])

    log_file = open(os.path.join(log_dir, f"node_{node['port']}.log"), "a", encoding="utf-8")
    subprocess.Popen(
        cmd,
        cwd=base_dir,
        env=env,
        creationflags=DETACHED_PROCESS,
        stdout=log_file,
        stderr=subprocess.STDOUT
    )
    role_str = "MINER ⛏" if node.get('is_miner') else "RELAY"
    print(f"    [+] Node {node['id']} @ Port {node['port']} ({role_str})")

print(f"[*] Khoi chay Blockchain Client @ Port 8080 (Signature: {sig_mode})...")
client_log = open(os.path.join(log_dir, "client_8080.log"), "a", encoding="utf-8")
subprocess.Popen(
    [py, 'blockchain_client/blockchain_client.py', '-p', '8080', '--sig', sig_mode],
    cwd=base_dir,
    env=env,
    creationflags=DETACHED_PROCESS,
    stdout=client_log,
    stderr=subprocess.STDOUT
)

print("[SUCCESS] Toan bo 7 tien trinh da duoc khoi chay ngam tach biet thanh cong!")
