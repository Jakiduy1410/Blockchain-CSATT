"""
Detached Background Network Launcher
Chạy toàn bộ 6 Node P2P và 1 Client 8080 ngầm độc lập với file log riêng cho từng tiến trình
"""

import json
import os
import subprocess
import sys

base_dir = os.path.dirname(os.path.abspath(__file__))
py = sys.executable

config_path = os.path.join(base_dir, 'configs', 'network_6nodes.json')
if not os.path.exists(config_path):
    config_path = os.path.join(base_dir, 'network_6nodes.json')

with open(config_path, 'r', encoding='utf-8') as f:
    net_cfg = json.load(f)

log_dir = os.path.join(base_dir, 'logs')
os.makedirs(log_dir, exist_ok=True)

# Cờ tạo tiến trình tách biệt hoàn toàn trên Windows
DETACHED_PROCESS = 0x00000008

print("[*] Khoi chay 6 Blockchain Nodes...")
for node in net_cfg['nodes']:
    cmd = [py, 'blockchain/blockchain.py', '-p', str(node['port'])]
    if node['peers']:
        cmd.extend(['--peers', ','.join(node['peers'])])

    log_file = open(os.path.join(log_dir, f"node_{node['port']}.log"), "a", encoding="utf-8")
    subprocess.Popen(
        cmd,
        cwd=base_dir,
        creationflags=DETACHED_PROCESS,
        stdout=log_file,
        stderr=subprocess.STDOUT
    )
    print(f"    [+] Node {node['id']} @ Port {node['port']}")

print("[*] Khoi chay Blockchain Client @ Port 8080...")
client_log = open(os.path.join(log_dir, "client_8080.log"), "a", encoding="utf-8")
subprocess.Popen(
    [py, 'blockchain_client/blockchain_client.py', '-p', '8080'],
    cwd=base_dir,
    creationflags=DETACHED_PROCESS,
    stdout=client_log,
    stderr=subprocess.STDOUT
)

print("[SUCCESS] Toan bo 7 tien trinh da duoc khoi chay ngam tach biet thanh cong!")
