"""
Interactive Network Launcher (Khoi chay mang tuong tac 6 Node P2P)
Muc tieu:
- Giu cac tien trinh chay ngam de nguoi dung tu do mo cac tab trinh duyet tuong tac tay
- Ho tro tu tay bam nut Mine tren tab Node 2 de quan sat chu trinh theo nhip do cua ban
- Bam Ctrl+C hoac go 'q' de tat toan bo an toan
"""

import json
import os
import subprocess
import sys
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


def get_python_cmd():
    if sys.executable and os.path.exists(sys.executable):
        return [sys.executable]
    import shutil
    for candidate in ['python3', 'python', 'py']:
        path = shutil.which(candidate)
        if path:
            return [path]
    return ['python']


def main():
    print("=" * 75)
    print("  KHOI CHAY MANG BLOCKCHAIN P2P 6 NODE - CHE DO TUONG TAC THUC TE")
    print("=" * 75)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, 'configs', 'network_6nodes.json')
    if not os.path.exists(config_path):
        config_path = os.path.join(base_dir, 'network_6nodes.json')
    with open(config_path, 'r', encoding='utf-8') as f:
        net_cfg = json.load(f)

    py_cmd = get_python_cmd()
    print(f"[*] He dieu hanh: {sys.platform} | Python: {' '.join(py_cmd)}")

    processes = []

    try:
        print("\n[*] 1. Dang khoi dong 6 Node P2P Mesh...")
        for node in net_cfg['nodes']:
            cmd = py_cmd + ['blockchain/blockchain.py', '-p', str(node['port'])]
            # De nguoi dung tu tay bam nut 'Mine' tren Web Node 2 quan sat chu trinh
            if node['peers']:
                cmd.extend(['--peers', ','.join(node['peers'])])

            p = subprocess.Popen(cmd, cwd=base_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(p)
            print(f"    [OK] Node {node['id']} dang chay tai: http://127.0.0.1:{node['port']} ({'MINER ⛏' if node['is_miner'] else 'RELAY'})")

        print("\n[*] 2. Dang khoi dong Blockchain Client...")
        p_client = subprocess.Popen(py_cmd + ['blockchain_client/blockchain_client.py', '-p', '8080'],
                                    cwd=base_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(p_client)
        print("    [OK] Client (Vi nguoi dung) tai: http://127.0.0.1:8080")

        print("\n" + "=" * 75)
        print("  DANH SACH DUONG DAN TRINH DUYET SAN SANG DE BAN MO VA TUONG TAC:")
        print("=" * 75)
        print("  * Tab 1 (Vi Client):   http://localhost:8080/make/transaction")
        print("  * Tab 2 (Node 1):      http://localhost:5000  (Ingress / Relay)")
        print("  * Tab 3 (Node 2):      http://localhost:5001  (Miner ⛏ - Co nut bam Mine)")
        print("  * Tab 4 (Node 3):      http://localhost:5002  (Relay)")
        print("  * Tab 5 (Node 4):      http://localhost:5003  (Relay)")
        print("  * Tab 6 (Node 5):      http://localhost:5004  (Relay)")
        print("  * Tab 7 (Node 6):      http://localhost:5005  (Relay)")
        print("  * VISUALIZER LIVE:     http://localhost:5000/visualizer (Hoac bat ky Node nao)")
        print("-" * 75)
        print("  Luu y:")
        print("  - Cac tab Node co che do 'Live Sync (2s)' tu dong cap nhat khong can F5.")
        print("  - Hop den 'Security Audit Trail' se in chi tiet qua trinh verify RSA & Merge Block.")
        print("=" * 75)
        print("\n>>> MANG DANG HOAT DONG. Nhan 'Ctrl+C' de dung toan bo mang <<<\n")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Nhan tin hieu dung tu ban phim...")
    finally:
        print("[*] Dang tat an toan toan bo 7 tien trinh...")
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
        print("[*] Da tat toan bo mang Blockchain. Tam biet!")


if __name__ == '__main__':
    main()
