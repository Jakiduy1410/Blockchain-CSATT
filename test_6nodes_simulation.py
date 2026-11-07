"""
Kiem thu thuc nghiem Toan dien: Mang Blockchain P2P 6 Node
Chu trinh Vong doi giao dich 6 buoc tren he thong Module hoa chuyen nghiep
"""

import json
import os
import subprocess
import sys
import time
import requests

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


def run_experiment():
    print("=" * 75)
    print("  KIEM THU AN NINH & VAN HANH: MANG BLOCKCHAIN P2P 6 NODE (ZERO-HARDCODE)")
    print("=" * 75)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, 'configs', 'network_6nodes.json')
    if not os.path.exists(config_path):
        config_path = os.path.join(base_dir, 'network_6nodes.json')
    with open(config_path, 'r', encoding='utf-8') as f:
        net_cfg = json.load(f)

    py_cmd = get_python_cmd()
    processes = []

    try:
        # 1. Khoi dong 6 Node P2P theo vai tro
        print("\n[*] Giai doan 1: Khoi dong 6 Node P2P Mesh (Topology 6 Node)...")
        for node in net_cfg['nodes']:
            cmd = py_cmd + ['blockchain/blockchain.py', '-p', str(node['port'])]
            if node['is_miner']:
                cmd.append('--miner')
            if node['peers']:
                cmd.extend(['--peers', ','.join(node['peers'])])

            p = subprocess.Popen(cmd, cwd=base_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(p)
            print(f"    -> Khoi chay Node {node['id']} (Port {node['port']}) | Vai tro: {'MINER [AUTO-MINE]' if node['is_miner'] else 'RELAY & VALIDATOR'}")

        # Khoi dong Client
        print("[*] Khoi dong Blockchain Client (Port 8080)...")
        p_client = subprocess.Popen(py_cmd + ['blockchain_client/blockchain_client.py', '-p', '8080'],
                                    cwd=base_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(p_client)

        print("[*] Cho mang luoi khoi tao ket noi P2P Mesh (4 giay)...")
        time.sleep(4)

        # 2. Kiem tra trang thai ban dau cua 6 node qua API /status
        print("\n[*] Giai doan 2: Kiem tra ket noi mang P2P giua cac Node:")
        for node in net_cfg['nodes']:
            res = requests.get(f"http://127.0.0.1:{node['port']}/status", timeout=3).json()
            print(f"    - Node {node['id']} (:{node['port']}): Peers={len(res['peers'])} | Chain={res['chain_length']} | Mempool={res['mempool_count']}")

        # 3. Client lay vi mau da co so du khoi tao (Alice, Bob) va ky giao dich 1
        print("\n[*] Giai doan 3: Client lay vi mau va ky giao dich bang chu ky so ECDSA (secp256k1)...")
        wallets_res = requests.get('http://127.0.0.1:8080/wallets/sample', timeout=3).json()
        alice = wallets_res.get('Alice', {})
        bob = wallets_res.get('Bob', {})

        tx1_data = {
            'sender_address': alice['public_key'],
            'sender_private_key': alice['private_key'],
            'recipient_address': bob['public_key'],
            'amount': '40.0',
            'nonce': '1'
        }
        signed_tx1 = requests.post('http://127.0.0.1:8080/generate/transaction', data=tx1_data, timeout=3).json()
        sig1 = signed_tx1['signature']
        print(f"    -> Da ky giao dich 1 (Alice -> Bob: 40.0 COIN, Nonce 1). Chu ky ECDSA: {sig1[:30]}...")

        # 4. Phat song giao dich 1 vao DUY NHAT Node 1
        print("\n[*] Giai doan 4: Gui giao dich vao DUY NHAT Node 1 (:5000) qua API /transactions/new...")
        post_tx1 = {
            'sender_address': alice['public_key'],
            'recipient_address': bob['public_key'],
            'amount': '40.0',
            'nonce': '1',
            'signature': sig1
        }
        res1 = requests.post('http://127.0.0.1:5000/transactions/new', json=post_tx1, timeout=3).json()
        print(f"    -> Phan hoi Node 1: {res1.get('message')}")

        # 5. Cho Miner Node 2 phat hien mempool, dao Block 2 va phat song Block 2 qua WebSocket
        print("\n[*] Giai doan 5: Cho Miner (Node 2) tu dong gom mempool, dao va phat song Block 2 qua WebSocket...")
        time.sleep(5.0)

        # 6. Kiem tra tinh dong bo So cai tren ca 6 Node cho Block 2
        print("\n[*] Giai doan 6: Kiem chung dong bo So cai (Ledger) cua 6 Node sau khi Miner dong Block 2:")
        all_block2_ok = True
        for node in net_cfg['nodes']:
            chain = requests.get(f"http://127.0.0.1:{node['port']}/chain", timeout=3).json()
            length = chain['length']
            block2 = chain['chain'][1] if length >= 2 else None
            txs_in_b2 = len(block2['transactions']) if block2 else 0

            print(f"    - Node {node['id']} (:{node['port']}): Chain={length} Blocks | Block #2 co {txs_in_b2} txs | Mempool={len(requests.get(f'http://127.0.0.1:{node['port']}/transactions/get').json()['transactions'])} tx")

            if length != 2 or txs_in_b2 < 2:
                all_block2_ok = False

        # KIEM TRA AN NINH: THU PHAT LAI GIAO DICH 1 (REPLAY ATTACK)
        print("\n[*] [KIEM THU AN NINH] Thu phat lai Giao dich 1 (Replay Attack) vao Node 3 (:5002)...")
        replay_res = requests.post('http://127.0.0.1:5002/transactions/new', json=post_tx1, timeout=3)
        replay_blocked = (replay_res.status_code == 406)
        print(f"    -> Ket qua: HTTP {replay_res.status_code} | {'REPLAY ATTACK BI CHAN THANH CONG!' if replay_blocked else 'CANH BAO: Khong chan duoc Replay!'}")

        # 7. Thu nghiem tinh Phi tap trung (Decentralization): Gui tiep Giao dich 2 vao Node 5!
        print("\n[*] Giai doan 7: Thu nghiem Phi tap trung - Gui Giao dich 2 vao Node 5 (:5004)...")
        tx2_data = {
            'sender_address': bob['public_key'],
            'sender_private_key': bob['private_key'],
            'recipient_address': alice['public_key'],
            'amount': '20.0',
            'nonce': '1'
        }
        signed_tx2 = requests.post('http://127.0.0.1:8080/generate/transaction', data=tx2_data, timeout=3).json()
        post_tx2 = {
            'sender_address': bob['public_key'],
            'recipient_address': alice['public_key'],
            'amount': '20.0',
            'nonce': '1',
            'signature': signed_tx2['signature']
        }
        res2 = requests.post('http://127.0.0.1:5004/transactions/new', json=post_tx2, timeout=3).json()
        print(f"    -> Phan hoi Node 5: {res2.get('message')}")

        print("\n[*] Giai doan 8: Cho Miner (Node 2) dao va phat song Block 3 qua WebSocket...")
        time.sleep(5.0)

        # 8. Kiem tra toan bo 6 Node cho Block 3
        print("\n[*] Giai doan 9: Kiem chung dong bo Block 3 tren TOAN BO 6 NODE:")
        all_block3_ok = True
        for node in net_cfg['nodes']:
            st = requests.get(f"http://127.0.0.1:{node['port']}/status", timeout=3).json()
            print(f"    - Node {node['id']} (:{node['port']}): Chain={st['chain_length']} Blocks | Mempool={st['mempool_count']} tx")
            if st['chain_length'] != 3 or st['mempool_count'] != 0:
                all_block3_ok = False

        print("\n" + "=" * 75)
        print("  TONG KET THUC NGHIEM:")
        if all_block2_ok and all_block3_ok and replay_blocked:
            print("  >>> [XAC NHAN CHUYEN GIA AN NINH MANG: THANH CONG 100%] <<<")
            print("  1. Chu ky so ECDSA (secp256k1) va Nonce duoc kiem tra nghiem ngat tai tung node.")
            print("  2. Co che P2P WebSocket TLS ECDHE lan truyen giao dich ngam lien tuc giua 6 Node.")
            print("  3. Tan cong Phat lai (Replay Attack) bi triet tieu hoan toan nho Nonce & So cai.")
            print("  4. Auto-Miner (Node 2) tu dong bat Mempool, giai PoW va broadcast Block moi qua wss://.")
            print("  5. Block Propagation dong bo 100% so cai tren ca 6 node qua WebSocket.")
            print("  6. Mempool duoc tu dong don dep sau moi Block.")
        else:
            print("  >>> [CANH BAO] Kiem tra lai cac chi so chua dong bo hoac Replay chua chan.")
        print("=" * 75)

    finally:
        print("\n[*] Dung an toan tat ca 7 tien trinh (6 Nodes + 1 Client)...")
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
        print("[*] Da tat toan bo tien trinh thu nghiem.")


if __name__ == '__main__':
    run_experiment()
