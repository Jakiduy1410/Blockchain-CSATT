"""
Macro-Benchmark Suite: End-to-End P2P Network Load & Consensus Benchmark
Measures: Real-world HTTP Ingestion TPS, Network Latency, Mining & Propagation Delay, Block Wire Payload
Platforms: Linux, Windows, macOS (Zero-Hardcode)
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import numpy as np

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


def get_python_cmd() -> List[str]:
    """Cross-platform python executable resolver."""
    if sys.executable and os.path.exists(sys.executable):
        return [sys.executable]
    import shutil
    for candidate in ['python3', 'python', 'py']:
        path = shutil.which(candidate)
        if path:
            return [path]
    return ['python']


def is_node_online(url: str, timeout: float = 1.0) -> bool:
    """Check if a node is listening and healthy."""
    try:
        res = requests.get(f"{url.rstrip('/')}/status", timeout=timeout)
        return res.status_code == 200
    except Exception:
        return False


def load_wallets(base_dir: Path) -> Dict[str, dict]:
    """Load sample wallets from configs/wallets.json."""
    wallets_path = base_dir / "configs" / "wallets.json"
    if not wallets_path.exists():
        wallets_path = base_dir.parent / "configs" / "wallets.json"

    if wallets_path.exists():
        with open(wallets_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def create_signed_ecdsa_transaction(sender: dict, recipient_pubkey: str, amount: str, nonce: int = 1) -> dict:
    """Tạo và ký số giao dịch chuẩn ECDSA (secp256k1) kèm nonce chống Replay."""
    from collections import OrderedDict
    import ecdsa

    tx_dict = OrderedDict([
        ('sender_address', sender['public_key']),
        ('recipient_address', recipient_pubkey),
        ('value', str(amount)),
        ('nonce', str(nonce))
    ])
    tx_bytes = str(tx_dict).encode('utf-8')
    sk_bytes = bytes.fromhex(sender['private_key'])
    sk = ecdsa.SigningKey.from_string(sk_bytes, curve=ecdsa.SECP256k1)
    sig_bytes = sk.sign(tx_bytes)

    return {
        'sender_address': sender['public_key'],
        'recipient_address': recipient_pubkey,
        'amount': str(amount),
        'nonce': nonce,
        'signature': sig_bytes.hex()
    }


def create_signed_mldsa_transaction(sender: dict, recipient_pubkey: str, amount: str, nonce: int = 1) -> dict:
    """Create and sign a post-quantum ML-DSA-44 transaction."""
    from collections import OrderedDict
    import oqs

    tx_dict = OrderedDict([
        ('sender_address', sender['public_key']),
        ('recipient_address', recipient_pubkey),
        ('value', str(amount)),
        ('nonce', str(nonce))
    ])
    tx_bytes = str(tx_dict).encode('utf-8')
    priv_bytes = bytes.fromhex(sender['private_key'])
    with oqs.Signature('ML-DSA-44', secret_key=priv_bytes) as signer:
        sig_bytes = signer.sign(tx_bytes)

    return {
        'sender_address': sender['public_key'],
        'recipient_address': recipient_pubkey,
        'amount': str(amount),
        'nonce': nonce,
        'signature': sig_bytes.hex()
    }


def create_signed_transaction(sender: dict, recipient_pubkey: str, amount: str, nonce: int = 1) -> dict:
    """Polymorphic transaction signer: auto-detects ML-DSA-44 or ECDSA."""
    pub = sender.get('public_key', '')
    if len(pub) > 1000:
        return create_signed_mldsa_transaction(sender, recipient_pubkey, amount, nonce)
    return create_signed_ecdsa_transaction(sender, recipient_pubkey, amount, nonce)


def run_macro_benchmark(config: dict, base_dir: Path, out_dir: Path) -> Dict:
    macro_cfg = config.get('macro', {})
    tx_count = macro_cfg.get('tx_count', 30)
    ingress_url = macro_cfg.get('ingress_url', "http://127.0.0.1:5000")
    miner_url = macro_cfg.get('miner_url', "http://127.0.0.1:5001")
    nodes = macro_cfg.get('nodes', [
        "http://127.0.0.1:5000", "http://127.0.0.1:5001", "http://127.0.0.1:5002",
        "http://127.0.0.1:5003", "http://127.0.0.1:5004", "http://127.0.0.1:5005"
    ])

    print("=" * 80)
    print("  MACRO-BENCHMARK: KIEM THU TAI & HIEU NANG MANG P2P 6-NODE (E2E LIVE NETWORK)")
    print(f"  Muc tieu: {tx_count} Transactions | Ingress Node: {ingress_url} | Miner: {miner_url}")
    print(f"  He dieu hanh: {sys.platform} | Python: {' '.join(get_python_cmd())}")
    print("=" * 80)

    # 1. Kiem tra mang luoi
    spawned_processes = []
    nodes_alive = all(is_node_online(u) for u in nodes)

    if not nodes_alive:
        print("\n[*] Mang 6 Node chua khoi chay. Tu dong khoi dong P2P Mesh (Topology 6 Node)...")
        net_cfg_path = base_dir / "configs" / "network_6nodes.json"
        if not net_cfg_path.exists():
            net_cfg_path = base_dir.parent / "configs" / "network_6nodes.json"

        with open(net_cfg_path, 'r', encoding='utf-8') as f:
            net_cfg = json.load(f)

        py_cmd = get_python_cmd()
        for node in net_cfg['nodes']:
            cmd = py_cmd + ['blockchain/blockchain.py', '-p', str(node['port'])]
            if node.get('is_miner'):
                cmd.append('--miner')
            if node.get('peers'):
                cmd.extend(['--peers', ','.join(node['peers'])])

            work_dir = str(base_dir if (base_dir / "blockchain").exists() else base_dir.parent)
            p = subprocess.Popen(cmd, cwd=work_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            spawned_processes.append(p)

        print("[*] Cho mang luoi 6 Node P2P khoi dong va ket noi Mesh...")
        for _ in range(20):
            time.sleep(0.5)
            if all(is_node_online(u, timeout=0.5) for u in nodes):
                break
    else:
        print("\n[+] Phat hien mang P2P 6 Node dang hoat dong san sang. Tien hanh do luong truc tiep...")

    try:
        # Lay trang thai chuoi ban dau
        initial_status = {}
        for u in nodes:
            try:
                res = requests.get(f"{u}/status", timeout=3.0).json()
                initial_status[u] = res['chain_length']
            except Exception:
                initial_status[u] = 1
        base_chain_len = max(initial_status.values())

        # 2. Sinh tap giao dich hop le chéo giữa các ví (Alice, Bob, Charlie, Dave)
        wallets = load_wallets(base_dir)
        if not wallets:
            raise RuntimeError("Khong tim thay vi mau configs/wallets.json")

        wallet_names = list(wallets.keys())
        first_wallet = wallets[wallet_names[0]]
        alg_label = "ML-DSA-44" if len(first_wallet.get('public_key', '')) > 1000 else "ECDSA"

        print(f"\n[*] Dang tao va ky so {tx_count} giao dich {alg_label} ngau nhien cheo {len(wallet_names)} vi ({', '.join(wallet_names)})...")
        test_txs = []
        wallet_nonces = {name: 1 for name in wallet_names}
        sim_balances = {name: float(wallets[name].get('initial_balance', 10.0)) for name in wallet_names}

        import random
        random.seed(42)  # Cố định seed ngẫu nhiên để benchmark có tính lặp lại khoa học

        for i in range(tx_count):
            # Chọn người gửi có số dư khả dụng > 1.0 COIN
            eligible_senders = [name for name in wallet_names if sim_balances[name] > 1.0]
            if not eligible_senders:
                eligible_senders = wallet_names
            sender_name = random.choice(eligible_senders)

            # Chọn người nhận khác người gửi
            recipient_candidates = [name for name in wallet_names if name != sender_name]
            recipient_name = random.choice(recipient_candidates)

            # Số tiền nhỏ biến thiên hợp lệ (0.01 đến 0.15 COIN)
            amount_val = round(0.02 + (i % 20) * 0.005, 4)
            sender_w = wallets[sender_name]
            recip_w = wallets[recipient_name]

            tx = create_signed_transaction(
                sender_w,
                recip_w['public_key'],
                str(amount_val),
                nonce=wallet_nonces[sender_name]
            )

            # Cập nhật nonce và số dư mô phỏng để mọi giao dịch đều 100% hợp lệ
            wallet_nonces[sender_name] += 1
            sim_balances[sender_name] -= amount_val
            sim_balances[recipient_name] += amount_val

            test_txs.append(tx)

        # 3. Benchmark Ingestion Phase (Bắn tải HTTP)
        print(f"\n[*] GIAI DOAN 1: Ban tai {tx_count} giao dich vao Ingress Node ({ingress_url}/transactions/new)...")
        tx_latencies_ms = []
        accepted_count = 0
        t_ingest_start = time.perf_counter()

        raw_csv_path = out_dir / "macro_transactions_raw.csv"
        raw_csv_path.parent.mkdir(parents=True, exist_ok=True)

        with open(raw_csv_path, 'w', newline='', encoding='utf-8') as f:
            csv_w = csv.writer(f)
            csv_w.writerow(['Tx_Index', 'HTTP_Status', 'Latency_ms', 'Result'])

            for idx, tx in enumerate(test_txs):
                t0 = time.perf_counter()
                try:
                    resp = requests.post(f"{ingress_url}/transactions/new", json=tx, timeout=5.0)
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    status_code = resp.status_code
                    if status_code in (200, 201):
                        accepted_count += 1
                        csv_w.writerow([idx + 1, status_code, round(dt_ms, 3), 'ACCEPTED'])
                    else:
                        csv_w.writerow([idx + 1, status_code, round(dt_ms, 3), 'REJECTED'])
                except Exception as ex:
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    csv_w.writerow([idx + 1, 0, round(dt_ms, 3), f'ERROR: {ex}'])

                tx_latencies_ms.append(dt_ms)

        t_ingest_total = time.perf_counter() - t_ingest_start
        ingest_tps = accepted_count / t_ingest_total if t_ingest_total > 0 else 0.0

        latencies_arr = np.array(tx_latencies_ms)
        mean_lat = float(np.mean(latencies_arr))
        median_lat = float(np.median(latencies_arr))
        p95_lat = float(np.percentile(latencies_arr, 95))
        min_lat = float(np.min(latencies_arr))
        max_lat = float(np.max(latencies_arr))

        print(f"    -> Da tiep nhan: {accepted_count}/{tx_count} giao dich ({accepted_count/tx_count*100:.1f}%)")
        print(f"    -> Tong thoi gian ban tai: {t_ingest_total:.3f} s")
        print(f"    -> Ingestion TPS Thuc te:  {ingest_tps:.2f} tx/s")
        print(f"    -> Do tre tiep nhan (Mean): {mean_lat:.2f} ms | Median: {median_lat:.2f} ms | P95: {p95_lat:.2f} ms")

        # 4. Benchmark Consensus & Block Propagation Phase qua WebSocket
        print(f"\n[*] GIAI DOAN 2: Do luong thoi gian Miner dong khoi va Block Propagation tu nhien qua WebSocket...")
        target_chain_len = base_chain_len + 1

        # Chờ 1 giây để đảm bảo toàn bộ giao dịch từ Ingress Node (5000) đã Gossip qua WebSocket tới Miner Node (5001)
        time.sleep(1.0)

        # Kích hoạt đào trực tiếp tại Miner Node (Port 5001), không gọi tại Ingress Node
        print(f"    [*] Kich hoat khai thac Block #{target_chain_len} tai Miner Node ({miner_url}/mine)...")
        t_prop_start = time.perf_counter()
        try:
            mine_res = requests.get(f"{miner_url}/mine", timeout=10.0)
            if mine_res.status_code == 200:
                print(f"    [+] Miner Node ({miner_url}) khai thac thanh cong!")
            else:
                print(f"    [!] Miner phan hoi: {mine_res.status_code}")
        except Exception as ex:
            print(f"    [!] Loi khi goi miner: {ex}")

        # Đo độ trễ lan truyền tự nhiên: KHÔNG gọi cưỡng bức /nodes/resolve
        # Quan sát toàn bộ 6 Node tự động nhận Block qua đường ống WebSocket mở sẵn
        all_synced = False
        max_wait = 15.0
        poll_interval = 0.2
        waited = 0.0

        while waited < max_wait:
            time.sleep(poll_interval)
            waited += poll_interval
            statuses = []
            for u in nodes:
                try:
                    st = requests.get(f"{u}/status", timeout=1.0).json()
                    statuses.append(st.get('chain_length', 0))
                except Exception:
                    statuses.append(0)

            if all(s >= target_chain_len for s in statuses):
                all_synced = True
                break

        t_prop_total = time.perf_counter() - t_prop_start
        print(f"    -> Toan bo {len(nodes)} Node dong bo Block #{target_chain_len} tu nhien qua WebSocket sau: {t_prop_total:.3f} s (Dong bo 100%: {all_synced})")

        # 5. Do luong Block Wire Payload (Kich thuoc goi tin qua WebSocket/Wire)
        print(f"\n[*] GIAI DOAN 3: Do luong kich thuoc Block Payload tren duong truyen...")
        chain_data = requests.get(f"{ingress_url}/chain", timeout=2.0).json()
        latest_block = chain_data['chain'][-1] if chain_data['chain'] else {}
        block_wire_bytes = len(json.dumps(latest_block).encode('utf-8'))
        tx_in_block = len(latest_block.get('transactions', []))
        avg_tx_bytes = (block_wire_bytes / tx_in_block) if tx_in_block > 0 else 0

        print(f"    -> So giao dich trong Block moi: {tx_in_block} txs")
        print(f"    -> Kich thuoc Block thuc te tren duong truyen: {block_wire_bytes / 1024:.2f} KB ({block_wire_bytes} bytes)")
        print(f"    -> Dung luong trung binh tren 1 transaction:  {avg_tx_bytes:.1f} bytes/tx")

        # Tong hop ket qua Macro
        macro_results = {
            'benchmark_name': 'Macro-Benchmark 6-Node P2P (WebSocket TLS ECDHE)',
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'workload': {
                'total_tx_sent': tx_count,
                'accepted_tx': accepted_count,
                'success_rate_pct': round((accepted_count / tx_count) * 100, 2)
            },
            'ingestion_performance': {
                'total_duration_seconds': round(t_ingest_total, 3),
                'e2e_ingestion_tps': round(ingest_tps, 2),
                'latency_mean_ms': round(mean_lat, 2),
                'latency_median_ms': round(median_lat, 2),
                'latency_p95_ms': round(p95_lat, 2),
                'latency_min_ms': round(min_lat, 2),
                'latency_max_ms': round(max_lat, 2)
            },
            'consensus_propagation': {
                'nodes_participating': len(nodes),
                'all_nodes_synced': all_synced,
                'block_propagation_delay_seconds': round(t_prop_total, 3)
            },
            'network_wire_payload': {
                'block_wire_bytes': block_wire_bytes,
                'block_wire_kb': round(block_wire_bytes / 1024.0, 2),
                'tx_count_in_block': tx_in_block,
                'average_bytes_per_tx': round(avg_tx_bytes, 1)
            }
        }

        # Luu JSON
        summary_path = out_dir / "macro_benchmark_summary.json"
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(macro_results, f, indent=2)

        print("\n" + "=" * 80)
        print("  TONG KET MACRO-BENCHMARK:")
        print(f"  * E2E Ingestion TPS:             {ingest_tps:.2f} tx/s")
        print(f"  * Mean HTTP Ingestion Latency:   {mean_lat:.2f} ms")
        print(f"  * Block Propagation to 6 Nodes:  {t_prop_total:.3f} s")
        print(f"  * Block Wire Size ({tx_in_block} txs):       {block_wire_bytes/1024:.2f} KB")
        print(f"  * File tong hop da luu tai:      {summary_path}")
        print("=" * 80)

        return macro_results

    finally:
        if spawned_processes:
            print("\n[*] Dang tat an toan cac tien trinh Node da khoi dong tu dong...")
            for p in spawned_processes:
                try:
                    p.terminate()
                except Exception:
                    pass
            print("[*] Da tat toan bo tien trinh.")


def main():
    parser = argparse.ArgumentParser(description="Macro-Benchmark Suite: Blockchain P2P Network")
    parser.add_argument('-n', '--tx-count', type=int, default=0, help="So luong giao dich ban tai")
    parser.add_argument('-c', '--config', type=str, default="", help="Duong dan file JSON cau hinh")
    parser.add_argument('-o', '--output-dir', type=str, default="", help="Thu muc xuat ket qua")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent.parent
    config_file = Path(args.config) if args.config else base_dir / "benchmarks" / "configs" / "benchmark_config.json"

    cfg = {}
    if config_file.exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            cfg = json.load(f)

    if args.tx_count > 0:
        cfg.setdefault('macro', {})['tx_count'] = args.tx_count

    out_dir = Path(args.output_dir) if args.output_dir else base_dir / "benchmarks" / "results" / "blockchain_macro"
    out_dir.mkdir(parents=True, exist_ok=True)

    run_macro_benchmark(cfg, base_dir, out_dir)


if __name__ == '__main__':
    main()
