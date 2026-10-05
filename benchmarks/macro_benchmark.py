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


def create_signed_ecdsa_transaction(sender: dict, recipient_pubkey: str, amount: str) -> dict:
    """Create and sign an ECDSA SECP256k1 transaction directly."""
    from collections import OrderedDict
    from ecdsa import SigningKey, SECP256k1

    tx_dict = OrderedDict([
        ('sender_address', sender['public_key']),
        ('recipient_address', recipient_pubkey),
        ('value', str(amount))
    ])

    sk_bytes = bytes.fromhex(sender['private_key'])
    sk = SigningKey.from_string(sk_bytes, curve=SECP256k1)
    sig_hex = sk.sign(str(tx_dict).encode('utf-8')).hex()

    return {
        'sender_address': sender['public_key'],
        'recipient_address': recipient_pubkey,
        'amount': str(amount),
        'signature': sig_hex
    }


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

        # 2. Sinh tap giao dich hop le
        wallets = load_wallets(base_dir)
        if not wallets:
            raise RuntimeError("Khong tim thay vi mau configs/wallets.json")

        alice = wallets.get('Alice')
        bob = wallets.get('Bob')

        print(f"\n[*] Dang tao va ky so {tx_count} giao dich ECDSA hop le...")
        test_txs = []
        for i in range(tx_count):
            # Luan phien Alice -> Bob va Bob -> Alice voi so tien nho hop le
            if i % 2 == 0:
                tx = create_signed_ecdsa_transaction(alice, bob['public_key'], "0.5")
            else:
                tx = create_signed_ecdsa_transaction(bob, alice['public_key'], "0.5")
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

        # 4. Benchmark Consensus & Block Propagation Phase
        print(f"\n[*] GIAI DOAN 2: Do luong thoi gian Miner dong khoi va Block Propagation tren 6 Node...")
        t_mine_start = time.perf_counter()
        target_chain_len = base_chain_len + 1

        all_synced = False
        max_wait = 15.0
        poll_interval = 0.5
        waited = 0.0

        while waited < max_wait:
            time.sleep(poll_interval)
            waited += poll_interval
            statuses = []
            for u in nodes:
                try:
                    st = requests.get(f"{u}/status", timeout=1.0).json()
                    statuses.append(st['chain_length'])
                except Exception:
                    statuses.append(0)

            if all(s >= target_chain_len for s in statuses):
                all_synced = True
                break

        t_prop_total = time.perf_counter() - t_mine_start
        print(f"    -> Toan bo 6 Node dong bo Block moi sau: {t_prop_total:.3f} s")

        # 5. Do luong Block Wire Payload (Kich thuoc goi tin qua HTTP)
        print(f"\n[*] GIAI DOAN 3: Do luong kich thuoc Block Payload qua HTTP...")
        chain_data = requests.get(f"{ingress_url}/chain", timeout=2.0).json()
        latest_block = chain_data['chain'][-1] if chain_data['chain'] else {}
        block_wire_bytes = len(json.dumps(latest_block).encode('utf-8'))
        tx_in_block = len(latest_block.get('transactions', []))
        avg_tx_bytes = (block_wire_bytes / tx_in_block) if tx_in_block > 0 else 0

        print(f"    -> So giao dich trong Block moi: {tx_in_block} txs")
        print(f"    -> Kich thuoc Block thuc te tren duong truyen HTTP: {block_wire_bytes / 1024:.2f} KB ({block_wire_bytes} bytes)")
        print(f"    -> Dung luong trung binh tren 1 transaction:       {avg_tx_bytes:.1f} bytes/tx")

        # Tong hop ket qua Macro
        macro_results = {
            'benchmark_name': 'Macro-Benchmark 6-Node P2P (HTTP)',
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

    out_dir = Path(args.output_dir) if args.output_dir else base_dir / "benchmarks" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)

    run_macro_benchmark(cfg, base_dir, out_dir)


if __name__ == '__main__':
    main()
