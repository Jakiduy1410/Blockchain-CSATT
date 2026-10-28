"""
PERF-01 Macro-Benchmark Suite: Heterogeneous P2P Network Benchmark
Khao sat hieu nang End-to-End cua Mang Luoi Blockchain P2P gom 3 Node phan cap:
  1. Node 0 (Server Node): 4 vCPU, 4GB RAM (Datacenter / Ingress & Miner Node) - Port 5000
  2. Node 1 (Edge Node):   1 vCPU, 512MB RAM (Raspberry Pi 4 / Router & Relay) - Port 5001
  3. Node 2 (IoT Node):    0.5 vCPU, 128MB RAM (Smart Meter / Constrained Validator) - Port 5002

So sanh toan dien 3 Thuật toán Ký số:
  - ECDSA (secp256k1)
  - RSA-2048 (PKCS#1 v1.5)
  - ML-DSA-87 (NIST PQC Level 5)
Cac chi so do luong:
  - Do tre lan truyen & tham dinh khoi (Block Propagation & Verification Delay) tu Server -> Edge -> IoT
  - Tong dung luong du lieu qua day mang (Wire Payload Size: Txs va Mined Block)
  - Muc do nghen co chai tai nguyen CPU / RAM tren Node IoT so voi Node Server
  - Thong luong End-to-End TPS cua toan he thong
"""

import concurrent.futures
import csv
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

PERF_DIR = Path(__file__).resolve().parent
BASE_DIR = PERF_DIR.parent.parent
RESULTS_DIR = BASE_DIR / "benchmarks" / "results" / "perf01_resource_stress"
DATA_DIR = RESULTS_DIR / "data"

NETWORK_NAME = "perf-macro-net"

NODES_SPEC = {
    "server": {
        "name": "Node Server (Ingress & Miner)",
        "container": "btc-macro-server",
        "cpus": "4.0",
        "memory": "4096m",
        "mem_limit_mb": 4096,
        "host_port": 5000,
        "internal_host": "btc-macro-server",
        "role": "Full Miner & Ingress"
    },
    "edge": {
        "name": "Node Edge (Relay Gateway)",
        "container": "btc-macro-edge",
        "cpus": "1.0",
        "memory": "512m",
        "mem_limit_mb": 512,
        "host_port": 5001,
        "internal_host": "btc-macro-edge",
        "role": "P2P Relay & Validator"
    },
    "iot": {
        "name": "Node IoT (Constrained Validator)",
        "container": "btc-macro-iot",
        "cpus": "0.5",
        "memory": "128m",
        "mem_limit_mb": 128,
        "host_port": 5002,
        "internal_host": "btc-macro-iot",
        "role": "Light Validator"
    }
}


def clean_environment():
    for node in NODES_SPEC.values():
        subprocess.run(["docker", "rm", "-f", node["container"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["docker", "network", "rm", NETWORK_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def setup_network():
    clean_environment()
    subprocess.run(["docker", "network", "create", NETWORK_NAME], check=True, stdout=subprocess.DEVNULL)


def start_node(node_key: str) -> bool:
    spec = NODES_SPEC[node_key]
    cmd = [
        "docker", "run", "-d",
        "--name", spec["container"],
        "--network", NETWORK_NAME,
        f"--cpus={spec['cpus']}",
        f"-m={spec['memory']}",
        f"--memory-swap={spec['memory']}",
        "-p", f"{spec['host_port']}:5000",
        "blockchain-node:perf"
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.returncode == 0


def wait_nodes_ready(timeout_sec: int = 25) -> bool:
    t0 = time.time()
    for key, spec in NODES_SPEC.items():
        url = f"http://127.0.0.1:{spec['host_port']}/status"
        ready = False
        while time.time() - t0 < timeout_sec:
            try:
                r = requests.get(url, timeout=1.0)
                if r.status_code == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.5)
        if not ready:
            print(f"[!] Node {spec['name']} chua san sang sau {timeout_sec}s!")
            return False
    return True


def register_p2p_peers():
    requests.post("http://127.0.0.1:5000/nodes/register",
                  json={"nodes": ["btc-macro-edge:5000", "btc-macro-iot:5000"]}, timeout=3.0)
    requests.post("http://127.0.0.1:5001/nodes/register",
                  json={"nodes": ["btc-macro-server:5000", "btc-macro-iot:5000"]}, timeout=3.0)
    requests.post("http://127.0.0.1:5002/nodes/register",
                  json={"nodes": ["btc-macro-server:5000", "btc-macro-edge:5000"]}, timeout=3.0)
    time.sleep(2.0)


def get_cgroup_stats(container_name: str) -> Tuple[int, float]:
    try:
        cmd = ["docker", "exec", container_name, "sh", "-c", "cat /sys/fs/cgroup/cpu.stat; echo '---'; cat /sys/fs/cgroup/memory.current"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.0)
        if res.returncode == 0 and res.stdout.strip():
            parts = res.stdout.strip().split('---')
            cpu_usec = 0
            for line in parts[0].strip().splitlines():
                if line.startswith('usage_usec'):
                    cpu_usec = int(line.split()[1])
                    break
            mem_mb = int(parts[1].strip().splitlines()[0]) / 1048576.0
            return cpu_usec, mem_mb
    except Exception:
        pass
    return 0, 0.0


def run_macro_test_round(algo_id: str, algo_name: str, tx_dataset: list, batch_size: int = 100) -> dict:
    print(f"\n{'='*80}")
    print(f"  MACRO BENCHMARK ROUND: {algo_name}")
    print(f"  Mang 3 Node: Server (4 vCPU) -> Edge (1 vCPU) -> IoT (0.5 vCPU)")
    print(f"  So luong giao dich thu nghiem: {batch_size} txs")
    print(f"{'='*80}")

    setup_network()
    for k in NODES_SPEC:
        start_node(k)
    
    if not wait_nodes_ready():
        raise RuntimeError("Khong the khoi dong cum Node Macro!")

    register_p2p_peers()
    print("[+] He thong mang P2P da san sang voi 3 Node noi bo.")

    initial_stats = {}
    for k, spec in NODES_SPEC.items():
        cpu_u, mem_m = get_cgroup_stats(spec["container"])
        initial_stats[k] = {'cpu_init': cpu_u, 'baseline_mem': mem_m}
        print(f"    - {spec['name']}: Baseline RAM = {mem_m:.2f} MB / {spec['mem_limit_mb']} MB")

    txs_to_send = tx_dataset[:batch_size]

    sample_tx_bytes = len(json.dumps(txs_to_send[0]).encode('utf-8'))
    total_wire_txs_kb = round((sample_tx_bytes * batch_size) / 1024.0, 2)
    print(f"[*] Uoc tinh Wire Payload: {sample_tx_bytes} B/tx -> Tong {batch_size} txs = {total_wire_txs_kb} KB")

    # 1. Giai doan 1: Ban batch giao dich vao Node Server (Ingress)
    print(f"[*] Giai doan 1: Ban {batch_size} txs vao Server Node (Port 5000)...")
    t_ingest_start = time.time()
    accepted = 0

    def send_tx(tx):
        try:
            r = requests.post("http://127.0.0.1:5000/transactions/new", json={
                'sender_address': tx['sender_address'],
                'recipient_address': tx['recipient_address'],
                'amount': str(tx['amount']),
                'nonce': tx['nonce'],
                'signature': tx['signature']
            }, timeout=5.0)
            return r.status_code == 201
        except Exception:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(send_tx, tx) for tx in txs_to_send]
        for f in concurrent.futures.as_completed(futs):
            if f.result():
                accepted += 1

    t_ingest_end = time.time()
    ingest_time = round(t_ingest_end - t_ingest_start, 3)
    ingest_tps = round(accepted / max(0.001, ingest_time), 2)
    print(f"[+] Server Ingress: Da nhan {accepted}/{batch_size} txs trong {ingest_time}s ({ingest_tps} tx/s)")

    # 2. Giai doan 2: Khai thac Khoi (Mining) tai Node Server voi 50 txs
    print("[*] Giai doan 2: Server khai thac khoi (Mining Block chua 50 giao dich)...")
    t_mine_start = time.time()
    try:
        r_mine = requests.get("http://127.0.0.1:5000/mine?max_txs=50", timeout=20.0)
        mine_res = r_mine.json() if r_mine.status_code == 200 else {}
    except Exception as e:
        print(f"[!] Loi mining: {e}")
        mine_res = {}
    t_mine_end = time.time()
    mine_duration = round(t_mine_end - t_mine_start, 3)

    block_data = mine_res.get('block') or {
        'block_number': mine_res.get('block_number', 1),
        'timestamp': mine_res.get('timestamp', time.time()),
        'transactions': mine_res.get('transactions', []),
        'nonce': mine_res.get('nonce', 0),
        'previous_hash': mine_res.get('previous_hash', '')
    }

    mined_tx_count = len(block_data.get('transactions', []))
    block_number = block_data.get('block_number', 1)
    block_wire_bytes = len(json.dumps(block_data).encode('utf-8'))
    block_wire_kb = round(block_wire_bytes / 1024.0, 2)
    print(f"[+] Server da dao xong Block #{block_number} chua {mined_tx_count} txs (Size: {block_wire_kb} KB) trong {mine_duration}s")

    # 3. Giai doan 3: Lan truyen khoi P2P & Do thoi gian xac thuc tren Edge va IoT
    print("[*] Giai doan 3: Phat song khoi toi Edge va IoT de do thoi gian xac thuc chuoi tren tung hardware...")
    
    # Do thoi gian Node Edge (1 vCPU) tham dinh khoi
    t0_edge = time.time()
    try:
        r_edge = requests.post("http://127.0.0.1:5001/p2p/blocks/receive", json={'block': block_data}, timeout=15.0)
        edge_accepted = r_edge.status_code == 200 and r_edge.json().get('accepted', False)
    except Exception:
        edge_accepted = False
    edge_prop_delay_ms = round((time.time() - t0_edge) * 1000.0, 2)

    # Do thoi gian Node IoT (0.5 vCPU) tham dinh khoi
    t0_iot = time.time()
    try:
        r_iot = requests.post("http://127.0.0.1:5002/p2p/blocks/receive", json={'block': block_data}, timeout=25.0)
        iot_accepted = r_iot.status_code == 200 and r_iot.json().get('accepted', False)
    except Exception:
        iot_accepted = False
    iot_prop_delay_ms = round((time.time() - t0_iot) * 1000.0, 2)

    total_e2e_time = round(ingest_time + mine_duration + ((edge_prop_delay_ms + iot_prop_delay_ms) / 1000.0), 3)
    e2e_tps = round(accepted / max(0.001, total_e2e_time), 2)

    print(f"[+] Ket qua Lan truyen Khoi (Block Propagation):")
    print(f"    - Edge Node Propagation & Verification Delay: {edge_prop_delay_ms} ms (Accepted: {edge_accepted})")
    print(f"    - IoT Node Propagation & Verification Delay:  {iot_prop_delay_ms} ms (Accepted: {iot_accepted}) [Constrained Bottleneck]")
    print(f"    - Tong thoi gian End-to-End:                  {total_e2e_time} s")
    print(f"    - Thong luong End-to-End TPS:                 {e2e_tps} tx/s")

    # 4. Do tai nguyen sau khi hoan tat tren ca 3 Node
    nodes_metrics = {}
    for k, spec in NODES_SPEC.items():
        cpu_final, mem_final = get_cgroup_stats(spec["container"])
        cpu_consumed_sec = (cpu_final - initial_stats[k]['cpu_init']) / 1000000.0
        avg_cpu = round((cpu_consumed_sec / max(0.001, total_e2e_time)) * 100.0, 2)
        normalized_cpu = round(avg_cpu / float(spec['cpus']), 2)
        
        peak_cmd = ["docker", "exec", spec["container"], "cat", "/sys/fs/cgroup/memory.peak"]
        peak_res = subprocess.run(peak_cmd, stdout=subprocess.PIPE, text=True)
        peak_ram = int(peak_res.stdout.strip()) / 1048576.0 if peak_res.returncode == 0 and peak_res.stdout.strip().isdigit() else mem_final

        nodes_metrics[k] = {
            'baseline_ram_mb': round(initial_stats[k]['baseline_mem'], 2),
            'peak_ram_mb': round(peak_ram, 2),
            'ram_limit_mb': spec['mem_limit_mb'],
            'ram_utilization_pct': round((peak_ram / spec['mem_limit_mb']) * 100.0, 2),
            'avg_cpu_pct': avg_cpu,
            'normalized_cpu_pct': normalized_cpu
        }
        print(f"    - {spec['name']}: Peak RAM = {peak_ram:.2f} MB ({nodes_metrics[k]['ram_utilization_pct']}%) | Avg CPU = {avg_cpu}% (Norm: {normalized_cpu}%)")

    clean_environment()

    return {
        'algorithm_id': algo_id,
        'algorithm_name': algo_name,
        'batch_size': batch_size,
        'accepted_txs': accepted,
        'mined_block_txs': mined_tx_count,
        'wire_tx_bytes': sample_tx_bytes,
        'total_wire_txs_kb': total_wire_txs_kb,
        'block_wire_kb': block_wire_kb,
        'server_ingest_time_s': ingest_time,
        'server_ingest_tps': ingest_tps,
        'mine_duration_s': mine_duration,
        'edge_prop_delay_ms': edge_prop_delay_ms,
        'iot_prop_delay_ms': iot_prop_delay_ms,
        'e2e_total_time_s': total_e2e_time,
        'e2e_tps': e2e_tps,
        'nodes': nodes_metrics
    }


def plot_macro_chart(macro_results: List[dict], out_path: Path):
    fig, axes = plt.subplots(1, 3, figsize=(21, 6), dpi=300)
    fig.suptitle("PERF-01: MACRO-BENCHMARK - SO SÁNH HIỆU NĂNG MẠNG P2P PHÂN CẤP (3 NODES)\nECDSA vs RSA-2048 vs ML-DSA-87 (NIST PQC Level 5) End-to-End Flow",
                 fontsize=14, fontweight='bold', y=0.98)

    labels = [r['algorithm_name'] for r in macro_results]
    x = np.arange(len(labels))
    width = 0.35

    # 1. Block Propagation Delay & E2E Time
    ax1 = axes[0]
    edge_delays = [r['edge_prop_delay_ms'] for r in macro_results]
    iot_delays = [r['iot_prop_delay_ms'] for r in macro_results]

    b1 = ax1.bar(x - width/2, edge_delays, width, label='Edge Block Delay (ms)', color='#2ca02c')
    b2 = ax1.bar(x + width/2, iot_delays, width, label='IoT Block Delay (ms)', color='#d62728')

    for b in b1:
        ax1.annotate(f"{b.get_height():.1f}ms", xy=(b.get_x() + b.get_width() / 2, b.get_height()),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=9, fontweight='bold')
    for b in b2:
        ax1.annotate(f"{b.get_height():.1f}ms", xy=(b.get_x() + b.get_width() / 2, b.get_height()),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax1.set_ylabel("Độ trễ lan truyền & xác thực (ms)", fontsize=11, fontweight='bold')
    ax1.set_title("1. Độ Trễ Lan Truyền Khối (Block Propagation)", fontsize=12, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontweight='bold', fontsize=9)
    ax1.legend(loc='upper left', fontsize=9)
    ax1.grid(axis='y', linestyle='--', alpha=0.5)

    # 2. Wire Payload Size (Block & Txs)
    ax2 = axes[1]
    block_sizes = [r['block_wire_kb'] for r in macro_results]
    txs_sizes = [r['total_wire_txs_kb'] for r in macro_results]

    b3 = ax2.bar(x - width/2, txs_sizes, width, label='100 Txs Payload (KB)', color='#1f77b4')
    b4 = ax2.bar(x + width/2, block_sizes, width, label='Forged Block Wire Size (KB)', color='#ff7f0e')

    for b in b3:
        ax2.annotate(f"{b.get_height():.1f}KB", xy=(b.get_x() + b.get_width() / 2, b.get_height()),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=9, fontweight='bold')
    for b in b4:
        ax2.annotate(f"{b.get_height():.1f}KB", xy=(b.get_x() + b.get_width() / 2, b.get_height()),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax2.set_ylabel("Dung lượng qua dây mạng (KB)", fontsize=11, fontweight='bold')
    ax2.set_title("2. Kích Thước Dữ Liệu Qua Mạng (Network Wire Payload)", fontsize=12, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, fontweight='bold', fontsize=9)
    ax2.legend(loc='upper left', fontsize=9)
    ax2.grid(axis='y', linestyle='--', alpha=0.5)

    # 3. IoT vs Server Normalized CPU
    ax3 = axes[2]
    server_cpu = [r['nodes']['server']['normalized_cpu_pct'] for r in macro_results]
    iot_cpu = [r['nodes']['iot']['normalized_cpu_pct'] for r in macro_results]

    b5 = ax3.bar(x - width/2, server_cpu, width, label='Server Normalized CPU (%)', color='#3b528b')
    b6 = ax3.bar(x + width/2, iot_cpu, width, label='IoT Normalized CPU (%)', color='#b51d14')

    for b in b5:
        ax3.annotate(f"{b.get_height():.1f}%", xy=(b.get_x() + b.get_width() / 2, b.get_height()),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=9, fontweight='bold')
    for b in b6:
        ax3.annotate(f"{b.get_height():.1f}%", xy=(b.get_x() + b.get_width() / 2, b.get_height()),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax3.set_ylabel("Normalized CPU (%) [Đo trên hạn ngạch]", fontsize=11, fontweight='bold')
    ax3.set_title("3. Mức Bão Hòa CPU: Server vs IoT Node", fontsize=12, fontweight='bold')
    ax3.set_xticks(x)
    ax3.set_xticklabels(labels, fontweight='bold', fontsize=9)
    ax3.legend(loc='upper left', fontsize=9)
    ax3.grid(axis='y', linestyle='--', alpha=0.5)

    plt.tight_layout()
    plt.savefig(out_path, bbox_inches='tight')
    plt.close()
    print(f"[+] Da xuat bieu do Macro Benchmark: {out_path}")


def save_macro_csv(macro_results: List[dict], out_path: Path):
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Algorithm", "Batch Size (Txs)", "Tx Wire Size (Bytes)", "100 Txs Wire (KB)", "Block Wire Size (KB)",
            "Server Ingest Time (s)", "Server Ingest TPS", "Block Mining Time (s)",
            "Edge Prop Delay (ms)", "IoT Prop Delay (ms)", "E2E Total Time (s)", "E2E TPS",
            "Server Peak RAM (MB)", "Server Avg CPU (%)",
            "Edge Peak RAM (MB)", "Edge Avg CPU (%)",
            "IoT Peak RAM (MB)", "IoT Normalized CPU (%)"
        ])
        for r in macro_results:
            writer.writerow([
                r['algorithm_name'], r['batch_size'], r['wire_tx_bytes'], r['total_wire_txs_kb'], r['block_wire_kb'],
                r['server_ingest_time_s'], r['server_ingest_tps'], r['mine_duration_s'],
                r['edge_prop_delay_ms'], r['iot_prop_delay_ms'], r['e2e_total_time_s'], r['e2e_tps'],
                r['nodes']['server']['peak_ram_mb'], r['nodes']['server']['avg_cpu_pct'],
                r['nodes']['edge']['peak_ram_mb'], r['nodes']['edge']['avg_cpu_pct'],
                r['nodes']['iot']['peak_ram_mb'], r['nodes']['iot']['normalized_cpu_pct']
            ])
    print(f"[+] Da xuat bang CSV Macro-Benchmark: {out_path}")


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("  KHOI CHAY PERF-01 MACRO-BENCHMARK: MANG BLOCKCHAIN P2P 3 NODES")
    print("  So sanh ECDSA vs RSA-2048 vs ML-DSA-87 tren ha tang Server - Edge - IoT phan cap")
    print("=" * 80)

    ecdsa_file = DATA_DIR / "txs_500_ecdsa.json"
    rsa_file = DATA_DIR / "txs_500_rsa.json"
    mldsa_file = DATA_DIR / "txs_500_mldsa87.json"

    if not ecdsa_file.exists() or not rsa_file.exists() or not mldsa_file.exists():
        print("[!] Thieu dataset. Chay perf/generate_perf01_txs.py truoc.")
        return

    ecdsa_txs = json.load(open(ecdsa_file, 'r', encoding='utf-8'))
    rsa_txs = json.load(open(rsa_file, 'r', encoding='utf-8'))
    mldsa_txs = json.load(open(mldsa_file, 'r', encoding='utf-8'))

    macro_results = []

    # 1. Round 1: ECDSA (secp256k1)
    res_ecdsa = run_macro_test_round("ecdsa", "ECDSA (secp256k1)", ecdsa_txs, batch_size=100)
    macro_results.append(res_ecdsa)
    time.sleep(2.0)

    # 2. Round 2: RSA-2048 (PKCS#1 v1.5)
    res_rsa = run_macro_test_round("rsa", "RSA-2048 (PKCS#1 v1.5)", rsa_txs, batch_size=100)
    macro_results.append(res_rsa)
    time.sleep(2.0)

    # 3. Round 3: ML-DSA-87 (NIST PQC Level 5)
    res_mldsa = run_macro_test_round("mldsa87", "ML-DSA-87 (NIST PQC Level 5)", mldsa_txs, batch_size=100)
    macro_results.append(res_mldsa)

    json_path = RESULTS_DIR / "perf01_macro_results.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(macro_results, f, indent=2, ensure_ascii=False)

    csv_path = RESULTS_DIR / "perf01_macro_matrix.csv"
    save_macro_csv(macro_results, csv_path)

    chart_path = RESULTS_DIR / "perf01_macro_chart.png"
    plot_macro_chart(macro_results, chart_path)

    clean_environment()

    print("\n" + "=" * 80)
    print("  HOAN TAT TOAN BO MACRO-BENCHMARK PERF-01 (3 THUAT TOAN)!")
    print(f"  - Ket qua JSON:   {json_path}")
    print(f"  - Bang CSV Macro: {csv_path}")
    print(f"  - Bieu do Macro:  {chart_path}")
    print("=" * 80)


if __name__ == '__main__':
    main()
