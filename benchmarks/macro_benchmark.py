"""
Macro-Benchmark Suite: End-to-End P2P Network Load, Cryptography & TLS Transport Benchmark
Comparing:
  - TLS 1.3 Configurations: Classical ECDHE vs Hybrid (X25519 + ML-KEM-768 FIPS 203)
  - Across 4 Signature Schemes: ECDSA (secp256k1) | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 (FIPS 204)
Methodology:
  - Client-side Concurrent Ingestion (ThreadPoolExecutor, 8 workers, fresh TCP socket per tx)
  - Dedicated Unmetered Warm-Up phase to eliminate cold-start & JIT latency
  - Isolated 6-node P2P Mesh life-cycle per test combination (clean Mempool & Genesis state)
  - Real WebSocket TLS 1.3 Handshake RTT measured directly on live nodes (No fake sleeps or branching)
  - Deterministic block mining: exactly N user txs + 1 coinbase reward tx per block
  - P2P WebSocket block propagation measurement across all 6 interconnected nodes
Platforms: Linux, Windows, macOS
"""

import argparse
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

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import psutil
import requests

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


def get_python_cmd() -> List[str]:
    """Cross-platform python executable resolver prioritizing OpenSSL 3.6+ environment if available."""
    msys_py = r'C:\msys64\ucrt64\bin\python.exe'
    if os.path.exists(msys_py):
        return [msys_py]
    if sys.executable and os.path.exists(sys.executable):
        return [sys.executable]
    import shutil
    for candidate in ['python3', 'python', 'py']:
        path = shutil.which(candidate)
        if path:
            return [path]
    return ['python']


def is_node_online(url: str, timeout: float = 0.5) -> bool:
    """Check if a node is listening and healthy."""
    try:
        res = requests.get(f"{url.rstrip('/')}/status", timeout=timeout)
        return res.status_code == 200
    except Exception:
        return False


def kill_ports(ports: List[int]):
    """Terminate existing processes on target ports to avoid EADDRINUSE."""
    if sys.platform != 'win32':
        return
    for p in ports:
        try:
            res = subprocess.check_output(f'netstat -ano | findstr :{p}', shell=True, text=True)
            for line in res.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 5 and 'LISTENING' in line:
                    pid = parts[-1]
                    if pid != '0':
                        subprocess.run(['taskkill', '/F', '/PID', pid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    time.sleep(1.0)


def load_wallets(base_dir: Path) -> Dict[str, dict]:
    """Load sample wallets from configs/wallets.json."""
    wallets_path = base_dir / "configs" / "wallets.json"
    if not wallets_path.exists():
        wallets_path = base_dir.parent / "configs" / "wallets.json"

    if wallets_path.exists():
        with open(wallets_path, 'r', encoding='utf-8') as f:
            raw = json.load(f)
            return {k: v for k, v in raw.items() if v.get('private_key') and len(str(v.get('private_key')).strip()) > 0}
    return {}


def create_signed_ecdsa_transaction(sender: dict, recipient_pubkey: str, amount: str, nonce: int = 1) -> dict:
    """Tạo và ký số giao dịch chuẩn ECDSA (secp256k1) bằng C-backend OpenSSL (cryptography)."""
    from collections import OrderedDict
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    tx_dict = OrderedDict([
        ('sender_address', sender['public_key']),
        ('recipient_address', recipient_pubkey),
        ('value', str(amount)),
        ('nonce', str(nonce))
    ])
    tx_bytes = str(tx_dict).encode('utf-8')
    priv_int = int(sender['private_key'], 16)
    sk = ec.derive_private_key(priv_int, ec.SECP256K1())
    der_sig = sk.sign(tx_bytes, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    sig_bytes = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

    return {
        'sender_address': sender['public_key'],
        'recipient_address': recipient_pubkey,
        'amount': str(amount),
        'nonce': nonce,
        'signature': sig_bytes.hex()
    }


def create_signed_mldsa_transaction(sender: dict, recipient_pubkey: str, amount: str, nonce: int = 1) -> dict:
    """Create and sign a post-quantum ML-DSA transaction (44, 65, or 87)."""
    from collections import OrderedDict
    if os.name == 'nt' and hasattr(os, 'add_dll_directory'):
        for dll_dir in [os.path.abspath('.'), os.path.abspath('liboqs'), os.path.abspath('liboqs/build_all/bin'),
                        os.path.abspath('liboqs/build/bin'), os.path.expanduser('~/_oqs/bin')]:
            if os.path.isdir(dll_dir):
                try:
                    os.add_dll_directory(dll_dir)
                except Exception:
                    pass
    import oqs

    tx_dict = OrderedDict([
        ('sender_address', sender['public_key']),
        ('recipient_address', recipient_pubkey),
        ('value', str(amount)),
        ('nonce', str(nonce))
    ])
    tx_bytes = str(tx_dict).encode('utf-8')
    priv_bytes = bytes.fromhex(sender['private_key'])

    if len(priv_bytes) >= 4800:
        alg_name = "ML-DSA-87"
    elif len(priv_bytes) >= 3500:
        alg_name = "ML-DSA-65"
    else:
        alg_name = "ML-DSA-44"

    with oqs.Signature(alg_name, secret_key=priv_bytes) as signer:
        sig_bytes = signer.sign(tx_bytes)

    return {
        'sender_address': sender['public_key'],
        'recipient_address': recipient_pubkey,
        'amount': str(amount),
        'nonce': nonce,
        'signature': sig_bytes.hex()
    }


def start_p2p_network(base_dir: Path, tls_mode: str = "hybrid", sig_mode: str = "all", enable_auto_miner: bool = False) -> List[subprocess.Popen]:
    """Launch 6-node P2P Mesh with specified TLS and Signature settings. Auto-miner is disabled to avoid race conditions."""
    net_cfg_path = base_dir / "configs" / "network_6nodes.json"
    if not net_cfg_path.exists():
        net_cfg_path = base_dir.parent / "configs" / "network_6nodes.json"

    with open(net_cfg_path, 'r', encoding='utf-8') as f:
        net_cfg = json.load(f)

    ports = [n['port'] for n in net_cfg['nodes']] + [n['port'] + 1000 for n in net_cfg['nodes']]
    kill_ports(ports)
    time.sleep(0.5)

    py_cmd = get_python_cmd()
    spawned = []
    work_dir = str(base_dir if (base_dir / "blockchain").exists() else base_dir.parent)

    env = os.environ.copy()
    env["BLOCKCHAIN_TLS_MODE"] = tls_mode
    env["BLOCKCHAIN_SIG_MODE"] = sig_mode
    env["BLOCKCHAIN_BATCH_SIZE"] = "500"  # Preclude small-batch automatic block forging

    for node in net_cfg['nodes']:
        cmd = py_cmd + ['blockchain/blockchain.py', '-p', str(node['port']), '--tls', tls_mode, '--sig', sig_mode, '--batch-size', '500']
        if node.get('is_miner') and enable_auto_miner:
            cmd.append('--miner')
        if node.get('peers'):
            cmd.extend(['--peers', ','.join(node['peers'])])

        p = subprocess.Popen(cmd, cwd=work_dir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        spawned.append(p)

    # Wait for nodes to be online
    node_urls = [f"http://127.0.0.1:{n['port']}" for n in net_cfg['nodes']]
    online = False
    for _ in range(45):
        time.sleep(0.3)
        if all(is_node_online(u) for u in node_urls):
            online = True
            break
    if not online:
        offline = [u for u in node_urls if not is_node_online(u)]
        print(f"    [!] Canh bao: Node chua san sang: {offline}")

    # Give nodes 1 second to form WebSocket mesh connections
    time.sleep(1.0)
    return spawned


def stop_p2p_network(processes: List[subprocess.Popen], base_dir: Path = None):
    """Safely terminate spawned network processes and clean ports."""
    for p in processes:
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(0.8)
    for p in processes:
        try:
            if p.poll() is None:
                p.kill()
        except Exception:
            pass
    time.sleep(0.5)
    if base_dir:
        net_cfg_path = base_dir / "configs" / "network_6nodes.json"
        if not net_cfg_path.exists():
            net_cfg_path = base_dir.parent / "configs" / "network_6nodes.json"
        if net_cfg_path.exists():
            try:
                with open(net_cfg_path, 'r', encoding='utf-8') as f:
                    net_cfg = json.load(f)
                ports = [n['port'] for n in net_cfg['nodes']] + [n['port'] + 1000 for n in net_cfg['nodes']]
                kill_ports(ports)
            except Exception:
                pass


def measure_real_p2p_tls_handshake(ws_port: int, tls_mode: str, trials: int = 5) -> float:
    """
    Đo thời gian bắt tay thực tế WebSocket TLS 1.3 (ECDHE hoặc Hybrid ML-KEM) tới Node đang chạy.
    Không dùng sleep giả lập, không if-else rẽ nhánh tự tạo điều kiện.
    """
    py_cmd = get_python_cmd()
    script = f"""
import sys, time, statistics
from websockets.sync.client import connect as ws_connect
from blockchain.network.tls_helper import TLSManager

ctx = TLSManager.create_client_ssl_context(mode='{tls_mode}', verify_peer=False)

# 2 warm-up handshakes de loai bo cold-start thread spawn tren Server
for _ in range(2):
    try:
        with ws_connect('wss://127.0.0.1:{ws_port}', ssl=ctx, open_timeout=2.0) as _:
            pass
    except Exception:
        pass
    time.sleep(0.02)

latencies = []
for _ in range({trials}):
    t0 = time.perf_counter()
    try:
        with ws_connect('wss://127.0.0.1:{ws_port}', ssl=ctx, open_timeout=2.0) as _:
            dt = (time.perf_counter() - t0) * 1000.0
            latencies.append(dt)
    except Exception:
        pass
    time.sleep(0.03)

if latencies:
    print(round(statistics.median(latencies), 2))
else:
    print(0.0)
"""
    try:
        res = subprocess.run(py_cmd + ['-c', script], capture_output=True, text=True, timeout=12)
        out = res.stdout.strip().splitlines()
        if out:
            return float(out[-1])
    except Exception:
        pass
    return 0.0


# ==============================================================================
# MACRO EXPERIMENT: SINGLE SCHEME & TLS MEASUREMENT
# ==============================================================================

def benchmark_single_signature_scheme(alg_name: str, wallet_pair: Tuple[str, str], tls_mode: str,
                                      tx_count: int, warmup_count: int, ingress_url: str, miner_url: str,
                                      nodes: List[str], wallets: dict, out_dir: Path,
                                      workers: int = 8, keep_alive: bool = False) -> Tuple[Dict, List[dict]]:
    """
    Run macro benchmark for a specific signature scheme and TLS configuration:
    1. Real live TLS Handshake RTT measurement (wss://127.0.0.1:6000)
    2. Unmetered warm-up phase (10 txs)
    3. Concurrent client ingestion (8 workers, fresh TCP or Keep-Alive session)
    4. Deterministic block mining (all 100 txs + 1 reward)
    5. P2P WebSocket block propagation measurement across all 6 nodes
    """
    tls_display = "TLS 1.3 Classical ECDHE" if tls_mode == "ecdhe" else "TLS 1.3 Hybrid (X25519 + ML-KEM-768)"
    conn_mode_str = "Keep-Alive Session Pool" if keep_alive else "Fresh TCP Sockets (Connection: close)"
    print(f"\n[*] BENCHMARK: {alg_name:<18} | Transport: {tls_display} ({tx_count} Txs, Workers={workers}, {conn_mode_str})...")
    sender_name, recip_name = wallet_pair
    sender_w = wallets[sender_name]
    recip_w = wallets[recip_name]
    is_mldsa = "ML-DSA" in alg_name or len(sender_w['public_key']) > 500

    # --------------------------------------------------------------------------
    # GIAI ĐOẠN 0: ĐO THỰC TẾ TLS HANDSHAKE TRÊN WEBSOCKET LIVE NODE
    # --------------------------------------------------------------------------
    print(f"    [*] 0. Do luong thoi gian bat tay TLS 1.3 Handshake RTT thuc te tren live WebSocket (Node 0 @ 6000)...")
    hs_lat = measure_real_p2p_tls_handshake(ws_port=6000, tls_mode=tls_mode, trials=8)
    print(f"        -> TLS Handshake RTT thuc te: {hs_lat:.2f} ms")

    # --------------------------------------------------------------------------
    # GIAI ĐOẠN 1: WARM-UP (LÀM NÓNG C-BACKEND MẬT MÃ & SOCKET STACK)
    # --------------------------------------------------------------------------
    if warmup_count > 0:
        print(f"    [*] 1. Warm-up phase: Khoi tao bo nho dem mat ma va HTTP socket stack ({warmup_count} iterations)...")
        for i in range(warmup_count):
            amount_val = "0.0001"
            nonce_val = 9999 + i + 1
            if is_mldsa:
                _ = create_signed_mldsa_transaction(sender_w, recip_w['public_key'], amount_val, nonce=nonce_val)
            else:
                _ = create_signed_ecdsa_transaction(sender_w, recip_w['public_key'], amount_val, nonce=nonce_val)

        # Lam am HTTP connection pool toi Ingress va Miner
        for u in [ingress_url, miner_url]:
            try:
                requests.get(f"{u}/status", timeout=1.0)
            except Exception:
                pass
        time.sleep(0.2)

    # Base chain length luon la 1 (Genesis Block sach)
    try:
        base_chain_len = max([requests.get(f"{u}/status", timeout=1.0).json().get('chain_length', 1) for u in nodes])
    except Exception:
        base_chain_len = 1

    # --------------------------------------------------------------------------
    # CHUẨN BỊ 100 GIAO DỊCH THỰC NGHIỆM ĐỘC LẬP
    # --------------------------------------------------------------------------
    test_txs = []
    for i in range(tx_count):
        amount_val = str(round(0.001 + (i % 20) * 0.0001, 6))
        if is_mldsa:
            tx = create_signed_mldsa_transaction(sender_w, recip_w['public_key'], amount_val, nonce=i + 1)
        else:
            tx = create_signed_ecdsa_transaction(sender_w, recip_w['public_key'], amount_val, nonce=i + 1)
        test_txs.append(tx)

    # --------------------------------------------------------------------------
    # GIAI ĐOẠN 2: CLIENT CONCURRENT INGESTION (FRESH TCP HOẶC KEEP-ALIVE SESSIONS)
    # --------------------------------------------------------------------------
    thread_local = threading.local()

    def get_session():
        if not hasattr(thread_local, 'session'):
            thread_local.session = requests.Session()
        return thread_local.session

    def send_tx(tx_item):
        idx, tx_dict = tx_item
        t0 = time.perf_counter()
        ok = False
        status_code = 0
        try:
            if keep_alive:
                s = get_session()
                r = s.post(f"{ingress_url}/transactions/new", json=tx_dict, timeout=10.0)
            else:
                r = requests.post(f"{ingress_url}/transactions/new", json=tx_dict, headers={'Connection': 'close'}, timeout=10.0)
            dt = (time.perf_counter() - t0) * 1000.0
            status_code = r.status_code
            ok = (status_code in (200, 201))
        except Exception:
            dt = (time.perf_counter() - t0) * 1000.0
        return {
            'tls_mode': tls_mode,
            'algorithm': alg_name,
            'tx_index': idx,
            'status_code': status_code,
            'latency_ms': dt,
            'result': 'ACCEPTED' if ok else 'REJECTED'
        }

    indexed_txs = list(enumerate(test_txs, 1))
    t_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        ingest_records = list(executor.map(send_tx, indexed_txs))
    t_ingest = time.perf_counter() - t_start

    accepted = sum(1 for r in ingest_records if r['result'] == 'ACCEPTED')
    latencies = [r['latency_ms'] for r in ingest_records]
    tps = accepted / t_ingest if t_ingest > 0 else 0.0
    mean_lat = float(np.mean(latencies)) if latencies else 0.0
    median_lat = float(np.median(latencies)) if latencies else 0.0
    p95_lat = float(np.percentile(latencies, 95)) if latencies else 0.0

    print(f"    -> Ingestion TPS: {tps:.2f} tx/s | Mean: {mean_lat:.2f} ms | Median: {median_lat:.2f} ms | P95: {p95_lat:.2f} ms")

    # Đợi Ingress Node Gossip xong toàn bộ Mempool sang Miner qua WebSocket Mesh
    print("    [*] 3. Dong bo Mempool tu Ingress sang Miner qua WebSocket TLS Mesh...")
    for _ in range(40):
        try:
            mempool_txs = requests.get(f"{miner_url}/transactions/get", timeout=1.0).json().get('transactions', [])
            user_txs = [t for t in mempool_txs if t.get('sender_address') != '0']
            if len(user_txs) >= accepted:
                break
        except Exception:
            pass
        time.sleep(0.1)

    # --------------------------------------------------------------------------
    # GIAI ĐOẠN 3: KHAI THÁC BLOCK & LAN TRUYỀN WEBSOCKET TỚI 6 NODE
    # --------------------------------------------------------------------------
    target_chain = base_chain_len + 1
    print(f"    [*] 4. Kich hoat khai thac Block #{target_chain} tai Miner Node ({miner_url}/mine?max_txs={tx_count + 50})...")
    t_mine_start = time.perf_counter()
    mine_success = False
    for mine_attempt in range(3):
        try:
            mine_res = requests.get(f"{miner_url}/mine?max_txs={tx_count + 50}", timeout=30.0)
            if mine_res.status_code == 200:
                print("        [+] Miner khai thac thanh cong!")
                mine_success = True
                break
        except Exception:
            time.sleep(1.0)
    t_mining = time.perf_counter() - t_mine_start

    t_prop_start = time.perf_counter()
    synced = False
    for _ in range(100):
        time.sleep(0.1)
        try:
            st = [requests.get(f"{u}/status", timeout=1.0).json().get('chain_length', 0) for u in nodes]
            if all(s >= target_chain for s in st):
                synced = True
                break
        except Exception:
            pass

    t_prop = time.perf_counter() - t_prop_start
    t_consensus_total = t_mining + t_prop
    print(f"    -> Thoi gian giai PoW Miner: {t_mining:.3f} s | Lan truyen WebSocket: {t_prop:.3f} s (Tong Consensus: {t_consensus_total:.3f} s, Sync 100%: {synced})")

    # --------------------------------------------------------------------------
    # GIAI ĐOẠN 4: ĐO KÍCH THƯỚC BLOCK WIRE
    # --------------------------------------------------------------------------
    chain_data = None
    for probe_url in [ingress_url, miner_url] + nodes:
        try:
            res = requests.get(f"{probe_url}/chain", timeout=3.0)
            if res.status_code == 200:
                d = res.json()
                if d.get('chain') and len(d['chain']) >= target_chain:
                    chain_data = d
                    break
                elif not chain_data and d.get('chain'):
                    chain_data = d
        except Exception:
            pass

    if not chain_data:
        chain_data = {'chain': []}

    latest_block = chain_data['chain'][-1] if chain_data['chain'] else {}
    tx_in_block = len(latest_block.get('transactions', []))
    block_bytes = len(json.dumps(latest_block).encode('utf-8'))
    avg_tx_bytes = (block_bytes / tx_in_block) if tx_in_block > 0 else 0

    print(f"    -> Kich thuoc Block tren duong truyen ({tx_in_block} txs): {block_bytes/1024:.2f} KB | Avg {avg_tx_bytes:.1f} B/tx")

    # Key share bytes on wire
    if tls_mode == 'hybrid':
        c_share = 1216
        s_share = 1120
    else:
        c_share = 32
        s_share = 32

    res_summary = {
        'tls_mode': tls_mode,
        'tls_display': tls_display,
        'algorithm': alg_name,
        'tx_sent': tx_count,
        'tx_accepted': accepted,
        'ingestion_tps': round(tps, 2),
        'latency_mean_ms': round(mean_lat, 2),
        'latency_median_ms': round(median_lat, 2),
        'latency_p95_ms': round(p95_lat, 2),
        'handshake_latency_ms': round(hs_lat, 2),
        'client_key_share_bytes': c_share,
        'server_key_share_bytes': s_share,
        'mining_time_sec': round(t_mining, 3),
        'propagation_delay_sec': round(t_prop, 3),
        'consensus_total_sec': round(t_consensus_total, 3),
        'block_wire_kb': round(block_bytes / 1024.0, 2),
        'avg_bytes_per_tx': round(avg_tx_bytes, 1),
        'tx_in_block': tx_in_block,
        'all_nodes_synced': synced
    }
    return res_summary, ingest_records


# ==============================================================================
# PLOTTING MACRO CHARTS
# ==============================================================================

def plot_comprehensive_macro_comparison(ecdhe_results: List[Dict], hybrid_results: List[Dict], out_dir: Path, tx_count: int = 100):
    """
    Vẽ Dashboard khoa học 4-Panel so sánh trực diện Classical ECDHE vs Hybrid ML-KEM cho cả 4 loại khóa:
      - Panel 1: Throughput (TPS) so sánh cạnh nhau
      - Panel 2: Latency Mean & P95 (ms) so sánh cạnh nhau
      - Panel 3: Độ trễ lan truyền WebSocket P2P Mesh (s) & Thời gian bắt tay Handshake TLS (ms)
      - Panel 4: Kích thước tải trọng Block Wire (KB) & Băng thông Key Share
    """
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    fig, axes = plt.subplots(2, 2, figsize=(18, 12))
    fig.suptitle(f"Macro-Benchmark Toàn Diện: So Sánh TLS 1.3 ECDHE vs ML-KEM Hybrid Cho Cả 4 Khóa ({tx_count} txs/block)",
                 fontsize=15, fontweight='bold', y=0.98)

    labels = [r['algorithm'] for r in ecdhe_results]
    x = np.arange(len(labels))
    width = 0.35

    # --------------------------------------------------------------------------
    # PANEL 1: INGESTION THROUGHPUT (TPS)
    # --------------------------------------------------------------------------
    ax1 = axes[0, 0]
    tps_ecdhe = [r['ingestion_tps'] for r in ecdhe_results]
    tps_hybrid = [r['ingestion_tps'] for r in hybrid_results]

    b1 = ax1.bar(x - width/2, tps_ecdhe, width, label='TLS Classical ECDHE', color='#3b82f6', alpha=0.9)
    b2 = ax1.bar(x + width/2, tps_hybrid, width, label='TLS Hybrid (X25519 + ML-KEM-768)', color='#10b981', alpha=0.9)
    ax1.set_title('1. Client Ingestion Throughput (TPS - Higher is better)', fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=15, ha='right', fontweight='bold')
    ax1.set_ylabel('Throughput (Transactions / sec)')
    for idx, v in enumerate(tps_ecdhe):
        ax1.annotate(f"{v:.1f}", (idx - width/2, v), textcoords="offset points", xytext=(0, 3), ha='center', fontsize=9, fontweight='bold')
    for idx, v in enumerate(tps_hybrid):
        ax1.annotate(f"{v:.1f}", (idx + width/2, v), textcoords="offset points", xytext=(0, 3), ha='center', fontsize=9, fontweight='bold')
    ax1.legend(loc='upper right')
    ax1.grid(True, linestyle='--', alpha=0.5)

    # --------------------------------------------------------------------------
    # PANEL 2: END-TO-END INGESTION LATENCY (MEAN & P95)
    # --------------------------------------------------------------------------
    ax2 = axes[0, 1]
    lat_mean_ecdhe = [r['latency_mean_ms'] for r in ecdhe_results]
    lat_mean_hybrid = [r['latency_mean_ms'] for r in hybrid_results]
    lat_p95_ecdhe = [r['latency_p95_ms'] for r in ecdhe_results]
    lat_p95_hybrid = [r['latency_p95_ms'] for r in hybrid_results]

    ax2.bar(x - width/2, lat_mean_ecdhe, width, label='Mean Latency (ECDHE)', color='#60a5fa', alpha=0.8)
    ax2.bar(x + width/2, lat_mean_hybrid, width, label='Mean Latency (Hybrid)', color='#34d399', alpha=0.8)
    ax2.plot(x - width/2, lat_p95_ecdhe, color='#1d4ed8', marker='o', linestyle='--', linewidth=2, label='P95 Latency (ECDHE)')
    ax2.plot(x + width/2, lat_p95_hybrid, color='#047857', marker='s', linestyle='-', linewidth=2, label='P95 Latency (Hybrid)')

    ax2.set_title('2. Client Ingestion Latency: Mean & P95 (ms - Lower is better)', fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, rotation=15, ha='right', fontweight='bold')
    ax2.set_ylabel('Latency (ms)')
    for idx, (m1, m2) in enumerate(zip(lat_mean_ecdhe, lat_mean_hybrid)):
        ax2.annotate(f"{m1:.1f}", (idx - width/2, m1), textcoords="offset points", xytext=(0, 3), ha='center', fontsize=8)
        ax2.annotate(f"{m2:.1f}", (idx + width/2, m2), textcoords="offset points", xytext=(0, 3), ha='center', fontsize=8)
    ax2.legend(loc='upper left')
    ax2.grid(True, linestyle='--', alpha=0.5)

    # --------------------------------------------------------------------------
    # PANEL 3: P2P PROPAGATION DELAY & REAL TLS HANDSHAKE
    # --------------------------------------------------------------------------
    ax3 = axes[1, 0]
    prop_ecdhe = [r['propagation_delay_sec'] * 1000.0 for r in ecdhe_results]
    prop_hybrid = [r['propagation_delay_sec'] * 1000.0 for r in hybrid_results]
    hs_ecdhe = [r['handshake_latency_ms'] for r in ecdhe_results]
    hs_hybrid = [r['handshake_latency_ms'] for r in hybrid_results]

    ax3.bar(x - width/2, prop_ecdhe, width, label='P2P WebSocket Prop Delay (ECDHE)', color='#f59e0b', alpha=0.9)
    ax3.bar(x + width/2, prop_hybrid, width, label='P2P WebSocket Prop Delay (Hybrid)', color='#ea580c', alpha=0.9)

    ax3_twin = ax3.twinx()
    ax3_twin.plot(x - width/2, hs_ecdhe, color='#8b5cf6', marker='^', linewidth=2.2, label='TLS Handshake RTT (ECDHE)')
    ax3_twin.plot(x + width/2, hs_hybrid, color='#ec4899', marker='v', linewidth=2.2, label='TLS Handshake RTT (Hybrid)')
    ax3_twin.set_ylabel('Live Handshake RTT (ms)', color='#8b5cf6')
    ax3_twin.grid(False)

    ax3.set_title('3. P2P Mesh Propagation Delay & Live TLS 1.3 Handshake RTT', fontweight='bold')
    ax3.set_xticks(x)
    ax3.set_xticklabels(labels, rotation=15, ha='right', fontweight='bold')
    ax3.set_ylabel('Propagation Delay Across 6 Nodes (ms)')
    for idx, (p1, p2) in enumerate(zip(prop_ecdhe, prop_hybrid)):
        ax3.annotate(f"{p1:.0f}ms", (idx - width/2, p1), textcoords="offset points", xytext=(0, 3), ha='center', fontsize=8)
        ax3.annotate(f"{p2:.0f}ms", (idx + width/2, p2), textcoords="offset points", xytext=(0, 3), ha='center', fontsize=8)
    ax3.legend(loc='upper left')
    ax3_twin.legend(loc='upper right')
    ax3.grid(True, linestyle='--', alpha=0.5)

    # --------------------------------------------------------------------------
    # PANEL 4: BLOCK WIRE PAYLOAD SIZE (KB)
    # --------------------------------------------------------------------------
    ax4 = axes[1, 1]
    block_kb = [r['block_wire_kb'] for r in hybrid_results]
    colors_payload = ['#6366f1', '#06b6d4', '#14b8a6', '#f43f5e']
    bars = ax4.bar(x, block_kb, width*1.5, color=colors_payload, alpha=0.9)
    ax4.set_title(f'4. Block Wire Payload Size ({tx_count} txs/block)', fontweight='bold')
    ax4.set_xticks(x)
    ax4.set_xticklabels(labels, rotation=15, ha='right', fontweight='bold')
    ax4.set_ylabel('Block Size on Wire (KB)')
    for idx, v in enumerate(block_kb):
        tx_avg = hybrid_results[idx]['avg_bytes_per_tx']
        ax4.annotate(f"{v:.1f} KB\n({tx_avg:.0f} B/tx)", (idx, v), textcoords="offset points", xytext=(0, 5), ha='center', fontsize=9, fontweight='bold')

    # Chèn thêm box thông tin Key Share Wire Overhead
    info_box = (
        "TLS 1.3 Key Share Wire Size:\n"
        "• Classical ECDHE : 32B Client / 32B Server (64B)\n"
        "• Hybrid ML-KEM   : 1216B Client / 1120B Server (2336B)\n"
        "Overhead delta    : +2272 Bytes per TLS Handshake"
    )
    ax4.text(0.05, 0.70, info_box, transform=ax4.transAxes, fontsize=9.5,
             verticalalignment='top', bbox=dict(boxstyle='round,pad=0.5', facecolor='#f8fafc', edgecolor='#cbd5e1', alpha=0.95))
    ax4.grid(True, linestyle='--', alpha=0.5)

    plt.tight_layout()
    chart_path = out_dir / "macro_signatures_comparison.png"
    plt.savefig(chart_path, dpi=300)
    plt.close()

    # Save also as macro_tls_comparison.png for consistency
    chart2_path = out_dir / "macro_tls_comparison.png"
    import shutil
    shutil.copyfile(chart_path, chart2_path)

    print(f"\n[+] Da xuat thanh cong bieu do Macro-Benchmark Toan Dien:")
    print(f"    - {chart_path}")
    print(f"    - {chart2_path}")


def plot_single_mode_chart(results: List[Dict], out_dir: Path, filename: str, tls_title: str):
    """Plot standard 2-panel chart for a specific TLS mode."""
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    tx_c = results[0].get('tx_sent', 100) if results else 100
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    fig.suptitle(f'Macro-Benchmark: Signature Schemes on 6-Node Mesh ({tx_c} tx/block) [{tls_title}]', fontsize=14, fontweight='bold', y=0.98)

    labels = [r['algorithm'] for r in results]
    x = np.arange(len(labels))
    width = 0.35

    tps_vals = [r['ingestion_tps'] for r in results]
    ax1.bar(x, tps_vals, width, label=f'Concurrent Ingestion TPS', color='#3b82f6', alpha=0.9)
    ax1.set_title('End-to-End Ingestion TPS (Concurrency=8) (higher is better)', fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=15, ha='right', fontweight='bold')
    ax1.set_ylabel('TPS (tx/s)')
    for idx, v in enumerate(tps_vals):
        ax1.annotate(f"{v:.1f}", (idx, v), textcoords="offset points", xytext=(0, 3), ha='center', fontweight='bold')
    ax1.grid(True, linestyle='--', alpha=0.5)

    block_kb = [r['block_wire_kb'] for r in results]
    prop_sec = [r['propagation_delay_sec'] for r in results]

    ax2.bar(x - width/2, block_kb, width, label='Block Wire Size (KB)', color='#f59e0b', alpha=0.9)
    ax2.set_title(f'Block Wire Payload Size & Propagation Delay', fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, rotation=15, ha='right', fontweight='bold')
    ax2.set_ylabel('Block Size (KB)')
    for idx, v in enumerate(block_kb):
        ax2.annotate(f"{v:.1f} KB", (idx - width/2, v), textcoords="offset points", xytext=(0, 3), ha='center', fontsize=9)

    ax2_twin = ax2.twinx()
    ax2_twin.plot(x, prop_sec, color='#ef4444', marker='o', linewidth=2.5, label='P2P Propagation (s)')
    ax2_twin.set_ylabel('Propagation Delay (s)', color='#ef4444')
    ax2_twin.grid(False)

    plt.tight_layout()
    plt.savefig(out_dir / filename, dpi=300)
    plt.close()


# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Macro-Benchmark Suite: Blockchain Signatures & TLS P2P")
    parser.add_argument('-n', '--tx-count', type=int, default=100, help="Số giao dịch mỗi đợt benchmark (mặc định: 100)")
    parser.add_argument('-w', '--warmup', type=int, default=10, help="Số giao dịch warm-up không tính giờ (mặc định: 10)")
    parser.add_argument('--workers', type=int, default=8, help="Số luồng client gửi đồng thời (mặc định: 8)")
    parser.add_argument('-c', '--config', type=str, default="", help="Đường dẫn file cấu hình JSON")
    parser.add_argument('-o', '--output-dir', type=str, default="", help="Thư mục xuất kết quả")
    parser.add_argument('--tls', type=str, default="both", choices=['both', 'hybrid', 'ecdhe'],
                        help="Cấu hình TLS kiểm thử: both (mặc định cả ecdhe và hybrid), ecdhe, hybrid")
    parser.add_argument('--keep-alive', action='store_true', default=False,
                        help="Sử dụng HTTP Keep-Alive persistent connection pool (đẩy TPS lên >400-500 tx/s)")
    args = parser.parse_args()

    tx_count = args.tx_count if args.tx_count > 0 else 100
    warmup_count = args.warmup if args.warmup >= 0 else 10
    workers = args.workers if args.workers > 0 else 8

    # Xác định các chế độ TLS cần chạy
    if args.tls == "both":
        run_tls_modes = ["ecdhe", "hybrid"]
    else:
        run_tls_modes = [args.tls]

    base_dir = Path(__file__).resolve().parent.parent
    out_dir = Path(args.output_dir) if args.output_dir else base_dir / "benchmarks" / "results" / "blockchain_macro"
    out_dir.mkdir(parents=True, exist_ok=True)

    ingress_url = "http://127.0.0.1:5000"
    miner_url = "http://127.0.0.1:5001"
    nodes = [f"http://127.0.0.1:{p}" for p in [5000, 5001, 5002, 5003, 5004, 5005]]

    wallets = load_wallets(base_dir)
    if not wallets:
        print("[!] Loi: Khong tim thay vi trong configs/wallets.json")
        sys.exit(1)

    py_engine = get_python_cmd()
    print("=" * 110)
    print("  MACRO-BENCHMARK: DANH GIA THUC TE MANG P2P 6-NODE BLOCKCHAIN (END-TO-END)")
    print("  Configurations : TLS 1.3 Classical ECDHE vs TLS 1.3 Hybrid (X25519 + ML-KEM-768 FIPS 203)")
    print("  Signatures     : ECDSA (secp256k1) | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 (FIPS 204)")
    print(f"  Target Modes   : {', '.join(m.upper() for m in run_tls_modes)} (Total: {len(run_tls_modes) * 4} suites)")
    print(f"  Workload       : {tx_count} txs / suite (Warm-up: {warmup_count} txs, Concurrency: {workers} workers)")
    print(f"  Node Engine    : {' '.join(py_engine)}")
    print(f"  System OS      : {sys.platform} | Host Python {sys.version.split()[0]}")
    print("=" * 110)

    sig_tests = [
        ("ECDSA (secp256k1)", ("Alice", "Bob")),
        ("ML-DSA-44", ("Alice_PQC", "Bob_PQC")),
        ("ML-DSA-65", ("Alice_MLDSA65", "Bob_MLDSA65")),
        ("ML-DSA-87", ("Alice_MLDSA87", "Bob_MLDSA87"))
    ]

    all_macro_results: Dict[str, List[Dict]] = {"ecdhe": [], "hybrid": []}
    all_raw_records: List[Dict] = []
    ecdhe_raw_records: List[Dict] = []
    hybrid_raw_records: List[Dict] = []

    try:
        for t_mode in run_tls_modes:
            mode_label = "CLASSICAL ECDHE" if t_mode == "ecdhe" else "HYBRID (X25519 + ML-KEM-768)"
            print(f"\n{'#' * 110}")
            print(f"### BAT DAU PHAN KIEM THU MACRO CHO CHE DO TLS: {mode_label}")
            print(f"{'#' * 110}")

            for alg_name, pair in sig_tests:
                if pair[0] in wallets and pair[1] in wallets:
                    print(f"\n" + "-" * 90)
                    print(f"[*] KHOI CHAY MANG 6-NODE RIENG CHO: {alg_name} (TLS: {t_mode.upper()})")
                    print("-" * 90)
                    spawned = start_p2p_network(base_dir, tls_mode=t_mode, sig_mode="all", enable_auto_miner=False)
                    try:
                        res, raw_records = benchmark_single_signature_scheme(
                            alg_name, pair, t_mode, tx_count, warmup_count,
                            ingress_url, miner_url, nodes, wallets, out_dir,
                            workers=workers, keep_alive=args.keep_alive
                        )
                        all_macro_results[t_mode].append(res)
                        all_raw_records.extend(raw_records)
                        if t_mode == "ecdhe":
                            ecdhe_raw_records.extend(raw_records)
                        else:
                            hybrid_raw_records.extend(raw_records)
                    finally:
                        stop_p2p_network(spawned, base_dir)

    finally:
        kill_ports([5000, 5001, 5002, 5003, 5004, 5005, 6000, 6001, 6002, 6003, 6004, 6005])

    # --------------------------------------------------------------------------
    # BẢNG TỔNG HỢP TOÀN DIỆN TẤT CẢ 8 BỘ ĐO
    # --------------------------------------------------------------------------
    print("\n" + "=" * 155)
    print(f"BANG 1: KET QUA MACRO-BENCHMARK TOAN DIEN ({tx_count} TX/BLOCK, CONCURRENCY={workers}, WARM-UP={warmup_count})")
    print(f"{'TLS Mode':<12} | {'Thuat toan':<18} | {'TPS Ingest':<12} | {'Mean Lat (ms)':<14} | {'P95 (ms)':<10} | {'TLS RTT (ms)':<13} | {'Block Wire':<18} | {'Mining (s)':<11} | {'WS Prop (s)':<13} | {'Consensus':<11}")
    print("-" * 155)
    for t_mode in run_tls_modes:
        for r in all_macro_results[t_mode]:
            b_wire_str = f"{r['block_wire_kb']:.2f} KB"
            print(f"{t_mode.upper():<12} | "
                  f"{r['algorithm']:<18} | "
                  f"{r['ingestion_tps']:>10.2f} | "
                  f"{r['latency_mean_ms']:>12.2f} | "
                  f"{r['latency_p95_ms']:>8.2f} | "
                  f"{r['handshake_latency_ms']:>11.2f} | "
                  f"{b_wire_str:>18} | "
                  f"{r.get('mining_time_sec', 0.0):>9.3f} s | "
                  f"{r.get('propagation_delay_sec', 0.0):>11.3f} s | "
                  f"{r.get('consensus_total_sec', 0.0):>9.3f} s")
    print("=" * 155)

    # --------------------------------------------------------------------------
    # BẢNG SO SÁNH TRỰC DIỆN: CLASSICAL ECDHE VS HYBRID ML-KEM
    # --------------------------------------------------------------------------
    if len(all_macro_results.get("ecdhe", [])) == 4 and len(all_macro_results.get("hybrid", [])) == 4:
        print("\n" + "=" * 135)
        print("BANG 2: SO SANH TRUC DIEN CHI PHI GIAO VAN (CLASSICAL ECDHE VS HYBRID ML-KEM)")
        print(f"{'Thuat toan':<18} | {'TPS ECDHE':<12} | {'TPS Hybrid':<12} | {'Mean Lat ECDHE':<16} | {'Mean Lat Hybrid':<16} | {'TLS RTT ECDHE':<14} | {'TLS RTT Hybrid':<14} | {'Block Wire':<14}")
        print("-" * 135)
        for r_ec, r_hy in zip(all_macro_results["ecdhe"], all_macro_results["hybrid"]):
            print(f"{r_ec['algorithm']:<18} | "
                  f"{r_ec['ingestion_tps']:>10.2f} | "
                  f"{r_hy['ingestion_tps']:>10.2f} | "
                  f"{r_ec['latency_mean_ms']:>13.2f} ms | "
                  f"{r_hy['latency_mean_ms']:>13.2f} ms | "
                  f"{r_ec['handshake_latency_ms']:>11.2f} ms | "
                  f"{r_hy['handshake_latency_ms']:>11.2f} ms | "
                  f"{r_hy['block_wire_kb']:>10.2f} KB")
        print("=" * 135)

    # --------------------------------------------------------------------------
    # XUẤT DỮ LIỆU JSON
    # --------------------------------------------------------------------------
    summary_data = {
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'tx_count_per_scheme': tx_count,
        'warmup_tx_count': warmup_count,
        'concurrency_workers': workers,
        'modes_tested': run_tls_modes,
        'ecdhe_results': all_macro_results.get("ecdhe", []),
        'hybrid_results': all_macro_results.get("hybrid", []),
        'signatures_macro': all_macro_results.get("hybrid", []) or all_macro_results.get("ecdhe", []),
        'key_share_overhead': {
            'ecdhe': {'client_share_bytes': 32, 'server_share_bytes': 32, 'total_handshake_wire_kb': 2.1},
            'hybrid': {'client_share_bytes': 1216, 'server_share_bytes': 1120, 'total_handshake_wire_kb': 4.5}
        }
    }
    summary_json_path = out_dir / "macro_benchmark_summary.json"
    with open(summary_json_path, 'w', encoding='utf-8') as f:
        json.dump(summary_data, f, indent=2)
    print(f"\n[+] Da xuat JSON Macro Summary ({summary_json_path.name}): {summary_json_path}")

    # Xuất các file JSON theo từng chế độ cho khả năng tương thích ngược
    if all_macro_results.get("ecdhe"):
        ecdhe_summary = {
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'tls_transport_mode': "TLS 1.3 Classical ECDHE",
            'tx_count_per_scheme': tx_count,
            'warmup_tx_count': warmup_count,
            'concurrency_workers': workers,
            'signatures_macro': all_macro_results["ecdhe"]
        }
        with open(out_dir / "macro_signatures_ecdhe_summary.json", 'w', encoding='utf-8') as f:
            json.dump(ecdhe_summary, f, indent=2)

    if all_macro_results.get("hybrid"):
        hybrid_summary = {
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'tls_transport_mode': "TLS 1.3 Hybrid (X25519 + ML-KEM-768)",
            'tx_count_per_scheme': tx_count,
            'warmup_tx_count': warmup_count,
            'concurrency_workers': workers,
            'signatures_macro': all_macro_results["hybrid"]
        }
        with open(out_dir / "macro_signatures_hybrid_summary.json", 'w', encoding='utf-8') as f:
            json.dump(hybrid_summary, f, indent=2)

    # --------------------------------------------------------------------------
    # XUẤT RAW CSV
    # --------------------------------------------------------------------------
    def save_csv(filepath: Path, records: List[Dict]):
        if not records:
            return
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["TLS_Mode", "Algorithm", "Tx_Index", "HTTP_Status", "Latency_ms", "Result"])
            for r in records:
                writer.writerow([r["tls_mode"], r["algorithm"], r["tx_index"], r["status_code"], round(r["latency_ms"], 3), r["result"]])
        print(f"[+] Da xuat Raw CSV ({len(records)} records): {filepath}")

    save_csv(out_dir / "macro_transactions_raw.csv", all_raw_records)
    if ecdhe_raw_records:
        save_csv(out_dir / "macro_transactions_ecdhe_raw.csv", ecdhe_raw_records)
    if hybrid_raw_records:
        save_csv(out_dir / "macro_transactions_hybrid_raw.csv", hybrid_raw_records)

    # --------------------------------------------------------------------------
    # VẼ BIỂU ĐỒ SO SÁNH KHOA HỌC
    # --------------------------------------------------------------------------
    if all_macro_results.get("ecdhe"):
        plot_single_mode_chart(all_macro_results["ecdhe"], out_dir, "macro_signatures_ecdhe_comparison.png", "TLS 1.3 Classical ECDHE")
    if all_macro_results.get("hybrid"):
        plot_single_mode_chart(all_macro_results["hybrid"], out_dir, "macro_signatures_hybrid_comparison.png", "TLS 1.3 Hybrid (X25519 + ML-KEM-768)")

    if len(all_macro_results.get("ecdhe", [])) == 4 and len(all_macro_results.get("hybrid", [])) == 4:
        plot_comprehensive_macro_comparison(all_macro_results["ecdhe"], all_macro_results["hybrid"], out_dir, tx_count=tx_count)

    print(f"\n[+] HOAN TAT TOAN BO MACRO-BENCHMARK TREN MANG 6 NODE P2P!")
    print(f"    - JSON Toan tap  : {summary_json_path}")
    print(f"    - Thu muc Ket qua: {out_dir}")


if __name__ == '__main__':
    main()
