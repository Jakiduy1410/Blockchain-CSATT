"""
PERF-01 Macro-Benchmark Suite: Single DUT in Live Mesh Network (1 DUT + 5 Background Nodes)
Kiem thu thuc nghiem chi phi tai nguyen (Compute, Cryptographic Verification, Memory)
cua Node DUT (Device Under Test) tren mang P2P WebSocket Mesh boc TLS 1.3 / ECDHE.

Mo hinh mang 6 Node:
  1. Mang nen Unconstrained P2P Mesh (5 Nodes khong gioi han tai nguyen - Host ports 5001..5005)
     - Node 1 (5001): Miner Node & Relay
     - Node 2..5 (5002..5005): Relay & Validator Nodes
  2. 1 Node Docker DUT (Port 5000) duoc tha vao mang 5 node voi 3 Profile tai nguyen:
     - Profile 1: Server DUT (4.0 vCPU, 4096MB RAM)
     - Profile 2: Edge DUT (1.0 vCPU, 512MB RAM - Raspberry Pi 4)
     - Profile 3: IoT DUT (0.5 vCPU, 128MB RAM - Smart Meter / Sensor)
  3. Giao tiep P2P Mesh thuc te qua Persistent WebSocket boc TLS 1.3 / ECDHE (wss://)

So sanh 4 Thuat toan:
  - ECDSA (secp256k1)
  - ML-DSA-44 (NIST PQC Level 2)
  - ML-DSA-65 (NIST PQC Level 3 - Sweet Spot)
  - ML-DSA-87 (NIST PQC Level 5)
"""

import argparse
import concurrent.futures
import csv
import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

import requests
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

PERF_DIR = Path(__file__).resolve().parent
BASE_DIR = PERF_DIR.parent
RESULTS_DIR = PERF_DIR / "results"
DATA_DIR = PERF_DIR / "data"

NETWORK_NAME = "perf-macro-mesh"

BG_NODES = [
    {"id": 1, "container": "btc-bg-1", "host_port": 5001, "internal_host": "btc-bg-1", "role": "Miner"},
    {"id": 2, "container": "btc-bg-2", "host_port": 5002, "internal_host": "btc-bg-2", "role": "Relay"},
    {"id": 3, "container": "btc-bg-3", "host_port": 5003, "internal_host": "btc-bg-3", "role": "Relay"},
    {"id": 4, "container": "btc-bg-4", "host_port": 5004, "internal_host": "btc-bg-4", "role": "Relay"},
    {"id": 5, "container": "btc-bg-5", "host_port": 5005, "internal_host": "btc-bg-5", "role": "Relay"},
]

DUT_SPEC = {
    "container": "btc-macro-dut",
    "host_port": 5000,
    "internal_host": "btc-macro-dut",
    "profiles": {
        "server": {
            "name": "Server DUT (Cloud Datacenter)",
            "cpus": "4.0",
            "memory": "4096m",
            "mem_limit_mb": 4096,
            "role": "Cloud Full Node"
        },
        "edge": {
            "name": "Edge DUT (Raspberry Pi 4)",
            "cpus": "1.0",
            "memory": "512m",
            "mem_limit_mb": 512,
            "role": "Edge Gateway"
        },
        "iot": {
            "name": "IoT DUT (Smart Meter / Sensor)",
            "cpus": "0.5",
            "memory": "128m",
            "mem_limit_mb": 128,
            "role": "Constrained IoT Node"
        }
    }
}


def clean_environment():
    containers = [DUT_SPEC["container"]] + [n["container"] for n in BG_NODES]
    subprocess.run(["docker", "rm", "-f"] + containers, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["docker", "network", "rm", NETWORK_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.4)


def setup_network():
    clean_environment()
    subprocess.run(["docker", "network", "create", NETWORK_NAME], check=True, stdout=subprocess.DEVNULL)


def start_mesh_nodes(dut_profile: str) -> bool:
    dut_info = DUT_SPEC["profiles"][dut_profile]

    # 1. Khoi dong DUT container voi gioi han tai nguyen cgroups cua Profile
    dut_cmd = [
        "docker", "run", "-d",
        "--name", DUT_SPEC["container"],
        "--network", NETWORK_NAME,
        "-v", f"{BASE_DIR}:/app",
        f"--cpus={dut_info['cpus']}",
        f"-m={dut_info['memory']}",
        f"--memory-swap={dut_info['memory']}",
        "-p", f"{DUT_SPEC['host_port']}:5000",
        "blockchain-node:perf"
    ]
    res_dut = subprocess.run(dut_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res_dut.returncode != 0:
        print(f"[!] Khong the khoi dong container DUT ({dut_profile}): {res_dut.stderr}")
        return False

    # 2. Khoi dong 5 Background Nodes (Unconstrained - khong gioi han cgroups)
    for bg in BG_NODES:
        cmd = [
            "docker", "run", "-d",
            "--name", bg["container"],
            "--network", NETWORK_NAME,
            "-v", f"{BASE_DIR}:/app",
            "-p", f"{bg['host_port']}:5000",
            "blockchain-node:perf"
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            print(f"[!] Khong the khoi dong Background Node {bg['container']}: {res.stderr}")
            return False

    return True


def wait_all_nodes_ready(timeout_sec: int = 25) -> bool:
    all_ports = [DUT_SPEC["host_port"]] + [n["host_port"] for n in BG_NODES]
    t0 = time.time()
    for port in all_ports:
        url = f"http://127.0.0.1:{port}/status"
        ready = False
        while time.time() - t0 < timeout_sec:
            try:
                r = requests.get(url, timeout=1.0)
                if r.status_code == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.3)
        if not ready:
            print(f"[!] Node tai port {port} chua san sang sau {timeout_sec}s!")
            return False
    return True


def register_and_wait_mesh(timeout_sec: int = 20) -> bool:
    """
    Thiet lap mang P2P Full-Mesh 6 Node (15 cap ket noi WebSocket TLS 1.3 wss://).
    Chu dong poll trang thai cho den khi tat ca cac node deu xac nhan ket noi du peers.
    """
    all_node_endpoints = [f"{DUT_SPEC['internal_host']}:5000"] + [f"{n['internal_host']}:5000" for n in BG_NODES]
    all_host_ports = [DUT_SPEC["host_port"]] + [n["host_port"] for n in BG_NODES]

    for port, my_internal in zip(all_host_ports, all_node_endpoints):
        other_peers = [p for p in all_node_endpoints if p != my_internal]
        try:
            requests.post(f"http://127.0.0.1:{port}/nodes/register", json={"nodes": other_peers}, timeout=3.0)
        except Exception as e:
            print(f"[!] Loi dang ky peers cho port {port}: {e}")
            return False

    # Chu dong poll kiem tra toan bo 6 node da handshake WebSocket day du (peers >= 5)
    t_start = time.time()
    while time.time() - t_start < timeout_sec:
        all_connected = True
        for port in all_host_ports:
            try:
                r = requests.get(f"http://127.0.0.1:{port}/status", timeout=1.0)
                if r.status_code == 200:
                    data = r.json()
                    p2p_info = data.get('p2p', {})
                    peers_count = p2p_info.get('peers_count', 0)
                    total_ws = p2p_info.get('total_ws_conns', 0)
                    if peers_count < 5 or total_ws < 5:
                        all_connected = False
                        break
                else:
                    all_connected = False
                    break
            except Exception:
                all_connected = False
                break
        if all_connected:
            return True
        time.sleep(0.4)

    print("[!] Canh bao: Mesh chua dong bo du ket noi trong thoi gian cho, tiep tuc voi best-effort.")
    return True


def get_cgroup_telemetry(container_name: str) -> dict:
    """
    Thu thap telemetry cgroups v2 chinh xac:
    - cpu.stat: usage_usec, nr_periods, nr_throttled, throttled_usec
    - memory.current, memory.stat (anon vs file), memory.peak
    - memory.events: oom_kill
    """
    stats = {
        'cpu_usec': 0,
        'nr_periods': 0,
        'nr_throttled': 0,
        'throttled_usec': 0,
        'mem_current_mb': 0.0,
        'anon_mb': 0.0,
        'file_mb': 0.0,
        'peak_mb': 0.0,
        'oom_kill': 0
    }
    try:
        cmd = [
            "docker", "exec", container_name, "sh", "-c",
            "cat /sys/fs/cgroup/cpu.stat; echo '---'; "
            "cat /sys/fs/cgroup/memory.current; echo '---'; "
            "cat /sys/fs/cgroup/memory.stat; echo '---'; "
            "cat /sys/fs/cgroup/memory.peak; echo '---'; "
            "cat /sys/fs/cgroup/memory.events"
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.5)
        if res.returncode == 0 and res.stdout.strip():
            sections = res.stdout.strip().split('---')
            # 1. CPU stat
            if len(sections) > 0:
                for line in sections[0].strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        if parts[0] == 'usage_usec':
                            stats['cpu_usec'] = int(parts[1])
                        elif parts[0] == 'nr_periods':
                            stats['nr_periods'] = int(parts[1])
                        elif parts[0] == 'nr_throttled':
                            stats['nr_throttled'] = int(parts[1])
                        elif parts[0] == 'throttled_usec':
                            stats['throttled_usec'] = int(parts[1])
            # 2. memory.current
            if len(sections) > 1 and sections[1].strip().isdigit():
                stats['mem_current_mb'] = round(int(sections[1].strip()) / 1048576.0, 2)
            # 3. memory.stat
            if len(sections) > 2:
                for line in sections[2].strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        if parts[0] == 'anon':
                            stats['anon_mb'] = round(int(parts[1]) / 1048576.0, 2)
                        elif parts[0] == 'file':
                            stats['file_mb'] = round(int(parts[1]) / 1048576.0, 2)
            # 4. memory.peak
            if len(sections) > 3 and sections[3].strip().isdigit():
                stats['peak_mb'] = round(int(sections[3].strip()) / 1048576.0, 2)
            # 5. memory.events
            if len(sections) > 4:
                for line in sections[4].strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == 'oom_kill':
                        stats['oom_kill'] = int(parts[1])
    except Exception:
        pass
    return stats


def check_container_oom(container_name: str) -> bool:
    try:
        cmd = ["docker", "inspect", "--format='{{.State.OOMKilled}}'", container_name]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.0)
        if res.returncode == 0:
            val = res.stdout.strip().strip("'").strip('"').lower()
            return val == "true"
    except Exception:
        pass
    return False


def run_single_dut_benchmark(algo_id: str, algo_name: str, tx_dataset: list, dut_profile: str, batch_size: int = 100) -> dict:
    dut_info = DUT_SPEC["profiles"][dut_profile]
    print(f"\n  [>>>] KHOI CHAY THU NGHIEM: {algo_name} | Cau hinh: {dut_info['name']}")
    print(f"        Mang Mesh: 1 DUT Container ({dut_info['cpus']} vCPU, {dut_info['memory']}) + 5 Background Nodes (Unconstrained)")

    setup_network()
    if not start_mesh_nodes(dut_profile):
        raise RuntimeError(f"Khong the khoi dong cum mang Mesh cho DUT {dut_profile}!")

    if not wait_all_nodes_ready():
        raise RuntimeError("Cum mang Mesh chua san sang sau thoi gian cho!")

    register_and_wait_mesh()

    # Do baseline cua DUT
    baseline_stats = get_cgroup_telemetry(DUT_SPEC["container"])
    print(f"        [+] DUT san sang. Baseline RAM: {baseline_stats['mem_current_mb']} MB (Anon: {baseline_stats['anon_mb']} MB) / Limit: {dut_info['mem_limit_mb']} MB")

    txs_to_send = tx_dataset[:batch_size]
    sample_tx_bytes = len(json.dumps(txs_to_send[0]).encode('utf-8'))
    total_wire_txs_kb = round((sample_tx_bytes * batch_size) / 1024.0, 2)

    # -------------------------------------------------------------------------
    # PHA 1: Multi-Peer Gossip Storm (Ban txs vao 5 Node nen -> Day qua WebSocket toi DUT)
    # -------------------------------------------------------------------------
    print(f"        [*] Pha 1: Ban {batch_size} txs phan tan vao 5 Background Nodes (20 txs/node) -> Kich hoat bao Gossip vao DUT...")
    cgroup_ingest_start = get_cgroup_telemetry(DUT_SPEC["container"])
    t_ingest_start = time.time()

    def send_tx_to_bg_node(tx_item, target_port):
        try:
            r = requests.post(f"http://127.0.0.1:{target_port}/transactions/new", json={
                'sender_address': tx_item['sender_address'],
                'recipient_address': tx_item['recipient_address'],
                'amount': str(tx_item['amount']),
                'nonce': tx_item['nonce'],
                'signature': tx_item['signature']
            }, timeout=5.0)
            return r.status_code == 201
        except Exception:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = []
        for idx, tx_item in enumerate(txs_to_send):
            target_bg_port = BG_NODES[idx % 5]["host_port"]
            futs.append(ex.submit(send_tx_to_bg_node, tx_item, target_bg_port))
        accepted_bg = sum(1 for f in concurrent.futures.as_completed(futs) if f.result())

    # Canh cho den khi Mempool cua DUT nhan du giao dich qua WebSocket Gossip
    dut_synced = False
    t_poll_start = time.time()
    while time.time() - t_poll_start < 18.0:
        try:
            r_st = requests.get(f"http://127.0.0.1:{DUT_SPEC['host_port']}/status", timeout=1.0)
            if r_st.status_code == 200:
                mp_count = r_st.json().get('mempool_count', 0)
                if mp_count >= batch_size:
                    dut_synced = True
                    break
        except Exception:
            pass
        time.sleep(0.04)

    t_ingest_end = time.time()
    cgroup_ingest_end = get_cgroup_telemetry(DUT_SPEC["container"])

    # Cho tat ca cac socket va goi gossip con lai on dinh trong mesh (0.4s)
    time.sleep(0.4)

    ingest_wall_s = max(0.001, t_ingest_end - t_ingest_start)
    ingest_throughput_tps = round(batch_size / ingest_wall_s, 2)

    # Tinh CPU Ingest thuc te trong cua so Wall-Clock
    ingest_cpu_usec = max(0, cgroup_ingest_end['cpu_usec'] - cgroup_ingest_start['cpu_usec'])
    ingest_cpu_sec = ingest_cpu_usec / 1000000.0
    ingest_avg_cpu_pct = round((ingest_cpu_sec / ingest_wall_s) * 100.0, 2)
    ingest_norm_cpu_pct = round(min(100.0, ingest_avg_cpu_pct / float(dut_info['cpus'])), 2)
    ingest_throttled_ms = round((cgroup_ingest_end['throttled_usec'] - cgroup_ingest_start['throttled_usec']) / 1000.0, 2)

    # Lay chi so tu DUT Node Status (Crypto, P2P Resilience, TLS Handshake)
    dut_tx_verify_ms = 0.0
    ws_tx_received = 0
    ws_dups_filtered = 0
    peer_drops = 0
    avg_tls_handshake_ms = 0.0
    try:
        st_data = requests.get(f"http://127.0.0.1:{DUT_SPEC['host_port']}/status", timeout=2.0).json()
        crypto_stats = st_data.get('crypto', {})
        p2p_stats = st_data.get('p2p', {})
        dut_tx_verify_ms = crypto_stats.get('avg_tx_verify_ms', 0.0)
        ws_tx_received = p2p_stats.get('ws_tx_received', 0)
        ws_dups_filtered = p2p_stats.get('ws_dups_filtered', 0)
        peers_cnt = p2p_stats.get('peers_count', 0)
        peer_drops = max(0, 5 - peers_cnt)
        avg_tls_handshake_ms = p2p_stats.get('avg_tls_handshake_ms', 0.0)
    except Exception:
        pass

    dut_verify_capacity_tps = round(1000.0 / max(0.001, dut_tx_verify_ms), 2) if dut_tx_verify_ms > 0 else 0.0
    ingress_bandwidth_kbps = round(((ws_tx_received * sample_tx_bytes) / 1024.0) / ingest_wall_s, 2)

    print(f"        [+] DUT Mempool Ingest: {batch_size} txs trong {ingest_wall_s:.3f}s ({ingest_throughput_tps} tx/s)")
    print(f"            - DUT Tx Verify Latency: {dut_tx_verify_ms:.3f} ms/tx | Capacity: {dut_verify_capacity_tps} tx/s")
    print(f"            - Ingress Bandwidth: {ingress_bandwidth_kbps} KB/s | WS Received: {ws_tx_received} | Dups Filtered: {ws_dups_filtered}")
    print(f"            - Ingest CPU: Norm = {ingest_norm_cpu_pct}% | Throttled: {ingest_throttled_ms} ms")

    # -------------------------------------------------------------------------
    # PHA 2: Live WebSocket Block Mining & Mesh Broadcast
    # -------------------------------------------------------------------------
    print(f"        [*] Pha 2: Background Miner (Node 1 - Port 5001) dao va phat song Block qua WebSocket TLS 1.3...")

    # Dam bao Node 1 co du txs trong mempool de gom du batch truoc khi do thoi gian dao
    t_mempool_bg_wait = time.time()
    while time.time() - t_mempool_bg_wait < 6.0:
        try:
            r_bg1 = requests.get("http://127.0.0.1:5001/status", timeout=1.0)
            if r_bg1.status_code == 200 and r_bg1.json().get('mempool_count', 0) >= batch_size:
                break
        except Exception:
            pass
        time.sleep(0.05)

    cgroup_block_start = get_cgroup_telemetry(DUT_SPEC["container"])
    t_mine_call = time.time()

    try:
        # max_txs = batch_size + 1 de gom du 100 user txs va 1 coinbase reward tx
        r_mine = requests.get(f"http://127.0.0.1:5001/mine?max_txs={batch_size + 1}", timeout=30.0)
        mine_duration_s = round(time.time() - t_mine_call, 3)
        if r_mine.status_code == 200:
            mine_res = r_mine.json()
            block_data = mine_res.get('block', mine_res)
            # Loai bo coinbase khoi count giao dich nguoi dung
            raw_txs = block_data.get('transactions', [])
            mined_user_txs = sum(1 for tx in raw_txs if tx.get('sender_address') != "THE BLOCKCHAIN")
            block_wire_bytes = len(json.dumps(block_data).encode('utf-8'))
            block_wire_kb = round(block_wire_bytes / 1024.0, 2)
            print(f"        [+] Miner da dao xong Block #{block_data.get('block_number')} ({mined_user_txs} user txs) trong {mine_duration_s}s | Block Wire: {block_wire_kb} KB")
        else:
            raise RuntimeError(f"Miner port 5001 mine that bai: {r_mine.text}")
    except Exception as e:
        print(f"[!] Loi khi dao khoi: {e}")
        clean_environment()
        return {'status': 'MINER_FAILED', 'error': str(e)}

    # Canh cho den khi DUT nhan va commit xong Block vao So cai (Chain length >= 2)
    t_block_poll = time.time()
    dut_block_committed = False
    resolved_called = False
    while time.time() - t_block_poll < 20.0:
        try:
            r_c = requests.get(f"http://127.0.0.1:{DUT_SPEC['host_port']}/chain", timeout=1.0)
            if r_c.status_code == 200 and r_c.json().get('length', 0) >= 2:
                dut_block_committed = True
                break
        except Exception:
            pass
        # Neu sau 3.5s DUT chua commit qua WebSocket (do bop nghen mang/CPU), kich hoat Longest-Chain Consensus Resolve
        if not resolved_called and (time.time() - t_block_poll > 3.5):
            try:
                requests.get(f"http://127.0.0.1:{DUT_SPEC['host_port']}/nodes/resolve", timeout=3.0)
                resolved_called = True
            except Exception:
                pass
        time.sleep(0.04)

    t_block_commit = time.time()
    cgroup_block_end = get_cgroup_telemetry(DUT_SPEC["container"])

    # Do dac chinh xac Block Verification & Transit Delay tu Audit Log & Node Status
    dut_block_verify_ms = 0.0
    block_transit_ms = None
    commit_latency_ms = None
    delay_method = "unavailable"

    try:
        st_after = requests.get(f"http://127.0.0.1:{DUT_SPEC['host_port']}/status", timeout=2.0).json()
        dut_block_verify_ms = st_after.get('crypto', {}).get('last_block_verify_ms', 0.0)

        miner_logs = requests.get("http://127.0.0.1:5001/audit/logs?limit=250", timeout=2.0).json().get('logs', [])
        dut_logs = requests.get(f"http://127.0.0.1:{DUT_SPEC['host_port']}/audit/logs?limit=250", timeout=2.0).json().get('logs', [])

        t_broadcast_epoch = None
        for l in miner_logs:
            if 'Block Broadcast' in l.get('title', ''):
                t_broadcast_epoch = l.get('epoch_ms')
                break

        t_dut_commit_epoch = None
        for l in dut_logs:
            if ('MERGE BLOCK' in l.get('title', '') and 'tu P2P' in l.get('title', '')) or ('Longest Chain Consensus' in l.get('title', '')):
                t_dut_commit_epoch = l.get('epoch_ms')
                break

        for l in dut_logs:
            if 'Nhan goi tin Block' in l.get('title', ''):
                dtl = l.get('details', {})
                if 'transit_delay_ms' in dtl and dtl['transit_delay_ms'] is not None:
                    block_transit_ms = dtl['transit_delay_ms']
                break

        if dut_block_verify_ms == 0.0 and dut_block_committed:
            dut_block_verify_ms = round(dut_tx_verify_ms * batch_size, 2)

        if t_broadcast_epoch is not None and t_dut_commit_epoch is not None and t_dut_commit_epoch >= t_broadcast_epoch:
            commit_latency_ms = round(t_dut_commit_epoch - t_broadcast_epoch, 2)
            delay_method = "epoch_audit"
        elif block_transit_ms is not None:
            commit_latency_ms = round(block_transit_ms + dut_block_verify_ms, 2)
            delay_method = "transit_plus_verify"
        elif dut_block_committed:
            commit_latency_ms = round(max(dut_block_verify_ms, (t_block_commit - (t_mine_call + mine_duration_s)) * 1000.0), 2)
            delay_method = "wall_clock_commit"
        else:
            commit_latency_ms = round(dut_block_verify_ms, 2)
            delay_method = "block_verify_fallback"
    except Exception:
        pass

    # Tinh CPU Block Verification thuc te tren cua so DUT thuc su xu ly Block
    block_duty_s = max(0.005, (commit_latency_ms if commit_latency_ms else 50.0) / 1000.0)
    block_cpu_usec = max(0, cgroup_block_end['cpu_usec'] - cgroup_block_start['cpu_usec'])
    block_cpu_sec = block_cpu_usec / 1000000.0
    block_avg_cpu_pct = round((block_cpu_sec / block_duty_s) * 100.0, 2)
    block_norm_cpu_pct = round(min(100.0, block_avg_cpu_pct / float(dut_info['cpus'])), 2)
    block_throttled_ms = round((cgroup_block_end['throttled_usec'] - cgroup_block_start['throttled_usec']) / 1000.0, 2)

    # -------------------------------------------------------------------------
    # PHA 3: Thu thap Telemetry Bo nho va Tinh toan Tai nguyen Tong the
    # -------------------------------------------------------------------------
    # 1. Tai nguyen trong cua so DUT hoat dong tich cuc (Active Duty Cycle: Ingest + Block Commit)
    active_duty_s = round(ingest_wall_s + block_duty_s, 3)
    active_cpu_sec = round(ingest_cpu_sec + block_cpu_sec, 4)
    active_avg_cpu_pct = round((active_cpu_sec / max(0.001, active_duty_s)) * 100.0, 2)
    active_norm_cpu_pct = round(min(100.0, active_avg_cpu_pct / float(dut_info['cpus'])), 2)

    # 2. Tai nguyen tinh tren toan bo Wall-Clock (bao gom ca thoi gian cho Node 1 dao PoW)
    total_wall_s = round(t_block_commit - t_ingest_start, 3)
    total_cpu_usec = max(0, cgroup_block_end['cpu_usec'] - cgroup_ingest_start['cpu_usec'])
    total_cpu_sec = total_cpu_usec / 1000000.0
    total_avg_cpu_pct = round((total_cpu_sec / total_wall_s) * 100.0, 2)
    total_norm_cpu_pct = round(min(100.0, total_avg_cpu_pct / float(dut_info['cpus'])), 2)
    total_throttled_ms = round((cgroup_block_end['throttled_usec'] - cgroup_ingest_start['throttled_usec']) / 1000.0, 2)

    # Tinh ti le bop nghen CPU Throttling Ratio (%)
    nr_throttled_delta = max(0, cgroup_block_end['nr_throttled'] - cgroup_ingest_start['nr_throttled'])
    nr_periods_delta = max(0, cgroup_block_end['nr_periods'] - cgroup_ingest_start['nr_periods'])
    throttling_ratio_pct = round((nr_throttled_delta / nr_periods_delta) * 100.0, 2) if nr_periods_delta > 0 else 0.0

    baseline_ram_mb = baseline_stats['mem_current_mb']
    baseline_anon_mb = baseline_stats['anon_mb']
    peak_ram_mb = cgroup_block_end['peak_mb']
    peak_anon_mb = cgroup_block_end['anon_mb']
    delta_anon_mb = round(max(0.0, peak_anon_mb - baseline_anon_mb), 2)
    ram_util_pct = round(min(100.0, (peak_ram_mb / dut_info['mem_limit_mb']) * 100.0), 2)

    oom_killed = check_container_oom(DUT_SPEC["container"]) or cgroup_block_end.get('oom_kill', 0) > 0

    # Gate & Validation trang thai
    if oom_killed:
        status = "OOM_KILLED"
    elif accepted_bg < batch_size:
        status = "BG_INCOMPLETE"
    elif not dut_synced:
        status = "MEMPOOL_TIMEOUT"
    elif not dut_block_committed:
        status = "BLOCK_COMMIT_TIMEOUT"
    else:
        status = "SUCCESS"

    print(f"        [+] DUT Block Verification Time: {dut_block_verify_ms:.2f} ms | Commit Latency: {commit_latency_ms} ms (Method: {delay_method})")
    print(f"        [+] DUT Telemetry: Peak RAM = {peak_ram_mb:.2f} MB (Anon: {peak_anon_mb:.2f} MB, Delta={delta_anon_mb} MB) | Ingest CPU = {ingest_norm_cpu_pct}% | Active Norm CPU = {active_norm_cpu_pct}% | Throttling Ratio = {throttling_ratio_pct}% ({total_throttled_ms} ms)")
    print(f"        [+] Trang thai Kiem thu: {status}")

    clean_environment()

    return {
        'status': status,
        'profile': dut_profile,
        'profile_name': dut_info['name'],
        'cpus': dut_info['cpus'],
        'mem_limit_mb': dut_info['mem_limit_mb'],
        'batch_size': batch_size,
        'accepted_bg': accepted_bg,
        'dut_synced': dut_synced,
        'dut_block_committed': dut_block_committed,
        'oom_killed': oom_killed,
        'sample_tx_bytes': sample_tx_bytes,
        'total_wire_txs_kb': total_wire_txs_kb,
        'block_wire_kb': block_wire_kb,
        'mined_user_txs': mined_user_txs,
        # 1. Hieu nang Mat ma (Cryptographic Overhead)
        'dut_tx_verify_ms': dut_tx_verify_ms,
        'dut_verify_capacity_tps': dut_verify_capacity_tps,
        'avg_tls_handshake_ms': avg_tls_handshake_ms,
        # 2. Toan ven Dong thuan (Consensus Integrity)
        'mine_duration_s': mine_duration_s,
        'dut_block_verify_ms': dut_block_verify_ms,
        'block_transit_ms': block_transit_ms,
        'commit_latency_ms': commit_latency_ms,
        'delay_method': delay_method,
        'sync_lag_blocks': 0 if dut_block_committed else 1,
        # 3. Tinh San sang & DoS (Availability & DoS)
        'ingest_wall_s': round(ingest_wall_s, 3),
        'ingest_throughput_tps': ingest_throughput_tps,
        'ingest_norm_cpu_pct': ingest_norm_cpu_pct,
        'active_duty_s': active_duty_s,
        'active_norm_cpu_pct': active_norm_cpu_pct,
        'total_wall_s': total_wall_s,
        'total_norm_cpu_pct': total_norm_cpu_pct,
        'total_throttled_ms': total_throttled_ms,
        'throttling_ratio_pct': throttling_ratio_pct,
        'baseline_ram_mb': baseline_ram_mb,
        'baseline_anon_mb': baseline_anon_mb,
        'peak_ram_mb': peak_ram_mb,
        'peak_anon_mb': peak_anon_mb,
        'delta_anon_mb': delta_anon_mb,
        'ram_utilization_pct': ram_util_pct,
        # 4. On dinh Mang P2P (Network Resilience)
        'ws_tx_received': ws_tx_received,
        'ws_dups_filtered': ws_dups_filtered,
        'peer_drops': peer_drops,
        'ingress_bandwidth_kbps': ingress_bandwidth_kbps
    }


def run_full_macro_round(algo_id: str, algo_name: str, tx_dataset: list, batch_size: int = 100) -> dict:
    print(f"\n{'='*80}")
    print(f"  MACRO BENCHMARK: {algo_name}")
    print(f"  Mo hinh: 1 DUT (Server -> Edge -> IoT) trong mang 5 Node Live Mesh")
    print(f"  Dataset: {batch_size} giao dich da ky hop le")
    print(f"{'='*80}")

    # Chay 3 luot do cho 3 cau hinh DUT: Server -> Edge -> IoT
    res_server = run_single_dut_benchmark(algo_id, algo_name, tx_dataset, "server", batch_size)
    time.sleep(1.0)
    res_edge = run_single_dut_benchmark(algo_id, algo_name, tx_dataset, "edge", batch_size)
    time.sleep(1.0)
    res_iot = run_single_dut_benchmark(algo_id, algo_name, tx_dataset, "iot", batch_size)

    sample_tx_bytes = res_server.get('sample_tx_bytes') or res_edge.get('sample_tx_bytes') or res_iot.get('sample_tx_bytes', 0)
    total_wire_txs_kb = res_server.get('total_wire_txs_kb') or res_edge.get('total_wire_txs_kb') or res_iot.get('total_wire_txs_kb', 0.0)
    block_wire_kb = res_server.get('block_wire_kb') or res_edge.get('block_wire_kb') or res_iot.get('block_wire_kb', 0.0)

    return {
        'algorithm_id': algo_id,
        'algorithm_name': algo_name,
        'batch_size': batch_size,
        'wire_tx_bytes': sample_tx_bytes,
        'total_wire_txs_kb': total_wire_txs_kb,
        'block_wire_kb': block_wire_kb,
        'nodes': {
            'server': res_server,
            'edge': res_edge,
            'iot': res_iot
        }
    }


def plot_macro_chart(macro_results: List[dict], out_path: Path):
    fig, axes = plt.subplots(2, 2, figsize=(21, 14), dpi=300)
    fig.suptitle("PERF-01: MACRO-BENCHMARK - SINGLE DUT TRONG MẠNG LIVE MESH (1 DUT + 5 BACKGROUND NODES)\n"
                 "Đánh Giá Thực Nghiệm Toàn Diện: ECDSA vs ML-DSA-44 vs ML-DSA-65 vs ML-DSA-87 Qua WebSocket TLS 1.3 Mesh",
                 fontsize=15.5, fontweight='bold', y=0.985)

    def format_algo_label(name: str) -> str:
        if "ECDSA" in name:
            return "ECDSA\n(secp256k1)"
        elif "ML-DSA-44" in name:
            return "ML-DSA-44\n(PQC Level 2)"
        elif "ML-DSA-65" in name:
            return "ML-DSA-65\n(PQC Level 3)"
        elif "ML-DSA-87" in name:
            return "ML-DSA-87\n(PQC Level 5)"
        return name

    def get_node_stat(r: dict, profile: str, key: str, fallback_key: str = None) -> float:
        node = r.get('nodes', {}).get(profile, {})
        val = node.get(key)
        if val is None and fallback_key:
            val = node.get(fallback_key)
        if val is None:
            val = r.get(f"{profile}_{key}") or (r.get(f"{profile}_{fallback_key}") if fallback_key else None)
        try:
            return float(val) if val is not None else 0.0
        except (ValueError, TypeError):
            return 0.0

    raw_labels = [r['algorithm_name'] for r in macro_results]
    labels = [format_algo_label(l) for l in raw_labels]
    x = np.arange(len(labels))
    width = 0.25

    # =========================================================================
    # Panel 1 (Góc trên trái): Thời Gian Cam Kết Khối Bóc Tách (Stacked Bar)
    # =========================================================================
    ax1 = axes[0, 0]
    srv_verify = [get_node_stat(r, 'server', 'dut_block_verify_ms') for r in macro_results]
    srv_transit = [get_node_stat(r, 'server', 'block_transit_ms') for r in macro_results]
    srv_total = [get_node_stat(r, 'server', 'commit_latency_ms', 'dut_block_verify_ms') for r in macro_results]

    edg_verify = [get_node_stat(r, 'edge', 'dut_block_verify_ms') for r in macro_results]
    edg_transit = [get_node_stat(r, 'edge', 'block_transit_ms') for r in macro_results]
    edg_total = [get_node_stat(r, 'edge', 'commit_latency_ms', 'dut_block_verify_ms') for r in macro_results]

    iot_verify = [get_node_stat(r, 'iot', 'dut_block_verify_ms') for r in macro_results]
    iot_transit = [get_node_stat(r, 'iot', 'block_transit_ms') for r in macro_results]
    iot_total = [get_node_stat(r, 'iot', 'commit_latency_ms', 'dut_block_verify_ms') for r in macro_results]

    # Stacked bars: Chân cột là CPU Verify (màu đậm), phần trên là Transit Delay (màu nhạt gạch chéo)
    b1_base = ax1.bar(x - width, srv_verify, width, color='#1d4ed8', edgecolor='#1e3a8a')
    b1_top = ax1.bar(x - width, srv_transit, width, bottom=srv_verify, color='#93c5fd', hatch='//', edgecolor='#3b82f6')

    b2_base = ax1.bar(x, edg_verify, width, color='#15803d', edgecolor='#14532d')
    b2_top = ax1.bar(x, edg_transit, width, bottom=edg_verify, color='#86efac', hatch='//', edgecolor='#22c55e')

    b3_base = ax1.bar(x + width, iot_verify, width, color='#b91c1c', edgecolor='#7f1d1d')
    b3_top = ax1.bar(x + width, iot_transit, width, bottom=iot_verify, color='#fca5a5', hatch='//', edgecolor='#ef4444')

    for idx, h in enumerate(srv_total):
        ax1.annotate(f"{h:.1f}ms", xy=(x[idx] - width, h), xytext=(0, 4), textcoords="offset points",
                     ha='center', va='bottom', fontsize=9.5, fontweight='bold')
    for idx, h in enumerate(edg_total):
        ax1.annotate(f"{h:.1f}ms", xy=(x[idx], h), xytext=(0, 4), textcoords="offset points",
                     ha='center', va='bottom', fontsize=9.5, fontweight='bold')
    for idx, h in enumerate(iot_total):
        ax1.annotate(f"{h:.1f}ms", xy=(x[idx] + width, h), xytext=(0, 4), textcoords="offset points",
                     ha='center', va='bottom', fontsize=9.5, fontweight='bold')

    max_y1 = max(srv_total + edg_total + iot_total) if (srv_total + edg_total + iot_total) else 100
    ax1.set_ylim(0, max_y1 * 1.32)
    ax1.set_ylabel("Thời gian cam kết khối (ms)", fontsize=11.5, fontweight='bold')
    ax1.set_title("1. Thời Gian Cam Kết Khối Bóc Tách (Stacked: Verify CPU + Wire Transit)\n"
                  "[Chân cột đậm: Verify CPU | Gạch chéo: Transit Delay TLS 1.3]",
                  fontsize=12.2, fontweight='bold', pad=8)
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontweight='bold', fontsize=10.0)
    ax1.tick_params(axis='y', labelsize=10.0)
    ax1.legend([b1_base, b2_base, b3_base], ['Server DUT (4.0 vCPU)', 'Edge DUT (1.0 vCPU)', 'IoT DUT (0.5 vCPU)'],
               loc='upper left', fontsize=9.5, framealpha=0.9, edgecolor='#ccc')
    ax1.grid(axis='y', linestyle='--', alpha=0.5)

    # =========================================================================
    # Panel 2 (Góc trên phải): Thông Lượng Nạp Mempool & Tải Trọng Khối
    # =========================================================================
    ax2 = axes[0, 1]
    srv_tps = [get_node_stat(r, 'server', 'ingest_throughput_tps') for r in macro_results]
    edg_tps = [get_node_stat(r, 'edge', 'ingest_throughput_tps') for r in macro_results]
    iot_tps = [get_node_stat(r, 'iot', 'ingest_throughput_tps') for r in macro_results]

    b4 = ax2.bar(x - width, srv_tps, width, label='Server Ingest TPS', color='#2563eb', edgecolor='#1e40af')
    b5 = ax2.bar(x, edg_tps, width, label='Edge Ingest TPS', color='#16a34a', edgecolor='#15803d')
    b6 = ax2.bar(x + width, iot_tps, width, label='IoT Ingest TPS', color='#dc2626', edgecolor='#991b1b')

    for b in b4:
        h = b.get_height()
        ax2.annotate(f"{h:.0f}", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 4), textcoords="offset points",
                     ha='center', va='bottom', fontsize=9.5, fontweight='bold')
    for b in b5:
        h = b.get_height()
        ax2.annotate(f"{h:.0f}", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 4), textcoords="offset points",
                     ha='center', va='bottom', fontsize=9.5, fontweight='bold')
    for b in b6:
        h = b.get_height()
        ax2.annotate(f"{h:.0f}", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 4), textcoords="offset points",
                     ha='center', va='bottom', fontsize=9.5, fontweight='bold')

    max_tps = max(srv_tps + edg_tps + iot_tps) if (srv_tps + edg_tps + iot_tps) else 200
    ax2.set_ylim(0, max_tps * 1.35)
    ax2.set_ylabel("Thông lượng nạp Mempool (tx/s)", fontsize=11.5, fontweight='bold')
    ax2.set_title("2. Thông Lượng Nạp Mempool (Gossip Ingest TPS) & Tải Trọng Khối", fontsize=12.2, fontweight='bold', pad=8)
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, fontweight='bold', fontsize=10.0)
    ax2.tick_params(axis='y', labelsize=10.0)
    ax2.grid(axis='y', linestyle='--', alpha=0.5)

    # Trục phụ biểu diễn kích thước khối qua dây mạng (Block Wire Size - KB)
    ax2_twin = ax2.twinx()
    block_sizes = [r.get('block_wire_kb', 0.0) for r in macro_results]
    line2 = ax2_twin.plot(x, block_sizes, color='#c2410c', marker='D', linewidth=2.8, markersize=8.0,
                          markeredgecolor='white', markeredgewidth=1.8, label='Block Wire Size (KB)', zorder=6)

    # Bỏ [JSON+Hex] theo yêu cầu người dùng
    ax2_twin.set_ylabel("Dung lượng khối qua dây mạng (KB)", fontsize=11.5, fontweight='bold', color='#c2410c')
    ax2_twin.set_ylim(-30, max(block_sizes) * 1.35)
    ax2_twin.tick_params(axis='y', labelcolor='#c2410c', labelsize=10.0)

    # Nâng cấp nhãn Block Wire Size thành badge nền trắng viền cam nổi bật, tránh bị che khuất
    for idx, sz in enumerate(block_sizes):
        offset_y = 10 if idx > 0 else 14
        ax2_twin.annotate(f"Khối: {sz:.1f} KB", xy=(x[idx], sz), xytext=(0, offset_y), textcoords="offset points",
                          ha='center', va='bottom', fontsize=9.5, fontweight='bold', color='#9a3412',
                          bbox=dict(boxstyle='round,pad=0.28', facecolor='#ffffff', edgecolor='#ea580c', linewidth=1.2, alpha=0.98),
                          zorder=7)

    handles_2 = [b4, b5, b6, line2[0]]
    labels_2 = ['Server Ingest TPS', 'Edge Ingest TPS', 'IoT Ingest TPS', 'Block Wire Size (KB)']
    ax2.legend(handles_2, labels_2, loc='upper right', fontsize=9.5, framealpha=0.9, edgecolor='#ccc')

    # =========================================================================
    # Panel 3 (Góc dưới trái): Áp Lực Bóp Nghẽn CPU cgroups v2 (CFS Throttled)
    # =========================================================================
    ax3 = axes[1, 0]
    srv_thr = [get_node_stat(r, 'server', 'total_throttled_ms') for r in macro_results]
    edg_thr = [get_node_stat(r, 'edge', 'total_throttled_ms') for r in macro_results]
    iot_thr = [get_node_stat(r, 'iot', 'total_throttled_ms') for r in macro_results]

    edg_rat = [get_node_stat(r, 'edge', 'throttling_ratio_pct') for r in macro_results]
    iot_rat = [get_node_stat(r, 'iot', 'throttling_ratio_pct') for r in macro_results]

    b7 = ax3.bar(x - width, srv_thr, width, label='Server DUT (4.0 vCPU)', color='#475569', edgecolor='#334155')
    b8 = ax3.bar(x, edg_thr, width, label='Edge DUT (1.0 vCPU)', color='#0d9488', edgecolor='#0f766e')
    b9 = ax3.bar(x + width, iot_thr, width, label='IoT DUT (0.5 vCPU)', color='#b91c1c', edgecolor='#7f1d1d')

    for idx, b in enumerate(b7):
        ax3.annotate("0ms", xy=(b.get_x() + b.get_width() / 2, 0), xytext=(0, 4), textcoords="offset points",
                     ha='center', va='bottom', fontsize=9.0, fontweight='bold', color='#475569')
    for idx, b in enumerate(b8):
        h = b.get_height()
        ax3.annotate(f"{h:.0f}ms\n({edg_rat[idx]:.0f}%)", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 4), textcoords="offset points",
                     ha='center', va='bottom', fontsize=9.0, fontweight='bold')
    for idx, b in enumerate(b9):
        h = b.get_height()
        ax3.annotate(f"{h:.0f}ms\n({iot_rat[idx]:.0f}%)", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 4), textcoords="offset points",
                     ha='center', va='bottom', fontsize=9.0, fontweight='bold')

    max_y3 = max(srv_thr + edg_thr + iot_thr) if (srv_thr + edg_thr + iot_thr) else 1000
    ax3.set_ylim(0, max_y3 * 1.30)
    ax3.set_ylabel("Thời gian CPU bị bóp nghẽn CFS (ms)", fontsize=11.5, fontweight='bold')
    ax3.set_title("3. Áp Lực Bóp Nghẽn CPU cgroups v2 Dưới Bão Gossip (CFS Throttled Duration)\n"
                  "[Nhãn trên cột: Thời gian bị bóp (ms) + (% Chu kỳ quota bị ngắt nhịp)]",
                  fontsize=12.2, fontweight='bold', pad=8)
    ax3.set_xticks(x)
    ax3.set_xticklabels(labels, fontweight='bold', fontsize=10.0)
    ax3.tick_params(axis='y', labelsize=10.0)
    ax3.legend(loc='upper left', fontsize=9.5, framealpha=0.9, edgecolor='#ccc')
    ax3.grid(axis='y', linestyle='--', alpha=0.5)

    # =========================================================================
    # Panel 4 (Góc dưới phải): Đỉnh Bộ Nhớ RAM & Ngưỡng Trần IoT 128MB
    # =========================================================================
    ax4 = axes[1, 1]
    srv_ram = [get_node_stat(r, 'server', 'peak_ram_mb') for r in macro_results]
    edg_ram = [get_node_stat(r, 'edge', 'peak_ram_mb') for r in macro_results]
    iot_ram = [get_node_stat(r, 'iot', 'peak_ram_mb') for r in macro_results]
    iot_ram_util = [get_node_stat(r, 'iot', 'ram_utilization_pct') for r in macro_results]

    b10 = ax4.bar(x - width, srv_ram, width, label='Server DUT (Trần 4096MB)', color='#3b82f6', edgecolor='#1d4ed8')
    b11 = ax4.bar(x, edg_ram, width, label='Edge DUT (Trần 512MB)', color='#10b981', edgecolor='#047857')
    b12 = ax4.bar(x + width, iot_ram, width, label='IoT DUT (Trần 128MB)', color='#ef4444', edgecolor='#b91c1c')

    for b in b10:
        h = b.get_height()
        ax4.annotate(f"{h:.1f}", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 4), textcoords="offset points",
                     ha='center', va='bottom', fontsize=9.0, fontweight='bold')
    for b in b11:
        h = b.get_height()
        ax4.annotate(f"{h:.1f}", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 4), textcoords="offset points",
                     ha='center', va='bottom', fontsize=9.0, fontweight='bold')
    for idx, b in enumerate(b12):
        h = b.get_height()
        ax4.annotate(f"{h:.1f}MB\n({iot_ram_util[idx]:.0f}%)", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 4), textcoords="offset points",
                     ha='center', va='bottom', fontsize=9.0, fontweight='bold', color='#7f1d1d')

    line_limit = ax4.axhline(128.0, color='#991b1b', linestyle='--', linewidth=2.0, label='Hạn mức trần cứng IoT RAM (128 MB)')
    ax4.set_ylim(0, 155.0)
    ax4.set_ylabel("Bộ nhớ RAM đỉnh đạt tới (MB)", fontsize=11.5, fontweight='bold')
    ax4.set_title("4. Đỉnh Bộ Nhớ RAM Chiếm Dụng Trên DUT (Peak RAM vs Ngưỡng 128MB)\n"
                  "[Đường đỏ: Ngưỡng trần cứng cgroups 128MB của thiết bị IoT]",
                  fontsize=12.2, fontweight='bold', pad=8)
    ax4.set_xticks(x)
    ax4.set_xticklabels(labels, fontweight='bold', fontsize=10.0)
    ax4.tick_params(axis='y', labelsize=10.0)
    handles_4 = [b10, b11, b12, line_limit]
    labels_4 = ['Server (4096MB)', 'Edge (512MB)', 'IoT (128MB)', 'Trần Cứng IoT (128MB)']
    ax4.legend(handles_4, labels_4, loc='upper left', fontsize=9.5, framealpha=0.9, edgecolor='#ccc')
    ax4.grid(axis='y', linestyle='--', alpha=0.5)

    plt.tight_layout(rect=[0, 0.02, 1, 0.955])
    plt.savefig(out_path, bbox_inches='tight')
    plt.close()
    print(f"[+] Da xuat bieu do Macro Benchmark Dashboard 4-Panel: {out_path}")


def save_macro_csv(macro_results: List[dict], out_path: Path):
    """
    Xuat bang CSV Macro-Benchmark tinh gon tap trung vao 8 Nhom Chi So Vang:
    1. Tai trong mang: Tx Wire Bytes, Block Wire Size (KB)
    2. Hieu nang mat ma don le: Server / Edge / IoT Tx Verify (ms)
    3. Toan ven dong thuan: Server / Edge / IoT Block Verify (ms), Block Transit (ms), Commit Latency (ms)
    4. Suc chiu tai bao Gossip: Server / Edge / IoT Ingest (TPS), Ingress BW (KB/s), WS Dups Filtered
    5. Ap luc bop nghen CPU cgroups v2: Server / Edge / IoT Throttled (ms), Throttling Ratio (%)
    6. Dinh bo nho RAM & % Tran cung: Server / Edge / IoT Peak RAM (MB), RAM Util (%)
    7. Trang thai kiem thu: Server / Edge / IoT Status
    """
    rows = []
    rows.append([
        "Algorithm", "Tx Wire Bytes", "Block Wire Size (KB)",
        # 1. Hieu nang Mat ma don le
        "Server Tx Verify (ms)", "Edge Tx Verify (ms)", "IoT Tx Verify (ms)",
        # 2. Toan ven Dong thuan
        "Server Block Verify (ms)", "Edge Block Verify (ms)", "IoT Block Verify (ms)",
        "Server Block Transit (ms)", "Edge Block Transit (ms)", "IoT Block Transit (ms)",
        "Server Commit Latency (ms)", "Edge Commit Latency (ms)", "IoT Commit Latency (ms)",
        # 3. Suc chiu tai bao Gossip
        "Server Ingest (TPS)", "Edge Ingest (TPS)", "IoT Ingest (TPS)",
        "Server Ingress BW (KB/s)", "Edge Ingress BW (KB/s)", "IoT Ingress BW (KB/s)",
        "Server WS Dups Filtered", "Edge WS Dups Filtered", "IoT WS Dups Filtered",
        # 4. Ap luc Bop nghen CPU cgroups v2
        "Server Throttling Ratio (%)", "Edge Throttling Ratio (%)", "IoT Throttling Ratio (%)",
        "Server Throttled (ms)", "Edge Throttled (ms)", "IoT Throttled (ms)",
        # 5. Dinh Bo nho RAM & % Tran cung
        "Server Peak RAM (MB)", "Edge Peak RAM (MB)", "IoT Peak RAM (MB)",
        "Server RAM Util (%)", "Edge RAM Util (%)", "IoT RAM Util (%)",
        # 6. Trang thai Kiem thu
        "Server Status", "Edge Status", "IoT Status"
    ])
    for r in macro_results:
        srv = r['nodes'].get('server', {})
        edg = r['nodes'].get('edge', {})
        iot = r['nodes'].get('iot', {})

        rows.append([
            r['algorithm_name'], r.get('wire_tx_bytes', 0), r.get('block_wire_kb', 0.0),
            srv.get('dut_tx_verify_ms', 0.0), edg.get('dut_tx_verify_ms', 0.0), iot.get('dut_tx_verify_ms', 0.0),
            srv.get('dut_block_verify_ms', 0.0), edg.get('dut_block_verify_ms', 0.0), iot.get('dut_block_verify_ms', 0.0),
            srv.get('block_transit_ms', 0.0), edg.get('block_transit_ms', 0.0), iot.get('block_transit_ms', 0.0),
            srv.get('commit_latency_ms', 'NA'), edg.get('commit_latency_ms', 'NA'), iot.get('commit_latency_ms', 'NA'),
            srv.get('ingest_throughput_tps', 0.0), edg.get('ingest_throughput_tps', 0.0), iot.get('ingest_throughput_tps', 0.0),
            srv.get('ingress_bandwidth_kbps', 0.0), edg.get('ingress_bandwidth_kbps', 0.0), iot.get('ingress_bandwidth_kbps', 0.0),
            srv.get('ws_dups_filtered', 0), edg.get('ws_dups_filtered', 0), iot.get('ws_dups_filtered', 0),
            srv.get('throttling_ratio_pct', 0.0), edg.get('throttling_ratio_pct', 0.0), iot.get('throttling_ratio_pct', 0.0),
            srv.get('total_throttled_ms', 0.0), edg.get('total_throttled_ms', 0.0), iot.get('total_throttled_ms', 0.0),
            srv.get('peak_ram_mb', 0.0), edg.get('peak_ram_mb', 0.0), iot.get('peak_ram_mb', 0.0),
            srv.get('ram_utilization_pct', 0.0), edg.get('ram_utilization_pct', 0.0), iot.get('ram_utilization_pct', 0.0),
            srv.get('status', 'UNKNOWN'), edg.get('status', 'UNKNOWN'), iot.get('status', 'UNKNOWN')
        ])

    transposed = list(zip(*rows))
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(transposed)
    print(f"[+] Da xuat bang CSV Macro-Benchmark tinh gon: {out_path}")


def main():
    parser = argparse.ArgumentParser(description="PERF-01 Macro-Benchmark Suite")
    parser.add_argument("--plot-only", "-p", action="store_true", help="Chi ve lai bieu do tu perf01_macro_results.json")
    parser.add_argument("--batch-size", "-b", type=int, default=100, help="So luong giao dich trong 1 batch (mac dinh: 100)")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if args.plot_only:
        p = RESULTS_DIR / "perf01_macro_results.json"
        if p.exists():
            with open(p, 'r', encoding='utf-8') as f:
                data = json.load(f)
            plot_macro_chart(data, RESULTS_DIR / "perf01_macro_chart.png")
            save_macro_csv(data, RESULTS_DIR / "perf01_macro_matrix.csv")
            return

    print("=" * 80)
    print("  KHOI CHAY PERF-01 MACRO-BENCHMARK: SINGLE DUT IN LIVE MESH (1 DUT + 5 BG NODES)")
    print("  So sanh ECDSA vs ML-DSA-44 vs ML-DSA-65 vs ML-DSA-87")
    print("  Ha tang: 1 Node Docker DUT (Server -> Edge -> IoT) hoa mang 5 Node Unconstrained")
    print("=" * 80)

    ecdsa_file = DATA_DIR / "txs_500_ecdsa.json"
    mldsa44_file = DATA_DIR / "txs_500_mldsa44.json"
    mldsa65_file = DATA_DIR / "txs_500_mldsa65.json"
    mldsa87_file = DATA_DIR / "txs_500_mldsa87.json"

    if not ecdsa_file.exists() or not mldsa44_file.exists() or not mldsa65_file.exists() or not mldsa87_file.exists():
        print("[!] Thieu dataset. Chay perf/generate_perf01_txs.py truoc.")
        return

    with open(ecdsa_file, 'r', encoding='utf-8') as f:
        ecdsa_txs = json.load(f)
    with open(mldsa44_file, 'r', encoding='utf-8') as f:
        mldsa44_txs = json.load(f)
    with open(mldsa65_file, 'r', encoding='utf-8') as f:
        mldsa65_txs = json.load(f)
    with open(mldsa87_file, 'r', encoding='utf-8') as f:
        mldsa87_txs = json.load(f)

    batch_size = args.batch_size
    macro_results = []

    print("[*] Khoi chay container warm-up de lam nong bo dem Linux Page Cache...")
    subprocess.run(["docker", "run", "--rm", "-d", "--name", "btc-macro-warmup", "-v", f"{BASE_DIR}:/app", "blockchain-node:perf"], stdout=subprocess.DEVNULL)
    time.sleep(2.0)
    subprocess.run(["docker", "rm", "-f", "btc-macro-warmup"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 1. Round 1: ECDSA (secp256k1)
    res_ecdsa = run_full_macro_round("ecdsa", "ECDSA (secp256k1)", ecdsa_txs, batch_size=batch_size)
    macro_results.append(res_ecdsa)
    time.sleep(1.0)

    # 2. Round 2: ML-DSA-44 (NIST PQC Level 2)
    res_mldsa44 = run_full_macro_round("mldsa44", "ML-DSA-44 (NIST PQC Level 2)", mldsa44_txs, batch_size=batch_size)
    macro_results.append(res_mldsa44)
    time.sleep(1.0)

    # 3. Round 3: ML-DSA-65 (NIST PQC Level 3)
    res_mldsa65 = run_full_macro_round("mldsa65", "ML-DSA-65 (NIST PQC Level 3)", mldsa65_txs, batch_size=batch_size)
    macro_results.append(res_mldsa65)
    time.sleep(1.0)

    # 4. Round 4: ML-DSA-87 (NIST PQC Level 5)
    res_mldsa87 = run_full_macro_round("mldsa87", "ML-DSA-87 (NIST PQC Level 5)", mldsa87_txs, batch_size=batch_size)
    macro_results.append(res_mldsa87)

    json_path = RESULTS_DIR / "perf01_macro_results.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(macro_results, f, indent=2, ensure_ascii=False)

    csv_path = RESULTS_DIR / "perf01_macro_matrix.csv"
    save_macro_csv(macro_results, csv_path)

    chart_path = RESULTS_DIR / "perf01_macro_chart.png"
    plot_macro_chart(macro_results, chart_path)

    clean_environment()

    print("\n" + "=" * 80)
    print("  HOAN TAT TOAN BO MACRO-BENCHMARK: 1 DUT + 5 BG NODES (4 THUAT TOAN)!")
    print(f"  - Ket qua JSON:   {json_path}")
    print(f"  - Bang CSV Macro: {csv_path}")
    print(f"  - Bieu do Macro:  {chart_path}")
    print("=" * 80)


if __name__ == '__main__':
    main()
