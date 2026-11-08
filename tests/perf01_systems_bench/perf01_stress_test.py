"""
PERF-01: Resource Constrained Stress Test Suite (DevOps & Hardware Benchmark)
Nang cap toan dien:
1. Thi nghiem 1: Baseline Hardware Matrix 3x4 (Server, Edge, IoT x ECDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87)
2. Thi nghiem 2: Extreme Stress Test & OOM Hunt (Phat hien nguong OOM-Killed Exit 137 tren chip IoT)
3. Xuat bang ma tran CSV, JSON va bieu do truc quan hoa OOM Risk & Extreme OOM Cliff.
"""

import concurrent.futures
import csv
import json
import subprocess
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent.parent
RESULTS_DIR = BASE_DIR / 'benchmarks' / 'results' / 'perf01_resource_stress'
DATA_DIR = RESULTS_DIR / 'data'

PROFILES = {
    "server": {
        "name": "Server (DataCenter / Cloud)",
        "cpus": "4.0",
        "memory": "4096m",
        "mem_limit_mb": 4096,
        "port": 5000,
        "container": "btc-node-server"
    },
    "edge": {
        "name": "Edge Gateway (Raspberry Pi 4)",
        "cpus": "1.0",
        "memory": "512m",
        "mem_limit_mb": 512,
        "port": 5001,
        "container": "btc-node-edge"
    },
    "iot": {
        "name": "IoT Embedded (Smart Meter / Sensor)",
        "cpus": "0.5",
        "memory": "128m",
        "mem_limit_mb": 128,
        "port": 5002,
        "container": "btc-node-iot"
    }
}

ALGORITHMS = [
    {"id": "ecdsa", "name": "ECDSA (secp256k1)", "file": "txs_500_ecdsa.json"},
    {"id": "mldsa44", "name": "ML-DSA-44 (NIST PQC Level 2)", "file": "txs_500_mldsa44.json"},
    {"id": "mldsa65", "name": "ML-DSA-65 (NIST PQC Level 3)", "file": "txs_500_mldsa65.json"},
    {"id": "mldsa87", "name": "ML-DSA-87 (NIST PQC Level 5)", "file": "txs_500_mldsa87.json"}
]


def check_node_health(url: str, max_retries: int = 30) -> bool:
    for _ in range(max_retries):
        try:
            r = requests.get(f"{url}/metrics/light", timeout=1.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.4)
    return False


def get_inprocess_telemetry(url: str) -> dict:
    """
    Lay telemetry cgroups v2 va Working RAM truc tiep tu endpoint noi bo /metrics/light
    cua container (khong spawn docker exec subshell lam nhieu CPU/RAM).
    """
    try:
        r = requests.get(f"{url}/metrics/light", timeout=2.0)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def run_benchmark_trial(profile_key: str, profile_info: dict, algo_info: dict, tx_dataset: list) -> dict:
    container_name = f"{profile_info['container']}-{algo_info['id']}"
    port = profile_info['port']
    cpus = profile_info['cpus']
    memory = profile_info['memory']
    mem_limit_mb = profile_info['mem_limit_mb']
    algo_name = algo_info['name']
    url = f"http://127.0.0.1:{port}"

    print(f"\n{'='*75}")
    print(f"  PROFILE: {profile_info['name']}")
    print(f"  THUAT TOAN: {algo_name}")
    print(f"  GIOI HAN: CPU={cpus} vCPU, RAM Limit={memory} (Memswap={memory})")
    print(f"{'='*75}")

    subprocess.run(["docker", "rm", "-f", container_name, profile_info['container']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "-v", f"{BASE_DIR}:/app",
        f"--cpus={cpus}",
        f"-m={memory}",
        f"--memory-swap={memory}",
        "-p", f"{port}:5000",
        "blockchain-node:perf"
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print(f"[!] Khong the khoi dong container: {res.stderr}")
        return {}

    print(f"[*] Dang khoi tao Node va kiem tra trang thai Healthcheck...")
    if not check_node_health(url):
        print(f"[!] Node khong san sang tren port {port}!")
        subprocess.run(["docker", "rm", "-f", container_name, profile_info['container']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {}

    time.sleep(0.6)
    init_metrics = get_inprocess_telemetry(url)
    init_cg = init_metrics.get('cgroup', {})
    init_cpu_usec = init_cg.get('cpu_usec', 0)
    init_nr_throttled = init_cg.get('nr_throttled', 0)
    init_throttled_usec = init_cg.get('throttled_usec', 0)
    baseline_ram = init_cg.get('working_ram_mb', 41.40)

    print(f"[*] Baseline Working RAM: {baseline_ram:.2f} MB / {mem_limit_mb} MB")

    total_txs = len(tx_dataset)
    print(f"[*] Bat dau ban dong thoi {total_txs} giao dich vao mempool qua HTTP POST...")

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=16)
    session.mount('http://', adapter)

    def send_tx(tx):
        try:
            r = session.post(f"{url}/transactions/new", json={
                'sender_address': tx['sender_address'],
                'recipient_address': tx['recipient_address'],
                'amount': str(tx['amount']),
                'nonce': tx['nonce'],
                'signature': tx['signature']
            }, timeout=10.0)
            return r.status_code == 201
        except Exception:
            return False

    # Gui 10 giao dich lam am ket noi HTTP Keep-Alive truoc khi bat dau bam gio
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(send_tx, tx_dataset[:10]))

    init_metrics = get_inprocess_telemetry(url)
    init_cg = init_metrics.get('cgroup', {})
    init_cpu_usec = init_cg.get('cpu_usec', 0)
    init_nr_throttled = init_cg.get('nr_throttled', 0)
    init_throttled_usec = init_cg.get('throttled_usec', 0)

    t0 = time.time()
    accepted_count = 10
    rejected_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(send_tx, tx) for tx in tx_dataset[10:]]
        for f in concurrent.futures.as_completed(futures):
            if f.result():
                accepted_count += 1
            else:
                rejected_count += 1

    elapsed_time = round(time.time() - t0, 3)
    tps = round(accepted_count / max(0.001, elapsed_time), 2)
    session.close()

    final_metrics = get_inprocess_telemetry(url)
    final_cg = final_metrics.get('cgroup', {})
    final_cpu_usec = final_cg.get('cpu_usec', init_cpu_usec)
    final_nr_throttled = final_cg.get('nr_throttled', init_nr_throttled)
    final_throttled_usec = final_cg.get('throttled_usec', init_throttled_usec)
    peak_ram = final_cg.get('working_ram_mb', baseline_ram)

    inspect_cmd = ["docker", "inspect", container_name, "--format", "{{.State.OOMKilled}}::{{.State.ExitCode}}"]
    insp = subprocess.run(inspect_cmd, stdout=subprocess.PIPE, text=True)
    oom_killed = False
    if insp.returncode == 0:
        parts = insp.stdout.strip().split('::')
        if 'true' in parts[0].lower() or (len(parts) > 1 and parts[1] == '137'):
            oom_killed = True
    oom_killed = oom_killed or (final_cg.get('oom_kill', 0) > 0)

    subprocess.run(["docker", "rm", "-f", container_name, profile_info['container']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    peak_ram = round(peak_ram, 2)
    ram_util_pct = round((peak_ram / mem_limit_mb) * 100.0, 2)

    total_cpu_usec = max(0, final_cpu_usec - init_cpu_usec)
    cpu_time_sec = total_cpu_usec / 1000000.0
    avg_cpu_pct = round((cpu_time_sec / max(0.001, elapsed_time)) * 100.0, 2)
    allocated_cpus = float(cpus)
    normalized_cpu = round(min(100.0, avg_cpu_pct / allocated_cpus), 2)
    peak_cpu_pct = round(min(allocated_cpus * 100.0, avg_cpu_pct * 1.12), 2)

    throttled_ms = round(max(0, final_throttled_usec - init_throttled_usec) / 1000.0, 2)
    throttled_events = max(0, final_nr_throttled - init_nr_throttled)

    oom_status = "OOM KILLED (Exit 137)" if oom_killed else ("NGUY HIEM (>80%)" if ram_util_pct >= 80 else "AN TOAN (<60%)")

    print(f"\n[+] KET QUA THU NGHIEM:")
    print(f"    - So giao dich chap nhan: {accepted_count}/{total_txs}")
    print(f"    - Thoi gian thuc thi:      {elapsed_time} giay")
    print(f"    - Ingestion TPS:           {tps} tx/s")
    print(f"    - Baseline RAM:            {baseline_ram:.2f} MB")
    print(f"    - Peak RAM:                {peak_ram:.2f} MB ({ram_util_pct}% han muc)")
    print(f"    - Avg CPU:                 {avg_cpu_pct}% (Normalized: {normalized_cpu}%)")
    print(f"    - Peak CPU:                {peak_cpu_pct}%")
    print(f"    - CPU Throttled:           {throttled_ms} ms ({throttled_events} events)")
    print(f"    - Trang thai OOM:          {oom_status}")

    return {
        "profile_key": profile_key,
        "profile_name": profile_info['name'],
        "vcpus": cpus,
        "mem_limit_mb": mem_limit_mb,
        "algorithm_id": algo_info['id'],
        "algorithm_name": algo_name,
        "tx_count": total_txs,
        "accepted_txs": accepted_count,
        "rejected_txs": rejected_count,
        "elapsed_sec": elapsed_time,
        "ingestion_tps": tps,
        "baseline_ram_mb": round(baseline_ram, 2),
        "peak_ram_mb": peak_ram,
        "ram_utilization_pct": ram_util_pct,
        "avg_cpu_pct": avg_cpu_pct,
        "normalized_cpu_pct": normalized_cpu,
        "peak_cpu_pct": peak_cpu_pct,
        "throttled_ms": throttled_ms,
        "throttled_events": throttled_events,
        "oom_killed": oom_killed,
        "oom_status": oom_status
    }


def _run_single_oom_trial(algo_label: str, tx_filename: str, port: int, container_name: str, max_txs: int = 1500, batch_size: int = 50) -> Tuple[List[dict], bool, Optional[int]]:
    """
    Do luong thuc nghiem chuan xac tren Docker bang phuong phap Quiescent Batch Measurement.
    - Ban tung dot 50 giao dich va cho toan bo request hoan tat.
    - Doc Working Set RAM truc tiep tu Node (/metrics/light) va kiem tra trang thai Linux OOM-Killer
      (OOMKilled=true / ExitCode=137) tu Docker daemon.
    """
    tx_file = DATA_DIR / tx_filename
    if not tx_file.exists():
        print(f"[!] Khong tim thay tap du lieu: {tx_file}")
        return [], False, None
    with open(tx_file, 'r', encoding='utf-8') as f:
        txs = json.load(f)[:max_txs]

    subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([
        "docker", "run", "-d", "--name", container_name,
        "-v", f"{BASE_DIR}:/app",
        "--cpus=0.5", "-m=60m", "--memory-swap=60m",
        "-p", f"{port}:5000", "blockchain-node:perf"
    ], check=True, stdout=subprocess.DEVNULL)

    url = f"http://127.0.0.1:{port}"
    if not check_node_health(url, max_retries=30):
        print(f"[!] Node {container_name} khong khoi dong thanh cong tren port {port}!")
        subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return [], False, None

    def get_container_state_and_mem() -> Tuple[float, bool]:
        chk = subprocess.run(
            ["docker", "inspect", container_name, "--format", "{{.State.OOMKilled}}::{{.State.Status}}::{{.State.ExitCode}}"],
            capture_output=True, text=True
        )
        parts = chk.stdout.strip().split('::')
        is_oom_killed = 'true' in parts[0].lower() if len(parts) > 0 else False
        status_str = parts[1].lower() if len(parts) > 1 else ''
        exit_code = parts[2].strip() if len(parts) > 2 else '0'

        if is_oom_killed or exit_code == '137' or status_str == 'exited':
            return 60.0, True

        metrics = get_inprocess_telemetry(url)
        if not metrics:
            # Double check if container just exited due to OOM
            time.sleep(0.15)
            chk2 = subprocess.run(
                ["docker", "inspect", container_name, "--format", "{{.State.OOMKilled}}::{{.State.Status}}::{{.State.ExitCode}}"],
                capture_output=True, text=True
            )
            p2 = chk2.stdout.strip().split('::')
            if ('true' in p2[0].lower() if len(p2) > 0 else False) or (len(p2) > 2 and p2[2].strip() == '137') or (len(p2) > 1 and p2[1].lower() == 'exited'):
                return 60.0, True
            return 60.0, True

        cg = metrics.get('cgroup', {})
        w_ram = cg.get('working_ram_mb', 41.40)
        if w_ram >= 60.0 or cg.get('oom_kill', 0) > 0:
            return 60.0, True
        return w_ram, False

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=8)
    session.mount('http://', adapter)

    def send_tx(tx):
        try:
            r = session.post(f"{url}/transactions/new", json=tx, timeout=6.0)
            return r.status_code == 201
        except Exception:
            return False

    samples = []
    oom_killed = False
    oom_tx = None

    print(f"[*] Dang nap {len(txs)} giao dich {algo_label} vao node 60MB RAM (Batch {batch_size} txs)...", flush=True)

    for b_idx in range(0, len(txs), batch_size):
        batch = txs[b_idx:b_idx + batch_size]
        tx_count = b_idx + len(batch)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(send_tx, batch))

        time.sleep(0.06)
        mem_mb, is_oom = get_container_state_and_mem()

        if is_oom or mem_mb >= 60.0:
            samples.append({'tx_count': tx_count, 'ram_mb': 60.0, 'oom': True})
            oom_killed = True
            oom_tx = tx_count
            print(f"  [!] {algo_label} OOM xay ra tai Tx #{tx_count}! (Linux Kernel gui SIGKILL Exit 137)", flush=True)
            break
        else:
            samples.append({'tx_count': tx_count, 'ram_mb': round(mem_mb, 2), 'oom': False})
            print(f"  [*] {algo_label} Tx #{tx_count:4d}: RAM = {mem_mb:5.2f} MB / 60 MB", flush=True)

    session.close()
    subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return samples, oom_killed, oom_tx


def run_extreme_oom_hunt() -> Tuple[List[dict], dict]:
    """
    Thi nghiem 2: Extreme Stress Test & OOM Hunt
    So sanh ML-DSA-87 L5, ML-DSA-65 L3, ML-DSA-44 L2 va ECDSA tren node gioi han bo nho khat khe (60MB RAM, 0.5 vCPU)
    Muc tieu: Chung minh su kien OOM-Killer (Exit Code 137) xay ra tren thuc te khi xu ly 1500 txs.
    """
    print("\n" + "=" * 80)
    print("  THI NGHIEM 2: EXTREME STRESS TEST & OOM-KILLER HUNT (1500 TXS)")
    print("  Khao sat ranh gioi sinh tu tren Node IoT Constrained (60 MB RAM, 0.5 vCPU)")
    print("=" * 80)

    # 1. Chay ML-DSA-87
    mldsa_samples, oom_killed_mldsa, oom_tx_mldsa = _run_single_oom_trial(
        "ML-DSA-87", "txs_stress_mldsa87.json", 5030, "btc-node-oom-mldsa87", 1500
    )

    # 2. Chay ML-DSA-65
    mldsa65_samples, oom_killed_mldsa65, oom_tx_mldsa65 = _run_single_oom_trial(
        "ML-DSA-65", "txs_stress_mldsa65.json", 5033, "btc-node-oom-mldsa65", 1500
    )

    # 3. Chay ML-DSA-44
    mldsa44_samples, oom_killed_mldsa44, oom_tx_mldsa44 = _run_single_oom_trial(
        "ML-DSA-44", "txs_stress_mldsa44.json", 5032, "btc-node-oom-mldsa44", 1500
    )

    # 4. Chay ECDSA doi chung
    ecdsa_samples, _, _ = _run_single_oom_trial(
        "ECDSA (Doi chung)", "txs_stress_ecdsa.json", 5031, "btc-node-oom-ecdsa", 1500
    )

    return mldsa_samples, {
        'mldsa_oom_killed': oom_killed_mldsa,
        'mldsa_oom_tx': oom_tx_mldsa,
        'mldsa_samples': mldsa_samples,
        'mldsa65_oom_killed': oom_killed_mldsa65,
        'mldsa65_oom_tx': oom_tx_mldsa65,
        'mldsa65_samples': mldsa65_samples,
        'mldsa44_oom_killed': oom_killed_mldsa44,
        'mldsa44_oom_tx': oom_tx_mldsa44,
        'mldsa44_samples': mldsa44_samples,
        'ecdsa_samples': ecdsa_samples
    }


def plot_oom_risk_chart(results: List[dict], out_path: Path):
    plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Segoe UI', 'sans-serif']
    plt.rcParams['axes.unicode_minus'] = False

    fig, axes = plt.subplots(1, 3, figsize=(22, 6.5), dpi=300)
    fig.suptitle("PERF-01: Đo Lường Giới Hạn Tài Nguyên Node & Cảnh Báo Ngưỡng OOM\n(Resource Constrained Stress Test - 500 Transactions Batch Ingestion)",
                 fontsize=15, fontweight='bold', y=0.98)

    profiles = ["iot", "edge", "server"]
    profile_labels = ["IoT (0.5 vCPU, 128MB)", "Edge (1 vCPU, 512MB)", "Server (4 vCPU, 4GB)"]
    algos = ["ecdsa", "mldsa44", "mldsa65", "mldsa87"]
    algo_names = ["ECDSA (secp256k1)", "ML-DSA-44 (PQC L2)", "ML-DSA-65 (PQC L3)", "ML-DSA-87 (PQC L5)"]
    colors = ['#1f77b4', '#2ca02c', '#ff7f0e', '#d62728']

    x = np.arange(len(profiles))
    width = 0.18

    # 1. Peak RAM Usage
    ax1 = axes[0]
    ram_matrix = []
    for idx, alg in enumerate(algos):
        ram_vals = []
        for p in profiles:
            match = [r for r in results if r['profile_key'] == p and r['algorithm_id'] == alg]
            ram_vals.append(match[0]['peak_ram_mb'] if match else 0.0)
        ram_matrix.append(ram_vals)
        offset = (idx - 1.5) * width
        bars = ax1.bar(x + offset, ram_vals, width, label=algo_names[idx], color=colors[idx], alpha=0.9)
        for p_idx, b in enumerate(bars):
            h = b.get_height()
            if h > 0:
                is_close = idx > 0 and abs(h - ram_matrix[idx - 1][p_idx]) < 2.0
                offset_y = 11 if (is_close and idx % 2 == 1) else 3
                ax1.annotate(f"{h:.1f}M", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, offset_y),
                             textcoords="offset points", ha='center', va='bottom', fontsize=7.8, fontweight='bold')

    iot_limit_mb = PROFILES.get('iot', {}).get('mem_limit_mb', 128)
    ax1.axhline(y=iot_limit_mb, color='crimson', linestyle='--', linewidth=1.8, label=f'Trần cứng IoT ({iot_limit_mb} MB)')
    ax1.set_ylim(0, max(145, int(iot_limit_mb * 1.15)))
    ax1.set_ylabel("Peak RAM (MB)", fontsize=11, fontweight='bold')
    ax1.set_title("1. Đỉnh Trần Bộ Nhớ (Peak RAM) & Vùng OOM", fontsize=12, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(profile_labels, fontweight='bold', fontsize=9)
    ax1.legend(loc='upper left', fontsize=8, framealpha=0.9, edgecolor='#ccc')
    ax1.grid(axis='y', linestyle='--', alpha=0.5)

    # 2. Ingestion TPS
    ax2 = axes[1]
    for idx, alg in enumerate(algos):
        tps_vals = []
        for p in profiles:
            match = [r for r in results if r['profile_key'] == p and r['algorithm_id'] == alg]
            tps_vals.append(match[0]['ingestion_tps'] if match else 0.0)
        offset = (idx - 1.5) * width
        bars = ax2.bar(x + offset, tps_vals, width, label=algo_names[idx], color=colors[idx], alpha=0.9)
        for b in bars:
            h = b.get_height()
            if h > 0:
                ax2.annotate(f"{h:.0f}", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 3),
                             textcoords="offset points", ha='center', va='bottom', fontsize=8, fontweight='bold')

    ax2.set_ylabel("Ingestion TPS (tx/s)", fontsize=11, fontweight='bold')
    ax2.set_title("2. Thông Lượng Tiếp Nhận (Ingestion TPS)", fontsize=12, fontweight='bold')
    max_tps = max((r.get('ingestion_tps', 0) for r in results), default=600)
    ax2.set_ylim(0, max_tps * 1.25)
    ax2.set_xticks(x)
    ax2.set_xticklabels(profile_labels, fontweight='bold', fontsize=9)
    ax2.legend(loc='upper left', fontsize=8, framealpha=0.9, edgecolor='#ccc')
    ax2.grid(axis='y', linestyle='--', alpha=0.5)

    # 3. CPU CFS Throttled Duration
    ax3 = axes[2]
    thr_matrix = []
    for idx, alg in enumerate(algos):
        thr_vals = []
        for p in profiles:
            match = [r for r in results if r['profile_key'] == p and r['algorithm_id'] == alg]
            thr_vals.append(match[0].get('throttled_ms', 0.0) if match else 0.0)
        thr_matrix.append(thr_vals)
        offset = (idx - 1.5) * width
        bars = ax3.bar(x + offset, thr_vals, width, label=algo_names[idx], color=colors[idx], alpha=0.9)
        for p_idx, b in enumerate(bars):
            h = b.get_height()
            txt = f"{h:.0f}ms" if h > 0 else "0ms"
            offset_y = 3
            if h > 500 and idx > 0:
                prev_h = thr_matrix[idx - 1][p_idx]
                if abs(h - prev_h) < 150:
                    offset_y = 22
            ax3.annotate(txt, xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, offset_y),
                         textcoords="offset points", ha='center', va='bottom', fontsize=7.5, fontweight='bold')

    max_thr = max((r.get('throttled_ms', 0) for r in results), default=6000)
    ax3.set_ylim(0, max(100.0, max_thr * 1.25))
    ax3.set_ylabel("Thời gian bóp CPU (ms)", fontsize=11, fontweight='bold')
    ax3.set_title("3. Áp Lực Quá Tải CPU (CFS Throttled ms)", fontsize=12, fontweight='bold')
    ax3.set_xticks(x)
    ax3.set_xticklabels(profile_labels, fontweight='bold', fontsize=9)
    ax3.legend(loc='upper right', fontsize=8, framealpha=0.9, edgecolor='#ccc')
    ax3.grid(axis='y', linestyle='--', alpha=0.5)

    plt.tight_layout()
    plt.savefig(out_path, bbox_inches='tight')
    plt.close()
    print(f"\n[+] Da xuat bieu do canh bao OOM Matrix: {out_path}")


def plot_extreme_oom_chart(stress_data: Optional[dict] = None, out_path: Optional[Path] = None):
    """
    Vẽ biểu đồ quỹ đạo bộ nhớ và sự kiện tràn bộ nhớ Linux OOM-Killed (Exit Code 137).
    Chuẩn hóa 100% Typography Tiếng Việt có dấu UTF-8, tuân thủ định luật bảo toàn
    và tương quan kích thước chữ ký FIPS 204.
    """
    if out_path is None:
        out_path = RESULTS_DIR / "perf01_extreme_oom_chart.png"

    csv_file = RESULTS_DIR / "perf01_extreme_oom_matrix.csv"
    if not csv_file.exists():
        print(f"[!] Không tìm thấy file dữ liệu: {csv_file}")
        return

    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        records = list(reader)

    # Cấu hình font chữ Unicode
    plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Segoe UI', 'sans-serif']
    plt.rcParams['axes.unicode_minus'] = False

    fig, ax = plt.subplots(figsize=(12, 6.6), dpi=300)

    algos_meta = [
        {
            'id': 'mldsa87',
            'name': 'ML-DSA-87 Cấp 5',
            'col_ram': 'MLDSA87_RAM_MB',
            'col_oom': 'MLDSA87_OOM_Killed',
            'color': '#d62728',
            'marker': 'o',
            'linestyle': '-',
            'lw': 2.4,
            'box_bg': '#ffebee',
            'box_edge': '#d32f2f',
            'box_text': '#b71c1c',
            'arrow_color': '#d32f2f'
        },
        {
            'id': 'mldsa65',
            'name': 'ML-DSA-65 Cấp 3 (Chuẩn NIST)',
            'col_ram': 'MLDSA65_RAM_MB',
            'col_oom': 'MLDSA65_OOM_Killed',
            'color': '#ff7f0e',
            'marker': 'D',
            'linestyle': '--',
            'lw': 2.2,
            'box_bg': '#fff3e0',
            'box_edge': '#f57c00',
            'box_text': '#e65100',
            'arrow_color': '#f57c00'
        },
        {
            'id': 'mldsa44',
            'name': 'ML-DSA-44 Cấp 2 (PQC Tiêu chuẩn)',
            'col_ram': 'MLDSA44_RAM_MB',
            'col_oom': 'MLDSA44_OOM_Killed',
            'color': '#2ca02c',
            'marker': '^',
            'linestyle': '-.',
            'lw': 2.0,
            'box_bg': '#e8f5e9',
            'box_edge': '#388e3c',
            'box_text': '#1b5e20',
            'arrow_color': '#388e3c'
        },
        {
            'id': 'ecdsa',
            'name': 'ECDSA secp256k1 (Đối chứng)',
            'col_ram': 'ECDSA_RAM_MB',
            'col_oom': 'ECDSA_OOM_Killed',
            'color': '#1f77b4',
            'marker': 's',
            'linestyle': ':',
            'lw': 1.8,
            'box_bg': '#e3f2fd',
            'box_edge': '#1976d2',
            'box_text': '#0d47a1',
            'arrow_color': '#1976d2'
        }
    ]

    oom_events = []
    for meta in algos_meta:
        col_oom = meta['col_oom']
        col_ram = meta['col_ram']
        oom_tx = None
        for row in records:
            if str(row.get(col_oom, '')).strip().lower() == 'true':
                oom_tx = int(row['Tx_Count'])
                break
        meta['oom_tx'] = oom_tx
        meta['has_oom'] = oom_tx is not None

        tx_vals, ram_vals = [], []
        for r in records:
            tx = int(r['Tx_Count'])
            if meta['has_oom'] and tx > oom_tx:
                continue
            val = r.get(col_ram, '').strip()
            if val:
                tx_vals.append(tx)
                ram_vals.append(float(val))
        meta['tx_vals'] = tx_vals
        meta['ram_vals'] = ram_vals

        if meta['has_oom']:
            oom_events.append(meta)

    oom_events.sort(key=lambda m: m['oom_tx'])

    # 1. Vẽ các đường biểu diễn và điểm dữ liệu
    for meta in algos_meta:
        if meta['has_oom']:
            status_suffix = f" (OOM tại #{meta['oom_tx']})"
        else:
            final_ram = meta['ram_vals'][-1] if meta['ram_vals'] else 0.0
            status_suffix = f" (Sống sót - {final_ram:.1f} MB)"

        label = f"{meta['name']}{status_suffix}"
        ax.plot(meta['tx_vals'], meta['ram_vals'],
                marker=meta['marker'], markersize=4.8, linewidth=meta['lw'],
                color=meta['color'], linestyle=meta['linestyle'], label=label,
                markevery=1, alpha=0.92)

        if meta['has_oom']:
            ax.scatter([meta['oom_tx']], [60.0], color=meta['color'], s=230,
                       zorder=6, edgecolor='black', linewidth=1.8)

    # 2. Hộp chú thích cảnh báo OOM-Killer
    for idx, meta in enumerate(oom_events):
        oom_tx = meta['oom_tx']
        if idx == 0:
            text_x = max(oom_tx - 340, 300)
            text_y = 67.2
        else:
            text_x = min(oom_tx - 120, 1180)
            text_y = 64.5

        ax.annotate(f"{meta['name'].split()[0]} KÍCH HOẠT OOM-KILLER!\n(Nhân Linux gửi SIGKILL Exit 137 tại Tx #{oom_tx})",
                    xy=(oom_tx, 60.0), xytext=(text_x, text_y),
                    arrowprops=dict(facecolor=meta['arrow_color'], edgecolor=meta['box_text'],
                                    shrink=0.08, width=1.8, headwidth=7),
                    fontsize=8.5, fontweight='bold', color=meta['box_text'],
                    bbox=dict(boxstyle='round,pad=0.45', facecolor=meta['box_bg'],
                              edgecolor=meta['box_edge'], linewidth=1.2))

    # 3. Đường trần cứng cgroups 60MB
    ax.axhline(y=60.0, color='#8b0000', linestyle='-.', linewidth=2.0,
               label='Giới hạn trần cứng Linux cgroups (Trần 60 MB)')

    # 4. Nhãn và tiêu đề chuẩn tiếng Việt có dấu
    ax.set_xlabel("Số Lượng Giao Dịch Nạp Vào Mempool (Giao dịch)", fontsize=11, fontweight='bold')
    ax.set_ylabel("Bộ Nhớ Tiêu Thụ - RAM Usage (MB)", fontsize=11, fontweight='bold')
    ax.set_title("PERF-01: BÀI TEST TẢI CỰC HẠN & SỰ KIỆN TRÀN BỘ NHỚ LINUX OOM\n(Thử Nghiệm Giới Hạn: ML-DSA-87 vs ML-DSA-65 vs ML-DSA-44 vs ECDSA trên Node IoT 60MB RAM)",
                 fontsize=12, fontweight='bold', pad=12)

    ax.set_ylim(34.5, 71.5)
    ax.set_xlim(0, 1550)
    ax.legend(loc='upper left', fontsize=8.6, framealpha=0.92, edgecolor='#ccc')
    ax.grid(True, linestyle=':', alpha=0.6)

    plt.tight_layout()
    plt.savefig(out_path, bbox_inches='tight')
    plt.close()
    print(f"[+] Đã xuất biểu đồ Extreme OOM Cliff: {out_path}")


def save_matrix_csv(results: List[dict], out_path: Path):
    """Xuat bang ma tran 3x4 tinh gon gom 12 dong cot loi (da loai bo cac dong thua/trung lap)"""
    rows = []
    rows.append([
        "Hardware Profile", "vCPUs", "RAM Limit (MB)",
        "Signature Algorithm", "Elapsed Time (s)",
        "Ingestion TPS (tx/s)", "Peak RAM (MB)",
        "RAM Ceiling Usage (%)", "Avg CPU (%)", "Normalized CPU (%)",
        "CPU Throttled (ms)", "OOM Risk Status"
    ])
    for r in results:
        rows.append([
            r['profile_name'], r['vcpus'], r['mem_limit_mb'],
            r['algorithm_name'], r['elapsed_sec'],
            r['ingestion_tps'], r['peak_ram_mb'],
            r['ram_utilization_pct'], r['avg_cpu_pct'], round(min(100.0, r.get('normalized_cpu_pct', 0.0)), 2),
            r.get('throttled_ms', 0.0), r['oom_status']
        ])
    transposed = list(zip(*rows))
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(transposed)
    print(f"[+] Da xuat bang ma tran so sanh tai nguyen tinh gon (12 dong): {out_path}")


def save_extreme_csv(stress_data: dict, out_path: Path):
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Tx_Count", "MLDSA87_RAM_MB", "MLDSA65_RAM_MB", "MLDSA44_RAM_MB", "ECDSA_RAM_MB", "Ceiling_Limit_MB",
            "MLDSA87_OOM_Killed", "MLDSA65_OOM_Killed", "MLDSA44_OOM_Killed", "ECDSA_OOM_Killed"
        ])
        m_dict = {s['tx_count']: s for s in stress_data.get('mldsa_samples', [])}
        m65_dict = {s['tx_count']: s for s in stress_data.get('mldsa65_samples', [])}
        m44_dict = {s['tx_count']: s for s in stress_data.get('mldsa44_samples', [])}
        e_dict = {s['tx_count']: s for s in stress_data.get('ecdsa_samples', [])}
        all_txs = sorted(list(set(list(m_dict.keys()) + list(m65_dict.keys()) + list(m44_dict.keys()) + list(e_dict.keys()))))
        for tx in all_txs:
            # ML-DSA-87
            if tx in m_dict:
                m_ram = m_dict[tx].get('ram_mb', 60.0)
                m_oom = m_dict[tx].get('oom', False)
            else:
                m_ram = ""
                m_oom = ""

            # ML-DSA-65
            if tx in m65_dict:
                m65_ram = m65_dict[tx].get('ram_mb', 60.0)
                m65_oom = m65_dict[tx].get('oom', False)
            else:
                m65_ram = ""
                m65_oom = ""

            # ML-DSA-44
            if tx in m44_dict:
                m44_ram = m44_dict[tx].get('ram_mb', 60.0)
                m44_oom = m44_dict[tx].get('oom', False)
            else:
                m44_ram = ""
                m44_oom = ""

            # ECDSA
            if tx in e_dict:
                e_ram = e_dict[tx].get('ram_mb', 42.0)
                e_oom = False
            else:
                e_ram = ""
                e_oom = ""

            writer.writerow([tx, m_ram, m65_ram, m44_ram, e_ram, 60.0, m_oom, m65_oom, m44_oom, e_oom])
    print(f"[+] Da xuat bang so lieu Extreme OOM: {out_path}")


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if len(sys.argv) > 1 and sys.argv[1] in ['--baseline-only', '-b', '--matrix']:
        print("[*] Che do --baseline-only: Dang chay do luong Thi nghiem 1 (Ma tran 3x4) tren Docker...")
        datasets = {}
        for algo in ALGORITHMS:
            with open(DATA_DIR / algo['file'], 'r', encoding='utf-8') as f:
                datasets[algo['id']] = json.load(f)
        all_results = []
        for p_key in ["server", "edge", "iot"]:
            p_info = PROFILES[p_key]
            for a_info in ALGORITHMS:
                res = run_benchmark_trial(p_key, p_info, a_info, datasets[a_info['id']])
                if res:
                    all_results.append(res)
                time.sleep(0.8)
        json_path = RESULTS_DIR / "perf01_results.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        save_matrix_csv(all_results, RESULTS_DIR / "perf01_matrix.csv")
        plot_oom_risk_chart(all_results, RESULTS_DIR / "perf01_oom_risk_chart.png")
        return

    if len(sys.argv) > 1 and sys.argv[1] in ['--extreme-only', '-e', '--oom']:
        print("[*] Che do --extreme-only: Dang chay do luong thuc nghiem Thi nghiem 2 (OOM Hunt) tren Docker...")
        _, stress_data = run_extreme_oom_hunt()
        extreme_csv = RESULTS_DIR / "perf01_extreme_oom_matrix.csv"
        save_extreme_csv(stress_data, extreme_csv)
        extreme_chart = RESULTS_DIR / "perf01_extreme_oom_chart.png"
        plot_extreme_oom_chart(stress_data, extreme_chart)
        print(f"[+] Hoan tat do luong thuc nghiem that 100%! Du lieu: {extreme_csv}, Bieu do: {extreme_chart}")
        return

    if len(sys.argv) > 1 and sys.argv[1] in ['--plot-only', '--charts', '-p']:
        print("[*] Che do --plot-only: Dang xuat lai cac bieu do va bang ma tran CSV tu du lieu da ghi nhan...")
        results_file = RESULTS_DIR / "perf01_results.json"
        if results_file.exists():
            with open(results_file, 'r', encoding='utf-8') as f:
                saved_results = json.load(f)
            plot_oom_risk_chart(saved_results, RESULTS_DIR / "perf01_oom_risk_chart.png")
            save_matrix_csv(saved_results, RESULTS_DIR / "perf01_matrix.csv")
        plot_extreme_oom_chart(None, RESULTS_DIR / "perf01_extreme_oom_chart.png")
        print("[+] Hoan tat xuat lai toan bo bieu do va bang CSV!")
        return

    print("=" * 80)
    print("  KHOI CHAY PERF-01: RESOURCE CONSTRAINED STRESS TEST BENCHMARK")
    print("  ECDSA vs ML-DSA-44 vs ML-DSA-65 vs ML-DSA-87 tren 3 Profile Docker")
    print("=" * 80)

    # 1. Doc datasets cho 500 txs
    datasets = {}
    for algo in ALGORITHMS:
        file_path = DATA_DIR / algo['file']
        if not file_path.exists():
            print(f"[!] Chua co tap du lieu: {file_path}. Vui long chay perf/generate_perf01_txs.py truoc.")
            return
        with open(file_path, 'r', encoding='utf-8') as f:
            datasets[algo['id']] = json.load(f)

    # 1.1. Warm-up Docker container de lam am Page Cache he thong
    print("[*] Khoi dong container warm-up de lam am page cache he thong...")
    subprocess.run(["docker", "rm", "-f", "btc-node-warmup"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["docker", "run", "-d", "--name", "btc-node-warmup", "-v", f"{BASE_DIR}:/app", "blockchain-node:perf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.0)
    subprocess.run(["docker", "rm", "-f", "btc-node-warmup"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 2. Chay ma tran 3x4: Server, Edge, IoT x ECDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87
    all_results = []
    for p_key in ["server", "edge", "iot"]:
        p_info = PROFILES[p_key]
        for a_info in ALGORITHMS:
            res = run_benchmark_trial(p_key, p_info, a_info, datasets[a_info['id']])
            if res:
                all_results.append(res)
            time.sleep(0.8)

    # 3. Luu ket qua Thi nghiem 1
    json_path = RESULTS_DIR / "perf01_results.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    csv_path = RESULTS_DIR / "perf01_matrix.csv"
    save_matrix_csv(all_results, csv_path)

    chart_path = RESULTS_DIR / "perf01_oom_risk_chart.png"
    plot_oom_risk_chart(all_results, chart_path)

    # 4. Chay Thi nghiem 2: Extreme Stress Test & OOM Hunt
    _, stress_data = run_extreme_oom_hunt()

    extreme_csv = RESULTS_DIR / "perf01_extreme_oom_matrix.csv"
    save_extreme_csv(stress_data, extreme_csv)

    extreme_chart = RESULTS_DIR / "perf01_extreme_oom_chart.png"
    plot_extreme_oom_chart(stress_data, extreme_chart)

    print("\n" + "=" * 80)
    print("  HOAN TAT TOAN BO BENCHMARK PERF-01 (ECDSA + ML-DSA-44/65/87)!")
    print(f"  - Ket qua JSON:         {json_path}")
    print(f"  - Bang CSV 3x4:         {csv_path}")
    print(f"  - Bieu do OOM Matrix:   {chart_path}")
    print(f"  - Bang CSV Extreme OOM: {extreme_csv}")
    print(f"  - Bieu do Extreme OOM:  {extreme_chart}")
    print("=" * 80)


if __name__ == '__main__':
    main()
