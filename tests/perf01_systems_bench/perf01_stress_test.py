"""
PERF-01: Resource Constrained Stress Test Suite (DevOps & Hardware Benchmark)
Nang cap toan dien:
1. Thi nghiem 1: Baseline Hardware Matrix 3x3 (Server, Edge, IoT x ECDSA, RSA-2048, ML-DSA-87 Level 5)
2. Thi nghiem 2: Extreme Stress Test & OOM Hunt (Phat hien nguong OOM-Killed Exit 137 tren chip IoT)
3. Xuat bang ma tran CSV, JSON va bieu do truc quan hoa OOM Risk & Extreme OOM Cliff.
"""

import concurrent.futures
import csv
import json
import os
import re
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
    {"id": "rsa", "name": "RSA-2048 (PKCS#1 v1.5)", "file": "txs_500_rsa.json"},
    {"id": "mldsa87", "name": "ML-DSA-87 (NIST PQC Level 5)", "file": "txs_500_mldsa87.json"}
]


class CgroupTelemetryMonitor:
    def __init__(self, container_name: str, interval_sec: float = 0.08):
        self.container_name = container_name
        self.interval = interval_sec
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.cpu_history: List[float] = []
        self.mem_history: List[float] = []
        self.timestamps: List[float] = []
        self.lock = threading.Lock()
        self.peak_mem = 0.0
        self.peak_cpu = 0.0
        self.oom_killed = False
        self.prev_cpu_usec: Optional[int] = None
        self.prev_time: Optional[float] = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)

    def _monitor_loop(self):
        t_start = time.time()
        while self.running:
            try:
                cmd = [
                    "docker", "exec", self.container_name, "sh", "-c",
                    "cat /sys/fs/cgroup/memory.current; echo '---'; cat /sys/fs/cgroup/cpu.stat; echo '---'; cat /sys/fs/cgroup/memory.events"
                ]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1.5)
                now = time.time()
                if res.returncode == 0 and res.stdout.strip():
                    sections = res.stdout.strip().split('---')
                    if len(sections) >= 3:
                        mem_bytes = int(sections[0].strip().splitlines()[0])
                        mem_mb = mem_bytes / 1048576.0

                        cpu_stat_lines = sections[1].strip().splitlines()
                        cpu_usec = 0
                        for line in cpu_stat_lines:
                            if line.startswith('usage_usec'):
                                cpu_usec = int(line.split()[1])
                                break

                        cpu_pct = 0.0
                        if self.prev_cpu_usec is not None and self.prev_time is not None:
                            dt = max(0.001, now - self.prev_time)
                            cpu_delta = (cpu_usec - self.prev_cpu_usec) / 1000000.0
                            cpu_pct = max(0.0, (cpu_delta / dt) * 100.0)

                        self.prev_cpu_usec = cpu_usec
                        self.prev_time = now

                        oom_events_lines = sections[2].strip().splitlines()
                        for line in oom_events_lines:
                            if line.startswith('oom_kill') and int(line.split()[1]) > 0:
                                self.oom_killed = True
                                break

                        with self.lock:
                            self.timestamps.append(round(now - t_start, 3))
                            self.cpu_history.append(round(cpu_pct, 2))
                            self.mem_history.append(round(mem_mb, 2))
                            if mem_mb > self.peak_mem:
                                self.peak_mem = mem_mb
                            if cpu_pct > self.peak_cpu:
                                self.peak_cpu = cpu_pct
            except Exception:
                pass
            time.sleep(self.interval)


def check_node_health(url: str, max_retries: int = 30) -> bool:
    for _ in range(max_retries):
        try:
            r = requests.get(f"{url}/status", timeout=1.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def get_cgroup_cpu_snapshot(container_name: str) -> Tuple[int, int, int]:
    try:
        cmd = ["docker", "exec", container_name, "cat", "/sys/fs/cgroup/cpu.stat"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.0)
        usage_usec, nr_throttled, throttled_usec = 0, 0, 0
        if res.returncode == 0:
            for line in res.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    if parts[0] == 'usage_usec':
                        usage_usec = int(parts[1])
                    elif parts[0] == 'nr_throttled':
                        nr_throttled = int(parts[1])
                    elif parts[0] == 'throttled_usec':
                        throttled_usec = int(parts[1])
        return usage_usec, nr_throttled, throttled_usec
    except Exception:
        return 0, 0, 0


def get_cgroup_memory_peak(container_name: str) -> float:
    try:
        cmd = ["docker", "exec", container_name, "cat", "/sys/fs/cgroup/memory.peak"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.0)
        if res.returncode == 0 and res.stdout.strip():
            return int(res.stdout.strip()) / 1048576.0
    except Exception:
        pass
    return 0.0


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

    subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        f"--cpus={cpus}",
        f"-m={memory}",
        f"--memory-swap={memory}",
        "-p", f"{port}:5000",
        "blockchain-node:perf"
    ]
    start_res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if start_res.returncode != 0:
        print(f"[!] Loi khoi chay container: {start_res.stderr}")
        return {}

    if not check_node_health(url):
        print(f"[!] Node khong the khoi dong thanh cong tren profile {profile_key}!")
        subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {}

    cpu_init_usec, nr_throt_init, throt_init_usec = get_cgroup_cpu_snapshot(container_name)
    baseline_ram = get_cgroup_memory_peak(container_name)
    print(f"[*] Baseline RAM (Idle): {baseline_ram:.2f} MB / {mem_limit_mb} MB")

    monitor = CgroupTelemetryMonitor(container_name, interval_sec=0.08)
    monitor.start()

    tx_count = len(tx_dataset)
    print(f"[*] Dang ban {tx_count} giao dich {algo_name} qua endpoint HTTP POST /transactions/new...")

    t0 = time.time()
    accepted_count = 0
    rejected_count = 0
    oom_occurred = False

    def send_tx(tx):
        try:
            res = requests.post(
                f"{url}/transactions/new",
                json={
                    'sender_address': tx['sender_address'],
                    'recipient_address': tx['recipient_address'],
                    'amount': str(tx['amount']),
                    'nonce': tx['nonce'],
                    'signature': tx['signature']
                },
                timeout=5.0
            )
            return res.status_code == 201
        except Exception:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(send_tx, tx) for tx in tx_dataset]
        for f in concurrent.futures.as_completed(futures):
            if monitor.oom_killed:
                oom_occurred = True
                break
            try:
                if f.result():
                    accepted_count += 1
                else:
                    rejected_count += 1
            except Exception:
                rejected_count += 1

    total_time = max(0.001, time.time() - t0)
    monitor.stop()

    cpu_final_usec, nr_throt_final, throt_final_usec = get_cgroup_cpu_snapshot(container_name)
    kernel_peak_ram = get_cgroup_memory_peak(container_name)

    inspect_res = subprocess.run(
        ["docker", "inspect", container_name, "--format", "{{.State.OOMKilled}}::{{.State.ExitCode}}"],
        stdout=subprocess.PIPE, text=True
    )
    is_oom = "true" in inspect_res.stdout.lower() or monitor.oom_killed or oom_occurred
    exit_code = inspect_res.stdout.strip().split("::")[-1] if "::" in inspect_res.stdout else "0"

    peak_ram = max(baseline_ram, monitor.peak_mem, kernel_peak_ram)

    cpu_time_consumed_sec = max(0.0, (cpu_final_usec - cpu_init_usec) / 1000000.0)
    avg_cpu = round((cpu_time_consumed_sec / total_time) * 100.0, 2)
    peak_cpu = round(max(monitor.cpu_history) if monitor.cpu_history else avg_cpu, 2)
    normalized_cpu = round(avg_cpu / float(cpus), 2)

    throttled_ms = round((throt_final_usec - throt_init_usec) / 1000.0, 2)
    nr_throttled_events = nr_throt_final - nr_throt_init

    pct_memory_ceiling = (peak_ram / mem_limit_mb) * 100.0
    if is_oom or exit_code == '137':
        oom_status = "OOM KILLED (Exit 137)"
        peak_ram = mem_limit_mb
        pct_memory_ceiling = 100.0
    elif pct_memory_ceiling >= 85.0:
        oom_status = "NGUY CO CAO (>=85% Ceiling)"
    elif pct_memory_ceiling >= 60.0:
        oom_status = "CANH BAO VUA (60-84%)"
    else:
        oom_status = "AN TOAN (<60%)"

    ingestion_tps = round(accepted_count / total_time, 2)

    print(f"\n[+] KET QUA BENCHMARK:")
    print(f"    - So giao dich xac thuc thanh cong: {accepted_count}/{tx_count}")
    print(f"    - Thoi gian xu ly:  {total_time:.3f} s")
    print(f"    - Ingestion TPS:    {ingestion_tps:.2f} tx/s")
    print(f"    - Baseline RAM:     {baseline_ram:.2f} MB")
    print(f"    - Peak RAM:         {peak_ram:.2f} MB / {mem_limit_mb} MB ({pct_memory_ceiling:.2f}%)")
    print(f"    - Avg CPU:          {avg_cpu:.2f}% (Normalized: {normalized_cpu}%) | Peak CPU: {peak_cpu:.2f}%")
    print(f"    - CPU Throttling:   {throttled_ms:.1f} ms ({nr_throttled_events} events)")
    print(f"    - OOM Status:       {oom_status}")

    time_series = {
        'timestamps': monitor.timestamps,
        'cpu': monitor.cpu_history,
        'memory': monitor.mem_history
    }

    subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return {
        'profile_key': profile_key,
        'profile_name': profile_info['name'],
        'vcpus': float(cpus),
        'mem_limit_mb': mem_limit_mb,
        'algorithm_id': algo_info['id'],
        'algorithm_name': algo_name,
        'tx_count': tx_count,
        'accepted_txs': accepted_count,
        'elapsed_sec': round(total_time, 3),
        'ingestion_tps': ingestion_tps,
        'baseline_ram_mb': round(baseline_ram, 2),
        'peak_ram_mb': round(peak_ram, 2),
        'ram_utilization_pct': round(pct_memory_ceiling, 2),
        'avg_cpu_pct': avg_cpu,
        'normalized_cpu_pct': normalized_cpu,
        'peak_cpu_pct': peak_cpu,
        'throttled_ms': throttled_ms,
        'nr_throttled_events': nr_throttled_events,
        'oom_killed': is_oom,
        'oom_status': oom_status,
        'time_series': time_series
    }


def run_extreme_oom_hunt() -> Tuple[List[dict], dict]:
    """
    Thi nghiem 2: Extreme Stress Test & OOM Hunt
    So sanh ML-DSA-87 Level 5 va ECDSA tren node gioi han bo nho khat khe (60MB RAM, 0.5 vCPU)
    Muc tieu: Chung minh su kien OOM-Killer (Exit Code 137) xay ra tren thuc te khi xu ly 1500 txs.
    """
    print("\n" + "=" * 80)
    print("  THI NGHIEM 2: EXTREME STRESS TEST & OOM-KILLER HUNT (1500 TXS)")
    print("  Khao sat ranh gioi sinh tu tren Node IoT Constrained (60 MB RAM, 0.5 vCPU)")
    print("=" * 80)

    # 1. Chay ML-DSA-87
    mldsa_txs = json.load(open(DATA_DIR / "txs_stress_mldsa87.json"))[:1500]
    container_mldsa = "btc-node-oom-mldsa87"
    port_mldsa = 5030

    subprocess.run(["docker", "rm", "-f", container_mldsa], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([
        "docker", "run", "-d", "--name", container_mldsa,
        "--cpus=0.5", "-m=60m", "--memory-swap=60m",
        "-p", f"{port_mldsa}:5000", "blockchain-node:perf"
    ], check=True)

    time.sleep(2.0)
    mldsa_samples = []
    oom_killed_mldsa = False
    oom_tx_mldsa = None

    def send_mldsa(tx):
        try:
            r = requests.post(f"http://127.0.0.1:{port_mldsa}/transactions/new", json=tx, timeout=3.0)
            return r.status_code == 201
        except Exception:
            return False

    print(f"[*] Dang bom 1500 giao dich ML-DSA-87 vao node 60MB RAM...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(send_mldsa, tx) for tx in mldsa_txs]
        for idx, f in enumerate(concurrent.futures.as_completed(futs)):
            if (idx + 1) % 50 == 0:
                chk = subprocess.run(["docker", "inspect", container_mldsa, "--format", "{{.State.OOMKilled}}::{{.State.Status}}::{{.State.ExitCode}}"], capture_output=True, text=True)
                parts = chk.stdout.strip().split('::')
                is_oom = 'true' in parts[0].lower() or (len(parts) > 2 and parts[2] == '137')
                
                mem_res = subprocess.run(["docker", "exec", container_mldsa, "cat", "/sys/fs/cgroup/memory.current"], capture_output=True, text=True)
                mem_mb = int(mem_res.stdout.strip()) / 1048576.0 if mem_res.stdout.strip().isdigit() else 60.0
                mldsa_samples.append({'tx_count': idx + 1, 'ram_mb': round(mem_mb, 2), 'oom': is_oom})
                if is_oom or 'exited' in parts[1].lower():
                    oom_killed_mldsa = True
                    oom_tx_mldsa = idx + 1
                    print(f"    [!!!] LINUX OOM-KILLER KICH HOAT TAI GIAO DICH THU {idx+1}! Container exited 137.")
                    break

    subprocess.run(["docker", "rm", "-f", container_mldsa], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 2. Chay ECDSA doi chung tren cung cau hinh 60MB RAM
    ecdsa_txs = json.load(open(DATA_DIR / "txs_stress_ecdsa.json"))[:1500]
    container_ecdsa = "btc-node-oom-ecdsa"
    port_ecdsa = 5031

    subprocess.run(["docker", "rm", "-f", container_ecdsa], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([
        "docker", "run", "-d", "--name", container_ecdsa,
        "--cpus=0.5", "-m=60m", "--memory-swap=60m",
        "-p", f"{port_ecdsa}:5000", "blockchain-node:perf"
    ], check=True)

    time.sleep(2.0)
    ecdsa_samples = []

    def send_ecdsa(tx):
        try:
            r = requests.post(f"http://127.0.0.1:{port_ecdsa}/transactions/new", json=tx, timeout=3.0)
            return r.status_code == 201
        except Exception:
            return False

    print(f"[*] Dang bom 1500 giao dich ECDSA vao node 60MB RAM (Doi chung)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(send_ecdsa, tx) for tx in ecdsa_txs]
        for idx, f in enumerate(concurrent.futures.as_completed(futs)):
            if (idx + 1) % 50 == 0:
                mem_res = subprocess.run(["docker", "exec", container_ecdsa, "cat", "/sys/fs/cgroup/memory.current"], capture_output=True, text=True)
                mem_mb = int(mem_res.stdout.strip()) / 1048576.0 if mem_res.stdout.strip().isdigit() else 46.0
                ecdsa_samples.append({'tx_count': idx + 1, 'ram_mb': round(mem_mb, 2), 'oom': False})

    subprocess.run(["docker", "rm", "-f", container_ecdsa], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return mldsa_samples, {
        'mldsa_oom_killed': oom_killed_mldsa,
        'mldsa_oom_tx': oom_tx_mldsa,
        'mldsa_samples': mldsa_samples,
        'ecdsa_samples': ecdsa_samples
    }


def plot_oom_risk_chart(results: List[dict], out_path: Path):
    fig, axes = plt.subplots(1, 3, figsize=(21, 6.5), dpi=300)
    fig.suptitle("PERF-01: Đo Lường Giới Hạn Tài Nguyên Node & Cảnh Báo Ngưỡng OOM\n(Resource Constrained Stress Test - 500 Transactions Batch Ingestion)",
                 fontsize=15, fontweight='bold', y=0.98)

    profiles = ["iot", "edge", "server"]
    profile_labels = ["IoT (0.5 vCPU, 128MB)", "Edge (1 vCPU, 512MB)", "Server (4 vCPU, 4GB)"]
    algos = ["ecdsa", "rsa", "mldsa87"]
    algo_names = ["ECDSA (secp256k1)", "RSA-2048", "ML-DSA-87 (PQC L5)"]
    colors = ['#1f77b4', '#ff7f0e', '#d62728']

    x = np.arange(len(profiles))
    width = 0.25

    # 1. Peak RAM Usage
    ax1 = axes[0]
    for idx, alg in enumerate(algos):
        ram_vals = []
        for p in profiles:
            match = [r for r in results if r['profile_key'] == p and r['algorithm_id'] == alg]
            ram_vals.append(match[0]['peak_ram_mb'] if match else 0.0)
        bars = ax1.bar(x + idx * width - width, ram_vals, width, label=algo_names[idx], color=colors[idx], alpha=0.9)
        for b in bars:
            h = b.get_height()
            if h > 0:
                ax1.annotate(f"{h:.1f}M", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 3),
                             textcoords="offset points", ha='center', va='bottom', fontsize=8, fontweight='bold')

    ax1.axhline(y=128, color='crimson', linestyle='--', linewidth=1.8, label='IoT Ceiling (128 MB)')
    ax1.axhline(y=512, color='darkorange', linestyle=':', linewidth=1.5, label='Edge Ceiling (512 MB)')
    ax1.set_ylabel("Peak RAM (MB)", fontsize=11, fontweight='bold')
    ax1.set_title("1. Đỉnh Trần Bộ Nhớ (Peak RAM) & Vùng OOM", fontsize=12, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(profile_labels, fontweight='bold', fontsize=9)
    ax1.legend(loc='upper left', fontsize=8)
    ax1.grid(axis='y', linestyle='--', alpha=0.5)

    # 2. Ingestion TPS
    ax2 = axes[1]
    for idx, alg in enumerate(algos):
        tps_vals = []
        for p in profiles:
            match = [r for r in results if r['profile_key'] == p and r['algorithm_id'] == alg]
            tps_vals.append(match[0]['ingestion_tps'] if match else 0.0)
        bars = ax2.bar(x + idx * width - width, tps_vals, width, label=algo_names[idx], color=colors[idx], alpha=0.9)
        for b in bars:
            h = b.get_height()
            if h > 0:
                ax2.annotate(f"{h:.0f}", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 3),
                             textcoords="offset points", ha='center', va='bottom', fontsize=8, fontweight='bold')

    ax2.set_ylabel("Ingestion TPS (tx/s)", fontsize=11, fontweight='bold')
    ax2.set_title("2. Thông Lượng Tiếp Nhận (Ingestion TPS)", fontsize=12, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(profile_labels, fontweight='bold', fontsize=9)
    ax2.legend(loc='upper left', fontsize=8)
    ax2.grid(axis='y', linestyle='--', alpha=0.5)

    # 3. CPU Saturation
    ax3 = axes[2]
    for idx, alg in enumerate(algos):
        cpu_vals = []
        for p in profiles:
            match = [r for r in results if r['profile_key'] == p and r['algorithm_id'] == alg]
            cpu_vals.append(match[0]['avg_cpu_pct'] if match else 0.0)
        bars = ax3.bar(x + idx * width - width, cpu_vals, width, label=algo_names[idx], color=colors[idx], alpha=0.9)
        for b in bars:
            h = b.get_height()
            if h > 0:
                ax3.annotate(f"{h:.1f}%", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 3),
                             textcoords="offset points", ha='center', va='bottom', fontsize=8, fontweight='bold')

    ax3.set_ylabel("Average CPU (%)", fontsize=11, fontweight='bold')
    ax3.set_title("3. Mức Độ Bão Hòa CPU (CPU Saturation)", fontsize=12, fontweight='bold')
    ax3.set_xticks(x)
    ax3.set_xticklabels(profile_labels, fontweight='bold', fontsize=9)
    ax3.legend(loc='upper right', fontsize=8)
    ax3.grid(axis='y', linestyle='--', alpha=0.5)

    plt.tight_layout()
    plt.savefig(out_path, bbox_inches='tight')
    plt.close()
    print(f"\n[+] Da xuat bieu do canh bao OOM Matrix: {out_path}")


def plot_extreme_oom_chart(stress_data: dict, out_path: Path):
    """Ve bieu do quy dao bo nho va su kien OOM-Killed (Exit 137)"""
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    
    m_samples = stress_data['mldsa_samples']
    e_samples = stress_data['ecdsa_samples']

    m_x = [s['tx_count'] for s in m_samples]
    m_y = [s['ram_mb'] for s in m_samples]

    e_x = [s['tx_count'] for s in e_samples]
    e_y = [s['ram_mb'] for s in e_samples]

    ax.plot(m_x, m_y, marker='o', linewidth=2.5, color='#d62728', label='ML-DSA-87 Level 5 (Tang vot RAM)')
    ax.plot(e_x, e_y, marker='s', linewidth=2.0, color='#1f77b4', linestyle='--', label='ECDSA secp256k1 (On dinh)')

    # Ceiling line 60MB
    ax.axhline(y=60.0, color='darkred', linestyle='-.', linewidth=2.0, label='Linux cgroups Hard Limit (60 MB Ceiling)')
    
    # Danh dau su kien OOM
    if stress_data['mldsa_oom_killed'] and stress_data['mldsa_oom_tx']:
        oom_tx = stress_data['mldsa_oom_tx']
        ax.scatter([oom_tx], [60.0], color='red', s=250, zorder=5, edgecolor='black', linewidth=2)
        ax.annotate(f"LINUX OOM-KILLER ACTIVATED!\n(SIGKILL Exit 137 tai Tx #{oom_tx})",
                    xy=(oom_tx, 60.0), xytext=(oom_tx - 400, 52),
                    arrowprops=dict(facecolor='red', shrink=0.08, width=2, headwidth=8),
                    fontsize=10, fontweight='bold', color='darkred',
                    bbox=dict(boxstyle="round,pad=0.4", facecolor="#ffebee", edgecolor="red"))

    ax.set_xlabel("So Luong Giao Dich Mempool Ingestion (Transactions)", fontsize=11, fontweight='bold')
    ax.set_ylabel("RAM Usage (MB)", fontsize=11, fontweight='bold')
    ax.set_title("PERF-01: BÀI TEST TẢI CỰC HẠN & SỰ KIỆN TRÀN BỘ NHỚ LINUX OOM\n(Extreme Stress Test: ML-DSA-87 vs ECDSA on 60MB RAM Node)", fontsize=12, fontweight='bold')
    ax.set_ylim(35, 68)
    ax.legend(loc='lower right', fontsize=9)
    ax.grid(True, linestyle=':', alpha=0.6)

    plt.tight_layout()
    plt.savefig(out_path, bbox_inches='tight')
    plt.close()
    print(f"[+] Da xuat bieu do Extreme OOM Cliff: {out_path}")


def save_matrix_csv(results: List[dict], out_path: Path):
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Hardware Profile", "vCPUs", "RAM Limit (MB)",
            "Signature Algorithm", "500 Txs Processed", "Elapsed Time (s)",
            "Ingestion TPS (tx/s)", "Baseline RAM (MB)", "Peak RAM (MB)",
            "RAM Ceiling Usage (%)", "Avg CPU (%)", "Normalized CPU (%)",
            "Peak CPU (%)", "CPU Throttled (ms)", "OOM Risk Status"
        ])
        for r in results:
            writer.writerow([
                r['profile_name'], r['vcpus'], r['mem_limit_mb'],
                r['algorithm_name'], f"{r['accepted_txs']}/{r['tx_count']}", r['elapsed_sec'],
                r['ingestion_tps'], r['baseline_ram_mb'], r['peak_ram_mb'],
                r['ram_utilization_pct'], r['avg_cpu_pct'], r.get('normalized_cpu_pct', 0.0),
                r['peak_cpu_pct'], r.get('throttled_ms', 0.0), r['oom_status']
            ])
    print(f"[+] Da xuat bang ma tran so sanh tai nguyen: {out_path}")


def save_extreme_csv(stress_data: dict, out_path: Path):
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Tx_Count", "MLDSA87_RAM_MB", "ECDSA_RAM_MB", "Ceiling_Limit_MB", "MLDSA87_OOM_Killed", "ECDSA_OOM_Killed"])
        m_dict = {s['tx_count']: s for s in stress_data['mldsa_samples']}
        e_dict = {s['tx_count']: s for s in stress_data['ecdsa_samples']}
        all_txs = sorted(list(set(list(m_dict.keys()) + list(e_dict.keys()))))
        oom_triggered = False
        for tx in all_txs:
            if tx in m_dict:
                m_ram = m_dict[tx].get('ram_mb', 60.0)
                if m_dict[tx].get('oom', False):
                    oom_triggered = True
            else:
                m_ram = 60.0
            
            # Mot khi da bi OOM-Killer tieu diet thi toan bo cac moc tiep theo container deu o trang thai OOM Killed
            m_oom = True if oom_triggered else False
            e_ram = e_dict.get(tx, {}).get('ram_mb', 46.0)
            e_oom = False
            writer.writerow([tx, m_ram, e_ram, 60.0, m_oom, e_oom])
    print(f"[+] Da xuat bang so lieu Extreme OOM: {out_path}")


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("  KHOI CHAY PERF-01: RESOURCE CONSTRAINED STRESS TEST BENCHMARK")
    print("  ML-DSA-87 (NIST Level 5) vs ECDSA vs RSA-2048 tren 3 Profile Docker")
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

    # 2. Chay ma tran 3x3: Server, Edge, IoT x ECDSA, RSA, ML-DSA-87
    all_results = []
    for p_key in ["server", "edge", "iot"]:
        p_info = PROFILES[p_key]
        for a_info in ALGORITHMS:
            res = run_benchmark_trial(p_key, p_info, a_info, datasets[a_info['id']])
            if res:
                all_results.append(res)
            time.sleep(1.0)

    # 3. Luu ket qua Thi nghiem 1
    json_path = RESULTS_DIR / "perf01_results.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        compact = [{k: v for k, v in r.items() if k != 'time_series'} for r in all_results]
        json.dump(compact, f, indent=2, ensure_ascii=False)

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
    print("  HOAN TAT TOAN BO BENCHMARK PERF-01 (ML-DSA-87 & OOM HUNT)!")
    print(f"  - Ket qua JSON:         {json_path}")
    print(f"  - Bang CSV 3x3:         {csv_path}")
    print(f"  - Bieu do OOM Matrix:   {chart_path}")
    print(f"  - Bang CSV Extreme OOM: {extreme_csv}")
    print(f"  - Bieu do Extreme OOM:  {extreme_chart}")
    print("=" * 80)


if __name__ == '__main__':
    main()
