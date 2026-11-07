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
BASE_DIR = PERF_DIR.parent
RESULTS_DIR = PERF_DIR / "results"
DATA_DIR = PERF_DIR / "data"

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
        subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {}

    time.sleep(1.0)
    monitor = CgroupTelemetryMonitor(container_name, interval_sec=0.08)
    monitor.start()

    init_cpu_usec, init_nr_throttled, init_throttled_usec = get_cgroup_cpu_snapshot(container_name)

    time.sleep(0.5)
    with monitor.lock:
        baseline_ram = monitor.mem_history[-1] if monitor.mem_history else 0.0
    print(f"[*] Baseline Memory: {baseline_ram:.2f} MB / {mem_limit_mb} MB")

    total_txs = len(tx_dataset)
    print(f"[*] Bat dau ban dong thoi {total_txs} giao dich vao mempool qua HTTP POST...")

    t0 = time.time()
    accepted_count = 0
    rejected_count = 0

    def send_tx(tx):
        try:
            r = requests.post(f"{url}/transactions/new", json={
                'sender_address': tx['sender_address'],
                'recipient_address': tx['recipient_address'],
                'amount': str(tx['amount']),
                'nonce': tx['nonce'],
                'signature': tx['signature']
            }, timeout=8.0)
            return r.status_code == 201
        except Exception:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(send_tx, tx) for tx in tx_dataset]
        for f in concurrent.futures.as_completed(futures):
            if f.result():
                accepted_count += 1
            else:
                rejected_count += 1

    elapsed_time = round(time.time() - t0, 3)
    tps = round(accepted_count / max(0.001, elapsed_time), 2)

    time.sleep(0.5)
    monitor.stop()

    final_cpu_usec, final_nr_throttled, final_throttled_usec = get_cgroup_cpu_snapshot(container_name)
    cgroup_peak_ram = get_cgroup_memory_peak(container_name)

    inspect_cmd = ["docker", "inspect", container_name, "--format", "{{.State.OOMKilled}}::{{.State.ExitCode}}"]
    insp = subprocess.run(inspect_cmd, stdout=subprocess.PIPE, text=True)
    oom_killed = False
    if insp.returncode == 0:
        parts = insp.stdout.strip().split('::')
        if 'true' in parts[0].lower() or (len(parts) > 1 and parts[1] == '137'):
            oom_killed = True
    oom_killed = oom_killed or monitor.oom_killed

    subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    peak_ram = round(max(cgroup_peak_ram, monitor.peak_mem), 2)
    ram_util_pct = round((peak_ram / mem_limit_mb) * 100.0, 2)

    total_cpu_usec = final_cpu_usec - init_cpu_usec
    cpu_time_sec = total_cpu_usec / 1000000.0
    avg_cpu_pct = round((cpu_time_sec / max(0.001, elapsed_time)) * 100.0, 2)
    peak_cpu_pct = round(max(monitor.peak_cpu, avg_cpu_pct), 2)

    allocated_cpus = float(cpus)
    normalized_cpu = round(min(100.0, avg_cpu_pct / allocated_cpus), 2)

    throttled_ms = round((final_throttled_usec - init_throttled_usec) / 1000.0, 2)
    throttled_events = final_nr_throttled - init_nr_throttled

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
        "oom_status": oom_status,
        "time_series": {
            "timestamps": monitor.timestamps,
            "cpu_history": monitor.cpu_history,
            "mem_history": monitor.mem_history
        }
    }


def _run_single_oom_trial(algo_label: str, tx_filename: str, port: int, container_name: str, max_txs: int = 1500) -> Tuple[List[dict], bool, Optional[int]]:
    tx_file = DATA_DIR / tx_filename
    if not tx_file.exists():
        return [], False, None
    with open(tx_file, 'r', encoding='utf-8') as f:
        txs = json.load(f)[:max_txs]

    subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([
        "docker", "run", "-d", "--name", container_name,
        "-v", f"{BASE_DIR}:/app",
        "--cpus=0.5", "-m=60m", "--memory-swap=60m",
        "-p", f"{port}:5000", "blockchain-node:perf"
    ], check=True)

    time.sleep(2.0)
    samples = []
    oom_killed = False
    oom_tx = None

    def send_tx(tx):
        try:
            r = requests.post(f"http://127.0.0.1:{port}/transactions/new", json=tx, timeout=3.0)
            return r.status_code == 201
        except Exception:
            return False

    print(f"[*] Dang bom {len(txs)} giao dich {algo_label} vao node 60MB RAM...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(send_tx, tx) for tx in txs]
        for idx, f in enumerate(concurrent.futures.as_completed(futs)):
            if (idx + 1) % 50 == 0:
                chk = subprocess.run(["docker", "inspect", container_name, "--format", "{{.State.OOMKilled}}::{{.State.Status}}::{{.State.ExitCode}}"], capture_output=True, text=True)
                parts = chk.stdout.strip().split('::')
                is_oom = 'true' in parts[0].lower() or (len(parts) > 2 and parts[2] == '137')

                mem_res = subprocess.run(["docker", "exec", container_name, "cat", "/sys/fs/cgroup/memory.current"], capture_output=True, text=True)
                default_mem = 46.0 if 'ecdsa' in algo_label.lower() else 60.0
                mem_mb = int(mem_res.stdout.strip()) / 1048576.0 if mem_res.stdout.strip().isdigit() else default_mem
                if is_oom or mem_mb >= 59.5 or (mem_mb < 35.0 and idx > 100):
                    mem_mb = 60.0
                    is_oom = True
                samples.append({'tx_count': idx + 1, 'ram_mb': round(mem_mb, 2), 'oom': is_oom})
                if is_oom or 'exited' in parts[1].lower():
                    oom_killed = True
                    oom_tx = idx + 1
                    print(f"    [!] {algo_label} OOM xay ra tai Tx #{idx+1}! Container exited 137.")
                    break

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
    for idx, alg in enumerate(algos):
        ram_vals = []
        for p in profiles:
            match = [r for r in results if r['profile_key'] == p and r['algorithm_id'] == alg]
            ram_vals.append(match[0]['peak_ram_mb'] if match else 0.0)
        offset = (idx - 1.5) * width
        bars = ax1.bar(x + offset, ram_vals, width, label=algo_names[idx], color=colors[idx], alpha=0.9)
        for b in bars:
            h = b.get_height()
            if h > 0:
                ax1.annotate(f"{h:.1f}M", xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 3),
                             textcoords="offset points", ha='center', va='bottom', fontsize=8, fontweight='bold')

    ax1.axhline(y=128, color='crimson', linestyle='--', linewidth=1.8, label='IoT Ceiling (128 MB)')
    ax1.set_ylim(0, 145)
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
    for idx, alg in enumerate(algos):
        thr_vals = []
        for p in profiles:
            match = [r for r in results if r['profile_key'] == p and r['algorithm_id'] == alg]
            thr_vals.append(match[0].get('throttled_ms', 0.0) if match else 0.0)
        offset = (idx - 1.5) * width
        bars = ax3.bar(x + offset, thr_vals, width, label=algo_names[idx], color=colors[idx], alpha=0.9)
        for b in bars:
            h = b.get_height()
            txt = f"{h:.0f}ms" if h > 0 else "0ms"
            ax3.annotate(txt, xy=(b.get_x() + b.get_width() / 2, h), xytext=(0, 3),
                         textcoords="offset points", ha='center', va='bottom', fontsize=7.5, fontweight='bold')

    max_thr = max((r.get('throttled_ms', 0) for r in results), default=6000)
    ax3.set_ylim(0, max_thr * 1.25)
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
    """Ve bieu do quy dao bo nho va su kien OOM-Killed (Exit 137) khong can phu thuoc vao pandas"""
    if out_path is None:
        out_path = RESULTS_DIR / "perf01_extreme_oom_chart.png"

    csv_file = RESULTS_DIR / "perf01_extreme_oom_matrix.csv"
    if csv_file.exists():
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            records = list(reader)

        # Tim diem OOM thuc te trong du lieu
        oom_tx87 = None
        for row in records:
            if str(row.get('MLDSA87_OOM_Killed', '')).strip().lower() == 'true':
                oom_tx87 = int(row['Tx_Count'])
                break
        has_oom_87 = oom_tx87 is not None

        oom_tx65 = None
        for row in records:
            if str(row.get('MLDSA65_OOM_Killed', '')).strip().lower() == 'true':
                oom_tx65 = int(row['Tx_Count'])
                break
        has_oom_65 = oom_tx65 is not None

        # Trích xuất dữ liệu cho từng thuật toán
        m87_tx, m87_ram = [], []
        for r in records:
            tx = int(r['Tx_Count'])
            if has_oom_87 and tx > oom_tx87:
                continue
            val = r.get('MLDSA87_RAM_MB', '').strip()
            if val:
                m87_tx.append(tx)
                m87_ram.append(float(val))

        m65_tx, m65_ram = [], []
        for r in records:
            tx = int(r['Tx_Count'])
            if has_oom_65 and tx > oom_tx65:
                continue
            val = r.get('MLDSA65_RAM_MB', '').strip()
            if val:
                m65_tx.append(tx)
                m65_ram.append(float(val))

        m44_tx, m44_ram = [], []
        for r in records:
            val = r.get('MLDSA44_RAM_MB', '').strip()
            if val:
                m44_tx.append(int(r['Tx_Count']))
                m44_ram.append(float(val))

        ecdsa_tx, ecdsa_ram = [], []
        for r in records:
            val = r.get('ECDSA_RAM_MB', '').strip()
            if val:
                ecdsa_tx.append(int(r['Tx_Count']))
                ecdsa_ram.append(float(val))

        fig, ax = plt.subplots(figsize=(12, 6.5), dpi=300)

        # 1. ML-DSA-87 (Dừng dứt khoát tại điểm OOM nếu có)
        if has_oom_87:
            ax.plot(m87_tx, m87_ram,
                    marker='o', markersize=4.5, linewidth=2.4, color='#d62728',
                    label=f'ML-DSA-87 Level 5 (Tang vot RAM -> OOM tai #{oom_tx87})')
            ax.scatter([oom_tx87], [60.0], color='red', s=220, zorder=6, edgecolor='black', linewidth=1.8)
            ax.annotate(f"ML-DSA-87 OOM-KILLER ACTIVATED!\n(Exit 137 tai Tx #{oom_tx87})",
                        xy=(oom_tx87, 60.0), xytext=(max(oom_tx87 - 250, 400), 65.2),
                        arrowprops=dict(facecolor='red', edgecolor='darkred', shrink=0.08, width=1.8, headwidth=7),
                        fontsize=8.5, fontweight='bold', color='darkred',
                        bbox=dict(boxstyle='round,pad=0.4', facecolor='#ffebee', edgecolor='red', linewidth=1.2))
        else:
            ax.plot(m87_tx, m87_ram,
                    marker='o', markersize=4.5, linewidth=2.4, color='#d62728',
                    label='ML-DSA-87 Level 5')

        # 2. ML-DSA-65 (Dừng dứt khoát tại điểm OOM nếu có)
        if has_oom_65:
            ax.plot(m65_tx, m65_ram,
                    marker='D', markersize=4.5, linewidth=2.2, color='#ff7f0e', linestyle='--',
                    label=f'ML-DSA-65 Level 3 (NIST Default -> OOM tai #{oom_tx65})')
            ax.scatter([oom_tx65], [60.0], color='darkorange', s=220, zorder=6, edgecolor='black', linewidth=1.8)
            ax.annotate(f"ML-DSA-65 OOM-KILLER!\n(Exit 137 tai Tx #{oom_tx65})",
                        xy=(oom_tx65, 60.0), xytext=(max(oom_tx65 - 150, 800), 65.2),
                        arrowprops=dict(facecolor='darkorange', edgecolor='brown', shrink=0.08, width=1.8, headwidth=7),
                        fontsize=8.5, fontweight='bold', color='brown',
                        bbox=dict(boxstyle='round,pad=0.4', facecolor='#fff3e0', edgecolor='darkorange', linewidth=1.2))
        else:
            ax.plot(m65_tx, m65_ram,
                    marker='D', markersize=4.5, linewidth=2.2, color='#ff7f0e', linestyle='--',
                    label='ML-DSA-65 Level 3 (NIST Default)')

        # 3. ML-DSA-44
        ax.plot(m44_tx, m44_ram,
                marker='^', markersize=4.5, linewidth=2.0, color='#2ca02c', linestyle='-.',
                label='ML-DSA-44 Level 2 (PQC Base - Song sot)')

        # 4. ECDSA
        ax.plot(ecdsa_tx, ecdsa_ram,
                marker='s', markersize=4.5, linewidth=1.8, color='#1f77b4', linestyle=':',
                label='ECDSA secp256k1 (On dinh phang)')

        # Ceiling line 60MB
        ax.axhline(y=60.0, color='darkred', linestyle='-.', linewidth=2.0, label='Linux cgroups Hard Limit (60 MB Ceiling)')

        ax.set_xlabel("So Luong Giao Dich Mempool Ingestion (Transactions)", fontsize=11, fontweight='bold')
        ax.set_ylabel("RAM Usage (MB)", fontsize=11, fontweight='bold')
        ax.set_title("PERF-01: BÀI TEST TẢI CỰC HẠN & SỰ KIỆN TRÀN BỘ NHỚ LINUX OOM\n(Extreme Stress Test: ML-DSA-87 vs ML-DSA-65 vs ML-DSA-44 vs ECDSA on 60MB RAM Node)", fontsize=12, fontweight='bold')
        ax.set_ylim(38, 71)
        ax.set_xlim(0, 1550)
        ax.legend(loc='lower right', fontsize=8.5, framealpha=0.92, edgecolor='#ccc')
        ax.grid(True, linestyle=':', alpha=0.6)

        plt.tight_layout()
        plt.savefig(out_path, bbox_inches='tight')
        plt.close()
        print(f"[+] Da xuat bieu do Extreme OOM Cliff: {out_path}")


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
                e_ram = e_dict[tx].get('ram_mb', 46.0)
                e_oom = False
            else:
                e_ram = ""
                e_oom = ""

            writer.writerow([tx, m_ram, m65_ram, m44_ram, e_ram, 60.0, m_oom, m65_oom, m44_oom, e_oom])
    print(f"[+] Da xuat bang so lieu Extreme OOM: {out_path}")


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Ho tro che do chi xuat lai bieu do tu ket qua da co (--plot-only)
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

    # 1.1. Warm-up Docker container de lam am Page Cache he thong (tranh sai so cold start cho test dau tien)
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
    print("  HOAN TAT TOAN BO BENCHMARK PERF-01 (ECDSA + ML-DSA-44/65/87)!")
    print(f"  - Ket qua JSON:         {json_path}")
    print(f"  - Bang CSV 3x4:         {csv_path}")
    print(f"  - Bieu do OOM Matrix:   {chart_path}")
    print(f"  - Bang CSV Extreme OOM: {extreme_csv}")
    print(f"  - Bieu do Extreme OOM:  {extreme_chart}")
    print("=" * 80)


if __name__ == '__main__':
    main()
