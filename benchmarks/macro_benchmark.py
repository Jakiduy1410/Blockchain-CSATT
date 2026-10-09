"""
Macro-Benchmark Suite: End-to-End P2P Network Load & Consensus Benchmark
Measures: Real-world HTTP vs HTTPS (TLS with Classical ECDHE & Post-Quantum KEMs)
KEMs Tested:
- ECDHE (secp256r1 / NIST P-256)
- ECDHE (X25519 / Curve25519)
- ML-KEM-768 (Kyber-768 / NIST FIPS 203)
- FrodoKEM-640 (Unstructured LWE / NIST Round 3)
- HQC-128 (Hamming Quasi-Cyclic / NIST Round 4)
Transaction Signature: ECDSA (secp256k1)
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
import urllib3

# Vô hiệu hóa cảnh báo chứng chỉ tự ký khi chạy mạng nội bộ thử nghiệm
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Import KEM Suite
try:
    from benchmarks.kem_suite import perform_kem_handshake, KEM_CATALOG
except ImportError:
    from kem_suite import perform_kem_handshake, KEM_CATALOG


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


def kill_processes(processes: List[subprocess.Popen]):
    """Dọn dẹp triệt để các tiến trình node trên đa nền tảng."""
    for p in processes:
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(p.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            else:
                p.terminate()
                p.wait(timeout=2)
        except Exception:
            pass


def is_node_online(url: str, timeout: float = 1.0) -> bool:
    """Check if a node is listening and healthy."""
    try:
        res = requests.get(f"{url.rstrip('/')}/status", timeout=timeout, verify=False)
        return res.status_code == 200
    except Exception:
        return False


def ensure_certificates(base_dir: Path) -> Tuple[Path, Path]:
    """Đảm bảo chứng chỉ TLS hợp lệ sẵn sàng."""
    certs_dir = base_dir / "certs"
    cert_path = certs_dir / "server.crt"
    key_path = certs_dir / "server.key"

    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    certs_dir.mkdir(parents=True, exist_ok=True)
    print("[*] Khong tim thay chung chi TLS. Tu dong sinh chung chi tai certs/...")
    try:
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path),
            "-out", str(cert_path),
            "-days", "365", "-nodes",
            "-subj", "/CN=127.0.0.1/O=Blockchain-CSATT"
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(f"[+] Da tao chung chi thanh cong: {cert_path}")
        return cert_path, key_path
    except Exception as e:
        raise RuntimeError(f"Khong the tu sinh chung chi TLS: {e}")


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


def spawn_6nodes_mesh(base_dir: Path, use_tls: bool = False) -> List[subprocess.Popen]:
    """Khởi động mạng 6-Node P2P Mesh."""
    net_cfg_path = base_dir / "configs" / "network_6nodes.json"
    if not net_cfg_path.exists():
        net_cfg_path = base_dir.parent / "configs" / "network_6nodes.json"

    with open(net_cfg_path, 'r', encoding='utf-8') as f:
        net_cfg = json.load(f)

    scheme = "HTTPS" if use_tls else "HTTP"
    print(f"\n[*] Khoi dong tu dong mang 6 Node P2P Mesh ({scheme})...")
    spawned_processes = []
    py_cmd = get_python_cmd()

    for node in net_cfg['nodes']:
        cmd = py_cmd + ['blockchain/blockchain.py', '-p', str(node['port'])]
        if use_tls:
            cmd.append('--tls')
        if node.get('is_miner'):
            cmd.append('--miner')
        if node.get('peers'):
            cmd.extend(['--peers', ','.join(node['peers'])])

        work_dir = str(base_dir if (base_dir / "blockchain").exists() else base_dir.parent)
        p = subprocess.Popen(cmd, cwd=work_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        spawned_processes.append(p)

    return spawned_processes


def wait_for_nodes_ready(nodes: List[str], max_retries: int = 25) -> bool:
    """Chờ mạng 6-Node sẵn sàng kết nối."""
    for _ in range(max_retries):
        time.sleep(0.5)
        if all(is_node_online(u, timeout=0.5) for u in nodes):
            return True
    return False


def run_macro_benchmark_kem(
    config: dict,
    base_dir: Path,
    out_dir: Path,
    kem_key: str = "secp256r1",
    spawned_processes: Optional[List[subprocess.Popen]] = None
) -> Dict:
    """
    Thực hiện kiểm thử Macro-Benchmark cho một KEM cụ thể qua kênh TLS:
    - Kênh TLS đàm phán KEM chỉ định
    - Chữ ký số giao dịch: ECDSA secp256k1
    - Ghi nhận chi tiết ra macro_<kem>_raw.csv và macro_<kem>_summary.json
    """
    kem_key = kem_key.lower().strip()
    kem_info = KEM_CATALOG.get(kem_key, {
        'name': kem_key,
        'category': 'Unknown',
        'subfamily': 'Unknown',
        'nist_level': 'N/A',
        'quantum_resistant': False,
        'pk_size': 0,
        'ct_size': 0,
        'shared_secret_size': 0
    })

    macro_cfg = config.get('macro', {})
    tx_count = macro_cfg.get('tx_count', 30)

    raw_ingress = macro_cfg.get('ingress_url', "https://127.0.0.1:5000")
    raw_miner = macro_cfg.get('miner_url', "https://127.0.0.1:5001")
    raw_nodes = macro_cfg.get('nodes', [
        "https://127.0.0.1:5000", "https://127.0.0.1:5001", "https://127.0.0.1:5002",
        "https://127.0.0.1:5003", "https://127.0.0.1:5004", "https://127.0.0.1:5005"
    ])

    ingress_url = raw_ingress.replace("http://", "https://")
    miner_url = raw_miner.replace("http://", "https://")
    nodes = [u.replace("http://", "https://") for u in raw_nodes]

    print("=" * 85)
    print(f"  MACRO-BENCHMARK: TLS KEY EXCHANGE [{kem_info['name'].upper()}]")
    print(f"  * Phan loai KEM:          {kem_info['category']} ({kem_info['subfamily']})")
    print(f"  * Khang luong tu:         {'CO (Quantum-Safe)' if kem_info['quantum_resistant'] else 'KHONG (Classical ECC)'}")
    print(f"  * Kich thuoc goi KEM:     PK: {kem_info['pk_size']} B | CT: {kem_info['ct_size']} B | Wire: {kem_info['pk_size'] + kem_info['ct_size']} B")
    print(f"  * Chu ky so giao dich:    ECDSA (secp256k1)")
    print(f"  * So luong ban tai:       {tx_count} Transactions -> Ingress: {ingress_url}")
    print("=" * 85)

    ensure_certificates(base_dir)

    internal_spawned = []
    if spawned_processes is None and not all(is_node_online(u) for u in nodes):
        internal_spawned = spawn_6nodes_mesh(base_dir, use_tls=True)
        if not wait_for_nodes_ready(nodes):
            kill_processes(internal_spawned)
            raise RuntimeError("Khong the khoi dong mang 6 Node qua HTTPS/TLS!")

    try:
        # Lấy chain length ban đầu
        initial_status = {}
        for u in nodes:
            try:
                res = requests.get(f"{u}/status", timeout=3.0, verify=False).json()
                initial_status[u] = res['chain_length']
            except Exception:
                initial_status[u] = 1
        base_chain_len = max(initial_status.values())

        # Sinh tập giao dịch hợp lệ có chữ ký ECDSA
        wallets = load_wallets(base_dir)
        if not wallets:
            raise RuntimeError("Khong tim thay vi mau configs/wallets.json")
        alice = wallets.get('Alice')
        bob = wallets.get('Bob')

        test_txs = []
        for i in range(tx_count):
            if i % 2 == 0:
                tx = create_signed_ecdsa_transaction(alice, bob['public_key'], "0.5")
            else:
                tx = create_signed_ecdsa_transaction(bob, alice['public_key'], "0.5")
            test_txs.append(tx)

        # Giai đoạn 1: Bắn tải qua kênh TLS KEM
        print(f"\n[*] GIAI DOAN 1: Ban tai {tx_count} giao dich qua kenh TLS ({kem_info['name']})...")
        e2e_latencies_ms = []
        handshake_latencies_ms = []
        ingest_latencies_ms = []
        accepted_count = 0

        raw_csv_path = out_dir / f"macro_{kem_key}_raw.csv"
        raw_csv_path.parent.mkdir(parents=True, exist_ok=True)

        t_batch_start = time.perf_counter()

        with open(raw_csv_path, 'w', newline='', encoding='utf-8') as f:
            csv_w = csv.writer(f)
            csv_w.writerow([
                'Tx_Index', 'KEM_Algorithm', 'KEM_Handshake_ms', 'HTTP_Ingest_ms',
                'E2E_Latency_ms', 'KEM_PK_Bytes', 'KEM_CT_Bytes', 'Total_KEM_Wire_Bytes',
                'HTTP_Status', 'Result'
            ])

            for idx, tx in enumerate(test_txs):
                # 1. Đo lường đàm phán KEM Handshake
                dt_kem_ms, pk_b, ct_b, wire_b = perform_kem_handshake(kem_key)
                handshake_latencies_ms.append(dt_kem_ms)

                # 2. Gửi giao dịch qua HTTPS vào Ingress Node
                t0 = time.perf_counter()
                try:
                    resp = requests.post(f"{ingress_url}/transactions/new", json=tx, timeout=10.0, verify=False)
                    dt_http_ms = (time.perf_counter() - t0) * 1000.0
                    status_code = resp.status_code
                    if status_code in (200, 201):
                        accepted_count += 1
                        result_str = 'ACCEPTED'
                    else:
                        result_str = 'REJECTED'
                except Exception as ex:
                    dt_http_ms = (time.perf_counter() - t0) * 1000.0
                    status_code = 0
                    result_str = f'ERROR: {ex}'

                dt_total_ms = dt_kem_ms + dt_http_ms
                e2e_latencies_ms.append(dt_total_ms)
                ingest_latencies_ms.append(dt_http_ms)

                csv_w.writerow([
                    idx + 1, kem_info['name'], round(dt_kem_ms, 3), round(dt_http_ms, 3),
                    round(dt_total_ms, 3), pk_b, ct_b, wire_b, status_code, result_str
                ])

        t_batch_total = time.perf_counter() - t_batch_start
        ingest_tps = accepted_count / t_batch_total if t_batch_total > 0 else 0.0

        lat_arr = np.array(e2e_latencies_ms)
        hs_arr = np.array(handshake_latencies_ms)

        mean_lat = float(np.mean(lat_arr))
        median_lat = float(np.median(lat_arr))
        p95_lat = float(np.percentile(lat_arr, 95))
        min_lat = float(np.min(lat_arr))
        max_lat = float(np.max(lat_arr))

        mean_hs = float(np.mean(hs_arr))

        print(f"    -> Da tiep nhan:              {accepted_count}/{tx_count} txs ({accepted_count/tx_count*100:.1f}%)")
        print(f"    -> Thoi gian ban tai tong:     {t_batch_total:.3f} s")
        print(f"    -> Thong luong Ingestion TPS:  {ingest_tps:.2f} tx/s")
        print(f"    -> KEM Handshake trung binh:   {mean_hs:.3f} ms")
        print(f"    -> E2E Latency (Mean):         {mean_lat:.2f} ms | Median: {median_lat:.2f} ms | P95: {p95_lat:.2f} ms")

        # Giai đoạn 2: Đo lường Consensus & Block Propagation
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
                    st = requests.get(f"{u}/status", timeout=1.0, verify=False).json()
                    statuses.append(st['chain_length'])
                except Exception:
                    statuses.append(0)

            if all(s >= target_chain_len for s in statuses):
                all_synced = True
                break

        t_prop_total = time.perf_counter() - t_mine_start
        print(f"    -> Toan bo 6 Node dong bo Block #{target_chain_len} sau: {t_prop_total:.3f} s")

        # Giai đoạn 3: Đo lường Block Wire Payload
        print(f"\n[*] GIAI DOAN 3: Do luong kich thuoc Block Payload qua HTTPS...")
        chain_data = requests.get(f"{ingress_url}/chain", timeout=2.0, verify=False).json()
        latest_block = chain_data['chain'][-1] if chain_data['chain'] else {}
        block_wire_bytes = len(json.dumps(latest_block).encode('utf-8'))
        tx_in_block = len(latest_block.get('transactions', []))
        avg_tx_bytes = (block_wire_bytes / tx_in_block) if tx_in_block > 0 else 0

        print(f"    -> So giao dich trong Block moi: {tx_in_block} txs")
        print(f"    -> Kich thuoc Block thuc te:     {block_wire_bytes / 1024:.2f} KB ({block_wire_bytes} bytes)")

        # Tổng hợp kết quả JSON
        kem_result = {
            'benchmark_name': f"Macro-Benchmark 6-Node P2P (TLS with {kem_info['name']})",
            'kem_key': kem_key,
            'kem_metadata': kem_info,
            'tx_signature_scheme': "ECDSA (secp256k1)",
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'workload': {
                'total_tx_sent': tx_count,
                'accepted_tx': accepted_count,
                'success_rate_pct': round((accepted_count / tx_count) * 100, 2)
            },
            'performance': {
                'total_duration_seconds': round(t_batch_total, 3),
                'e2e_ingestion_tps': round(ingest_tps, 2),
                'handshake_latency_mean_ms': round(mean_hs, 3),
                'e2e_latency_mean_ms': round(mean_lat, 2),
                'e2e_latency_median_ms': round(median_lat, 2),
                'e2e_latency_p95_ms': round(p95_lat, 2),
                'e2e_latency_min_ms': round(min_lat, 2),
                'e2e_latency_max_ms': round(max_lat, 2)
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
                'average_bytes_per_tx': round(avg_tx_bytes, 1),
                'kem_handshake_wire_bytes': kem_info['pk_size'] + kem_info['ct_size']
            }
        }

        summary_path = out_dir / f"macro_{kem_key}_summary.json"
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(kem_result, f, indent=2)

        print("\n" + "=" * 85)
        print(f"  TONG KET [{kem_info['name']}]:")
        print(f"  * E2E Ingestion TPS:             {ingest_tps:.2f} tx/s")
        print(f"  * Handshake Overhead (Mean):     {mean_hs:.3f} ms")
        print(f"  * Mean E2E Latency:              {mean_lat:.2f} ms | P95: {p95_lat:.2f} ms")
        print(f"  * Block Propagation to 6 Nodes:  {t_prop_total:.3f} s")
        print(f"  * KEM Wire Size (PK + CT):       {kem_info['pk_size'] + kem_info['ct_size']} bytes")
        print(f"  * File chi tiet da luu tai:      {summary_path}")
        print("=" * 85)

        return kem_result

    finally:
        if internal_spawned:
            print("\n[*] Dang tat cac tien trinh node da khoi dong ngam...")
            kill_processes(internal_spawned)


def run_all_kems_benchmark(config: dict, base_dir: Path, out_dir: Path, tx_count: int = 0):
    """
    Chạy toàn bộ 5 cơ chế KEM và xuất bảng so sánh song song:
    1. secp256r1 (ECDHE NIST P-256)
    2. X25519 (ECDHE Curve25519)
    3. ML-KEM-768 (Kyber-768)
    4. HQC-128 (Code-based)
    5. FrodoKEM-640 (Unstructured LWE)
    """
    if tx_count > 0:
        config.setdefault('macro', {})['tx_count'] = tx_count

    ensure_certificates(base_dir)

    print("\n" + "#" * 90)
    print("  KHOI DONG THUC NGHIEM TOAN DIEN: SO SANH CAC KENH TLS KEM TREN MANG 6 NODE P2P")
    print("  Chu ky so giao dich: ECDSA (secp256k1) [GIU NGUYEN]")
    print("  Danh sach KEM: ECDHE (secp256r1, X25519), ML-KEM-768, HQC-128, FrodoKEM-640")
    print("#" * 90 + "\n")

    nodes = config.get('macro', {}).get('nodes', [
        "https://127.0.0.1:5000", "https://127.0.0.1:5001", "https://127.0.0.1:5002",
        "https://127.0.0.1:5003", "https://127.0.0.1:5004", "https://127.0.0.1:5005"
    ])
    nodes = [u.replace("http://", "https://") for u in nodes]

    spawned = []
    if not all(is_node_online(u) for u in nodes):
        spawned = spawn_6nodes_mesh(base_dir, use_tls=True)
        if not wait_for_nodes_ready(nodes):
            kill_processes(spawned)
            raise RuntimeError("Khong the khoi dong mang 6 Node qua HTTPS/TLS!")
        print("[+] Mang 6-Node Mesh (HTTPS) da san sang!")

    kems_to_test = ['secp256r1', 'x25519', 'mlkem768', 'hybrid_mlkem768', 'hqc128', 'frodokem640']
    results_map = {}

    try:
        for idx, k in enumerate(kems_to_test, 1):
            print(f"\n>>> [KEM {idx}/{len(kems_to_test)}]: TIEN HANH DO LUONG {KEM_CATALOG[k]['name']}...")
            res = run_macro_benchmark_kem(config, base_dir, out_dir, kem_key=k, spawned_processes=spawned)
            results_map[k] = res
            time.sleep(1.0)

        # Tính toán so sánh song song
        comparison_payload = {
            'benchmark_name': 'Consolidated Macro Benchmark: Classical ECDHE vs Post-Quantum KEMs vs Hybrid',
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'tx_signature_scheme': 'ECDSA (secp256k1)',
            'workload_per_kem': config.get('macro', {}).get('tx_count', 30),
            'nodes_count': 6,
            'results_by_kem': results_map
        }

        comparison_json_path = out_dir / "macro_kem_comparison_summary.json"
        with open(comparison_json_path, 'w', encoding='utf-8') as f:
            json.dump(comparison_payload, f, indent=2)

        # In bảng so sánh song song đa chiều
        print("\n" + "=" * 125)
        print("  BANG SO SANH TONG HOP CAC CO CHE KEM TRONG KENH TLS (CHU KY GIAO DICH: ECDSA secp256k1)")
        print("=" * 125)
        header = f" {'Chi so (Metric)':<26} | {'ECDHE-P256':<12} | {'ECDHE-X25519':<13} | {'ML-KEM-768':<12} | {'Hybrid(X255+ML)':<15} | {'HQC-128':<12} | {'FrodoKEM-640':<13}"
        print(header)
        print("-" * 125)

        r_p256 = results_map['secp256r1']
        r_x255 = results_map['x25519']
        r_mlkem = results_map['mlkem768']
        r_hybrid = results_map['hybrid_mlkem768']
        r_hqc = results_map['hqc128']
        r_frodo = results_map['frodokem640']

        def get_val(r, key1, key2, fmt="{:.2f}"):
            return fmt.format(r[key1][key2])

        print(f" {'Phan loai mat ma':<26} | {'Classical ECC':<12} | {'Classical ECC':<13} | {'PQC (M-LWE)':<12} | {'Hybrid Dual':<15} | {'PQC (Code)':<12} | {'PQC (LWE)':<13}")
        print(f" {'Khang may tinh luong tu':<26} | {'KHONG':<12} | {'KHONG':<13} | {'CO (Safe)':<12} | {'CO (Safe)':<15} | {'CO (Safe)':<12} | {'CO (Safe)':<13}")
        print(f" {'KEM PK Size (Bytes)':<26} | {'65':<12} | {'32':<13} | {'1,184':<12} | {'1,216':<15} | {'2,241':<12} | {'9,616':<13}")
        print(f" {'KEM CT Size (Bytes)':<26} | {'32':<12} | {'32':<13} | {'1,088':<12} | {'1,120':<15} | {'4,433':<12} | {'9,720':<13}")
        print(f" {'Handshake Wire (Bytes)':<26} | {'97':<12} | {'64':<13} | {'2,272':<12} | {'2,336':<15} | {'6,674':<12} | {'19,336':<13}")
        print("-" * 125)
        print(f" {'KEM Handshake Time (ms)':<26} | "
              f"{get_val(r_p256, 'performance', 'handshake_latency_mean_ms', '{:.3f}'):<12} | "
              f"{get_val(r_x255, 'performance', 'handshake_latency_mean_ms', '{:.3f}'):<13} | "
              f"{get_val(r_mlkem, 'performance', 'handshake_latency_mean_ms', '{:.3f}'):<12} | "
              f"{get_val(r_hybrid, 'performance', 'handshake_latency_mean_ms', '{:.3f}'):<15} | "
              f"{get_val(r_hqc, 'performance', 'handshake_latency_mean_ms', '{:.3f}'):<12} | "
              f"{get_val(r_frodo, 'performance', 'handshake_latency_mean_ms', '{:.3f}'):<13}")

        print(f" {'E2E Ingestion Latency (ms)':<26} | "
              f"{get_val(r_p256, 'performance', 'e2e_latency_mean_ms'):<12} | "
              f"{get_val(r_x255, 'performance', 'e2e_latency_mean_ms'):<13} | "
              f"{get_val(r_mlkem, 'performance', 'e2e_latency_mean_ms'):<12} | "
              f"{get_val(r_hybrid, 'performance', 'e2e_latency_mean_ms'):<15} | "
              f"{get_val(r_hqc, 'performance', 'e2e_latency_mean_ms'):<12} | "
              f"{get_val(r_frodo, 'performance', 'e2e_latency_mean_ms'):<13}")

        print(f" {'P95 Latency (ms)':<26} | "
              f"{get_val(r_p256, 'performance', 'e2e_latency_p95_ms'):<12} | "
              f"{get_val(r_x255, 'performance', 'e2e_latency_p95_ms'):<13} | "
              f"{get_val(r_mlkem, 'performance', 'e2e_latency_p95_ms'):<12} | "
              f"{get_val(r_hybrid, 'performance', 'e2e_latency_p95_ms'):<15} | "
              f"{get_val(r_hqc, 'performance', 'e2e_latency_p95_ms'):<12} | "
              f"{get_val(r_frodo, 'performance', 'e2e_latency_p95_ms'):<13}")

        print(f" {'Ingestion TPS (tx/s)':<26} | "
              f"{get_val(r_p256, 'performance', 'e2e_ingestion_tps'):<12} | "
              f"{get_val(r_x255, 'performance', 'e2e_ingestion_tps'):<13} | "
              f"{get_val(r_mlkem, 'performance', 'e2e_ingestion_tps'):<12} | "
              f"{get_val(r_hybrid, 'performance', 'e2e_ingestion_tps'):<15} | "
              f"{get_val(r_hqc, 'performance', 'e2e_ingestion_tps'):<12} | "
              f"{get_val(r_frodo, 'performance', 'e2e_ingestion_tps'):<13}")

        print(f" {'Block Propagation (s)':<26} | "
              f"{get_val(r_p256, 'consensus_propagation', 'block_propagation_delay_seconds', '{:.3f}'):<12} | "
              f"{get_val(r_x255, 'consensus_propagation', 'block_propagation_delay_seconds', '{:.3f}'):<13} | "
              f"{get_val(r_mlkem, 'consensus_propagation', 'block_propagation_delay_seconds', '{:.3f}'):<12} | "
              f"{get_val(r_hybrid, 'consensus_propagation', 'block_propagation_delay_seconds', '{:.3f}'):<15} | "
              f"{get_val(r_hqc, 'consensus_propagation', 'block_propagation_delay_seconds', '{:.3f}'):<12} | "
              f"{get_val(r_frodo, 'consensus_propagation', 'block_propagation_delay_seconds', '{:.3f}'):<13}")

        print("=" * 125)
        print(f"[*] File ket qua tong hop da luu tai: {comparison_json_path}")
        print("=" * 125 + "\n")

    finally:
        if spawned:
            print("[*] Tat an toan mang 6 Node...")
            kill_processes(spawned)
            print("[*] Da tat toan bo tien trinh node.")


def run_macro_benchmark_http(
    config: dict,
    base_dir: Path,
    out_dir: Path,
    spawned_processes: Optional[List[subprocess.Popen]] = None
) -> Dict:
    """
    Thực hiện kiểm thử Macro-Benchmark qua HTTP truyền thống (Cleartext, không dùng TLS):
    - Giao thức: HTTP thuần
    - Chữ ký số giao dịch: ECDSA secp256k1
    - Ghi nhận chi tiết ra macro_http_raw.csv và macro_http_summary.json
    """
    macro_cfg = config.get('macro', {})
    tx_count = macro_cfg.get('tx_count', 30)

    raw_ingress = macro_cfg.get('ingress_url', "http://127.0.0.1:5000")
    raw_miner = macro_cfg.get('miner_url', "http://127.0.0.1:5001")
    raw_nodes = macro_cfg.get('nodes', [
        "http://127.0.0.1:5000", "http://127.0.0.1:5001", "http://127.0.0.1:5002",
        "http://127.0.0.1:5003", "http://127.0.0.1:5004", "http://127.0.0.1:5005"
    ])

    ingress_url = raw_ingress.replace("https://", "http://")
    miner_url = raw_miner.replace("https://", "http://")
    nodes = [u.replace("https://", "http://") for u in raw_nodes]

    print("=" * 85)
    print("  MACRO-BENCHMARK: MANG P2P 6-NODE THUAN HTTP (KHONG MA HOA / CLEARTEXT)")
    print(f"  * Giao thuc mang:         HTTP (Cleartext, khong su dung TLS/KEM)")
    print(f"  * Chu ky so giao dich:    ECDSA (secp256k1)")
    print(f"  * So luong ban tai:       {tx_count} Transactions -> Ingress: {ingress_url}")
    print("=" * 85)

    internal_spawned = []
    if spawned_processes is None and not all(is_node_online(u) for u in nodes):
        internal_spawned = spawn_6nodes_mesh(base_dir, use_tls=False)
        if not wait_for_nodes_ready(nodes):
            kill_processes(internal_spawned)
            raise RuntimeError("Khong the khoi dong mang 6 Node qua HTTP!")

    try:
        # Lấy chain length ban đầu
        initial_status = {}
        for u in nodes:
            try:
                res = requests.get(f"{u}/status", timeout=3.0).json()
                initial_status[u] = res['chain_length']
            except Exception:
                initial_status[u] = 1
        base_chain_len = max(initial_status.values())

        # Sinh tập giao dịch hợp lệ ECDSA
        wallets = load_wallets(base_dir)
        if not wallets:
            raise RuntimeError("Khong tim thay vi mau configs/wallets.json")
        alice = wallets.get('Alice')
        bob = wallets.get('Bob')

        test_txs = []
        for i in range(tx_count):
            if i % 2 == 0:
                tx = create_signed_ecdsa_transaction(alice, bob['public_key'], "0.5")
            else:
                tx = create_signed_ecdsa_transaction(bob, alice['public_key'], "0.5")
            test_txs.append(tx)

        # Giai đoạn 1: Bắn tải qua HTTP
        print(f"\n[*] GIAI DOAN 1: Ban tai {tx_count} giao dich qua HTTP vao Ingress ({ingress_url}/transactions/new)...")
        http_latencies_ms = []
        accepted_count = 0

        raw_csv_path = out_dir / "macro_http_raw.csv"
        raw_csv_path.parent.mkdir(parents=True, exist_ok=True)

        t_batch_start = time.perf_counter()

        with open(raw_csv_path, 'w', newline='', encoding='utf-8') as f:
            csv_w = csv.writer(f)
            csv_w.writerow(['Tx_Index', 'Protocol', 'HTTP_Latency_ms', 'HTTP_Status', 'Result'])

            for idx, tx in enumerate(test_txs):
                t0 = time.perf_counter()
                try:
                    resp = requests.post(f"{ingress_url}/transactions/new", json=tx, timeout=10.0)
                    dt_http_ms = (time.perf_counter() - t0) * 1000.0
                    status_code = resp.status_code
                    if status_code in (200, 201):
                        accepted_count += 1
                        result_str = 'ACCEPTED'
                    else:
                        result_str = 'REJECTED'
                except Exception as ex:
                    dt_http_ms = (time.perf_counter() - t0) * 1000.0
                    status_code = 0
                    result_str = f'ERROR: {ex}'

                http_latencies_ms.append(dt_http_ms)
                csv_w.writerow([idx + 1, 'HTTP', round(dt_http_ms, 3), status_code, result_str])

        t_batch_total = time.perf_counter() - t_batch_start
        ingest_tps = accepted_count / t_batch_total if t_batch_total > 0 else 0.0

        lat_arr = np.array(http_latencies_ms)
        mean_lat = float(np.mean(lat_arr))
        median_lat = float(np.median(lat_arr))
        p95_lat = float(np.percentile(lat_arr, 95))
        min_lat = float(np.min(lat_arr))
        max_lat = float(np.max(lat_arr))

        print(f"    -> Da tiep nhan:              {accepted_count}/{tx_count} txs ({accepted_count/tx_count*100:.1f}%)")
        print(f"    -> Thoi gian ban tai tong:     {t_batch_total:.3f} s")
        print(f"    -> Thong luong Ingestion TPS:  {ingest_tps:.2f} tx/s")
        print(f"    -> HTTP Latency (Mean):        {mean_lat:.2f} ms | Median: {median_lat:.2f} ms | P95: {p95_lat:.2f} ms")

        # Giai đoạn 2: Consensus & Block Propagation
        print(f"\n[*] GIAI DOAN 2: Do luong thoi gian Miner dong khoi va Block Propagation tren 6 Node (HTTP)...")
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
        print(f"    -> Toan bo 6 Node dong bo Block #{target_chain_len} sau: {t_prop_total:.3f} s")

        # Giai đoạn 3: Block Wire Payload
        print(f"\n[*] GIAI DOAN 3: Do luong kich thuoc Block Payload qua HTTP...")
        chain_data = requests.get(f"{ingress_url}/chain", timeout=2.0).json()
        latest_block = chain_data['chain'][-1] if chain_data['chain'] else {}
        block_wire_bytes = len(json.dumps(latest_block).encode('utf-8'))
        tx_in_block = len(latest_block.get('transactions', []))
        avg_tx_bytes = (block_wire_bytes / tx_in_block) if tx_in_block > 0 else 0

        print(f"    -> So giao dich trong Block moi: {tx_in_block} txs")
        print(f"    -> Kich thuoc Block thuc te:     {block_wire_bytes / 1024:.2f} KB ({block_wire_bytes} bytes)")

        http_result = {
            'benchmark_name': "Macro-Benchmark 6-Node P2P (HTTP Cleartext)",
            'protocol': "HTTP",
            'tls_enabled': False,
            'tx_signature_scheme': "ECDSA (secp256k1)",
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'workload': {
                'total_tx_sent': tx_count,
                'accepted_tx': accepted_count,
                'success_rate_pct': round((accepted_count / tx_count) * 100, 2)
            },
            'performance': {
                'total_duration_seconds': round(t_batch_total, 3),
                'e2e_ingestion_tps': round(ingest_tps, 2),
                'handshake_latency_mean_ms': 0.0,
                'e2e_latency_mean_ms': round(mean_lat, 2),
                'e2e_latency_median_ms': round(median_lat, 2),
                'e2e_latency_p95_ms': round(p95_lat, 2),
                'e2e_latency_min_ms': round(min_lat, 2),
                'e2e_latency_max_ms': round(max_lat, 2)
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
                'average_bytes_per_tx': round(avg_tx_bytes, 1),
                'kem_handshake_wire_bytes': 0
            }
        }

        # Lưu kết quả duy nhất cho kịch bản HTTP
        summary_path = out_dir / "macro_http_summary.json"
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(http_result, f, indent=2)

        print("\n" + "=" * 85)
        print("  TONG KET [HTTP CLEARTEXT]:")
        print(f"  * E2E Ingestion TPS:             {ingest_tps:.2f} tx/s")
        print(f"  * Mean Ingestion Latency:        {mean_lat:.2f} ms | P95: {p95_lat:.2f} ms")
        print(f"  * Block Propagation to 6 Nodes:  {t_prop_total:.3f} s")
        print(f"  * Block Wire Size ({tx_in_block} txs):       {block_wire_bytes/1024:.2f} KB")
        print(f"  * File chi tiet da luu tai:      {summary_path}")
        print("=" * 85)

        return http_result

    finally:
        if internal_spawned:
            print("\n[*] Dang tat cac tien trinh node da khoi dong ngam...")
            kill_processes(internal_spawned)


def main():
    parser = argparse.ArgumentParser(description="Macro-Benchmark Suite: Blockchain P2P Network (HTTP & TLS KEM Evaluation)")
    parser.add_argument('-n', '--tx-count', type=int, default=0, help="So luong giao dich ban tai")
    parser.add_argument('-c', '--config', type=str, default="", help="Duong dan file JSON cau hinh")
    parser.add_argument('-o', '--output-dir', type=str, default="", help="Thu muc xuat ket qua")
    parser.add_argument('--http', action='store_true', help="Chay kiem thu tai mang thuan HTTP (Cleartext, khong dung TLS)")
    parser.add_argument('--kem', type=str, default="", help="Chi dinh 1 KEM cu the: hybrid_mlkem768, mlkem768, x25519, secp256r1, hqc128, frodokem640")
    parser.add_argument('--compare-kems', action='store_true', help="Chay kiem thu toan bo 6 co che KEM va so sanh song song")
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

    if args.http:
        run_macro_benchmark_http(cfg, base_dir, out_dir)
    elif args.compare_kems:
        run_all_kems_benchmark(cfg, base_dir, out_dir, tx_count=args.tx_count)
    elif args.kem:
        kem_key = args.kem.lower().strip()
        if kem_key not in KEM_CATALOG:
            print(f"[!] KEM khong hop le: '{args.kem}'. Lua chon: {list(KEM_CATALOG.keys())}")
            sys.exit(1)
        run_macro_benchmark_kem(cfg, base_dir, out_dir, kem_key=kem_key)
    else:
        # Mặc định: Chạy kiểm thử HTTP thuần
        print("\n[*] Khong chi dinh co dac biet -> Tien hanh chay Macro-Benchmark thuan HTTP (Cleartext).")
        print("[*] (Meo: Su dung '--http' de chay HTTP, '--kem <ten>' de chay 1 KEM, hoac '--compare-kems' de so sanh 6 KEM)\n")
        run_macro_benchmark_http(cfg, base_dir, out_dir)


if __name__ == '__main__':
    main()
