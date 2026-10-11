"""
Macro-Benchmark Suite: End-to-End P2P Network Load & Consensus Benchmark
Measures: Real-world HTTP vs HTTPS (TLS with Classical ECDHE & Post-Quantum KEMs)
KEMs: secp256r1, x25519, mlkem768, hybrid_mlkem768, frodokem640, hqc128
Transaction Signature: ML-DSA-44 (NIST FIPS 204 Post-Quantum Digital Signature)
Platforms: Linux, Windows, macOS (Zero-Hardcode)
"""

import argparse
from collections import OrderedDict
import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

import numpy as np
import requests
import urllib3

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

# ML-DSA-44 Signature library
try:
    import pqcrypto.sign.ml_dsa_44 as mldsa_pqc
except ImportError:
    mldsa_pqc = None

try:
    import oqs
except BaseException:
    oqs = None


# ==============================================================================
# Helpers: Tiến trình mạng, chứng chỉ & giao dịch
# ==============================================================================

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
    """Dọn dẹp triệt để các tiến trình node đa nền tảng."""
    for p in processes:
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                p.terminate()
                p.wait(timeout=2)
        except Exception:
            pass


def is_node_online(url: str, timeout: float = 1.0) -> bool:
    try:
        return requests.get(f"{url.rstrip('/')}/status", timeout=timeout, verify=False).status_code == 200
    except Exception:
        return False


def wait_for_nodes_ready(nodes: List[str], max_retries: int = 25) -> bool:
    for _ in range(max_retries):
        time.sleep(0.5)
        if all(is_node_online(u, timeout=0.5) for u in nodes):
            return True
    return False


def ensure_certificates(base_dir: Path) -> Tuple[Path, Path]:
    certs_dir = base_dir / "certs"
    cert_path, key_path = certs_dir / "server.crt", certs_dir / "server.key"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    certs_dir.mkdir(parents=True, exist_ok=True)
    print("[*] Sinh chung chi TLS tai certs/...")
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key_path), "-out", str(cert_path),
        "-days", "365", "-nodes", "-subj", "/CN=127.0.0.1/O=Blockchain-CSATT"
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    return cert_path, key_path


def load_wallets(base_dir: Path) -> Dict[str, dict]:
    for p in [base_dir / "configs" / "wallets.json", base_dir.parent / "configs" / "wallets.json",
              base_dir / "configs" / "wallets_mldsa.json", base_dir.parent / "configs" / "wallets_mldsa.json"]:
        if p.exists():
            with open(p, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if data and 'Alice' in data:
                    return data
    return {}


def create_signed_mldsa_transaction(sender: dict, recipient_pubkey: str, amount: str) -> dict:
    """Tạo và ký số giao dịch sử dụng thuật toán Hậu lượng tử ML-DSA-44."""
    tx_dict = OrderedDict([
        ('sender_address', sender['public_key']),
        ('recipient_address', recipient_pubkey),
        ('value', str(amount))
    ])
    msg_bytes = str(tx_dict).encode('utf-8')
    priv_bytes = bytes.fromhex(sender['private_key'])

    if mldsa_pqc is not None:
        sig_bytes = mldsa_pqc.sign(priv_bytes, msg_bytes)
        sig_hex = sig_bytes.hex()
    elif oqs is not None:
        with oqs.Signature('ML-DSA-44', secret_key=priv_bytes) as signer:
            sig_bytes = signer.sign(msg_bytes)
            sig_hex = sig_bytes.hex()
    else:
        raise RuntimeError("Khong tim thay thu vien ho tro ky so ML-DSA-44 (pqcrypto hoac liboqs).")

    return {
        'sender_address': sender['public_key'],
        'recipient_address': recipient_pubkey,
        'amount': str(amount),
        'signature': sig_hex
    }


def prepare_test_transactions(base_dir: Path, tx_count: int) -> List[dict]:
    wallets = load_wallets(base_dir)
    if not wallets:
        raise RuntimeError("Khong tim thay vi mau configs/wallets.json hoac configs/wallets_mldsa.json")
    alice, bob = wallets.get('Alice'), wallets.get('Bob')
    return [
        create_signed_mldsa_transaction(alice if i % 2 == 0 else bob, bob['public_key'] if i % 2 == 0 else alice['public_key'], "0.5")
        for i in range(tx_count)
    ]


def spawn_6nodes_mesh(base_dir: Path, use_tls: bool = False) -> List[subprocess.Popen]:
    net_cfg_path = base_dir / "configs" / "network_6nodes.json"
    if not net_cfg_path.exists():
        net_cfg_path = base_dir.parent / "configs" / "network_6nodes.json"
    with open(net_cfg_path, 'r', encoding='utf-8') as f:
        net_cfg = json.load(f)

    print(f"\n[*] Khoi dong tu dong mang 6 Node P2P Mesh ({'HTTPS' if use_tls else 'HTTP'})...")
    spawned, py_cmd = [], get_python_cmd()
    work_dir = str(base_dir if (base_dir / "blockchain").exists() else base_dir.parent)

    for node in net_cfg['nodes']:
        cmd = py_cmd + ['blockchain/blockchain.py', '-p', str(node['port'])]
        if use_tls:
            cmd.append('--tls')
        if node.get('is_miner'):
            cmd.append('--miner')
        if node.get('peers'):
            cmd.extend(['--peers', ','.join(node['peers'])])
        spawned.append(subprocess.Popen(cmd, cwd=work_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    return spawned


def ensure_cluster_running(base_dir: Path, nodes: List[str], use_tls: bool, spawned: Optional[List[subprocess.Popen]]) -> Tuple[List[subprocess.Popen], bool]:
    if spawned is not None:
        return spawned, False
    if not all(is_node_online(u) for u in nodes):
        new_spawned = spawn_6nodes_mesh(base_dir, use_tls=use_tls)
        if not wait_for_nodes_ready(nodes):
            kill_processes(new_spawned)
            raise RuntimeError(f"Khong the khoi dong mang 6 Node ({'HTTPS/TLS' if use_tls else 'HTTP'})!")
        return new_spawned, True
    return [], False


def get_base_chain_length(nodes: List[str]) -> int:
    lens = []
    for u in nodes:
        try:
            lens.append(requests.get(f"{u}/status", timeout=2.0, verify=False).json().get('chain_length', 1))
        except Exception:
            lens.append(1)
    return max(lens) if lens else 1


def wait_for_block_propagation(nodes: List[str], target_len: int, max_wait: float = 15.0, poll_interval: float = 0.5) -> Tuple[bool, float]:
    t_start, waited, all_synced = time.perf_counter(), 0.0, False
    while waited < max_wait:
        time.sleep(poll_interval)
        waited += poll_interval
        statuses = []
        for u in nodes:
            try:
                statuses.append(requests.get(f"{u}/status", timeout=1.0, verify=False).json().get('chain_length', 0))
            except Exception:
                statuses.append(0)
        if all(s >= target_len for s in statuses):
            all_synced = True
            break
    return all_synced, time.perf_counter() - t_start


def measure_block_payload(ingress_url: str) -> Tuple[int, int, float]:
    try:
        chain_data = requests.get(f"{ingress_url}/chain", timeout=2.0, verify=False).json()
        latest = chain_data['chain'][-1] if chain_data.get('chain') else {}
        wire = len(json.dumps(latest).encode('utf-8'))
        tx_count = len(latest.get('transactions', []))
        return wire, tx_count, (wire / tx_count) if tx_count > 0 else 0.0
    except Exception:
        return 0, 0, 0.0


# ==============================================================================
# Runner kiểm thử thống nhất (Unified Benchmark Runner)
# ==============================================================================

def run_macro_workload(
    config: dict,
    base_dir: Path,
    out_dir: Path,
    kem_key: Optional[str] = None,
    spawned_processes: Optional[List[subprocess.Popen]] = None
) -> Dict:
    is_tls = kem_key is not None
    macro_cfg = config.get('macro', {})
    tx_count = macro_cfg.get('tx_count', 30)

    proto, opp = ("https://", "http://") if is_tls else ("http://", "https://")
    ingress_url = macro_cfg.get('ingress_url', f"{proto}127.0.0.1:5000").replace(opp, proto)
    nodes = [u.replace(opp, proto) for u in macro_cfg.get('nodes', [f"{proto}127.0.0.1:{p}" for p in range(5000, 5006)])]

    kem_info = None
    if is_tls:
        kem_key = kem_key.lower().strip()
        kem_info = KEM_CATALOG.get(kem_key, {
            'name': kem_key, 'category': 'Unknown', 'subfamily': 'Unknown',
            'nist_level': 'N/A', 'quantum_resistant': False, 'pk_size': 0, 'ct_size': 0, 'shared_secret_size': 0
        })
        ensure_certificates(base_dir)

    print("=" * 85)
    if is_tls:
        print(f"  MACRO-BENCHMARK: TLS KEY EXCHANGE [{kem_info['name'].upper()}] + CHU KY ML-DSA-44")
        print(f"  * Loai KEM: {kem_info['category']} ({kem_info['subfamily']}) | Khang luong tu: {'CO' if kem_info['quantum_resistant'] else 'KHONG'}")
        print(f"  * Wire Size: PK: {kem_info['pk_size']} B | CT: {kem_info['ct_size']} B | Total: {kem_info['pk_size'] + kem_info['ct_size']} B")
    else:
        print("  MACRO-BENCHMARK: MANG P2P 6-NODE THUAN HTTP (CLEARTEXT) + CHU KY ML-DSA-44")
    print(f"  * Chu ky giao dich: ML-DSA-44 (NIST FIPS 204 PQC) | So luong: {tx_count} txs -> Ingress: {ingress_url}")
    print("=" * 85)

    proc_list, is_internal = ensure_cluster_running(base_dir, nodes, use_tls=is_tls, spawned=spawned_processes)

    try:
        base_chain_len = get_base_chain_length(nodes)
        test_txs = prepare_test_transactions(base_dir, tx_count)

        # Giai đoạn 1: Bắn tải và ghi CSV
        target_name = kem_info['name'] if is_tls else 'HTTP'
        print(f"\n[*] GIAI DOAN 1: Ban tai {tx_count} giao dich ({target_name})...")
        e2e_lats, hs_lats, accepted_count = [], [], 0

        raw_csv_path = out_dir / (f"macro_{kem_key}_raw.csv" if is_tls else "macro_http_raw.csv")
        raw_csv_path.parent.mkdir(parents=True, exist_ok=True)
        t_batch_start = time.perf_counter()

        with open(raw_csv_path, 'w', newline='', encoding='utf-8') as f:
            csv_w = csv.writer(f)
            if is_tls:
                csv_w.writerow(['Tx_Index', 'KEM_Algorithm', 'KEM_Handshake_ms', 'HTTP_Ingest_ms', 'E2E_Latency_ms', 'KEM_PK_Bytes', 'KEM_CT_Bytes', 'Total_KEM_Wire_Bytes', 'HTTP_Status', 'Result'])
            else:
                csv_w.writerow(['Tx_Index', 'Protocol', 'HTTP_Latency_ms', 'HTTP_Status', 'Result'])

            for idx, tx in enumerate(test_txs):
                dt_kem_ms, pk_b, ct_b, wire_b = (0.0, 0, 0, 0)
                if is_tls:
                    dt_kem_ms, pk_b, ct_b, wire_b = perform_kem_handshake(kem_key)
                    hs_lats.append(dt_kem_ms)

                t0 = time.perf_counter()
                try:
                    resp = requests.post(f"{ingress_url}/transactions/new", json=tx, timeout=10.0, verify=False)
                    dt_http_ms = (time.perf_counter() - t0) * 1000.0
                    status_code = resp.status_code
                    res_str = 'ACCEPTED' if status_code in (200, 201) else 'REJECTED'
                    if status_code in (200, 201):
                        accepted_count += 1
                except Exception as ex:
                    dt_http_ms = (time.perf_counter() - t0) * 1000.0
                    status_code, res_str = 0, f'ERROR: {ex}'

                dt_total = dt_kem_ms + dt_http_ms
                e2e_lats.append(dt_total)

                if is_tls:
                    csv_w.writerow([idx + 1, kem_info['name'], round(dt_kem_ms, 3), round(dt_http_ms, 3), round(dt_total, 3), pk_b, ct_b, wire_b, status_code, res_str])
                else:
                    csv_w.writerow([idx + 1, 'HTTP', round(dt_http_ms, 3), status_code, res_str])

        t_batch_total = time.perf_counter() - t_batch_start
        ingest_tps = (accepted_count / t_batch_total) if t_batch_total > 0 else 0.0
        lat_arr = np.array(e2e_lats)
        mean_hs = float(np.mean(hs_lats)) if hs_lats else 0.0

        print(f"    -> Tiep nhan: {accepted_count}/{tx_count} txs | Tong thoi gian: {t_batch_total:.3f} s | TPS: {ingest_tps:.2f} tx/s")
        if is_tls:
            print(f"    -> KEM Handshake trung binh: {mean_hs:.3f} ms")
        print(f"    -> Latency E2E (ms): Mean: {np.mean(lat_arr):.2f} | Median: {np.median(lat_arr):.2f} | P95: {np.percentile(lat_arr, 95):.2f}")

        # Giai đoạn 2: Đo lường Consensus & Block Propagation
        print(f"\n[*] GIAI DOAN 2: Do luong thoi gian Miner dong khoi va Block Propagation...")
        target_len = base_chain_len + 1
        all_synced, t_prop_total = wait_for_block_propagation(nodes, target_len)
        print(f"    -> 6 Node dong bo Block #{target_len} sau: {t_prop_total:.3f} s")

        # Giai đoạn 3: Đo lường Block Wire Payload
        print(f"\n[*] GIAI DOAN 3: Do luong kich thuoc Block Payload...")
        block_bytes, tx_in_block, avg_tx_bytes = measure_block_payload(ingress_url)
        print(f"    -> Block moi: {tx_in_block} txs | Kich thuoc: {block_bytes / 1024:.2f} KB ({block_bytes} bytes)")

        # Xuất file summary JSON (chuẩn schema đồng nhất)
        res = {
            'benchmark_name': f"Macro-Benchmark 6-Node P2P (TLS with {kem_info['name']})" if is_tls else "Macro-Benchmark 6-Node P2P (HTTP Cleartext)",
            'tx_signature_scheme': "ML-DSA-44",
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
                'e2e_latency_mean_ms': round(float(np.mean(lat_arr)), 2),
                'e2e_latency_median_ms': round(float(np.median(lat_arr)), 2),
                'e2e_latency_p95_ms': round(float(np.percentile(lat_arr, 95)), 2),
                'e2e_latency_min_ms': round(float(np.min(lat_arr)), 2),
                'e2e_latency_max_ms': round(float(np.max(lat_arr)), 2)
            },
            'consensus_propagation': {
                'nodes_participating': len(nodes),
                'all_nodes_synced': all_synced,
                'block_propagation_delay_seconds': round(t_prop_total, 3)
            },
            'network_wire_payload': {
                'block_wire_bytes': block_bytes,
                'block_wire_kb': round(block_bytes / 1024.0, 2),
                'tx_count_in_block': tx_in_block,
                'average_bytes_per_tx': round(avg_tx_bytes, 1),
                'kem_handshake_wire_bytes': (kem_info['pk_size'] + kem_info['ct_size']) if is_tls else 0
            }
        }
        if is_tls:
            res['kem_key'], res['kem_metadata'] = kem_key, kem_info
        else:
            res['protocol'], res['tls_enabled'] = "HTTP", False

        summary_path = out_dir / (f"macro_{kem_key}_summary.json" if is_tls else "macro_http_summary.json")
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(res, f, indent=2)

        print(f"[+] Ket qua da luu tai: {summary_path}")
        return res

    finally:
        if is_internal and proc_list:
            print("\n[*] Dang tat cac node khoi dong ngam...")
            kill_processes(proc_list)


# Wrappers tương thích ngược
def run_macro_benchmark_kem(config: dict, base_dir: Path, out_dir: Path, kem_key: str = "secp256r1", spawned_processes: Optional[List[subprocess.Popen]] = None) -> Dict:
    return run_macro_workload(config, base_dir, out_dir, kem_key=kem_key, spawned_processes=spawned_processes)


def run_macro_benchmark_http(config: dict, base_dir: Path, out_dir: Path, spawned_processes: Optional[List[subprocess.Popen]] = None) -> Dict:
    return run_macro_workload(config, base_dir, out_dir, kem_key=None, spawned_processes=spawned_processes)


# ==============================================================================
# So sánh Đa KEM & In Bảng
# ==============================================================================

def print_kem_comparison_table(results_map: Dict[str, dict], kems: List[str]):
    col_w, total_w = 14, 28 + 17 * len(kems)
    print("\n" + "=" * total_w)
    print("  BANG SO SANH TONG HOP CAC CO CHE KEM TRONG KENH TLS (CHU KY: ML-DSA-44 PQC)")
    print("=" * total_w)
    print(f" {'Chi so (Metric)':<26} | " + " | ".join(f"{KEM_CATALOG[k]['name'][:col_w]:<{col_w}}" for k in kems))
    print("-" * total_w)

    def print_row(label: str, vals: List[str]):
        print(f" {label:<26} | " + " | ".join(f"{v:<{col_w}}" for v in vals))

    print_row("Phan loai mat ma", [KEM_CATALOG[k]['category'][:col_w] for k in kems])
    print_row("Khang luong tu", ["CO (Safe)" if KEM_CATALOG[k]['quantum_resistant'] else "KHONG" for k in kems])
    print_row("KEM PK Size (Bytes)", [f"{KEM_CATALOG[k]['pk_size']:,}" for k in kems])
    print_row("KEM CT Size (Bytes)", [f"{KEM_CATALOG[k]['ct_size']:,}" for k in kems])
    print_row("Handshake Wire (Bytes)", [f"{KEM_CATALOG[k]['pk_size'] + KEM_CATALOG[k]['ct_size']:,}" for k in kems])
    print("-" * total_w)
    print_row("KEM Handshake (ms)", [f"{results_map[k]['performance']['handshake_latency_mean_ms']:.3f}" for k in kems])
    print_row("E2E Latency Mean (ms)", [f"{results_map[k]['performance']['e2e_latency_mean_ms']:.2f}" for k in kems])
    print_row("P95 Latency (ms)", [f"{results_map[k]['performance']['e2e_latency_p95_ms']:.2f}" for k in kems])
    print_row("Ingestion TPS (tx/s)", [f"{results_map[k]['performance']['e2e_ingestion_tps']:.2f}" for k in kems])
    print_row("Block Propagation (s)", [f"{results_map[k]['consensus_propagation']['block_propagation_delay_seconds']:.3f}" for k in kems])
    print("=" * total_w + "\n")


def run_all_kems_benchmark(config: dict, base_dir: Path, out_dir: Path, tx_count: int = 0):
    if tx_count > 0:
        config.setdefault('macro', {})['tx_count'] = tx_count
    ensure_certificates(base_dir)

    macro_cfg = config.get('macro', {})
    nodes = [u.replace("http://", "https://") for u in macro_cfg.get('nodes', [f"https://127.0.0.1:{p}" for p in range(5000, 5006)])]

    spawned = []
    if not all(is_node_online(u) for u in nodes):
        spawned = spawn_6nodes_mesh(base_dir, use_tls=True)
        if not wait_for_nodes_ready(nodes):
            kill_processes(spawned)
            raise RuntimeError("Khong the khoi dong mang 6 Node qua HTTPS/TLS!")
        print("[+] Mang 6-Node Mesh (HTTPS) da san sang!")

    kems = ['secp256r1', 'x25519', 'mlkem768', 'hybrid_mlkem768', 'hqc128', 'frodokem640']
    results_map = {}

    try:
        for idx, k in enumerate(kems, 1):
            print(f"\n>>> [KEM {idx}/{len(kems)}]: TIEN HANH DO LUONG {KEM_CATALOG[k]['name']}...")
            results_map[k] = run_macro_workload(config, base_dir, out_dir, kem_key=k, spawned_processes=spawned)
            time.sleep(1.0)

        cmp_file = out_dir / "macro_kem_comparison_summary.json"
        with open(cmp_file, 'w', encoding='utf-8') as f:
            json.dump({
                'benchmark_name': 'Consolidated Macro Benchmark: Classical ECDHE vs Post-Quantum KEMs vs Hybrid (ML-DSA-44)',
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'tx_signature_scheme': 'ML-DSA-44',
                'workload_per_kem': config.get('macro', {}).get('tx_count', 30),
                'nodes_count': 6,
                'results_by_kem': results_map
            }, f, indent=2)

        print_kem_comparison_table(results_map, kems)
        print(f"[*] File ket qua tong hop da luu tai: {cmp_file}")

    finally:
        if spawned:
            kill_processes(spawned)


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Macro-Benchmark Suite: Blockchain P2P Network (HTTP & TLS KEM Evaluation with ML-DSA-44)")
    parser.add_argument('-n', '--tx-count', type=int, default=0, help="So luong giao dich ban tai")
    parser.add_argument('-c', '--config', type=str, default="", help="Duong dan file JSON cau hinh")
    parser.add_argument('-o', '--output-dir', type=str, default="", help="Thu muc xuat ket qua")
    parser.add_argument('--http', action='store_true', help="Chay kiem thu tai mang thuan HTTP (Cleartext)")
    parser.add_argument('--kem', type=str, default="", help="Chi dinh 1 KEM: hybrid_mlkem768, mlkem768, x25519, secp256r1, hqc128, frodokem640")
    parser.add_argument('--compare-kems', action='store_true', help="Chay kiem thu toan bo 6 co che KEM va so sanh song song")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent.parent
    config_file = Path(args.config) if args.config else base_dir / "benchmarks" / "configs" / "benchmark_config.json"
    cfg = json.load(open(config_file, 'r', encoding='utf-8')) if config_file.exists() else {}

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
        print("\n[*] Mac dinh: Chay Macro-Benchmark thuan HTTP (Cleartext).\n")
        run_macro_benchmark_http(cfg, base_dir, out_dir)


if __name__ == '__main__':
    main()
