"""
Micro-Benchmark Suite: Isolated Cryptographic Primitive Performance
Measures: RSA-2048 vs ECDSA (secp256k1) vs ML-DSA-44 (NIST PQC)
Platforms: Linux, Windows, macOS
"""

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import scipy.stats as stats

# Cryptography primitives
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization

# PQC check (Graceful cross-platform detection)
OQS_AVAILABLE = False
oqs = None
try:
    import oqs
    OQS_AVAILABLE = True
except BaseException:
    OQS_AVAILABLE = False
    oqs = None


if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


def calculate_stats(data: np.ndarray) -> Dict[str, float]:
    """Calculate descriptive statistics and 95% Bootstrap Confidence Interval."""
    mean_val = float(np.mean(data))
    median_val = float(np.median(data))
    std_val = float(np.std(data, ddof=1)) if len(data) > 1 else 0.0

    ci_low, ci_high = mean_val, mean_val
    if len(data) > 1 and np.max(data) > np.min(data):
        try:
            res = stats.bootstrap((data,), np.mean, confidence_level=0.95, n_resamples=5000, method='percentile')
            ci_low, ci_high = float(res.confidence_interval.low), float(res.confidence_interval.high)
        except Exception:
            ci_low, ci_high = mean_val, mean_val

    return {
        'mean': round(mean_val, 4),
        'median': round(median_val, 4),
        'std': round(std_val, 4),
        'ci_95_low': round(ci_low, 4),
        'ci_95_high': round(ci_high, 4)
    }


def save_raw_csv(filepath: Path, iterations: int, keygen: np.ndarray, sign: np.ndarray,
                 verify: np.ndarray, pk_sizes: np.ndarray, sig_sizes: np.ndarray):
    """Save raw benchmark trials to CSV for scientific reproducibility."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Iteration', 'Keygen_ms', 'Sign_ms', 'Verify_ms', 'PK_bytes', 'Sig_bytes'])
        for i in range(iterations):
            writer.writerow([i + 1, round(keygen[i], 4), round(sign[i], 4), round(verify[i], 4),
                             int(pk_sizes[i]), int(sig_sizes[i])])


def run_rsa_benchmark(iterations: int, message: bytes) -> Tuple[Dict, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    keygen_ms = np.zeros(iterations)
    sign_ms = np.zeros(iterations)
    verify_ms = np.zeros(iterations)
    pk_sizes = np.zeros(iterations)
    sig_sizes = np.zeros(iterations)

    step = max(1, iterations // 5)
    for i in range(iterations):
        if (i + 1) % step == 0 or i == iterations - 1:
            print(f"    [RSA-2048] Tien do: {i + 1}/{iterations} trials...", flush=True)

        # 1. Key generation
        t0 = time.perf_counter()
        sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pk = sk.public_key()
        keygen_ms[i] = (time.perf_counter() - t0) * 1000.0

        pk_bytes = pk.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
        pk_sizes[i] = len(pk_bytes)

        # 2. Sign
        t0 = time.perf_counter()
        sig = sk.sign(message, padding.PKCS1v15(), hashes.SHA256())
        sign_ms[i] = (time.perf_counter() - t0) * 1000.0
        sig_sizes[i] = len(sig)

        # 3. Verify
        t0 = time.perf_counter()
        pk.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())
        verify_ms[i] = (time.perf_counter() - t0) * 1000.0

    return {
        'algorithm': 'RSA-2048',
        'keygen_ms': calculate_stats(keygen_ms),
        'sign_ms': calculate_stats(sign_ms),
        'verify_ms': calculate_stats(verify_ms),
        'pk_bytes': calculate_stats(pk_sizes),
        'sig_bytes': calculate_stats(sig_sizes)
    }, keygen_ms, sign_ms, verify_ms, pk_sizes, sig_sizes


def run_ecdsa_benchmark(iterations: int, message: bytes) -> Tuple[Dict, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    keygen_ms = np.zeros(iterations)
    sign_ms = np.zeros(iterations)
    verify_ms = np.zeros(iterations)
    pk_sizes = np.zeros(iterations)
    sig_sizes = np.zeros(iterations)

    for i in range(iterations):
        # 1. Key generation
        t0 = time.perf_counter()
        sk = ec.generate_private_key(ec.SECP256K1())
        pk = sk.public_key()
        keygen_ms[i] = (time.perf_counter() - t0) * 1000.0

        pk_bytes = pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        pk_sizes[i] = len(pk_bytes)  # 33 bytes compressed point

        # 2. Sign
        t0 = time.perf_counter()
        sig_der = sk.sign(message, ec.ECDSA(hashes.SHA256()))
        sign_ms[i] = (time.perf_counter() - t0) * 1000.0

        r, s = decode_dss_signature(sig_der)
        raw_sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        sig_sizes[i] = len(raw_sig)  # 64 bytes raw (r || s)

        # 3. Verify
        t0 = time.perf_counter()
        pk.verify(sig_der, message, ec.ECDSA(hashes.SHA256()))
        verify_ms[i] = (time.perf_counter() - t0) * 1000.0

    return {
        'algorithm': 'ECDSA (secp256k1)',
        'keygen_ms': calculate_stats(keygen_ms),
        'sign_ms': calculate_stats(sign_ms),
        'verify_ms': calculate_stats(verify_ms),
        'pk_bytes': calculate_stats(pk_sizes),
        'sig_bytes': calculate_stats(sig_sizes)
    }, keygen_ms, sign_ms, verify_ms, pk_sizes, sig_sizes


def run_mldsa_benchmark(iterations: int, message: bytes, alg_name: str = "ML-DSA-44") -> Optional[Tuple[Dict, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]]:
    if not OQS_AVAILABLE:
        return None

    try:
        keygen_ms = np.zeros(iterations)
        sign_ms = np.zeros(iterations)
        verify_ms = np.zeros(iterations)
        pk_sizes = np.zeros(iterations)
        sig_sizes = np.zeros(iterations)

        with oqs.Signature(alg_name) as signer:
            for i in range(iterations):
                # 1. Key generation
                t0 = time.perf_counter()
                pk = signer.generate_keypair()
                keygen_ms[i] = (time.perf_counter() - t0) * 1000.0
                pk_sizes[i] = signer.details['length_public_key']

                # 2. Sign
                t0 = time.perf_counter()
                sig = signer.sign(message)
                sign_ms[i] = (time.perf_counter() - t0) * 1000.0
                sig_sizes[i] = signer.details['length_signature']

                # 3. Verify
                t0 = time.perf_counter()
                signer.verify(message, sig, pk)
                verify_ms[i] = (time.perf_counter() - t0) * 1000.0

        return {
            'algorithm': f'PQC: {alg_name}',
            'keygen_ms': calculate_stats(keygen_ms),
            'sign_ms': calculate_stats(sign_ms),
            'verify_ms': calculate_stats(verify_ms),
            'pk_bytes': calculate_stats(pk_sizes),
            'sig_bytes': calculate_stats(sig_sizes)
        }, keygen_ms, sign_ms, verify_ms, pk_sizes, sig_sizes
    except Exception as e:
        print(f"[!] Warning: liboqs initialization skipped ({e})")
        return None


def main():
    parser = argparse.ArgumentParser(description="Micro-Benchmark Suite: Blockchain Digital Signature Schemes")
    parser.add_argument('-n', '--iterations', type=int, default=1000, help="Số lần lặp kiểm thử (mặc định: 1000)")
    parser.add_argument('-c', '--config', type=str, default="", help="Đường dẫn file cấu hình JSON")
    parser.add_argument('-o', '--output-dir', type=str, default="", help="Thư mục xuất kết quả")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    config_file = Path(args.config) if args.config else base_dir / "configs" / "benchmark_config.json"

    iterations = args.iterations
    payload_bytes = 250
    block_txs = 1000

    if config_file.exists():
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                cfg_data = json.load(f)
            m_cfg = cfg_data.get('micro', {})
            iterations = m_cfg.get('iterations', iterations)
            payload_bytes = m_cfg.get('payload_bytes', payload_bytes)
            block_txs = m_cfg.get('simulated_block_txs', block_txs)
        except Exception:
            pass

    out_dir = Path(args.output_dir) if args.output_dir else base_dir / "results"
    out_dir.mkdir(parents=True, exist_ok=True)

    message = b'{"sender": "Alice", "recipient": "Bob", "amount": 100.0}'

    print("=" * 80)
    print("  MICRO-BENCHMARK: DANH GIA SO SANH HIEU NANG MAT MA BLOCKCHAIN")
    print("  Thuat toan: RSA-2048 | ECDSA (secp256k1) | ML-DSA-44 (NIST Post-Quantum)")
    print(f"  So lan lap: {iterations} trials | Moi truong: {sys.platform} | Python {sys.version.split()[0]}")
    print("=" * 80)

    results = []

    # 1. RSA
    print("\n[*] Dang chay thuc nghiem RSA-2048...")
    rsa_res, rsa_kg, rsa_sg, rsa_vf, rsa_pk, rsa_sig = run_rsa_benchmark(iterations, message)
    results.append(rsa_res)
    save_raw_csv(out_dir / "RSA_2048_micro_raw.csv", iterations, rsa_kg, rsa_sg, rsa_vf, rsa_pk, rsa_sig)

    # 2. ECDSA
    print("[*] Dang chay thuc nghiem ECDSA (secp256k1)...")
    ecdsa_res, e_kg, e_sg, e_vf, e_pk, e_sig = run_ecdsa_benchmark(iterations, message)
    results.append(ecdsa_res)
    save_raw_csv(out_dir / "ECDSA_secp256k1_micro_raw.csv", iterations, e_kg, e_sg, e_vf, e_pk, e_sig)

    # 3. ML-DSA
    print("[*] Dang kiem tra ho tro thu vien liboqs (ML-DSA-44)...")
    mldsa_out = run_mldsa_benchmark(iterations, message, "ML-DSA-44")
    if mldsa_out:
        mldsa_res, m_kg, m_sg, m_vf, m_pk, m_sig = mldsa_out
        results.append(mldsa_res)
        save_raw_csv(out_dir / "ML_DSA_44_micro_raw.csv", iterations, m_kg, m_sg, m_vf, m_pk, m_sig)
        print("    -> ML-DSA-44 hoan tat thanh cong!")
    else:
        print("    -> [Luu y] Liboqs chua duoc bien dich tren OS hien tai. Thuật toán ML-DSA se duoc chay tren Linux/Kali co liboqs.")

    # In bang tong hop
    print("\n" + "=" * 90)
    print(f"{'Thuat toan':<22} | {'Keygen (ms)':<14} | {'Sign (ms)':<14} | {'Verify (ms)':<14} | {'PK (B)':<8} | {'Sig (B)':<8}")
    print("-" * 90)
    for r in results:
        print(f"{r['algorithm']:<22} | "
              f"{r['keygen_ms']['mean']:>6.3f} ± {r['keygen_ms']['std']:<4.2f} | "
              f"{r['sign_ms']['mean']:>6.3f} ± {r['sign_ms']['std']:<4.2f} | "
              f"{r['verify_ms']['mean']:>6.3f} ± {r['verify_ms']['std']:<4.2f} | "
              f"{int(r['pk_bytes']['mean']):<8} | "
              f"{int(r['sig_bytes']['mean']):<8}")
    print("=" * 90)

    # In mo phong Blockchain
    print("\n[+] UOC TINH HE THONG BLOCKCHAIN THEO MO HINH LY THUYET:")
    print(f"    Gia dinh: 1 Block chua {block_txs} transactions, Payload metadata = {payload_bytes} bytes/tx")
    print("-" * 90)
    for r in results:
        mean_pk = r['pk_bytes']['mean']
        mean_sig = r['sig_bytes']['mean']
        mean_vf = r['verify_ms']['mean']
        est_block_bytes = block_txs * (mean_sig + mean_pk + payload_bytes)
        theo_tps = (1000.0 / mean_vf) if mean_vf > 0 else 0.0

        r['blockchain_extrapolation'] = {
            'simulated_block_kb': round(est_block_bytes / 1024.0, 2),
            'theoretical_crypto_tps': round(theo_tps, 2)
        }
        print(f"  * {r['algorithm']:<22}: Kich thuoc Block = {est_block_bytes/1024.0:>8.2f} KB | "
              f"Crypto TPS Ly thuyet = {theo_tps:>8.2f} tx/s")
    print("=" * 90)

    summary_file = out_dir / "micro_benchmark_summary.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Da xuat toan bo bao cao Micro-Benchmark ra:")
    print(f"    - JSON Tong hop: {summary_file}")
    print(f"    - Raw CSV data:  {out_dir}")


if __name__ == '__main__':
    main()
