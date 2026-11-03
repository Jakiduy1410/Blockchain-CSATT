"""
Micro-Benchmark Suite: Isolated Cryptographic Primitive Performance
Measures:
  - Signatures: ECDSA (secp256k1) vs ML-DSA-44 vs ML-DSA-65 vs ML-DSA-87 (NIST FIPS 204)
  - Key Encapsulation (KEM / TLS): Classical ECDHE (X25519) vs Pure ML-KEM-512 vs Pure ML-KEM-768 vs Hybrid (X25519 + ML-KEM-768)
Features:
  - Warm-up phase (unmetered runs to eliminate cold start and JIT/CPU frequency jitter)
  - Pre-allocated context objects (pure primitive execution measurement)
  - Bootstrap 95% Confidence Intervals & publication-quality charts
Platforms: Linux, Windows, macOS
"""

import argparse
import csv
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import scipy.stats as stats
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Cryptography primitives
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization

# PQC check
OQS_AVAILABLE = False
oqs = None
try:
    if os.name == 'nt' and hasattr(os, 'add_dll_directory'):
        dll_dirs = [
            os.path.abspath('.'),
            os.path.abspath('liboqs'),
            os.path.abspath('liboqs/build_all/bin'),
            os.path.abspath('liboqs/build/bin'),
            os.path.abspath('liboqs/build/bin/Release'),
            os.path.expanduser('~/_oqs/bin')
        ]
        liboqs_env = os.environ.get('LIBOQS_DIR')
        if liboqs_env:
            dll_dirs.extend([liboqs_env, os.path.join(liboqs_env, 'bin')])
        for d in dll_dirs:
            if os.path.isdir(d):
                try:
                    os.add_dll_directory(d)
                except Exception:
                    pass
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
            res = stats.bootstrap((data,), np.mean, confidence_level=0.95, n_resamples=2000, method='percentile')
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


def save_raw_sig_csv(filepath: Path, iterations: int, keygen: np.ndarray, sign: np.ndarray,
                     verify: np.ndarray, pk_sizes: np.ndarray, sig_sizes: np.ndarray):
    """Save raw signature benchmark trials to CSV."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Iteration', 'Keygen_ms', 'Sign_ms', 'Verify_ms', 'PK_bytes', 'Sig_bytes'])
        for i in range(iterations):
            writer.writerow([i + 1, round(keygen[i], 4), round(sign[i], 4), round(verify[i], 4),
                             int(pk_sizes[i]), int(sig_sizes[i])])


def save_raw_kem_csv(filepath: Path, iterations: int, keygen: np.ndarray, encap: np.ndarray,
                     decap: np.ndarray, pk_sizes: np.ndarray, ct_sizes: np.ndarray, ss_sizes: np.ndarray):
    """Save raw KEM benchmark trials to CSV."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Iteration', 'Keygen_ms', 'Encap_ms', 'Decap_ms', 'PK_bytes', 'CT_bytes', 'SS_bytes'])
        for i in range(iterations):
            writer.writerow([i + 1, round(keygen[i], 4), round(encap[i], 4), round(decap[i], 4),
                             int(pk_sizes[i]), int(ct_sizes[i]), int(ss_sizes[i])])


# ==============================================================================
# SIGNATURE BENCHMARKS
# ==============================================================================

def run_ecdsa_benchmark(iterations: int, message: bytes, warmup: int = 20) -> Tuple[Dict, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Benchmark ECDSA (secp256k1) with unmetered warm-up."""
    # Warm-up phase
    for _ in range(warmup):
        sk_w = ec.generate_private_key(ec.SECP256K1())
        sig_w = sk_w.sign(message, ec.ECDSA(hashes.SHA256()))
        sk_w.public_key().verify(sig_w, message, ec.ECDSA(hashes.SHA256()))

    keygen_ms = np.zeros(iterations)
    sign_ms = np.zeros(iterations)
    verify_ms = np.zeros(iterations)
    pk_sizes = np.zeros(iterations)
    sig_sizes = np.zeros(iterations)

    for i in range(iterations):
        t0 = time.perf_counter()
        sk = ec.generate_private_key(ec.SECP256K1())
        pk = sk.public_key()
        keygen_ms[i] = (time.perf_counter() - t0) * 1000.0

        pk_bytes = pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        pk_sizes[i] = len(pk_bytes)

        t0 = time.perf_counter()
        sig_der = sk.sign(message, ec.ECDSA(hashes.SHA256()))
        sign_ms[i] = (time.perf_counter() - t0) * 1000.0

        r, s = decode_dss_signature(sig_der)
        raw_sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        sig_sizes[i] = len(raw_sig)

        t0 = time.perf_counter()
        pk.verify(sig_der, message, ec.ECDSA(hashes.SHA256()))
        verify_ms[i] = (time.perf_counter() - t0) * 1000.0

    return {
        'algorithm': 'ECDSA (secp256k1)',
        'type': 'signature',
        'security_level': 'Classical 128-bit',
        'keygen_ms': calculate_stats(keygen_ms),
        'sign_ms': calculate_stats(sign_ms),
        'verify_ms': calculate_stats(verify_ms),
        'pk_bytes': calculate_stats(pk_sizes),
        'sig_bytes': calculate_stats(sig_sizes)
    }, keygen_ms, sign_ms, verify_ms, pk_sizes, sig_sizes


def run_mldsa_benchmark(iterations: int, message: bytes, alg_name: str, warmup: int = 20) -> Optional[Tuple[Dict, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]]:
    """Benchmark ML-DSA variants (ML-DSA-44, ML-DSA-65, ML-DSA-87) with warm-up."""
    if not OQS_AVAILABLE:
        return None

    sec_map = {
        'ML-DSA-44': 'NIST Category 2 (AES-128 / SHA-256 equivalent)',
        'ML-DSA-65': 'NIST Category 3 (AES-192 equivalent)',
        'ML-DSA-87': 'NIST Category 5 (AES-256 equivalent)'
    }

    try:
        keygen_ms = np.zeros(iterations)
        sign_ms = np.zeros(iterations)
        verify_ms = np.zeros(iterations)
        pk_sizes = np.zeros(iterations)
        sig_sizes = np.zeros(iterations)

        with oqs.Signature(alg_name) as signer:
            # Warm-up phase
            for _ in range(warmup):
                pk_w = signer.generate_keypair()
                sig_w = signer.sign(message)
                signer.verify(message, sig_w, pk_w)

            # Measured trials
            for i in range(iterations):
                t0 = time.perf_counter()
                pk = signer.generate_keypair()
                keygen_ms[i] = (time.perf_counter() - t0) * 1000.0
                pk_sizes[i] = signer.details['length_public_key']

                t0 = time.perf_counter()
                sig = signer.sign(message)
                sign_ms[i] = (time.perf_counter() - t0) * 1000.0
                sig_sizes[i] = len(sig)

                t0 = time.perf_counter()
                signer.verify(message, sig, pk)
                verify_ms[i] = (time.perf_counter() - t0) * 1000.0

        return {
            'algorithm': alg_name,
            'type': 'signature',
            'security_level': sec_map.get(alg_name, 'Post-Quantum'),
            'keygen_ms': calculate_stats(keygen_ms),
            'sign_ms': calculate_stats(sign_ms),
            'verify_ms': calculate_stats(verify_ms),
            'pk_bytes': calculate_stats(pk_sizes),
            'sig_bytes': calculate_stats(sig_sizes)
        }, keygen_ms, sign_ms, verify_ms, pk_sizes, sig_sizes
    except Exception as e:
        print(f"[!] Warning: {alg_name} benchmark error: {e}")
        return None


# ==============================================================================
# KEY ENCAPSULATION (KEM / TLS KEY EXCHANGE) BENCHMARKS
# ==============================================================================

def run_x25519_benchmark(iterations: int, warmup: int = 20) -> Tuple[Dict, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Benchmark Classical ECDHE (X25519) Key Exchange with warm-up."""
    # Warm-up phase
    for _ in range(warmup):
        c_p = x25519.X25519PrivateKey.generate()
        s_p = x25519.X25519PrivateKey.generate()
        ss_s = s_p.exchange(c_p.public_key())
        ss_c = c_p.exchange(s_p.public_key())
        assert ss_s == ss_c

    keygen_ms = np.zeros(iterations)
    encap_ms = np.zeros(iterations)
    decap_ms = np.zeros(iterations)
    pk_sizes = np.zeros(iterations)
    ct_sizes = np.zeros(iterations)
    ss_sizes = np.zeros(iterations)

    for i in range(iterations):
        # 1. Client keygen
        t0 = time.perf_counter()
        client_priv = x25519.X25519PrivateKey.generate()
        client_pub = client_priv.public_key().public_bytes_raw()
        keygen_ms[i] = (time.perf_counter() - t0) * 1000.0
        pk_sizes[i] = len(client_pub)

        # 2. Server "Encap" (Server generates ephemeral pair and derives secret)
        t0 = time.perf_counter()
        server_priv = x25519.X25519PrivateKey.generate()
        server_pub = server_priv.public_key().public_bytes_raw()
        ss_server = server_priv.exchange(x25519.X25519PublicKey.from_public_bytes(client_pub))
        encap_ms[i] = (time.perf_counter() - t0) * 1000.0
        ct_sizes[i] = len(server_pub)

        # 3. Client "Decap" (Client derives secret from server public key)
        t0 = time.perf_counter()
        ss_client = client_priv.exchange(x25519.X25519PublicKey.from_public_bytes(server_pub))
        decap_ms[i] = (time.perf_counter() - t0) * 1000.0
        ss_sizes[i] = len(ss_client)
        assert ss_server == ss_client

    return {
        'algorithm': 'Classical ECDHE (X25519)',
        'type': 'kem',
        'security_level': 'Classical 128-bit (RFC 7748)',
        'keygen_ms': calculate_stats(keygen_ms),
        'encap_ms': calculate_stats(encap_ms),
        'decap_ms': calculate_stats(decap_ms),
        'pk_bytes': calculate_stats(pk_sizes),
        'ct_bytes': calculate_stats(ct_sizes),
        'ss_bytes': calculate_stats(ss_sizes)
    }, keygen_ms, encap_ms, decap_ms, pk_sizes, ct_sizes, ss_sizes


def run_pure_mlkem_benchmark(iterations: int, kem_name: str, warmup: int = 20) -> Optional[Tuple[Dict, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]]:
    """Benchmark Pure ML-KEM (ML-KEM-512, ML-KEM-768) with pre-allocated context & warm-up."""
    if not OQS_AVAILABLE:
        return None

    sec_map = {
        'ML-KEM-512': 'NIST Category 1 (AES-128 equivalent)',
        'ML-KEM-768': 'NIST Category 3 (AES-192 equivalent)',
        'ML-KEM-1024': 'NIST Category 5 (AES-256 equivalent)'
    }

    try:
        keygen_ms = np.zeros(iterations)
        encap_ms = np.zeros(iterations)
        decap_ms = np.zeros(iterations)
        pk_sizes = np.zeros(iterations)
        ct_sizes = np.zeros(iterations)
        ss_sizes = np.zeros(iterations)

        # Pre-instantiate both client and server contexts outside the loop to eliminate object allocation jitter
        with oqs.KeyEncapsulation(kem_name) as client_kem, oqs.KeyEncapsulation(kem_name) as server_kem:
            # Warm-up phase
            for _ in range(warmup):
                pk_w = client_kem.generate_keypair()
                ct_w, ss_w1 = server_kem.encap_secret(pk_w)
                ss_w2 = client_kem.decap_secret(ct_w)
                assert ss_w1 == ss_w2

            # Measured runs
            for i in range(iterations):
                # 1. Key generation
                t0 = time.perf_counter()
                pk = client_kem.generate_keypair()
                keygen_ms[i] = (time.perf_counter() - t0) * 1000.0
                pk_sizes[i] = len(pk)

                # 2. Encapsulation (Server side)
                t0 = time.perf_counter()
                ct, ss_server = server_kem.encap_secret(pk)
                encap_ms[i] = (time.perf_counter() - t0) * 1000.0
                ct_sizes[i] = len(ct)

                # 3. Decapsulation (Client side)
                t0 = time.perf_counter()
                ss_client = client_kem.decap_secret(ct)
                decap_ms[i] = (time.perf_counter() - t0) * 1000.0
                ss_sizes[i] = len(ss_client)
                assert ss_server == ss_client

        return {
            'algorithm': f'Pure {kem_name}',
            'type': 'kem',
            'security_level': sec_map.get(kem_name, 'FIPS 203 Post-Quantum'),
            'keygen_ms': calculate_stats(keygen_ms),
            'encap_ms': calculate_stats(encap_ms),
            'decap_ms': calculate_stats(decap_ms),
            'pk_bytes': calculate_stats(pk_sizes),
            'ct_bytes': calculate_stats(ct_sizes),
            'ss_bytes': calculate_stats(ss_sizes)
        }, keygen_ms, encap_ms, decap_ms, pk_sizes, ct_sizes, ss_sizes
    except Exception as e:
        print(f"[!] Warning: {kem_name} benchmark error: {e}")
        return None


def run_hybrid_kem_benchmark(iterations: int, warmup: int = 20) -> Optional[Tuple[Dict, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]]:
    """Benchmark Hybrid X25519 + ML-KEM-768 Key Exchange with pre-allocated context & warm-up."""
    if not OQS_AVAILABLE:
        return None

    try:
        keygen_ms = np.zeros(iterations)
        encap_ms = np.zeros(iterations)
        decap_ms = np.zeros(iterations)
        pk_sizes = np.zeros(iterations)
        ct_sizes = np.zeros(iterations)
        ss_sizes = np.zeros(iterations)

        # Pre-instantiate client and server KEM contexts
        with oqs.KeyEncapsulation('ML-KEM-768') as kem_client, oqs.KeyEncapsulation('ML-KEM-768') as kem_server:
            # Warm-up phase
            for _ in range(warmup):
                c_x = x25519.X25519PrivateKey.generate()
                c_k = kem_client.generate_keypair()
                s_x = x25519.X25519PrivateKey.generate()
                s_x_ss = s_x.exchange(c_x.public_key())
                ct_k, s_k_ss = kem_server.encap_secret(c_k)
                ss_s = hashlib.sha256(s_x_ss + s_k_ss).digest()
                c_x_ss = c_x.exchange(s_x.public_key())
                c_k_ss = kem_client.decap_secret(ct_k)
                ss_c = hashlib.sha256(c_x_ss + c_k_ss).digest()
                assert ss_s == ss_c

            # Measured trials
            for i in range(iterations):
                # 1. Client keygen: X25519 + ML-KEM-768
                t0 = time.perf_counter()
                client_x = x25519.X25519PrivateKey.generate()
                client_x_pub = client_x.public_key().public_bytes_raw()
                client_kem_pub = kem_client.generate_keypair()
                keygen_ms[i] = (time.perf_counter() - t0) * 1000.0
                pk_sizes[i] = len(client_x_pub) + len(client_kem_pub)

                # 2. Server encap: X25519 exchange + ML-KEM encap
                t0 = time.perf_counter()
                server_x = x25519.X25519PrivateKey.generate()
                server_x_pub = server_x.public_key().public_bytes_raw()
                ss_x_server = server_x.exchange(x25519.X25519PublicKey.from_public_bytes(client_x_pub))
                ct_kem, ss_kem_server = kem_server.encap_secret(client_kem_pub)
                ss_hybrid_server = hashlib.sha256(ss_x_server + ss_kem_server).digest()
                encap_ms[i] = (time.perf_counter() - t0) * 1000.0
                ct_sizes[i] = len(server_x_pub) + len(ct_kem)

                # 3. Client decap: X25519 exchange + ML-KEM decap
                t0 = time.perf_counter()
                ss_x_client = client_x.exchange(x25519.X25519PublicKey.from_public_bytes(server_x_pub))
                ss_kem_client = kem_client.decap_secret(ct_kem)
                ss_hybrid_client = hashlib.sha256(ss_x_client + ss_kem_client).digest()
                decap_ms[i] = (time.perf_counter() - t0) * 1000.0
                ss_sizes[i] = len(ss_hybrid_client)

                assert ss_hybrid_client == ss_hybrid_server

        return {
            'algorithm': 'Hybrid (X25519 + ML-KEM-768)',
            'type': 'kem',
            'security_level': 'Hybrid Dual-Defense (RFC 7748 + FIPS 203 Level 3)',
            'keygen_ms': calculate_stats(keygen_ms),
            'encap_ms': calculate_stats(encap_ms),
            'decap_ms': calculate_stats(decap_ms),
            'pk_bytes': calculate_stats(pk_sizes),
            'ct_bytes': calculate_stats(ct_sizes),
            'ss_bytes': calculate_stats(ss_sizes)
        }, keygen_ms, encap_ms, decap_ms, pk_sizes, ct_sizes, ss_sizes
    except Exception as e:
        print(f"[!] Warning: Hybrid KEM benchmark error: {e}")
        return None


# ==============================================================================
# PLOTTING CHARTS
# ==============================================================================

def plot_micro_charts(sig_results: List[Dict], kem_results: List[Dict], out_dir: Path):
    """Plot scientific comparison charts for Signatures and KEMs."""
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')

    # 1. CHART 1: SIGNATURE PERFORMANCE (Latency & Payload Size)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    fig.suptitle('Micro-Benchmark: Digital Signature Schemes (Consensus & Transaction Security)', fontsize=14, fontweight='bold', y=0.98)

    sig_labels = [r['algorithm'] for r in sig_results]
    x = np.arange(len(sig_labels))
    width = 0.25

    # Latency Bars
    sign_means = [r['sign_ms']['mean'] for r in sig_results]
    verify_means = [r['verify_ms']['mean'] for r in sig_results]
    keygen_means = [r['keygen_ms']['mean'] for r in sig_results]

    ax1.bar(x - width, keygen_means, width, label='KeyGen (ms)', color='#3b82f6', alpha=0.9)
    ax1.bar(x, sign_means, width, label='Sign (ms)', color='#10b981', alpha=0.9)
    ax1.bar(x + width, verify_means, width, label='Verify (ms)', color='#f59e0b', alpha=0.9)
    ax1.set_title('Execution Latency (lower is better)', fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(sig_labels, rotation=15, ha='right', fontweight='bold')
    ax1.set_ylabel('Time (ms)')
    ax1.legend()
    ax1.grid(True, linestyle='--', alpha=0.5)

    # Size Bars
    pk_sizes = [r['pk_bytes']['mean'] for r in sig_results]
    sig_sizes = [r['sig_bytes']['mean'] for r in sig_results]

    ax2.bar(x - width/2, pk_sizes, width, label='Public Key (Bytes)', color='#6366f1', alpha=0.9)
    ax2.bar(x + width/2, sig_sizes, width, label='Signature (Bytes)', color='#ef4444', alpha=0.9)
    ax2.set_title('Wire Payload Size Overhead (Bytes)', fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(sig_labels, rotation=15, ha='right', fontweight='bold')
    ax2.set_ylabel('Size (Bytes)')
    for idx, (p, s) in enumerate(zip(pk_sizes, sig_sizes)):
        ax2.annotate(f"{int(p)}B", (idx - width/2, p), textcoords="offset points", xytext=(0, 3), ha='center', fontsize=9)
        ax2.annotate(f"{int(s)}B", (idx + width/2, s), textcoords="offset points", xytext=(0, 3), ha='center', fontsize=9)
    ax2.legend()
    ax2.grid(True, linestyle='--', alpha=0.5)

    plt.tight_layout()
    chart1_path = out_dir / "micro_signatures_benchmark.png"
    plt.savefig(chart1_path, dpi=300)
    plt.close()

    # 2. CHART 2: KEM / TLS PERFORMANCE (Latency & Wire Size)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    fig.suptitle('Micro-Benchmark: Key Encapsulation Mechanisms (TLS 1.3 Transport Security)', fontsize=14, fontweight='bold', y=0.98)

    kem_labels = [r['algorithm'] for r in kem_results]
    xk = np.arange(len(kem_labels))

    kg_kems = [r['keygen_ms']['mean'] for r in kem_results]
    enc_kems = [r['encap_ms']['mean'] for r in kem_results]
    dec_kems = [r['decap_ms']['mean'] for r in kem_results]

    ax1.bar(xk - width, kg_kems, width, label='KeyGen (ms)', color='#0ea5e9', alpha=0.9)
    ax1.bar(xk, enc_kems, width, label='Encap / Exchange (ms)', color='#8b5cf6', alpha=0.9)
    ax1.bar(xk + width, dec_kems, width, label='Decap / Derive (ms)', color='#ec4899', alpha=0.9)
    ax1.set_title('KEM Latency (lower is better)', fontweight='bold')
    ax1.set_xticks(xk)
    ax1.set_xticklabels(kem_labels, rotation=15, ha='right', fontweight='bold')
    ax1.set_ylabel('Time (ms)')
    ax1.legend()
    ax1.grid(True, linestyle='--', alpha=0.5)

    # KEM Sizes
    pk_kems = [r['pk_bytes']['mean'] for r in kem_results]
    ct_kems = [r['ct_bytes']['mean'] for r in kem_results]

    ax2.bar(xk - width/2, pk_kems, width, label='Client Public Key / Share (Bytes)', color='#14b8a6', alpha=0.9)
    ax2.bar(xk + width/2, ct_kems, width, label='Server Ciphertext / Share (Bytes)', color='#f97316', alpha=0.9)
    ax2.set_title('TLS Handshake Key Share Overhead (Bytes)', fontweight='bold')
    ax2.set_xticks(xk)
    ax2.set_xticklabels(kem_labels, rotation=15, ha='right', fontweight='bold')
    ax2.set_ylabel('Size (Bytes)')
    for idx, (p, c) in enumerate(zip(pk_kems, ct_kems)):
        ax2.annotate(f"{int(p)}B", (idx - width/2, p), textcoords="offset points", xytext=(0, 3), ha='center', fontsize=9)
        ax2.annotate(f"{int(c)}B", (idx + width/2, c), textcoords="offset points", xytext=(0, 3), ha='center', fontsize=9)
    ax2.legend()
    ax2.grid(True, linestyle='--', alpha=0.5)

    plt.tight_layout()
    chart2_path = out_dir / "micro_kem_benchmark.png"
    plt.savefig(chart2_path, dpi=300)
    plt.close()

    print(f"\n[+] Da xuat thanh cong 2 bieu do Micro-Benchmark:")
    print(f"    1. {chart1_path}")
    print(f"    2. {chart2_path}")


# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Micro-Benchmark Suite: Blockchain Signatures & TLS KEM")
    parser.add_argument('-n', '--iterations', type=int, default=100, help="Số lần lặp kiểm thử (mặc định: 100)")
    parser.add_argument('-w', '--warmup', type=int, default=20, help="Số lần chạy khởi động Warm-up không ghi nhận (mặc định: 20)")
    parser.add_argument('-o', '--output-dir', type=str, default="", help="Thư mục xuất kết quả")
    args = parser.parse_args()

    iterations = args.iterations if args.iterations > 0 else 100
    warmup = args.warmup if args.warmup >= 0 else 20
    base_dir = Path(__file__).resolve().parent
    out_dir = Path(args.output_dir) if args.output_dir else base_dir / "results" / "crypto_micro"
    out_dir.mkdir(parents=True, exist_ok=True)

    message = b'{"sender": "Alice_PQC", "recipient": "Bob_PQC", "amount": 25.5, "nonce": 42}'

    print("=" * 96)
    print("  MICRO-BENCHMARK: DANH GIA HIEN TRANG MAT MA HAU LUONG TU (PQC & CLASSICAL)")
    print("  Signatures : ECDSA (secp256k1) | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 (FIPS 204)")
    print("  KEM / TLS  : Classical X25519 | Pure ML-KEM-512 | Pure ML-KEM-768 | Hybrid X25519+ML-KEM-768")
    print(f"  Warm-up    : {warmup} unmetered cycles | Trials: {iterations} iterations | Platform: {sys.platform}")
    print("=" * 96)

    sig_results = []
    kem_results = []

    # 1. Signatures
    print("\n--- PHAN 1: CHU KY SO GIAO DICH (SIGNATURES) ---")

    print(f"[*] 1/4 Dang chay ECDSA (secp256k1) [Warmup: {warmup}, Trials: {iterations}]...")
    res, kg, sg, vf, pk, sig = run_ecdsa_benchmark(iterations, message, warmup=warmup)
    sig_results.append(res)
    save_raw_sig_csv(out_dir / "ECDSA_secp256k1_raw.csv", iterations, kg, sg, vf, pk, sig)

    for mldsa_alg in ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']:
        print(f"[*] Dang chay {mldsa_alg} (FIPS 204) [Warmup: {warmup}, Trials: {iterations}]...")
        m_out = run_mldsa_benchmark(iterations, message, mldsa_alg, warmup=warmup)
        if m_out:
            res, kg, sg, vf, pk, sig = m_out
            sig_results.append(res)
            save_raw_sig_csv(out_dir / f"{mldsa_alg.replace('-', '_')}_raw.csv", iterations, kg, sg, vf, pk, sig)

    # 2. KEMs
    print("\n--- PHAN 2: TRAO DOI KHOA TLS (KEY ENCAPSULATION / KEM) ---")

    print(f"[*] 1/4 Dang chay Classical ECDHE (X25519) [Warmup: {warmup}, Trials: {iterations}]...")
    k_res, kg, enc, dec, pk, ct, ss = run_x25519_benchmark(iterations, warmup=warmup)
    kem_results.append(k_res)
    save_raw_kem_csv(out_dir / "Classical_X25519_raw.csv", iterations, kg, enc, dec, pk, ct, ss)

    for kem_alg in ['ML-KEM-512', 'ML-KEM-768']:
        print(f"[*] Dang chay Pure {kem_alg} (FIPS 203) [Warmup: {warmup}, Trials: {iterations}]...")
        k_out = run_pure_mlkem_benchmark(iterations, kem_alg, warmup=warmup)
        if k_out:
            res, kg, enc, dec, pk, ct, ss = k_out
            kem_results.append(res)
            save_raw_kem_csv(out_dir / f"Pure_{kem_alg.replace('-', '_')}_raw.csv", iterations, kg, enc, dec, pk, ct, ss)

    print(f"[*] 4/4 Dang chay Hybrid (X25519 + ML-KEM-768) [Warmup: {warmup}, Trials: {iterations}]...")
    h_out = run_hybrid_kem_benchmark(iterations, warmup=warmup)
    if h_out:
        res, kg, enc, dec, pk, ct, ss = h_out
        kem_results.append(res)
        save_raw_kem_csv(out_dir / "Hybrid_X25519_MLKEM768_raw.csv", iterations, kg, enc, dec, pk, ct, ss)

    # In bang Signature
    print("\n" + "=" * 105)
    print("BANG 1: KET QUA MICRO-BENCHMARK CHU KY SO GIAO DICH (SAU WARM-UP)")
    print(f"{'Thuat toan':<22} | {'Keygen (ms)':<14} | {'Sign (ms)':<14} | {'Verify (ms)':<14} | {'PK (B)':<8} | {'Sig (B)':<8}")
    print("-" * 105)
    for r in sig_results:
        print(f"{r['algorithm']:<22} | "
              f"{r['keygen_ms']['mean']:>6.3f} ± {r['keygen_ms']['std']:<4.2f} | "
              f"{r['sign_ms']['mean']:>6.3f} ± {r['sign_ms']['std']:<4.2f} | "
              f"{r['verify_ms']['mean']:>6.3f} ± {r['verify_ms']['std']:<4.2f} | "
              f"{int(r['pk_bytes']['mean']):<8} | "
              f"{int(r['sig_bytes']['mean']):<8}")
    print("=" * 105)

    # In bang KEM
    print("\n" + "=" * 115)
    print("BANG 2: KET QUA MICRO-BENCHMARK TRAO DOI KHOA TLS (KEM) (SAU WARM-UP)")
    print(f"{'Co che KEM':<30} | {'Keygen (ms)':<14} | {'Encap (ms)':<14} | {'Decap (ms)':<14} | {'PK (B)':<8} | {'CT (B)':<8}")
    print("-" * 115)
    for r in kem_results:
        print(f"{r['algorithm']:<30} | "
              f"{r['keygen_ms']['mean']:>6.3f} ± {r['keygen_ms']['std']:<4.2f} | "
              f"{r['encap_ms']['mean']:>6.3f} ± {r['encap_ms']['std']:<4.2f} | "
              f"{r['decap_ms']['mean']:>6.3f} ± {r['decap_ms']['std']:<4.2f} | "
              f"{int(r['pk_bytes']['mean']):<8} | "
              f"{int(r['ct_bytes']['mean']):<8}")
    print("=" * 115)

    # Luu JSON tong hop
    summary_data = {
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'iterations': iterations,
        'warmup_cycles': warmup,
        'signatures': sig_results,
        'kems': kem_results
    }
    summary_file = out_dir / "micro_benchmark_summary.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary_data, f, indent=2)

    # Ve bieu do
    plot_micro_charts(sig_results, kem_results, out_dir)

    print(f"\n[+] Da hoan tat toan bo Micro-Benchmark va luu tai:")
    print(f"    - JSON: {summary_file}")
    print(f"    - Thu muc CSV & Bieu do: {out_dir}")


if __name__ == '__main__':
    main()
