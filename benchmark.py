import time
import csv
import numpy as np
import scipy.stats as stats
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import oqs

# --- CẤU HÌNH THỰC NGHIỆM ---
MESSAGE = b'{"sender": "Alice", "recipient": "Bob", "amount": 100.0}'
ITERATIONS_STD = 1000

# --- CẤU HÌNH MÔ PHỎNG BLOCKCHAIN ---
N_TX = 1000       # Số lượng giao dịch trong 1 khối
D_PAYLOAD = 250   # Tải trọng dữ liệu mỗi giao dịch (bytes)


def calculate_and_print_stats(metric_name, data):
    """Tính toán và in các chỉ số thống kê bao gồm khoảng tin cậy Bootstrap 95%."""
    mean = np.mean(data)
    median = np.median(data)
    std = np.std(data, ddof=1) if len(data) > 1 else 0
    
    # Tính Bootstrap 95% CI bằng 10.000 lần lấy mẫu lại
    res = stats.bootstrap((data,), np.mean, confidence_level=0.95, n_resamples=10000, method='percentile')
    ci_low, ci_high = res.confidence_interval.low, res.confidence_interval.high
    
    print(f"  {metric_name}:")
    print(f"    - Trung bình đại số: {mean:.4f}")
    print(f"    - Trung vị (Median): {median:.4f}")
    print(f"    - Độ lệch chuẩn:     {std:.4f}")
    print(f"    - 95% Bootstrap CI:  [{ci_low:.4f}, {ci_high:.4f}]")
    
    return mean


def save_to_csv(algo_name, iterations, keygen_times, sign_times, verify_times, pk_sizes, sig_sizes):
    """Lưu toàn bộ đo lường thô tại mỗi lần lặp ra file CSV để đảm bảo tính tái lập."""
    safe_algo_name = algo_name.replace(' ', '_').replace('+', '_plus')
    csv_filename = f"{safe_algo_name}_raw_data.csv"
    with open(csv_filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Iteration', 'Keygen_ms', 'Sign_ms', 'Verify_ms', 'PK_bytes', 'Sig_bytes'])
        for i in range(iterations):
            writer.writerow([i+1, keygen_times[i], sign_times[i], verify_times[i], pk_sizes[i], sig_sizes[i]])
    print(f"  => Đã xuất dữ liệu thô ra: {csv_filename}")


def simulate_blockchain(mean_pk, mean_sig, mean_verify_ms):
    """Tính toán các chỉ số ước tính theo mô hình mô phỏng Blockchain."""
    # Ước tính kích thước khối: B_block = N_tx * (σ_sig + σ_pk + D)
    b_block_bytes = N_TX * (mean_sig + mean_pk + D_PAYLOAD)
    
    # Ước tính thông lượng (TPS): TPS_crypto = 1.000 / t_verify_ms
    tps = 1000 / mean_verify_ms if mean_verify_ms > 0 else float('inf')
    
    print(f"\n  [MÔ PHỎNG BLOCKCHAIN]")
    print(f"    - Kích thước khối ước tính (B_block): {b_block_bytes / 1024:.2f} KB ({b_block_bytes:.0f} bytes)")
    print(f"    - Thông lượng giao dịch (TPS_crypto): {tps:.2f} tx/s")


def process_results(algo_name, iterations, keygen_times, sign_times, verify_times, pk_sizes, sig_sizes):
    """Quy trình tổng hợp để phân tích, in thống kê và mô phỏng sau khi có dữ liệu."""
    print(f"\n  [KẾT QUẢ THỐNG KÊ QUA {iterations} LẦN LẶP]")
    calculate_and_print_stats("Độ trễ tạo khóa (ms)", keygen_times)
    calculate_and_print_stats("Độ trễ ký (ms)", sign_times)
    mean_verify = calculate_and_print_stats("Độ trễ xác thực (ms)", verify_times)
    
    mean_pk = calculate_and_print_stats("Kích thước Public-key (bytes)", pk_sizes)
    mean_sig = calculate_and_print_stats("Kích thước Chữ ký (bytes)", sig_sizes)
    
    save_to_csv(algo_name, iterations, keygen_times, sign_times, verify_times, pk_sizes, sig_sizes)
    simulate_blockchain(mean_pk, mean_sig, mean_verify)


def measure_rsa():
    """Benchmark cho RSA 2048-bit."""
    print(f"\n{'='*60}\n--- RSA (2048-bit - cryptography) ---")
    iterations = ITERATIONS_STD
    
    keygen_times, sign_times, verify_times = np.zeros(iterations), np.zeros(iterations), np.zeros(iterations)
    pk_sizes, sig_sizes = np.zeros(iterations), np.zeros(iterations)

    for i in range(iterations):
        # 1. Tạo khóa
        t0 = time.perf_counter()
        sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pk = sk.public_key()
        t1 = time.perf_counter()
        keygen_times[i] = (t1 - t0) * 1000
        
        # Lấy định dạng PKCS1 nguyên thủy thay vì bọc X.509
        pk_bytes = pk.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
        pk_sizes[i] = len(pk_bytes)

        # 2. Ký
        t0 = time.perf_counter()
        sig = sk.sign(MESSAGE, padding.PKCS1v15(), hashes.SHA256())
        t1 = time.perf_counter()
        sign_times[i] = (t1 - t0) * 1000
        sig_sizes[i] = len(sig) # Chữ ký RSA cố định bằng kích thước khóa (256 bytes)

        # 3. Xác thực
        t0 = time.perf_counter()
        pk.verify(sig, MESSAGE, padding.PKCS1v15(), hashes.SHA256())
        t1 = time.perf_counter()
        verify_times[i] = (t1 - t0) * 1000

    process_results("RSA_2048", iterations, keygen_times, sign_times, verify_times, pk_sizes, sig_sizes)


def measure_ecdsa():
    """Benchmark cho ECDSA sử dụng thư viện cryptography trên đường cong secp256k1 (Chuẩn định dạng Blockchain)."""
    print(f"\n{'='*60}\n--- ECDSA (secp256k1 - cryptography - RAW Format) ---")
    iterations = ITERATIONS_STD
    
    keygen_times, sign_times, verify_times = np.zeros(iterations), np.zeros(iterations), np.zeros(iterations)
    pk_sizes, sig_sizes = np.zeros(iterations), np.zeros(iterations)

    for i in range(iterations):
        # 1. Tạo khóa
        t0 = time.perf_counter()
        sk = ec.generate_private_key(ec.SECP256K1())
        pk = sk.public_key()
        t1 = time.perf_counter()
        keygen_times[i] = (t1 - t0) * 1000
        
        # Bỏ X.509, sử dụng chuẩn nén điểm X962 (CompressedPoint) giống Blockchain thực tế
        pk_bytes = pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        pk_sizes[i] = len(pk_bytes) # Sẽ luôn là 33 bytes

        # 2. Ký
        t0 = time.perf_counter()
        sig_der = sk.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))
        t1 = time.perf_counter()
        sign_times[i] = (t1 - t0) * 1000
        
        # Trích xuất 2 số nguyên r, s từ ASN.1 DER để lấy chữ ký RAW
        r, s = decode_dss_signature(sig_der)
        # Ép độ dài chuẩn r và s mỗi số thành 32 byte
        raw_sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        sig_sizes[i] = len(raw_sig) # Sẽ luôn là 64 bytes

        # 3. Xác thực
        t0 = time.perf_counter()
        pk.verify(sig_der, MESSAGE, ec.ECDSA(hashes.SHA256()))
        t1 = time.perf_counter()
        verify_times[i] = (t1 - t0) * 1000

    process_results("ECDSA", iterations, keygen_times, sign_times, verify_times, pk_sizes, sig_sizes)


def measure_oqs(alg_name, iterations):
    """Benchmark cho các thuật toán Hậu lượng tử thông qua liboqs."""
    print(f"\n{'='*60}\n--- PQC: {alg_name} ---")
    
    keygen_times, sign_times, verify_times = np.zeros(iterations), np.zeros(iterations), np.zeros(iterations)
    pk_sizes, sig_sizes = np.zeros(iterations), np.zeros(iterations)

    with oqs.Signature(alg_name) as signer:
        for i in range(iterations):
            # 1. Tạo khóa
            t0 = time.perf_counter()
            pk = signer.generate_keypair()
            t1 = time.perf_counter()
            keygen_times[i] = (t1 - t0) * 1000
            pk_sizes[i] = signer.details['length_public_key'] # Raw bytes

            # 2. Ký
            t0 = time.perf_counter()
            sig = signer.sign(MESSAGE)
            t1 = time.perf_counter()
            sign_times[i] = (t1 - t0) * 1000
            sig_sizes[i] = signer.details['length_signature'] # Raw bytes

            # 3. Xác thực
            t0 = time.perf_counter()
            signer.verify(MESSAGE, sig, pk)
            t1 = time.perf_counter()
            verify_times[i] = (t1 - t0) * 1000

    process_results(alg_name, iterations, keygen_times, sign_times, verify_times, pk_sizes, sig_sizes)


if __name__ == '__main__':
    print("BẮT ĐẦU QUÁ TRÌNH BENCHMARK VÀ MÔ PHỎNG CHO 3 THUẬT TOÁN")
    
    measure_rsa()
    measure_ecdsa()
    measure_oqs("ML-DSA-44", ITERATIONS_STD)
