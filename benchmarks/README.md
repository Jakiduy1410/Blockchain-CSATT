# 📊 Bộ Đôi Benchmark: Micro & Macro Benchmark Suite (ML-DSA-44 & TLS KEMs)

Thư mục `benchmarks/` cung cấp hệ thống kiểm thử thực nghiệm khoa học toàn diện cho mạng Blockchain P2P, đối sánh chi phí tính toán mật mã và đánh giá hiệu năng mạng lưới thời gian thực khi kết hợp **Chữ ký số Hậu lượng tử ML-DSA-44 (NIST FIPS 204)** cùng **6 cơ chế trao đổi khóa TLS 1.3 (ECDHE & Post-Quantum KEMs)**.

---

## 📁 1. Cấu trúc thư mục

```text
benchmarks/
├── configs/
│   └── benchmark_config.json               # Cấu hình tham số kiểm thử (Zero-Hardcode)
├── kem_suite.py                            # Module đàm phán 6 cơ chế KEM (ECDHE, ML-KEM, Hybrid, HQC, FrodoKEM)
├── micro_benchmark.py                      # Đo lường tầng mật mã cô lập trên CPU (1.000 trials)
├── macro_benchmark.py                      # Đo tải End-to-End mạng 6-Node P2P (HTTP vs HTTPS với ML-DSA-44)
└── results/                                # Kết quả thô xuất tự động ra CSV và JSON
    ├── ML_DSA_44_micro_raw.csv             # Dữ liệu 1.000 lần lặp ML-DSA-44
    ├── ECDSA_secp256k1_micro_raw.csv       # Dữ liệu 1.000 lần lặp ECDSA
    ├── RSA_2048_micro_raw.csv              # Dữ liệu 1.000 lần lặp RSA-2048
    ├── micro_benchmark_summary.json        # Thống kê tổng hợp Micro-Benchmark
    ├── macro_http_raw.csv                  # Dữ liệu tải mạng HTTP
    ├── macro_http_summary.json             # Tóm tắt kết quả tải HTTP
    ├── macro_hybrid_mlkem768_raw.csv       # Dữ liệu TLS Hybrid (X25519 + ML-KEM-768)
    ├── macro_hybrid_mlkem768_summary.json  # Tóm tắt TLS Hybrid
    ├── macro_mlkem768_raw.csv              # Dữ liệu TLS ML-KEM-768
    ├── macro_mlkem768_summary.json         # Tóm tắt TLS ML-KEM-768
    ├── macro_x25519_raw.csv                # Dữ liệu TLS ECDHE X25519
    ├── macro_x25519_summary.json           # Tóm tắt TLS ECDHE X25519
    ├── macro_secp256r1_raw.csv             # Dữ liệu TLS ECDHE P-256
    ├── macro_secp256r1_summary.json        # Tóm tắt TLS ECDHE P-256
    ├── macro_hqc128_raw.csv                # Dữ liệu TLS HQC-128
    ├── macro_hqc128_summary.json           # Tóm tắt TLS HQC-128
    ├── macro_frodokem640_raw.csv           # Dữ liệu TLS FrodoKEM-640
    ├── macro_frodokem640_summary.json      # Tóm tắt TLS FrodoKEM-640
    └── macro_kem_comparison_summary.json   # Tổng hợp ma trận so sánh song song cả 6 KEM
```

---

## 🔬 2. Micro-Benchmark: Đo lường chi phí toán học tầng mật mã

### 2.1. Mục tiêu đo lường
Đo lường cô lập trên CPU qua $1.000$ lần lặp cho 3 thế hệ chữ ký số:
1. **RSA-2048:** Mật mã khóa công khai truyền thống (Chuẩn PKCS#1 v1.5).
2. **ECDSA (secp256k1):** Đường cong Elliptic tiêu chuẩn vàng của Bitcoin & Ethereum.
3. **ML-DSA-44 (Dilithium-2):** Chuẩn chữ ký số Hậu lượng tử quốc tế **NIST FIPS 204** dựa trên mạng tinh thể (Module-LWE).

### 2.2. Lệnh thực thi

```powershell
# Chạy mặc định 1.000 lần lặp:
python benchmarks/micro_benchmark.py

# Hoặc tùy biến số lần lặp:
python benchmarks/micro_benchmark.py -n 500
```

### 2.3. Bảng kết quả thực nghiệm Micro-Benchmark ($1.000$ trials)

| Thuật toán | KeyGen (ms) | Sign (ms) | Verify (ms) | Public Key | Chữ ký | Crypto TPS Lý thuyết | Block 1.000 txs |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RSA-2048** | $40.852$ | $0.627$ | $0.038$ | $270\text{ B}$ | $256\text{ B}$ | **$26.315\text{ tx/s}$** | $626\text{ KB}$ |
| **ECDSA (secp256k1)** | **$0.043$** | $0.187$ | $0.685$ | **$33\text{ B}$** | **$64\text{ B}$** | **$1.459\text{ tx/s}$** | **$338\text{ KB}$** |
| **ML-DSA-44 (PQC)** | $0.052$ | **$0.118$** | **$0.082$** | $1.312\text{ B}$ | $2.420\text{ B}$ | **$12.195\text{ tx/s}$** | **$3.88\text{ MB}$** |

> **Nhận xét kiến trúc & Đánh đổi thực tế:**
> - **ML-DSA-44** sở hữu tốc độ ký và xác thực rất cao ($0.118\text{ ms}$ và $0.082\text{ ms}$), vượt trội so với ECDSA nhờ cấu trúc phép nhân đa thức NTT trên mạng tinh thể.
> - **Đánh đổi lưu trữ:** Kích thước chữ ký ML-DSA-44 ($2.420\text{ bytes}$) và Public Key ($1.312\text{ bytes}$) khiến khối phình to lên tới **$3.88\text{ MB}$** cho 1.000 giao dịch (gấp 11.5 lần so với ECDSA $338\text{ KB}$).

---

## 🌐 3. Macro-Benchmark: Đo tải mạng phân tán 6-Node P2P (HTTP vs HTTPS/TLS KEMs với ML-DSA-44)

### 3.1. Mục tiêu đo lường
Kiểm thử toàn trình (**End-to-End Live Network**) trên mô hình mạng Mesh 6 Node (`Port 5000` đến `5005`):
- **Chữ ký số giao dịch:** Chữ ký số Hậu lượng tử **ML-DSA-44 (NIST FIPS 204)** cho toàn bộ giao dịch trong khối.
- **Kênh truyền TLS:** Đánh giá và so sánh thực nghiệm giữa **HTTP Cleartext** và **6 cơ chế trao đổi khóa TLS 1.3 (Key Exchange / KEM)**:
  1. **ECDHE (secp256r1):** Đường cong Weierstrass (NIST P-256).
  2. **ECDHE (X25519):** Đường cong Montgomery (Curve25519).
  3. **ML-KEM-768:** Chuẩn mạng tinh thể (Module-LWE / NIST FIPS 203 / Kyber-768).
  4. **Hybrid (X25519 + ML-KEM-768):** Cơ chế lai chuẩn IETF TLS 1.3 Draft (Bảo vệ kép: Cổ điển + Hậu lượng tử).
  5. **HQC-128:** Chuẩn mã sửa sai (Hamming Quasi-Cyclic / NIST Round 4).
  6. **FrodoKEM-640:** Chuẩn mạng tinh thể phi cấu trúc (Standard LWE / NIST Round 3).

### 3.2. Lệnh thực thi

```powershell
# 1. Chạy bài kiểm thử thuần HTTP (Cleartext, không dùng TLS):
python benchmarks/macro_benchmark.py --http

# 2. Chạy bài kiểm thử TOÀN BỘ 6 CƠ CHẾ KEM và tự động xuất bảng so sánh song song:
python benchmarks/macro_benchmark.py --compare-kems

# 3. Chạy bài kiểm thử cho 1 cơ chế KEM cụ thể:
python benchmarks/macro_benchmark.py --kem hybrid_mlkem768   # Cơ chế Lai Hybrid X25519 + ML-KEM-768
python benchmarks/macro_benchmark.py --kem mlkem768          # ML-KEM-768 thuần
python benchmarks/macro_benchmark.py --kem x25519            # ECDHE X25519
python benchmarks/macro_benchmark.py --kem secp256r1         # ECDHE P-256
python benchmarks/macro_benchmark.py --kem hqc128            # HQC-128
python benchmarks/macro_benchmark.py --kem frodokem640       # FrodoKEM-640

# 4. Tùy biến số lượng giao dịch bắn tải:
python benchmarks/macro_benchmark.py --http -n 30
python benchmarks/macro_benchmark.py --compare-kems -n 30
```

*Lưu ý: Script tự động kích hoạt mạng 6-Node (HTTP hoặc HTTPS tương ứng) ngầm và tự động thu hồi/tắt tiến trình khi kết thúc.*

### 3.3. Bảng so sánh thực nghiệm tổng hợp các cơ chế KEM (Kết hợp chữ ký ML-DSA-44)

| Chỉ số đo lường (Metric) | HTTP (Cleartext) | ECDHE-P256 | ECDHE-X25519 | ML-KEM-768 (PQC) | Hybrid (X255+ML) | HQC-128 (PQC) | FrodoKEM-640 (PQC) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Bảo vệ truyền thông** | ❌ Không TLS | Classical ECC | Classical ECC | **Lattice (M-LWE)** | **Hybrid Dual** | **Code-based** | **Lattice (LWE)** |
| **Kháng máy tính lượng tử** | ❌ Không | ❌ KHÔNG | ❌ KHÔNG | ✅ **CÓ (Safe)** | ✅ **CÓ (Bảo vệ kép)**| ✅ **CÓ (Safe)** | ✅ **CÓ (Safe)** |
| **Chữ ký giao dịch** | **ML-DSA-44** | **ML-DSA-44** | **ML-DSA-44** | **ML-DSA-44** | **ML-DSA-44** | **ML-DSA-44** | **ML-DSA-44** |
| **KEM Handshake Wire** | $0\text{ B}$ | **$97\text{ B}$** | **$64\text{ B}$** | $2.272\text{ B}$ | **$2.336\text{ B}$** | $6.674\text{ B}$ | $19.336\text{ B}$ |
| **KEM Handshake Time** | $0.0\text{ ms}$ | $0.988\text{ ms}$ | $2.740\text{ ms}$ | **$0.205\text{ ms}$** | **$0.320\text{ ms}$** | $4.872\text{ ms}$ | $571.864\text{ ms}$ |
| **E2E Ingestion Latency** | **$10.77\text{ ms}$** | $60.90\text{ ms}$ | **$45.72\text{ ms}$** | $64.92\text{ ms}$ | **$52.79\text{ ms}$** | $59.27\text{ ms}$ | $591.36\text{ ms}$ |
| **Độ trễ P95 (Latency)** | **$20.85\text{ ms}$** | $83.39\text{ ms}$ | **$59.78\text{ ms}$** | $89.86\text{ ms}$ | **$80.66\text{ ms}$** | $74.63\text{ ms}$ | $602.29\text{ ms}$ |
| **Ingestion TPS** | **$91.51\text{ tx/s}$** | $16.39\text{ tx/s}$ | **$21.82\text{ tx/s}$** | $15.36\text{ tx/s}$ | **$18.91\text{ tx/s}$** | $16.84\text{ tx/s}$ | $1.69\text{ tx/s}$ |
| **Block Wire Size (4 txs)** | $30.39\text{ KB}$ | $30.38\text{ KB}$ | $30.38\text{ KB}$ | $30.38\text{ KB}$ | $30.38\text{ KB}$ | $30.38\text{ KB}$ | $30.38\text{ KB}$ |
| **Average Bytes / Tx** | **$7.778\text{ B}$** | **$7.778\text{ B}$** | **$7.778\text{ B}$** | **$7.778\text{ B}$** | **$7.778\text{ B}$** | **$7.778\text{ B}$** | **$7.778\text{ B}$** |

> **Phân tích mô hình Bảo Mật Hậu Lượng Tử Toàn Diện (End-to-End Post-Quantum Security):**
> - **Nguyên lý bảo vệ kép (Double Quantum Defense):** Sự kết hợp giữa kênh truyền **TLS Hybrid (X25519 + ML-KEM-768)** và chữ ký số **ML-DSA-44** mang lại khả năng chống lại các cuộc tấn công *Harvest Now, Decrypt Later* từ máy tính lượng tử trên cả tầng truyền thông (Transport) và tầng ứng dụng phân tán (Blockchain Consensus).
> - **Kích thước gói tin lớn hơn:** Do kích thước chữ ký ML-DSA-44 ($2.420\text{ bytes}$) và Public Key ($1.312\text{ bytes}$) lớn hơn đáng kể so với ECDSA, mỗi giao dịch chiếm khoảng **$7.78\text{ KB}$**, khiến block 4 giao dịch đạt xấp xỉ **$30.38\text{ KB}$**. Mặc dù vậy, thông lượng tiếp nhận trên mạng thật vẫn duy trì ở mức $15 - 21\text{ tx/s}$ trên các kênh TLS và đạt $91.5\text{ tx/s}$ trên kênh HTTP.

---

## 📈 4. Dữ liệu thô phục vụ báo cáo khoa học (`results/`)

Toàn bộ dữ liệu đo đạc chi tiết được tự động lưu trữ dưới định dạng `.csv` và `.json` theo từng thuật toán riêng biệt:

### 4.1. File dữ liệu thô (.csv) và tóm tắt (.json) từng kịch bản:
- **HTTP thuần (Không mã hóa):** [`results/macro_http_raw.csv`](results/macro_http_raw.csv), [`results/macro_http_summary.json`](results/macro_http_summary.json)
- **Hybrid (X25519 + ML-KEM-768):** [`results/macro_hybrid_mlkem768_raw.csv`](results/macro_hybrid_mlkem768_raw.csv), [`results/macro_hybrid_mlkem768_summary.json`](results/macro_hybrid_mlkem768_summary.json)
- **ML-KEM-768:** [`results/macro_mlkem768_raw.csv`](results/macro_mlkem768_raw.csv), [`results/macro_mlkem768_summary.json`](results/macro_mlkem768_summary.json)
- **ECDHE (X25519):** [`results/macro_x25519_raw.csv`](results/macro_x25519_raw.csv), [`results/macro_x25519_summary.json`](results/macro_x25519_summary.json)
- **ECDHE (secp256r1):** [`results/macro_secp256r1_raw.csv`](results/macro_secp256r1_raw.csv), [`results/macro_secp256r1_summary.json`](results/macro_secp256r1_summary.json)
- **HQC-128:** [`results/macro_hqc128_raw.csv`](results/macro_hqc128_raw.csv), [`results/macro_hqc128_summary.json`](results/macro_hqc128_summary.json)
- **FrodoKEM-640:** [`results/macro_frodokem640_raw.csv`](results/macro_frodokem640_raw.csv), [`results/macro_frodokem640_summary.json`](results/macro_frodokem640_summary.json)

### 4.2. File tổng hợp so sánh song song:
- **[`results/macro_kem_comparison_summary.json`](results/macro_kem_comparison_summary.json)**: Chứa toàn bộ cấu trúc dữ liệu đối sánh song song của cả 6 cơ chế KEM phục vụ render biểu đồ so sánh.

---

## 🛠️ 5. Yêu cầu môi trường & Thư viện

- **Python:** Phiên bản 3.10+ (Khuyến nghị Python 3.12).
- **Cài đặt toàn bộ thư viện mật mã & phụ thuộc:**
  ```powershell
  pip install requests numpy scipy cryptography ecdsa pqcrypto frodokem-with-chat
  ```
- **Chứng chỉ TLS:** Tự động sinh bởi script hoặc chạy:
  ```powershell
  python certs/generate_certs.py
  ```
