# 📊 Blockchain Security & Performance Benchmark Suite

Bộ công cụ kiểm nghiệm thực nghiệm khoa học toàn diện (**Scientific Benchmark Suite**) cho hệ thống Blockchain, được thiết kế tuân thủ nguyên tắc **Zero-Hardcode**, hỗ trợ đa nền tảng (**Linux, macOS, Windows**) và chia làm 2 tầng kiểm thử chuyên biệt:
1. **Micro-Benchmark:** Đo lường cô lập chi phí toán học & không gian lưu trữ của các nguyên thủy mật mã (RSA-2048 vs ECDSA vs ML-DSA-44 Hậu lượng tử).
2. **Macro-Benchmark:** Đo tải thực tế mạng phân tán 6 Node P2P Mesh (Ingestion TPS, Network Latency, Block Propagation, Payload Wire Size) trên cả hai giao thức **HTTP (Cleartext)** và **HTTPS (TLS 1.3 / X.509)**.

---

## 📁 Cấu trúc thư mục `benchmarks/`

```text
benchmarks/
├── configs/
│   └── benchmark_config.json        # File cấu hình trung tâm (Zero-Hardcode)
├── results/                         # Thư mục xuất dữ liệu thô (.csv) & tổng hợp (.json)
│   ├── RSA_2048_micro_raw.csv
│   ├── ECDSA_secp256k1_micro_raw.csv
│   ├── micro_benchmark_summary.json
│   ├── macro_transactions_http_raw.csv
│   ├── macro_transactions_tls_raw.csv
│   ├── macro_benchmark_http_summary.json
│   ├── macro_benchmark_tls_summary.json
│   └── macro_benchmark_comparison.json
├── micro_benchmark.py               # Đo lường thuật toán mật mã CPU (Khoảng tin cậy CI 95%)
├── macro_benchmark.py               # Đo tải E2E mạng 6-Node (HTTP vs HTTPS/TLS)
└── README.md                        # Tài liệu hướng dẫn sử dụng chi tiết
```

---

## ⚙️ 1. Cấu hình kiểm nghiệm (`configs/benchmark_config.json`)

Mọi tham số kiểm thử đều được cấu hình độc lập, không hardcode trong mã nguồn:

```json
{
  "micro": {
    "iterations": 1000,              // Số vòng lặp thực nghiệm cho mỗi thuật toán
    "payload_bytes": 250,            // Kích thước bản tin giao dịch mẫu (bytes)
    "simulated_block_txs": 1000      // Số giao dịch để tính dung lượng khối giả lập
  },
  "macro": {
    "tx_count": 30,                  // Số lượng giao dịch ký số ECDSA bắn tải
    "ingress_url": "http://127.0.0.1:5000",
    "miner_url": "http://127.0.0.1:5001",
    "nodes": [
      "http://127.0.0.1:5000",
      "http://127.0.0.1:5001",
      "http://127.0.0.1:5002",
      "http://127.0.0.1:5003",
      "http://127.0.0.1:5004",
      "http://127.0.0.1:5005"
    ],
    "client_url": "http://127.0.0.1:8080",
    "timeout_seconds": 30,
    "use_tls": false,
    "ssl_cert": "certs/server.crt",
    "ssl_key": "certs/server.key"
  }
}
```

---

## 🔬 2. Micro-Benchmark: Đo lường cô lập tầng mật mã

### 2.1. Mục tiêu đo lường
Đánh giá hiệu năng và sự đánh đổi giữa 3 thuật toán chữ ký điện tử tiêu biểu:
- **RSA-2048:** Mật mã khóa công khai cổ điển (Dựa trên bài toán phân tích thừa số nguyên).
- **ECDSA (secp256k1):** Tiêu chuẩn vàng của Blockchain truyền thống (Bitcoin, Ethereum - Đường cong Elliptic).
- **ML-DSA-44 (Dilithium2):** Chuẩn mật mã hậu lượng tử NIST FIPS 204 (Dựa trên bài toán lưới - Module-LWE/SIS).

Các chỉ số thu thập qua phương pháp thống kê **Bootstrap 95% Confidence Interval ($CI_{95\%}$)**:
- Thời gian sinh khóa (**KeyGen** - ms).
- Thời gian ký số (**Sign** - ms).
- Thời gian xác thực (**Verify** - ms).
- Kích thước Khóa công khai (**Public Key Size** - bytes).
- Kích thước Chữ ký (**Signature Size** - bytes).
- Thông lượng lý thuyết tối đa (**Theoretical Max TPS** = $1 / \text{Verify\_time}$).
- Dung lượng khối giả lập cho 1.000 giao dịch (**1000-Tx Block Size** - KB/MB).

### 2.2. Lệnh thực thi

```powershell
# Chạy mặc định (1.000 trials theo cấu hình JSON):
python benchmarks/micro_benchmark.py

# Tùy biến số vòng lặp (Ví dụ: 500 vòng lặp):
python benchmarks/micro_benchmark.py -n 500

# Chỉ định file cấu hình hoặc thư mục kết quả khác:
python benchmarks/micro_benchmark.py -c benchmarks/configs/benchmark_config.json -o benchmarks/results/
```

### 2.3. Bảng kết quả thực nghiệm mẫu (1.000 trials)

| Thuật toán | KeyGen (ms) | Sign (ms) | Verify (ms) | PK (Bytes) | Sig (Bytes) | Max TPS Lý thuyết | Block 1.000 Tx |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RSA-2048** | $40.852$ | $0.627$ | $0.038$ | $270$ | $256$ | **$26.315\text{ tx/s}$** | $626\text{ KB}$ |
| **ECDSA (secp256k1)** | **$0.043$** | $0.187$ | $0.685$ | **$33$** | **$64$** | **$1.459\text{ tx/s}$** | **$338\text{ KB}$** |
| **ML-DSA-44 (PQC)** | $0.052$ | **$0.118$** | **$0.082$** | $1.312$ | $2.420$ | **$12.195\text{ tx/s}$** | **$3.88\text{ MB}$** |

> **Nhận xét an ninh & Đánh đổi kiến trúc:**
> - **ECDSA** là lựa chọn tối ưu nhất cho mạng Blockchain lưu trữ phân tán nhờ kích thước Public Key ($33\text{ B}$) và Signature ($64\text{ B}$) cực nhỏ, giúp khối 1.000 Tx chỉ nặng $338\text{ KB}$, giảm thiểu nghẽn băng thông P2P.
> - **ML-DSA-44** có tốc độ ký và xác thực rất cao cùng khả năng kháng máy tính lượng tử, nhưng kích thước chữ ký lớn ($2.420\text{ bytes}$) khiến khối phình to gấp 11.5 lần ($3.88\text{ MB}$).

---

## 🌐 3. Macro-Benchmark: Đo tải mạng phân tán 6-Node P2P (HTTP vs HTTPS/TLS)

### 3.1. Mục tiêu đo lường
Kiểm thử toàn trình (**End-to-End Live Network**) trên mô hình mạng Mesh 6 Node (`Port 5000` đến `5005`):
- **Chữ ký số giao dịch:** Giữ nguyên chuẩn **ECDSA (secp256k1)** cho các giao dịch trong khối.
- **Kênh truyền TLS:** Đánh giá và so sánh thực nghiệm 6 cơ chế trao đổi khóa (Key Exchange / KEM):
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
# hoặc chạy mặc định không cờ (tự động kích hoạt chế độ HTTP):
python benchmarks/macro_benchmark.py

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
python benchmarks/macro_benchmark.py --http -n 50
python benchmarks/macro_benchmark.py --compare-kems -n 30
```

*Lưu ý: Script tự động kích hoạt mạng 6-Node (HTTP hoặc HTTPS tương ứng) ngầm và tự động thu hồi/tắt tiến trình khi kết thúc.*

### 3.3. Bảng so sánh thực nghiệm tổng hợp các cơ chế KEM (Mạng 6-Node P2P)

| Chỉ số đo lường (Metric) | ECDHE-P256 | ECDHE-X25519 | ML-KEM-768 (PQC) | Hybrid (X255+ML) | HQC-128 (PQC) | FrodoKEM-640 (PQC) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Họ thuật toán** | Classical ECC | Classical ECC | **Lattice (M-LWE)** | **Hybrid Dual** | **Code-based** | **Lattice (LWE)** |
| **Kháng máy tính lượng tử** | ❌ KHÔNG | ❌ KHÔNG | ✅ **CÓ (Safe)** | ✅ **CÓ (Bảo vệ kép)** | ✅ **CÓ (Safe)** | ✅ **CÓ (Safe)** |
| **KEM Public Key Size** | $65\text{ B}$ | $32\text{ B}$ | $1.184\text{ B}$ | **$1.216\text{ B}$** | $2.241\text{ B}$ | $9.616\text{ B}$ |
| **KEM Ciphertext Size** | $32\text{ B}$ | $32\text{ B}$ | $1.088\text{ B}$ | **$1.120\text{ B}$** | $4.433\text{ B}$ | $9.720\text{ B}$ |
| **KEM Handshake Wire** | **$97\text{ B}$** | **$64\text{ B}$** | **$2.272\text{ B}$** | **$2.336\text{ B}$** | **$6.674\text{ B}$** | **$19.336\text{ B}$** |
| **KEM Handshake Time** | $0.693\text{ ms}$ | $3.085\text{ ms}$ | **$0.174\text{ ms}$** | **$0.327\text{ ms}$** | $4.763\text{ ms}$ | $550.756\text{ ms}$ |
| **E2E Ingestion Latency** | $50.81\text{ ms}$ | $58.56\text{ ms}$ | **$47.85\text{ ms}$** | **$45.54\text{ ms}$** | $61.57\text{ ms}$ | $576.91\text{ ms}$ |
| **Độ trễ P95 (Latency)** | $63.45\text{ ms}$ | $71.73\text{ ms}$ | $75.01\text{ ms}$ | **$60.82\text{ ms}$** | $84.76\text{ ms}$ | $583.74\text{ ms}$ |
| **Ingestion TPS** | $19.64\text{ tx/s}$ | $17.05\text{ tx/s}$ | $20.86\text{ tx/s}$ | **$21.89\text{ tx/s}$** | $16.22\text{ tx/s}$ | $1.73\text{ tx/s}$ |
| **Block Propagation Delay** | $1.975\text{ s}$ | $0.674\text{ s}$ | $0.677\text{ s}$ | $0.673\text{ s}$ | $0.643\text{ s}$ | $0.635\text{ s}$ |

> **Ưu thế vượt trội của cơ chế Lai Hybrid (X25519 + ML-KEM-768):**
> - **Nguyên lý bảo vệ kép (Defense-in-Depth):** Khóa phiên được phái sinh từ cả hai thành phần: $SS = \text{SHA256}(SS_{X25519} \parallel SS_{MLKEM})$. Kẻ tấn công phải phá vỡ đồng thời cả bài toán Logarithm rời rạc trên đường cong Elliptic VÀ bài toán mạng tinh thể Module-LWE thì mới có thể giải mã được gói tin.
> - **Hiệu năng thực tế:** Handshake chỉ tốn **$0.327\text{ ms}$**, gói tin bổ sung chỉ nặng **$2.34\text{ KB}$**, giữ được Ingestion TPS rất cao (**$21.89\text{ tx/s}$**). Đây là tiêu chuẩn đang được IETF, Google Chrome và Cloudflare lựa chọn triển khai vào TLS 1.3 thực tế.

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
