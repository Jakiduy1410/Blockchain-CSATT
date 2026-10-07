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
- **Giai đoạn 1 (Ingestion Phase):** Bắn tải liên tục $N$ giao dịch ký số ECDSA vào Node Ingress (`5000`), đo tỷ lệ chấp nhận, thời gian xử lý và thông lượng **Ingestion TPS**.
- **Giai đoạn 2 (Consensus & Block Propagation):** Node Miner (`5001`) tiến hành gom mempool, đào khối PoW và phát sóng P2P; đo thời gian lan truyền và đồng thuận chuỗi trên toàn bộ 6 Node.
- **Giai đoạn 3 (Wire Payload Analysis):** Đo lường kích thước gói tin thực tế truyền qua mạng HTTP/HTTPS và dung lượng trung bình trên mỗi transaction.
- **Giai đoạn 4 (Security Cost Analysis):** So sánh đối đầu giữa kênh truyền không mã hóa (**HTTP Cleartext**) và kênh truyền bảo mật (**HTTPS / TLS 1.3 / X.509**).

### 3.2. Lệnh thực thi

```powershell
# 1. Chạy bài kiểm thử tải thông thường qua HTTP (Cleartext):
python benchmarks/macro_benchmark.py

# 2. Chạy bài kiểm thử bảo mật qua HTTPS (TLS 1.3 / X.509):
python benchmarks/macro_benchmark.py --tls

# 3. CHẾ ĐỘ KHUYẾN NGHỊ: Chạy SO SÁNH ĐỐI ĐẦU HTTP vs HTTPS (TLS) tự động:
python benchmarks/macro_benchmark.py --compare

# 4. Tùy biến số lượng giao dịch bắn tải (Ví dụ: 50 transactions):
python benchmarks/macro_benchmark.py --compare -n 50
```

*Lưu ý: Nếu mạng 6 Node chưa chạy, script sẽ **tự động khởi tạo** các tiến trình Node ngầm và **tự dọn dẹp sạch sẽ** ngay khi hoàn tất kiểm nghiệm.*

### 3.3. Bảng so sánh thực nghiệm đối đầu: HTTP vs HTTPS (TLS 1.3)

| Chỉ số đo lường (Metric) | HTTP (Không mã hóa) | HTTPS (TLS 1.3 / X.509) | Chênh lệch / Chi phí an ninh TLS |
| :--- | :--- | :--- | :--- |
| **Ingestion TPS** | **$58.30\text{ tx/s}$** | **$9.52\text{ tx/s}$** | Giảm **$83.67\%$** do đàm phán bắt tay TLS (ECDHE + Verify Cert) |
| **Độ trễ tiếp nhận (Mean)** | **$17.06\text{ ms}$** | **$105.05\text{ ms}$** | Tăng thêm **$+87.99\text{ ms}$** ($\approx +515\%$) |
| **Độ trễ tiếp nhận (P95)** | **$29.80\text{ ms}$** | **$149.66\text{ ms}$** | Tăng thêm **$+119.86\text{ ms}$** cho các gói đàm phán phiên |
| **Block Propagation Delay** | **$1.722\text{ s}$** | **$1.357\text{ s}$** | Đồng bộ P2P thành công trên toàn bộ 6 Node |
| **Block Wire Size** | **$2.82\text{ KB}$** (5 txs) | **$2.82\text{ KB}$** (5 txs) | Payload dữ liệu khối đồng nhất ($576.8\text{ B/tx}$) |
| **Khả năng an ninh** | Dễ bị nghe lén, Man-in-the-Middle | **Kháng MitM, toàn vẹn & bí mật** | Bảo vệ tuyệt đối gói tin trên môi trường mạng mở |

---

## 📈 4. Dữ liệu thô phục vụ báo cáo khoa học (`results/`)

Toàn bộ dữ liệu đo đạc chi tiết được tự động lưu trữ dưới định dạng `.csv` và `.json` để phục vụ trích xuất bảng biểu và đồ thị:

- [`results/RSA_2048_micro_raw.csv`](results/RSA_2048_micro_raw.csv): $1.000$ dòng dữ liệu thô (Keygen, Sign, Verify, PK, Sig size của RSA).
- [`results/ECDSA_secp256k1_micro_raw.csv`](results/ECDSA_secp256k1_micro_raw.csv): $1.000$ dòng dữ liệu thô của ECDSA.
- [`results/micro_benchmark_summary.json`](results/micro_benchmark_summary.json): Báo cáo thống kê Mean, Median, Std, CI 95% của tầng mật mã.
- [`results/macro_transactions_http_raw.csv`](results/macro_transactions_http_raw.csv): Log độ trễ từng giao dịch bắn qua HTTP.
- [`results/macro_transactions_tls_raw.csv`](results/macro_transactions_tls_raw.csv): Log độ trễ từng giao dịch bắn qua HTTPS.
- [`results/macro_benchmark_http_summary.json`](results/macro_benchmark_http_summary.json): Kết quả tổng hợp đo tải HTTP.
- [`results/macro_benchmark_tls_summary.json`](results/macro_benchmark_tls_summary.json): Kết quả tổng hợp đo tải HTTPS (TLS).
- [`results/macro_benchmark_comparison.json`](results/macro_benchmark_comparison.json): Kết quả phân tích đối đầu (Delta TPS, Overhead Latency ms, %).

---

## 🛠️ 5. Yêu cầu môi trường & Thư viện

- **Python:** Phiên bản 3.10+ (Khuyến nghị Python 3.12).
- **Thư viện Python bắt buộc:**
  ```powershell
  pip install requests numpy scipy cryptography ecdsa
  ```
- **Chứng chỉ TLS:**
  Được tự động sinh trong thư mục `certs/` bằng lệnh OpenSSL hoặc chạy trực tiếp tiện ích:
  ```powershell
  python certs/generate_certs.py
  ```
