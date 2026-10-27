# BÁO CÁO KỸ THUẬT: KỊCH BẢN KIỂM THỬ PERF-01
# ĐO LƯỜNG GIỚI HẠN TÀI NGUYÊN NODE TRÊN PHẦN CỨNG YẾU (RESOURCE CONSTRAINED STRESS TEST)

**Học phần:** Cơ sở An toàn Thông tin / Blockchain Engineering  
**Vai trò phụ trách:** Thành viên 4 (Hardware Benchmark & DevOps)  
**Mã kịch bản:** `PERF-01`  
**Tên kịch bản:** Đo lường Giới hạn Tài nguyên Node trên Phần cứng Yếu (Resource Constrained Stress Test)  
**Nền tảng kiểm thử:** Docker Desktop (WSL2 Linux Kernel 6.18, Cgroups v2)  
**Ngày thực hiện & Nghiệm thu:** 27/10/2026  

---

## 1. TỔNG QUAN VÀ ĐẶT VẤN ĐỀ

### 1.1. Bối cảnh Nghiên cứu
Trong kiến trúc bảo mật của hệ thống Blockchain, việc chuyển đổi từ các thuật toán mật mã cổ điển (RSA-2048) và mật mã đường cong elliptic hiện đại (ECDSA secp256k1) sang **Mật mã Hậu lượng tử (Post-Quantum Cryptography - PQC)**, cụ thể là **ML-DSA-44 (FIPS 204)**, là yêu cầu sống còn nhằm vô hiệu hóa mối đe dọa từ máy tính lượng tử chạy thuật toán Shor.

Tuy nhiên, trong một mạng lưới Blockchain phân tán thực tế (như IoT Blockchain, Smart Grid, Logistics Supply Chain, Automotive V2X), các node tham gia không chỉ giới hạn ở các cụm máy chủ Datacenter cấu hình mạnh, mà phần lớn bao gồm các thiết bị biên (**Edge Gateway**) và thiết bị nhúng hạn chế tài nguyên (**IoT Embedded Nodes**). 

### 1.2. Mục tiêu Kịch bản `PERF-01`
Kịch bản `PERF-01` được thiết kế nhằm giải quyết 3 mục tiêu khoa học và kỹ thuật trọng tâm:
1. **Xác định ranh giới chịu tải phần cứng (Hardware Boundary):** Đo đạc hiện tượng bão hòa CPU (**CPU Saturation**) và áp lực trần bộ nhớ (**Memory Ceiling**) khi node blockchain phải thẩm định một khối tải 500 giao dịch ký số ML-DSA-44 so với ECDSA và RSA-2048 trên 3 cấu hình phần cứng: Server (4 vCPU, 4GB RAM), Edge (1 vCPU, 512MB RAM) và IoT (0.5 vCPU, 128MB RAM).
2. **Đánh giá nguy cơ tràn bộ nhớ (OOM Risk Assessment):** Phân tích nguy cơ cơ chế Linux Kernel OOM-Killer can thiệp tiêu diệt tiến trình Node (`SIGKILL` - Mã thoát 137) khi kích thước chữ ký và khóa công khai của PQC bùng nổ gấp ~29.1 lần so với ECDSA.
3. **Phân tích hiện tượng bão hòa và nghẽn CPU (CFS CPU Throttling):** Sử dụng các chỉ số kernel cgroups v2 (`nr_throttled`, `throttled_usec`) để lượng hóa chính xác thời gian tiến trình bị đóng băng do vượt quá hạn ngạch vCPU được cấp phát.

---

## 2. KIẾN TRÚC TRIỂN KHAI VÀ BỘ CÔNG CỤ DEVOPS

Hệ thống được đóng gói và cấu hình hoàn chỉnh theo tiêu chuẩn DevOps cô lập tài nguyên:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DOCKER CGROUPS V2 RUNTIME                          │
├──────────────────────────┬─────────────────────────┬────────────────────────┤
│     PROFILE 1: SERVER    │     PROFILE 2: EDGE     │     PROFILE 3: IOT     │
│   • 4.0 vCPU Quota       │   • 1.0 vCPU Quota      │   • 0.5 vCPU Quota     │
│   • 4096 MB RAM Limit    │   • 512 MB RAM Limit    │   • 128 MB RAM Limit   │
│   • Memswap: 4096 MB     │   • Memswap: 512 MB     │   • Memswap: 128 MB    │
│   • Port: 5000           │   • Port: 5001          │   • Port: 5002         │
├──────────────────────────┴─────────────────────────┴────────────────────────┤
│                          NODE BLOCKCHAIN ENGINE                             │
│   • Python 3.11-slim + liboqs C Library (FIPS 204 ML-DSA-44 Engine)         │
│   • Flask Multithreaded RESTful API + Mempool + Persistent P2P Engine       │
│   • Zero-Trust Cryptographic Signature Verification (ML-DSA / ECDSA / RSA)  │
├─────────────────────────────────────────────────────────────────────────────┤
│                     REAL-TIME CGROUP & DOCKER TELEMETRY                     │
│   • /sys/fs/cgroup/memory.peak (Kernel-level Ground Truth Peak RAM)         │
│   • /sys/fs/cgroup/cpu.stat (usage_usec, nr_throttled, throttled_usec)      │
│   • /sys/fs/cgroup/memory.events (oom_kill counter detection)               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.1. Đóng gói Containerization (`perf/Dockerfile`)
File [`perf/Dockerfile`](file:///d:/assignment/btl/Blockchain-CSATT/perf/Dockerfile) chuẩn hóa môi trường:
- Base image: `python:3.11-slim`.
- Biên dịch thư viện C **`liboqs` (Open Quantum Safe)** từ nguồn với `cmake` và `ninja-build`, kích hoạt cờ biên dịch tối ưu hóa hỗ trợ thuật toán **ML-DSA-44 (FIPS 204)**.
- Tích hợp module Python `liboqs-python`, `cryptography`, `pycryptodome`, `ecdsa`, `websockets`, `flask`, `psutil`, `matplotlib`.

### 2.2. Định nghĩa 3 Profile Phần cứng (`perf/docker-compose.yml`)
File [`perf/docker-compose.yml`](file:///d:/assignment/btl/Blockchain-CSATT/perf/docker-compose.yml) định nghĩa nghiêm ngặt 3 hạn ngạch phần cứng thông qua cgroups, triệt tiêu swap memory (`memswap_limit = memory`) để mô phỏng chính xác giới hạn vật lý:
- **`node-server` (Server / Datacenter Profile):** 4.0 vCPU, 4096 MB RAM (`mem_limit: 4096M`, `memswap_limit: 4096M`).
- **`node-edge` (Edge Gateway Profile):** 1.0 vCPU, 512 MB RAM (`mem_limit: 512M`, `memswap_limit: 512M`).
- **`node-iot` (IoT Embedded Profile):** 0.5 vCPU, 128 MB RAM (`mem_limit: 128M`, `memswap_limit: 128M`) — Vùng biên nhạy cảm với nguy cơ OOM.

### 2.3. Bộ Dữ liệu Tải Thực nghiệm Chuẩn hóa (`perf/generate_perf01_txs.py`)
Script sinh sẵn hai cấp độ tải dữ liệu ký số chuẩn:
1. **Cấp độ Cơ sở (500 Transactions):** Dùng để khảo sát ma trận chuẩn 3x3.
   - **ECDSA (secp256k1):** Khóa công khai 64 Bytes, Chữ ký 64 Bytes $\rightarrow$ **Tổng kích thước: 128 Bytes/tx** (`txs_500_ecdsa.json` = 266 KB).
   - **RSA-2048 (PKCS#1 v1.5):** Khóa công khai 294 Bytes, Chữ ký 256 Bytes $\rightarrow$ **Tổng kích thước: 550 Bytes/tx** (`txs_500_rsa.json` = 689 KB).
   - **ML-DSA-44 (NIST FIPS 204 PQC):** Khóa công khai 1,312 Bytes, Chữ ký 2,420 Bytes $\rightarrow$ **Tổng kích thước: 3,732 Bytes/tx** (`txs_500_mldsa.json` = **3.87 MB**, **gấp 29.1 lần ECDSA**).
2. **Cấp độ Cực hạn (3,000 Transactions):** Dùng cho bài thử nghiệm dập tải OOM Cliff Hunter (`txs_3000_mldsa.json` = **23.2 MB** và `txs_3000_ecdsa.json` = 1.6 MB).

### 2.4. Công cụ Giám sát Telemetry Tự động (`perf/perf01_stress_test.py`)
Trang bị lớp giám sát `CgroupTelemetryMonitor` truy vấn trực tiếp kernel cgroups v2 ở tần số cao (chu kỳ 80ms):
- Đo đạc chính xác **Baseline RAM (Idle)**, **Peak RAM**, **Tỉ lệ chiếm trần RAM (% Ceiling)**, **Average CPU %**, **Peak CPU %**, **Thời gian xử lý** và **Ingestion TPS**.
- Ghi nhận chỉ số **CPU Throttling (`throttled_usec`)** và số chu kỳ bị ngắt xung nhịp (`nr_throttled`) khi container chạm trần CPU quota.
- Bắt trực tiếp sự kiện kernel OOM (`memory.events` / `oom_kill` và Docker Exit Code 137).

---

## 3. BẢNG MA TRẬN SO SÁNH TÀI NGUYÊN (KẾT QUẢ THỰC NGHIỆM THẬT)

### 3.1. Ma trận 9 Kịch bản Chuẩn (500 Giao dịch)
Dưới đây là ma trận số liệu thực tế đo đạc qua 9 đợt thử nghiệm độc lập trên Docker Desktop (3 Profiles Phần cứng $\times$ 3 Thuật toán Ký số, mỗi đợt xử lý batch 500 giao dịch):

| Cấu hình Phần cứng | vCPU | Giới hạn RAM | Thuật toán Ký số | Số Tx Đạt | Thời gian (s) | Ingestion TPS | Baseline RAM | Peak RAM (MB) | % Đạt Trần RAM | Avg CPU (Docker / Core) | Normalized CPU (% Quota) | CPU Throttled (ms) | Trạng thái OOM |
| :--- | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Server (Datacenter)** | **4.0** | **4096 MB** | ECDSA (secp256k1) | 500/500 | 1.442 s | **346.68 tx/s** | 43.98 MB | 46.29 MB | 1.13% | 126.41% | **31.60%** | 0.0 ms (0 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Server (Datacenter)** | **4.0** | **4096 MB** | RSA-2048 | 500/500 | 1.204 s | **415.23 tx/s** | 45.96 MB | 50.86 MB | 1.24% | 113.18% | **28.30%** | 0.0 ms (0 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Server (Datacenter)** | **4.0** | **4096 MB** | **ML-DSA-44 (PQC)** | 500/500 | 0.851 s | **587.86 tx/s** | 45.77 MB | 53.33 MB | 1.30% | 137.46% | **34.37%** | 0.0 ms (0 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Edge Gateway** | **1.0** | **512 MB** | ECDSA (secp256k1) | 500/500 | 1.654 s | **302.30 tx/s** | 43.48 MB | 45.84 MB | 8.95% | 103.00% | **103.00%** | 842.2 ms (16 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Edge Gateway** | **1.0** | **512 MB** | RSA-2048 | 500/500 | 1.277 s | **391.63 tx/s** | 45.21 MB | 47.04 MB | 9.19% | 104.56% | **104.56%** | 789.4 ms (12 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Edge Gateway** | **1.0** | **512 MB** | **ML-DSA-44 (PQC)** | 500/500 | 1.178 s | **424.29 tx/s** | 43.32 MB | 51.94 MB | 10.14% | 104.93% | **104.93%** | 1077.5 ms (11 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **IoT Embedded** | **0.5** | **128 MB** | ECDSA (secp256k1) | 500/500 | 3.446 s | **145.10 tx/s** | 42.77 MB | 48.41 MB | 37.82% | 51.26% | **102.52%** | 5381.8 ms (35 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **IoT Embedded** | **0.5** | **128 MB** | RSA-2048 | 500/500 | 2.579 s | **193.90 tx/s** | 43.37 MB | 48.11 MB | 37.59% | 53.38% | **106.76%** | 5131.0 ms (26 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **IoT Embedded** | **0.5** | **128 MB** | **ML-DSA-44 (PQC)** | 500/500 | 2.158 s | **231.74 tx/s** | 42.43 MB | **54.16 MB** | **42.31%** | 52.21% | **104.42%** | 4111.2 ms (22 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |

*Bảng dữ liệu trích xuất từ file: [`perf/results/perf01_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_matrix.csv) và [`perf/results/perf01_results.json`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_results.json)*

---

### 3.2. Giải thích Chuyên sâu: Tại sao Avg CPU trên Server lên tới 126% - 137%?
Trong hệ điều hành Linux cũng như các công cụ giám sát container tiêu chuẩn (`docker stats`, Linux `top`, `htop`, Prometheus cAdvisor):
- **Quy ước chuẩn Per-Core:** $100\%$ CPU tương đương với **1.0 nhân CPU (vCPU/core) hoạt động hết công suất (Full Saturation)**.
- **Trên Profile Server (4.0 vCPU):** Hạn ngạch tối đa được cấp là:
  $$\text{CPU Capacity}_{\text{Server}} = 4.0 \times 100\% = 400\%$$
- **Bản chất kỹ thuật:** Do Flask Node chạy ở chế độ đa luồng (`threaded=True`) và nhận đồng thời 8 worker threads gửi các giao dịch ký số song song, tiến trình Node đã huy động đồng thời nhiều core cùng lúc để tính toán giải mã chữ ký.
- **Ý nghĩa con số:**
  - `Avg CPU = 126.41%` (với ECDSA) hoặc `137.46%` (với ML-DSA-44) nghĩa là tiến trình đang tiêu thụ tương đương **1.26 đến 1.37 core**.
  - So với tổng hạn ngạch 4 vCPU (400%) của Server, mức tải thực tế (**Normalized CPU %**) chỉ là:
    $$\text{Normalized CPU} = \frac{137.46\%}{400\%} = 34.37\%$$
    Node Server vẫn còn dư thừa hơn $65\%$ năng lực tính toán và hoàn toàn không bị ngắt xung nhịp (`throttled_ms = 0.0 ms`).
- **So sánh đối chứng:**
  - Trên **Edge Gateway (1.0 vCPU = 100% trần):** Đo được 103% - 105% $\rightarrow$ Chạm trần 1 core, CPU Throttling xuất hiện (~800 - 1000 ms).
  - Trên **IoT Embedded (0.5 vCPU = 50% trần):** Đo được 51% - 53% $\rightarrow$ Bão hòa tuyệt đối 100% hạn ngạch nửa core, Linux Kernel can thiệp điều tiết ngắt xung nhịp nặng nề (4 - 5.3 giây).

---

## 4. BÀI TEST TẢI CỰC HẠN 3,000 GIAO DỊCH: SĂN TÌM NGƯỠNG OOM THỰC TẾ

Để trả lời câu hỏi cốt lõi về **ranh giới sinh tử và nguy cơ OOM thực tế** khi node tiếp nhận khối lượng giao dịch lớn tích lũy trong Mempool, bài kiểm thử dập tải cực hạn (**Extreme Stress Test: 3,000 Transactions**) đã được thực hiện trực tiếp trên cấu hình yếu nhất: **IoT Embedded (128 MB RAM, 0.5 vCPU)**.

### 4.1. Kết quả Đo đạc Thực tế 3,000 Giao dịch trên Node IoT (128MB RAM)

| Số Giao dịch Đã gửi | RAM Hiện tại: ML-DSA-44 (MB) | RAM Hiện tại: ECDSA (MB) | Chênh lệch RAM ($\Delta$) | Tỉ lệ Trần RAM (ML-DSA) | Mức độ Nguy cơ OOM |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **0 txs (Idle)** | 42.43 MB | 42.77 MB | -0.34 MB | 33.1% | Vùng an toàn |
| **500 txs** | 73.91 MB | 44.50 MB | +29.41 MB | 57.7% | Vùng an toàn |
| **1,000 txs** | 79.24 MB | 45.88 MB | +33.36 MB | 61.9% | Cảnh báo vừa (>60%) |
| **1,500 txs** | 86.03 MB | 46.50 MB | +39.53 MB | 67.2% | Cảnh báo vừa |
| **2,000 txs** | 92.18 MB | 47.29 MB | +44.89 MB | 72.0% | Cảnh báo tăng dần |
| **2,500 txs** | 98.00 MB | 47.50 MB | +50.50 MB | 76.5% | Cận kề vùng đỏ (>75%) |
| **3,000 txs (Peak)** | **103.74 MB** | **47.83 MB** | **+55.91 MB** | **81.05%** | <span style="color:red;font-weight:bold;">NGUY CƠ CAO (>=80% Ceiling)</span> |

*Tổng thời gian xử lý 3,000 txs: ML-DSA-44 hoàn tất trong 16.49 giây (181.9 TPS); ECDSA hoàn tất trong 17.77 giây (168.8 TPS).*

```
┌─────────────────────────────────────────────────────────────────────────────┐
│               ĐƯỜNG BIỂU DIỄN TĂNG TRƯỞNG BỘ NHỚ THEO TẢI MEMPOOL           │
├─────────────────────────────────────────────────────────────────────────────┤
│ 128 MB ── [ LINUX KERNEL OOM-KILLER CLIFF (SIGKILL 137) ] ── (Khoảng ~5000 txs)
│        │                                                      ▲
│ 104 MB ┼─────────────────────────────────────────────● (3000 txs ML-DSA: 103.7 MB)
│        │                                     ● (2500 txs: 98.0 MB)
│  92 MB ┼────────────────────────────● (2000 txs: 92.2 MB)
│        │                    ● (1500 txs: 86.0 MB)
│  79 MB ┼───────────● (1000 txs: 79.2 MB)
│        │   ● (500 txs: 73.9 MB)
│  48 MB ┼───■───────■────────■───────■────────■───────■ (3000 txs ECDSA: 47.8 MB)
│  42 MB ├───(Baseline Idle)──────────────────────────────────────────────────
│        └───┴───────┴────────┴───────┴────────┴───────┴──────────────────────
│            500    1000     1500    2000     2500    3000 (Transactions)     
│            ──●── ML-DSA-44 (Tăng vọt 60 MB)    ──■── ECDSA (Gần như phẳng)   
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2. Phân tích Hiện tượng Kỹ thuật
1. **Sự tương phản rõ rệt giữa ECDSA và ML-DSA:**
   - **ECDSA:** Dù bơm dồn dập tới 3,000 giao dịch, kích thước payload quá nhỏ (128 Bytes/tx) khiến Peak RAM chỉ nhích từ **42.77 MB lên 47.83 MB (tăng vỏn vẹn ~5 MB)**. Đỉnh RAM chỉ dừng ở mức **37.4% trần 128MB**, nằm hoàn toàn trong vùng an toàn tuyệt đối.
   - **ML-DSA-44:** Với payload 3,732 Bytes/tx, 3,000 giao dịch mang theo **hơn 22.1 MB dữ liệu thô**. Khi giải mã sang các đối tượng Python và mảng đa thức Lattice, RAM tăng vọt thêm gần **60 MB**, đẩy Peak RAM lên **103.74 MB (chiếm 81.05% tổng trần bộ nhớ 128MB)**.
2. **Xác định Ranh giới Sụp đổ OOM (Extrapolated OOM Cliff):**
   - Tốc độ tiêu thụ bộ nhớ của ML-DSA-44 trên hàng đợi Mempool là:
     $$V_{\text{RAM}} \approx \frac{103.74\text{ MB} - 73.91\text{ MB}}{2,500\text{ txs}} \approx 0.01193\text{ MB / transaction}$$
   - Khoảng đệm an toàn còn lại của thiết bị IoT sau 3,000 giao dịch chỉ còn:
     $$\Delta \text{RAM}_{\text{free}} = 128\text{ MB} - 103.74\text{ MB} = 24.26\text{ MB}$$
   - **Ngưỡng sụp đổ OOM:**
     $$N_{\text{OOM}} = 3,000 + \frac{24.26\text{ MB}}{0.01193\text{ MB/tx}} \approx 5,033\text{ transactions}$$
   - **Kết luận:** Nếu một thiết bị IoT chạy Full Node PQC bị tấn công Mempool Flooding với khoảng **~5,000 giao dịch ML-DSA-44**, hoặc mạng bị fork khiến giao dịch ùn ứ chưa được đóng khối, **Linux Kernel OOM-Killer chắc chắn sẽ kích hoạt và tiêu diệt tiến trình Node ngay lập tức**!

---

## 5. BIỂU ĐỒ CẢNH BÁO NGƯỠNG OOM VÀ PHÂN TÍCH CHUYÊN SÂU

Toàn bộ kết quả thử nghiệm 500 txs được tổng hợp và trực quan hóa qua biểu đồ kỹ thuật 3 panel tại [`perf/results/perf01_oom_risk_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_oom_risk_chart.png):

### 5.1. Phân tích Panel 1: Đỉnh Trần Bộ Nhớ (Peak RAM) và Ranh giới Tràn Bộ Nhớ
- Trên **Server (4096 MB)**: Peak RAM 53.33 MB chỉ chiếm **1.30%** trần RAM $\rightarrow$ Vùng xanh tuyệt đối.
- Trên **Edge Gateway (512 MB)**: Peak RAM 51.94 MB chiếm **10.14%** trần RAM $\rightarrow$ An toàn.
- Trên **IoT Embedded (128 MB)**: Peak RAM 54.16 MB (với 500 txs) chiếm **42.31%** trần RAM và tăng vọt lên **103.74 MB (81.05%)** khi tải tăng lên 3,000 txs $\rightarrow$ Cảnh báo rủi ro cao.

### 5.2. Phân tích Panel 2 & 3: Nghịch lý Tốc độ Toán học PQC & Bão hòa CPU
1. **Nghịch lý Hiệu năng PQC (PQC Verification Paradox):**
   - Về tốc độ xác thực chữ ký: **ML-DSA-44 chạy nhanh nhất trong cả 3 thuật toán**:
     $$\text{Ingestion TPS (Server): ML-DSA-44 (587.86 tx/s)} > \text{RSA-2048 (415.23 tx/s)} > \text{ECDSA (346.68 tx/s)}$$
     $$\text{Ingestion TPS (IoT): ML-DSA-44 (231.74 tx/s)} > \text{RSA-2048 (193.90 tx/s)} > \text{ECDSA (145.10 tx/s)}$$
   - *Nguyên nhân:* Thuật toán biến đổi số học nhanh NTT (**Number Theoretic Transform**) của Dilithium/ML-DSA nhân đa thức vòng cực nhanh, không tốn chu kỳ CPU như phép nhân điểm elliptic vô hạn của ECDSA hay lũy thừa modulo 2048-bit của RSA.
2. **Hiện tượng Bão hòa và Nghẽn CPU (CFS Throttling Saturation):**
   - **Server (4.0 vCPU):** Không bị nghẽn (`CPU Throttled = 0.0 ms`).
   - **Edge (1.0 vCPU):** Chạm trần đơn nhân, CPU Throttling xuất hiện trong khoảng **789 ms - 1,077 ms**.
   - **IoT (0.5 vCPU):** Rơi vào trạng thái **bão hòa hoàn toàn**, CPU duy trì kịch trần 51% - 53% (bằng 100% hạn ngạch 0.5 vCPU được cấp). Linux Kernel liên tục can thiệp điều tiết ngắt xung nhịp với thời gian nghẽn lên tới **4,111 ms đến 5,381 ms**, khiến thời gian xử lý kéo dài gấp ~3-4 lần so với Server.

---

## 6. HƯỚNG DẪN TÁI LẬP KẾT QUẢ THỰC NGHIỆM (REPRODUCIBILITY GUIDE)

### Bước 1: Khởi động Docker Desktop
Đảm bảo daemon Docker Desktop đang chạy:
```powershell
docker info
```

### Bước 2: Đóng gói Node Blockchain Image
Tại thư mục gốc dự án `Blockchain-CSATT`:
```powershell
docker build -t blockchain-node:perf -f perf/Dockerfile .
```

### Bước 3: Kiểm tra và Sinh Bộ dữ liệu Tải (Nếu cần tạo mới)
Script sinh 500 và 3,000 giao dịch ký số chuẩn:
```powershell
docker run --rm -v "${PWD}:/app" blockchain-node:perf python perf/generate_perf01_txs.py
```

### Bước 4: Chạy Kịch bản Stress Test Tự động
Khởi chạy suite kiểm thử PERF-01:
```powershell
python perf/perf01_stress_test.py
```
Kết quả xuất tự động:
- Bảng ma trận CSV: [`perf/results/perf01_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_matrix.csv)
- Dữ liệu thô JSON: [`perf/results/perf01_results.json`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_results.json)
- Biểu đồ OOM: [`perf/results/perf01_oom_risk_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_oom_risk_chart.png)

---

## 7. KHUYẾN NGHỊ KIẾN TRÚC DEVOPS & AN TOÀN HỆ THỐNG

1. **Tuyệt đối không triển khai Full Node PQC trên Thiết bị Nhúng IoT yếu:**
   - Với RAM $\le 128\text{ MB}$, ranh giới an toàn của node chỉ chịu được khoảng ~2,000 đến ~3,000 giao dịch PQC trong Mempool.
   - Khi mạng bị nghẽn hoặc bị tấn công DoS, node IoT chắc chắn sẽ bị sập do OOM.
2. **Áp dụng Mô hình Node Phân cấp (Hierarchical Blockchain Topology):**
   - **IoT Node (Light Client / Signer-only):** Thiết bị IoT chỉ nắm giữ khóa bí mật để ký số giao dịch của cảm biến và đẩy dữ liệu lên mạng (chỉ tốn vài chục KB RAM tạm thời).
   - **Edge Gateway Node (Relay / Verifier):** Các trạm biên (Raspberry Pi 4 hoặc IPC công nghiệp với 512MB - 1GB RAM) đóng vai trò Relay Node, thực hiện thẩm định chữ ký ban đầu, lọc bỏ giao dịch rác.
   - **Server Datacenter (Validator / Miner):** Máy chủ mạnh (4GB+ RAM, 4+ vCPU) đảm nhận việc duy trì toàn bộ chuỗi khối và thực hiện đồng thuận Proof-of-Work.
3. **Cơ chế Bảo vệ Mempool (Mempool Byte-Quota):**
   - Node cần đặt giới hạn Mempool theo **tổng dung lượng byte (ví dụ tối đa 15 MB)** thay vì theo số lượng giao dịch, tự động từ chối giao dịch mới khi chạm trần để bảo vệ node khỏi sự cố OOM.

---

## 8. DANH MỤC SẢN PHẨM BÀN GIAO (DELIVERABLES)

| STT | Tên Sản phẩm / Tệp tin | Đường dẫn Tuyệt đối | Mô tả Chi tiết |
| :---: | :--- | :--- | :--- |
| 1 | **Dockerfile** | [`perf/Dockerfile`](file:///d:/assignment/btl/Blockchain-CSATT/perf/Dockerfile) | File cấu hình đóng gói Node tích hợp liboqs, Python 3.11, WebSocket và thư viện PQC FIPS 204. |
| 2 | **docker-compose.yml** | [`perf/docker-compose.yml`](file:///d:/assignment/btl/Blockchain-CSATT/perf/docker-compose.yml) | File định nghĩa 3 profile phần cứng: Server (4GB/4vCPU), Edge (512MB/1vCPU), IoT (128MB/0.5vCPU). |
| 3 | **Dataset Generator** | [`perf/generate_perf01_txs.py`](file:///d:/assignment/btl/Blockchain-CSATT/perf/generate_perf01_txs.py) | Script sinh 1,500 giao dịch (500/loại) và 6,000 giao dịch cực hạn (3,000/loại). |
| 4 | **Stress Test & Telemetry Driver** | [`perf/perf01_stress_test.py`](file:///d:/assignment/btl/Blockchain-CSATT/perf/perf01_stress_test.py) | Engine kiểm thử tự động, tích hợp giám sát cgroups v2 thời gian thực và vẽ biểu đồ. |
| 5 | **Bảng Ma trận So sánh Tài nguyên (CSV)** | [`perf/results/perf01_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_matrix.csv) | Bảng ma trận kết quả đo đạc thực nghiệm 9 đợt (TPS, Peak RAM, % Ceiling, Avg CPU, Throttling, OOM). |
| 6 | **Dữ liệu Thống kê Chi tiết (JSON)** | [`perf/results/perf01_results.json`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_results.json) | Dữ liệu thô JSON của 9 đợt benchmark phục vụ phân tích khoa học. |
| 7 | **Biểu đồ Cảnh báo Ngưỡng OOM (PNG)** | [`perf/results/perf01_oom_risk_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_oom_risk_chart.png) | Biểu đồ trực quan 3 panel: Peak RAM vs Memory Ceiling, Ingestion TPS, và Mức độ bão hòa CPU. |
| 8 | **Báo cáo Kỹ thuật Đầy đủ (MD)** | [`perf/PERF01_BENCHMARK_REPORT.md`](file:///d:/assignment/btl/Blockchain-CSATT/perf/PERF01_BENCHMARK_REPORT.md) | Báo cáo kỹ thuật chi tiết theo chuẩn học thuật và đề cương bài tập lớn. |
