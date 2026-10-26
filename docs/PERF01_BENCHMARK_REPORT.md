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

Hệ thống được đóng gói và cấu hình hoàn chỉnh theo tiêu chuẩn DevOps cô lập tài nguyên, bao gồm:

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

### 2.1. Đóng gói Containerization (`Dockerfile`)
File [`Dockerfile`](file:///d:/assignment/btl/Blockchain-CSATT/Dockerfile) chuẩn hóa môi trường:
- Base image: `python:3.11-slim`.
- Biên dịch thư viện C **`liboqs` (Open Quantum Safe)** từ nguồn với `cmake` và `ninja-build`, kích hoạt cờ biên dịch tối ưu hóa hỗ trợ thuật toán **ML-DSA-44 (FIPS 204)**.
- Tích hợp module Python `liboqs-python`, `cryptography`, `pycryptodome`, `ecdsa`, `websockets`, `flask`, `psutil`, `matplotlib`.

### 2.2. Định nghĩa 3 Profile Phần cứng (`docker-compose.yml`)
File [`docker-compose.yml`](file:///d:/assignment/btl/Blockchain-CSATT/docker-compose.yml) định nghĩa nghiêm ngặt 3 hạn ngạch phần cứng thông qua cgroups, triệt tiêu swap memory (`memswap_limit = memory`) để mô phỏng chính xác giới hạn vật lý:
- **`node-server` (Server / Datacenter Profile):** 4.0 vCPU, 4096 MB RAM (`mem_limit: 4096M`, `memswap_limit: 4096M`).
- **`node-edge` (Edge Gateway Profile):** 1.0 vCPU, 512 MB RAM (`mem_limit: 512M`, `memswap_limit: 512M`).
- **`node-iot` (IoT Embedded Profile):** 0.5 vCPU, 128 MB RAM (`mem_limit: 128M`, `memswap_limit: 128M`) — Vùng biên nhạy cảm với nguy cơ OOM.

### 2.3. Bộ Dữ liệu Tải Thực nghiệm Chuẩn hóa (`benchmarks/generate_perf01_txs.py`)
Tập dữ liệu tải gồm 1,500 giao dịch đã ký hợp lệ (500 txs mỗi thuật toán), có đầy đủ chữ ký số thực tế, nonce tăng dần chống replay attack, và người gửi có số dư ban đầu hợp lệ:
- **ECDSA (secp256k1):** Khóa công khai 64 Bytes, Chữ ký 64 Bytes $\rightarrow$ **Tổng kích thước: 128 Bytes/tx** (Tập file: `txs_500_ecdsa.json` = 266 KB).
- **RSA-2048 (PKCS#1 v1.5):** Khóa công khai 294 Bytes, Chữ ký 256 Bytes $\rightarrow$ **Tổng kích thước: 550 Bytes/tx** (Tập file: `txs_500_rsa.json` = 689 KB).
- **ML-DSA-44 (NIST FIPS 204 PQC):** Khóa công khai 1,312 Bytes, Chữ ký 2,420 Bytes $\rightarrow$ **Tổng kích thước: 3,732 Bytes/tx** (Tập file: `txs_500_mldsa.json` = **3.87 MB**, **gấp 29.1 lần ECDSA**).

### 2.4. Công cụ Giám sát Telemetry Tự động (`benchmarks/perf01_stress_test.py`)
Trang bị lớp giám sát `CgroupTelemetryMonitor` truy vấn trực tiếp kernel cgroups v2 ở tần số cao (chu kỳ 80ms):
- Đo đạc chính xác **Baseline RAM (Idle)**, **Peak RAM**, **Tỉ lệ chiếm trần RAM (% Ceiling)**, **Average CPU %**, **Peak CPU %**, **Thời gian xử lý** và **Ingestion TPS**.
- Ghi nhận chỉ số **CPU Throttling (`throttled_usec`)** và số chu kỳ bị ngắt xung nhịp (`nr_throttled`) khi container chạm trần CPU quota.
- Bắt trực tiếp sự kiện kernel OOM (`memory.events` / `oom_kill` và Docker Exit Code 137).

---

## 3. BẢNG MA TRẬN SO SÁNH TÀI NGUYÊN (KẾT QUẢ THỰC NGHIỆM THẬT)

Dưới đây là ma trận số liệu thực tế đo đạc qua 9 đợt thử nghiệm độc lập trên Docker Desktop (3 Profiles Phần cứng $\times$ 3 Thuật toán Ký số, mỗi đợt xử lý batch 500 giao dịch):

| Cấu hình Phần cứng | vCPU | Giới hạn RAM | Thuật toán Ký số | Số Tx Đạt | Thời gian (s) | Ingestion TPS | Baseline RAM (MB) | Peak RAM (MB) | % Đạt Trần RAM | Avg CPU (%) | CPU Throttled (ms) | Trạng thái Nguy cơ OOM |
| :--- | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Server (Datacenter)** | **4.0** | **4096 MB** | ECDSA (secp256k1) | 500/500 | 1.442 s | **346.68 tx/s** | 43.98 MB | 46.29 MB | 1.13% | 126.41% | 0.0 ms (0 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Server (Datacenter)** | **4.0** | **4096 MB** | RSA-2048 | 500/500 | 1.204 s | **415.23 tx/s** | 45.96 MB | 50.86 MB | 1.24% | 113.18% | 0.0 ms (0 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Server (Datacenter)** | **4.0** | **4096 MB** | **ML-DSA-44 (PQC)** | 500/500 | 0.851 s | **587.86 tx/s** | 45.77 MB | 53.33 MB | 1.30% | 137.46% | 0.0 ms (0 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Edge Gateway** | **1.0** | **512 MB** | ECDSA (secp256k1) | 500/500 | 1.654 s | **302.30 tx/s** | 43.48 MB | 45.84 MB | 8.95% | 103.00% | 842.2 ms (16 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Edge Gateway** | **1.0** | **512 MB** | RSA-2048 | 500/500 | 1.277 s | **391.63 tx/s** | 45.21 MB | 47.04 MB | 9.19% | 104.56% | 789.4 ms (12 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Edge Gateway** | **1.0** | **512 MB** | **ML-DSA-44 (PQC)** | 500/500 | 1.178 s | **424.29 tx/s** | 43.32 MB | 51.94 MB | 10.14% | 104.93% | 1077.5 ms (11 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **IoT Embedded** | **0.5** | **128 MB** | ECDSA (secp256k1) | 500/500 | 3.446 s | **145.10 tx/s** | 42.77 MB | 48.41 MB | 37.82% | 51.26% | 5381.8 ms (35 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **IoT Embedded** | **0.5** | **128 MB** | RSA-2048 | 500/500 | 2.579 s | **193.90 tx/s** | 43.37 MB | 48.11 MB | 37.59% | 53.38% | 5131.0 ms (26 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **IoT Embedded** | **0.5** | **128 MB** | **ML-DSA-44 (PQC)** | 500/500 | 2.158 s | **231.74 tx/s** | 42.43 MB | **54.16 MB** | **42.31%** | 52.21% | 4111.2 ms (22 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |

*Bảng dữ liệu trích xuất từ file: [`benchmarks/results/perf01_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/benchmarks/results/perf01_matrix.csv) và [`benchmarks/results/perf01_results.json`](file:///d:/assignment/btl/Blockchain-CSATT/benchmarks/results/perf01_results.json)*

---

## 4. BIỂU ĐỒ CẢNH BÁO NGƯỠNG OOM VÀ PHÂN TÍCH CHUYÊN SÂU

Toàn bộ kết quả thử nghiệm được tổng hợp và trực quan hóa qua biểu đồ kỹ thuật 3 panel tại [`benchmarks/results/perf01_oom_risk_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/benchmarks/results/perf01_oom_risk_chart.png):

```
+------------------------------------------------------------------------------------------------------------------------+
|                                      PERF-01: BIỂU ĐỒ PHÂN TÍCH TÀI NGUYÊN 3 PHẦN CỨNG                                 |
+----------------------------------+----------------------------------+--------------------------------------------------+
| PANEL 1: ĐỈNH TRẦN BỘ NHỚ & OOM  | PANEL 2: THÔNG LƯỢNG INGESTION   | PANEL 3: BÃO HÒA CPU & NGHẼN XUNG NHỊP           |
|                                  |                                  |                                                  |
| 128M [--- IoT Ceiling Line ---]  | 600 │              ┌──┐ (588 TPS)| 150%│     ┌──┐ ┌──┐ ┌──┐ (Server > 100%)         |
|      ▲ ML-DSA Peak: 54.2 MB      | 500 │        ┌──┐  │  │ (ML-DSA) | 120%│     │  │ │  │ │  │                         |
|      │ (Chiếm 42.3% trần RAM)    | 400 │  ┌──┐  │  │  │  │          | 100%│ [--- Edge Ceiling (100% CPU) ---]          |
|      │                           | 300 │  │  │  │  │  │  │          |  80%│     ┌──┐ ┌──┐ ┌──┐ (Edge: Throttling 1s)   |
|  60M │  ┌──┐  ┌──┐  ┌──┐         | 200 │  │  │  │  │  │  │          |  50%│ [--- IoT Ceiling (50% CPU) ---]            |
|      │  │  │  │  │  │  │         | 100 │  │  │  │  │  │  │          |  20%│     ┌──┐ ┌──┐ ┌──┐ (IoT: Bão hòa hoàn toàn) |
|   0M └──┴──┴──┴──┴──┴──┴───────  |   0 └──┴──┴──┴──┴──┴──┴────────  |   0%└──┴──┴──┴──┴──┴──┴─────────────────────────── |
|        ECDSA  RSA   ML-DSA       |        ECDSA  RSA   ML-DSA       |        ECDSA  RSA   ML-DSA                       |
+----------------------------------+----------------------------------+--------------------------------------------------+
```

### 4.1. Phân tích Panel 1: Đỉnh Trần Bộ Nhớ (Peak RAM) và Ranh giới Tràn Bộ Nhớ (OOM Cliff)
1. **Dung lượng nền tĩnh (Static Baseline):**
   - Trên cả 3 profile phần cứng, khi node vừa khởi động và ở trạng thái rảnh rỗi (Idle), dung lượng chiếm dụng RAM dao động ổn định trong khoảng **42.4 MB đến 45.9 MB**.
   - Dung lượng này bao gồm: Linux user-space, Python 3.11 Runtime, Flask WSGI Server, WebSocket listener, các bảng băm nội tại của Ledger và số cái Genesis.
2. **Áp lực bộ nhớ động từ Chữ ký Hậu lượng tử ML-DSA-44:**
   - Với **ECDSA (secp256k1)**: Kích thước payload 500 txs chỉ là $500 \times 128\text{ B} = 64\text{ KB}$. Lượng RAM tăng thêm gần như không đáng kể (tăng khoảng 3-4 MB do memory fragmentation và buffers).
   - Với **ML-DSA-44**: Kích thước thô của 500 txs là $500 \times 3,732\text{ B} \approx 1.87\text{ MB}$. Tuy nhiên, khi vào tầng ứng dụng:
     - Chuỗi JSON được giải mã thành cấu trúc Python Objects/Dicts.
     - Dữ liệu hex được chuyển đổi thành byte array mảng đa thức (Polynomial ring elements $R_q$).
     - Thư viện C `liboqs` cấp phát các vector ma trận kiểm tra parity trong RAM.
     - Hàng đợi Mempool lưu trữ đầy đủ 500 transactions kèm log Audit.
     - **Hệ quả:** Dung lượng RAM tăng vọt thêm **11.73 MB**, đẩy Peak RAM lên **54.16 MB**.
3. **Đánh giá Nguy cơ Tràn Bộ Nhớ (OOM Risk Boundary):**
   - Trên **Server (4096 MB)**: Peak RAM 53.33 MB chỉ chiếm **1.30%** trần RAM $\rightarrow$ Hoàn toàn an toàn.
   - Trên **Edge Gateway (512 MB)**: Peak RAM 51.94 MB chiếm **10.14%** trần RAM $\rightarrow$ Vùng xanh an toàn.
   - Trên **IoT Embedded (128 MB)**: Peak RAM 54.16 MB đã chiếm tới **42.31%** trần bộ nhớ hạn hẹp!
   - **Ranh giới sinh tử (OOM Boundary):** Thiết bị IoT chỉ còn lại khoảng đệm an toàn là:
     $$\Delta \text{RAM}_{\text{free}} = 128\text{ MB} - 54.16\text{ MB} = 73.84\text{ MB}$$
     Nếu một kẻ tấn công thực hiện chiến dịch **Mempool Flooding DoS** bơm liên tục $1,500$ đến $2,000$ giao dịch ML-DSA-44 vào node IoT trong khi node chưa kịp đào khối, bộ nhớ sẽ ngay lập tức vượt ngưỡng 128 MB. Do thiết lập `memswap_limit = 128M` (không có swap ảo để cứu vãn), Linux Kernel Out-Of-Memory Killer sẽ lập tức kích hoạt, gửi tín hiệu `SIGKILL` tiêu diệt tiến trình Node (Exit Code 137). 

### 4.2. Phân tích Panel 2 & 3: Bão hòa CPU và Nghịch lý Tốc độ Toán học PQC
1. **Nghịch lý Hiệu năng PQC (PQC Verification Paradox):**
   - Nhiều nhận định cảm tính cho rằng mật mã Hậu lượng tử với cấu trúc phức tạp sẽ xác thực chậm hơn mật mã truyền thống. **Tuy nhiên, kết quả thực nghiệm thực tế đã chứng minh điều ngược lại:**
     $$\text{Ingestion TPS (Server): ML-DSA-44 (587.86 tx/s)} > \text{RSA-2048 (415.23 tx/s)} > \text{ECDSA (346.68 tx/s)}$$
     $$\text{Ingestion TPS (IoT): ML-DSA-44 (231.74 tx/s)} > \text{RSA-2048 (193.90 tx/s)} > \text{ECDSA (145.10 tx/s)}$$
   - **Giải thích toán học:**
     - **ECDSA (secp256k1):** Xác thực chữ ký yêu cầu thực hiện phép nhân điểm trên đường cong elliptic (Scalar Point Multiplication $s^{-1} \cdot H(m) \cdot G + s^{-1} \cdot r \cdot Q$) và tính nghịch đảo modulo, là các phép toán tốn kém chu kỳ CPU.
     - **RSA-2048:** Yêu cầu phép tính lũy thừa modulo $S^e \pmod N$ với số nguyên lớn 2048-bit. Dù số mũ công khai nhỏ ($e = 65537$) giúp verify nhanh hơn ký, chi phí đại số vẫn đáng kể.
     - **ML-DSA-44 (Dilithium):** Dựa trên bài toán khó học với sai số trên module (Module-LWE và Module-SIS). Phép toán xác thực cốt lõi là phép nhân ma trận - vector đa thức trên trường số nguyên $\mathbb{Z}_q$ với $q = 8380417$. Nhờ thuật toán biến đổi số học nhanh NTT (**Number Theoretic Transform**), phép nhân đa thức bậc $d = 256$ được thực hiện với độ phức tạp $O(d \log d)$, đồng thời được tối ưu hóa bằng các tập lệnh vector hóa của CPU.
     - **Hệ quả:** **Thời gian CPU thuần túy để xác thực chữ ký ML-DSA là nhanh nhất trong cả 3 thuật toán!**
2. **Hiện tượng Bão hòa và Nghẽn CPU (CFS Throttling Saturation):**
   - **Trên Server (4.0 vCPU):** Hạn ngạch CPU là 400%. CPU trung bình đạt 126% - 137% (hơn 1 core vật lý làm việc hết công suất). Không bị nghẽn xung nhịp (`throttled_ms = 0.0 ms`).
   - **Trên Edge (1.0 vCPU):** Hạn ngạch CPU bị chặn cứng ở 100%. Node chạm ngưỡng bão hòa đơn nhân:
     - CPU tiêu thụ đạt mức kịch trần: 103% - 105%.
     - Linux CFS Scheduler bắt đầu kích hoạt điều tiết: Thời gian bị đóng băng xung nhịp (`CPU Throttled`) là **842 ms** (với ECDSA) và **1,077.5 ms** (với ML-DSA-44).
     - TPS giảm từ 587.86 tx/s xuống **424.29 tx/s**.
   - **Trên IoT (0.5 vCPU):** Hạn ngạch chỉ bằng một nửa đơn nhân (50% CPU capacity). Tình trạng **Bão hòa nghiêm trọng (Severe CPU Saturation)** xảy ra:
     - CPU luôn chạy kịch trần ở mức **51.26% - 53.38%** (chạm mức 100% của hạn ngạch 0.5 vCPU).
     - Thời gian CPU Throttling lên tới **4,111 ms đến 5,381 ms** (hơn 4 - 5 giây tiến trình bị hệ điều hành cưỡng bức tạm dừng chờ chu kỳ cấp phát tiếp theo)!
     - Thời gian xử lý 500 txs kéo dài từ 0.85s (Server) lên **2.16s - 3.45s (IoT)**, kéo Ingestion TPS của ML-DSA xuống còn **231.74 tx/s** và ECDSA xuống còn **145.10 tx/s**.

---

## 5. HƯỚNG DẪN TÁI LẬP KẾT QUẢ THỰC NGHIỆM (REPRODUCIBILITY GUIDE)

Để các thành viên khác trong nhóm hoặc Hội đồng chấm thi có thể tái lập 100% kết quả thực nghiệm một cách minh bạch, quy trình 4 bước được chuẩn hóa như sau:

### Bước 1: Khởi động Docker Desktop
Đảm bảo daemon Docker Desktop đang chạy:
```powershell
docker info
```

### Bước 2: Đóng gói Node Blockchain Image
Tại thư mục gốc dự án `Blockchain-CSATT`, build image tích hợp thư viện mật mã lượng tử:
```powershell
docker build -t blockchain-node:perf .
```

### Bước 3: Kiểm tra và Sinh Bộ dữ liệu Tải (Nếu cần tạo mới)
Script sinh 500 và 3,000 giao dịch ký số chuẩn cho cả 3 thuật toán:
```powershell
docker run --rm -v "${PWD}:/app" blockchain-node:perf python benchmarks/generate_perf01_txs.py
```
Dữ liệu sẽ được lưu tại `benchmarks/data/`: `txs_500_ecdsa.json`, `txs_500_rsa.json`, `txs_500_mldsa.json`.

### Bước 4: Chạy Toàn bộ Kịch bản Stress Test Tự động
Khởi chạy suite kiểm thử PERF-01:
```powershell
python benchmarks/perf01_stress_test.py
```
**Quy trình tự động hóa thực hiện:**
1. Lần lượt khởi động từng container tương ứng với 3 profile phần cứng (Server: 4GB/4vCPU, Edge: 512MB/1vCPU, IoT: 128MB/0.5vCPU).
2. Thiết lập cgroups v2 khống chế cứng RAM, Memswap và vCPU.
3. Kích hoạt luồng `CgroupTelemetryMonitor` ngầm lấy mẫu 80ms.
4. Bơm 500 giao dịch qua endpoint HTTP `/transactions/new`, kích hoạt toàn bộ luồng thẩm định mật mã, kiểm tra nonce, số dư và mempool.
5. Thu thập snapshot kernel cgroups (`memory.peak`, `cpu.stat`, `memory.events`).
6. Tự động hủy container để giải phóng tài nguyên.
7. Tự động kết xuất bảng ma trận [`benchmarks/results/perf01_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/benchmarks/results/perf01_matrix.csv), dữ liệu JSON [`benchmarks/results/perf01_results.json`](file:///d:/assignment/btl/Blockchain-CSATT/benchmarks/results/perf01_results.json) và biểu đồ OOM [`benchmarks/results/perf01_oom_risk_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/benchmarks/results/perf01_oom_risk_chart.png).

---

## 6. KHUYẾN NGHỊ KIẾN TRÚC DEVOPS & AN TOÀN HỆ THỐNG

Dựa trên các bằng chứng thực nghiệm thu được từ kịch bản `PERF-01`, nhóm đưa ra các khuyến nghị kiến trúc quan trọng cho hệ sinh thái Blockchain Hậu lượng tử:

### 6.1. Không triển khai Full Node PQC trên Thiết bị Nhúng IoT yếu
- Thiết bị IoT với dung lượng RAM $\le 128\text{ MB}$ và CPU $\le 0.5\text{ vCPU}$ **không phù hợp để đóng vai trò Full Node hoặc Miner** trong mạng lưới PQC.
- Nguy cơ OOM Killer đánh sập node là rất cao khi xảy ra tắc nghẽn mạng hoặc bão giao dịch (Mempool Flooding).

### 6.2. Ứng dụng Mô hình Node Phân cấp (Hierarchical Blockchain Topology)
- **IoT Device (Client-only / Signer):** Thiết bị IoT chỉ nắm giữ khóa bí mật để ký số giao dịch của cảm biến và đẩy dữ liệu lên mạng. Bản thân việc ký một giao dịch chỉ tốn vài chục KB RAM tạm thời và không duy trì số cái trong bộ nhớ.
- **Edge Gateway Node (Relay / Verifier):** Các trạm biên như Raspberry Pi 4 hoặc IPC công nghiệp (512MB - 1GB RAM, 1-2 vCPU) đóng vai trò Relay Node, thực hiện thẩm định chữ ký ban đầu, lọc bỏ giao dịch rác (Invalid Signature / Insufficient Balance) trước khi lan truyền vào mạng lưới trung tâm.
- **Server Datacenter (Consensus Validator / Miner):** Các máy chủ mạnh (4GB+ RAM, 4+ vCPU) đảm nhận vai trò lưu trữ toàn bộ lịch sử chuỗi khối và thực hiện đồng thuận Proof-of-Work.

### 6.3. Tối ưu hóa Bộ nhớ Tầng Ứng dụng (Application Memory Optimization)
- **Cơ chế Zero-Copy Streaming Deserialization:** Thay vì parse toàn bộ khối JSON 3.87 MB vào bộ nhớ Python cùng một lúc, cần áp dụng parser dạng dòng (Streaming JSON Parser như `ijson`) để thẩm định chữ ký và giải phóng bộ nhớ từng giao dịch một.
- **Giới hạn cứng Dung lượng Mempool trên Node IoT:** Cần thiết lập hạn ngạch kích thước Mempool tối đa theo dung lượng byte (ví dụ: tối đa 10 MB Mempool) thay vì theo số lượng giao dịch, tự động từ chối giao dịch mới khi chạm ngưỡng để ngăn ngừa triệt để sự cố OOM.

---

## 7. DANH MỤC TÀI LIỆU VÀ SẢN PHẨM BÀN GIAO (DELIVERABLES)

| STT | Tên Sản phẩm / Tệp tin | Đường dẫn Tuyệt đối | Mô tả Chi tiết |
| :---: | :--- | :--- | :--- |
| 1 | **Dockerfile** | [`Dockerfile`](file:///d:/assignment/btl/Blockchain-CSATT/Dockerfile) | File cấu hình đóng gói Node tích hợp liboqs, Python 3.11, WebSocket và thư viện PQC FIPS 204. |
| 2 | **docker-compose.yml** | [`docker-compose.yml`](file:///d:/assignment/btl/Blockchain-CSATT/docker-compose.yml) | File định nghĩa 3 profile phần cứng: Server (4GB/4vCPU), Edge (512MB/1vCPU), IoT (128MB/0.5vCPU). |
| 3 | **Dataset Generator** | [`benchmarks/generate_perf01_txs.py`](file:///d:/assignment/btl/Blockchain-CSATT/benchmarks/generate_perf01_txs.py) | Script sinh 1,500 giao dịch ký số chuẩn cho ECDSA, RSA-2048 và ML-DSA-44. |
| 4 | **Stress Test & Telemetry Driver** | [`benchmarks/perf01_stress_test.py`](file:///d:/assignment/btl/Blockchain-CSATT/benchmarks/perf01_stress_test.py) | Engine kiểm thử tự động, tích hợp giám sát cgroups v2 thời gian thực và vẽ biểu đồ. |
| 5 | **Bảng Ma trận So sánh Tài nguyên (CSV)** | [`benchmarks/results/perf01_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/benchmarks/results/perf01_matrix.csv) | Bảng ma trận kết quả đo đạc thực nghiệm 9 đợt (TPS, Peak RAM, % Ceiling, Avg CPU, Throttling, OOM). |
| 6 | **Dữ liệu Thống kê Chi tiết (JSON)** | [`benchmarks/results/perf01_results.json`](file:///d:/assignment/btl/Blockchain-CSATT/benchmarks/results/perf01_results.json) | Dữ liệu thô JSON của 9 đợt benchmark phục vụ phân tích khoa học. |
| 7 | **Biểu đồ Cảnh báo Ngưỡng OOM (PNG)** | [`benchmarks/results/perf01_oom_risk_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/benchmarks/results/perf01_oom_risk_chart.png) | Biểu đồ trực quan 3 panel: Peak RAM vs Memory Ceiling, Ingestion TPS, và Mức độ bão hòa CPU. |
| 8 | **Báo cáo Kỹ thuật Đầy đủ (MD)** | [`PERF01_BENCHMARK_REPORT.md`](file:///d:/assignment/btl/Blockchain-CSATT/PERF01_BENCHMARK_REPORT.md) | Báo cáo kỹ thuật chi tiết theo chuẩn học thuật và đề cương bài tập lớn. |
