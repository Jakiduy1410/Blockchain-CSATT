# 4. BÁO CÁO KỊCH BẢN KIỂM THỬ PERF-01: ĐO LƯỜNG GIỚI HẠN TÀI NGUYÊN NODE TRÊN PHẦN CỨNG YẾU (RESOURCE CONSTRAINED STRESS TEST)

## 4.1. Cài đặt môi trường (Environment Setup)

### 4.1.1. Hạ tầng phần cứng máy chủ & Nền tảng ảo hóa
Toàn bộ các kịch bản đo kiểm thực nghiệm được triển khai và cách ly hoàn toàn thông qua công nghệ đóng gói container Docker trên nền tảng nhân Linux cgroups v2.
* **Hệ điều hành Host:** Microsoft Windows 11 Pro 64-bit (Build 22631).
* **Môi trường Container Runtime:** Docker Desktop Engine (WSL2 Backend - Ubuntu Linux Kernel 5.15.x).
* **Cơ chế quản lý tài nguyên:** Linux Control Groups phiên bản 2 (cgroups v2) với tính năng khóa không gian nhớ tráo đổi (Memswap lock: `--memory-swap = memory`) nhằm kích hoạt trực tiếp phản ứng của bộ điều phối nhân và cơ chế ngắt tiến trình Out-Of-Memory (OOM-Killer).

### 4.1.2. Đặc tả Docker Image & Thư viện Mật mã Hậu lượng tử
Hình ảnh container `blockchain-node:perf` được xây dựng từ `python:3.11-slim` kết hợp môi trường biên dịch mã nguồn bản địa:
* **Thư viện Hậu lượng tử NIST FIPS 204:** Biên dịch trực tiếp thư viện mã nguồn mở `liboqs` (Open Quantum Safe v0.12.0) với trình biên dịch Clang/CMake và cờ `-DOQS_DIST_BUILD=ON -DOQS_BUILD_ONLY_LIB=ON`. Gói binding `liboqs-python` được kết nối qua FFI.
* **Thư viện Mật mã Cổ điển:** `cryptography` (OpenSSL v3.x backend) cho thuật toán ECDSA secp256k1 và SHA-256.
* **Giao thức Mạng & Web API:** Web Framework Flask đa luồng (`threaded=True`), WebSocket client/server phục vụ truyền thông P2P mã hóa TLS 1.3 qua chuẩn cipher suite `TLS_AES_256_GCM_SHA384`.

### 4.1.3. Định nghĩa các Cấu hình Phần cứng (Hardware Profiles)
Theo phân công kịch bản kiểm thử PERF-01 trong dự án, hệ thống thiết lập 3 cấu hình giới hạn tài nguyên đại diện cho các tầng kiến trúc mạng Blockchain thực tế:
1. **Server DUT (Cloud / DataCenter):** Phân bổ 4.0 vCPU, 4096 MB RAM (`-m=4096m --cpus=4.0`). Đại diện cho các node xác thực trung tâm và node khai thác mỏ.
2. **Edge Gateway DUT (Raspberry Pi 4 / Khung nhúng biên):** Phân bổ 1.0 vCPU, 512 MB RAM (`-m=512m --cpus=1.0`). Đại diện cho các trạm chuyển tiếp, cổng giao tiếp công nghiệp.
3. **IoT Embedded DUT (Smart Meter / Sensor):** Phân bổ 0.5 vCPU, 128 MB RAM (`-m=128m --cpus=0.5`). Đại diện cho các thiết bị đo lường thông minh bị giới hạn nghiêm ngặt về năng lượng và bộ nhớ.
4. **IoT Extreme OOM DUT:** Phân bổ 0.5 vCPU, 60 MB RAM (`-m=60m --cpus=0.5 --memory-swap=60m`). Cấu hình đặc thù dùng để phát hiện ngưỡng gãy vỡ bộ nhớ của các thuật toán chữ ký số.

### 4.1.4. Quy trình biên dịch và xác minh môi trường Docker
Lệnh xây dựng Docker Image từ thư mục gốc dự án:
```powershell
docker build -t blockchain-node:perf -f perf/Dockerfile .
```
Sau khi hoàn tất, kiểm tra trạng thái image bằng lệnh:
```powershell
docker images blockchain-node:perf
```

---

## 4.2. Kịch bản thực nghiệm (Test Scenarios & Methodology)

### 4.2.1. Mục tiêu và Giả thuyết Thực nghiệm
* **Mục tiêu:** Định lượng hóa chi phí tài nguyên (CPU Saturation, Memory Footprint, Throughput, Throttling Duration) khi tích hợp chữ ký số Hậu lượng tử NIST FIPS 204 (ML-DSA-44 Cấp 2, ML-DSA-65 Cấp 3, ML-DSA-87 Cấp 5) so với chữ ký truyền thống ECDSA (secp256k1) trên các thiết bị tài nguyên hạn chế.
* **Giả thuyết khoa học:**
  1. Do kích thước khóa công khai và chữ ký của ML-DSA tăng theo cấp số (từ 3.73 KB ở Cấp 2 lên 7.22 KB ở Cấp 5), dung lượng bộ nhớ Heap của hàng đợi giao dịch (Mempool) sẽ tăng tỷ lệ thuận với số lượng giao dịch, dẫn đến hiện tượng tràn bộ nhớ (OOM) sớm trên phần cứng yếu.
  2. Phép biến đổi ma trận đa thức NTT trong thẩm định chữ ký PQC sẽ đẩy mức tiêu thụ CPU chạm trần 100% trên thiết bị 1.0 vCPU và 0.5 vCPU, kích hoạt cơ chế bóp nghẽn chu kỳ CFS của nhân Linux.

### 4.2.2. Kịch bản 1: Ma trận Phần cứng Cơ sở 3x4 (Baseline Hardware Matrix)
* **Quy mô:** 500 giao dịch đã ký hợp lệ cho từng thuật toán (ECDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87).
* **Quy trình:** Nạp đồng thời qua giao diện HTTP REST API vào Mempool của từng profile (Server, Edge, IoT).
* **Chỉ số thu thập:** Thời gian nạp (Elapsed Time), Thông lượng nạp (Ingestion TPS), Đỉnh RAM chiếm dụng (Peak RAM), Tỷ lệ phần trăm hạn mức RAM (RAM Ceiling Usage), Phần trăm CPU chuẩn hóa (Normalized CPU), và Thời gian bóp nghẽn CPU (CFS Throttled Duration tính bằng mili-giây).

### 4.2.3. Kịch bản 2: Tải cực hạn & Săn tìm ngưỡng tràn bộ nhớ Linux (Extreme OOM Hunt)
* **Quy mô:** 1.500 giao dịch nạp liên tục theo từng đợt (batch 50 giao dịch) vào Node IoT giới hạn nghiêm ngặt 60.0 MB RAM (0.5 vCPU).
* **Mục tiêu kỹ thuật:** Xác định chính xác mốc giao dịch kích hoạt tín hiệu SIGKILL (Exit Code 137) từ bộ điều phối OOM-Killer của Linux Kernel. Đánh giá thuật toán nào có khả năng "sống sót" (survived) qua 1.500 giao dịch.

### 4.2.4. Kịch bản 3: Đo kiểm Vĩ mô Mạng Live Mesh 6 Node (Macro-Benchmark Mesh)
* **Mô hình mạng:** Mạng P2P Full-Mesh gồm 1 node kiểm thử chịu tải (DUT Container: Server, Edge hoặc IoT) liên kết với 5 node nền tảng (Background Nodes) qua 15 cặp kết nối WebSocket TLS 1.3 wss:// mở thường trực.
* **Pha 1 (Bão tin đồn Gossip):** Bắn 100 giao dịch phân tán vào 5 node nền tảng (20 txs/node). Các node phát sóng bão tin đồn tới DUT. Đo Ingest TPS, băng thông tiếp nhận (Ingress Bandwidth) và số lượng gói tin trùng lặp bị lọc bỏ (WS Dups Filtered).
* **Pha 2 (Đào và cam kết khối):** Node Miner 1 đào Khối số 2 chứa 100 giao dịch và phát sóng qua mạng. DUT thẩm định chữ ký toàn bộ khối, đo thời gian thẩm định (Block Verify CPU), độ trễ đường truyền vật lý (Wire Transit Delay) và độ trễ cam kết hoàn tất vào sổ cái (Commit Latency).

---

## 4.3. Tiến hành kịch bản thực nghiệm (Execution Procedure)

### 4.3.1. Cơ chế giám sát cgroups v2 và đo đạc không xâm lấn
Để loại bỏ hoàn toàn sai số do việc khởi tạo subshell bên ngoài (như gọi `docker exec sh -c cat /sys/fs/cgroup/...` làm phình to bộ nhớ Page Cache ảo), hệ thống tích hợp endpoint nội bộ `/metrics/light`. Endpoint này cho phép tiến trình Python tự đọc trực tiếp các thanh ghi nhân Linux trong cùng một chu kỳ I/O:
* Đọc CPU Stat: `/sys/fs/cgroup/cpu.stat` lấy chính xác `usage_usec`, `nr_throttled`, và `throttled_usec`.
* Đọc Memory Stat: `/sys/fs/cgroup/memory.stat` lấy chính xác dung lượng bộ nhớ làm việc thực tế (Working Set = `anon` + `kernel` + `sock` + `shmem`), loại bỏ hoàn toàn các dao động ảo do bộ nhớ đệm tập tin Linux (File Cache).
* Đo thời gian thẩm định mật mã: Sử dụng `time.thread_time()` đo riêng thời gian CPU thực tế của luồng thực thi, không bị ảnh hưởng bởi chu kỳ ngủ CFS throttling.

### 4.3.2. Quy trình Thực thi Kịch bản 1 & 2
Chạy kịch bản tự động hóa từ terminal PowerShell:
```powershell
python perf/perf01_stress_test.py
```
Tiến trình lần lượt khởi tạo các container tương ứng cho từng cặp cấu hình phần cứng và thuật toán, nạp dữ liệu giao dịch đã ký sẵn, thu thập telemetry cgroups, xuất kết quả ra file `perf01_matrix.csv`, `perf01_results.json` và kích hoạt thử nghiệm tải cực hạn xuất ra `perf01_extreme_oom_matrix.csv`.

### 4.3.3. Quy trình Thực thi Kịch bản 3
Chạy kịch bản macro mạng phân tán:
```powershell
python perf/perf01_macro_stress.py
```
Tiến trình thiết lập mạng mạng ảo bridge `btc-mesh-net`, khởi động 5 background node cùng 1 DUT node, đồng bộ topology kết nối WebSocket TLS 1.3, kích hoạt bão Gossip và đo đạc độ trễ cam kết khối.

---

## 4.4. Chụp kết quả từng bước (Step-by-Step Empirical Results & Data Tables)

### 4.4.1. Kết quả Kịch bản 1: Ma trận tài nguyên 3 Profile Phần cứng × 4 Thuật toán
Bảng 4.1 tổng hợp số liệu đo kiểm thực tế thu được từ quá trình chạy 500 giao dịch trên các container Docker:

#### Bảng 4.1: Ma trận tài nguyên thực nghiệm 3 Profile × 4 Thuật toán (500 Giao dịch Batch Ingestion)

| Cấu hình Phần cứng | Thuật toán Chữ ký | Thời gian Nạp (s) | Ingestion TPS (tx/s) | Peak RAM (MB) | Tỷ lệ RAM/Trần (%) | Normalized CPU (%) | CPU Throttled (ms) | Trạng thái OOM |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Server** (4 vCPU, 4GB) | ECDSA (secp256k1) | 0.526 | 950.57 | 36.95 | 0.90% | 29.14% | 0.00 | AN TOÀN (<60%) |
| **Server** (4 vCPU, 4GB) | ML-DSA-44 (PQC Cấp 2) | 0.640 | 781.25 | 43.40 | 1.06% | 32.91% | 0.00 | AN TOÀN (<60%) |
| **Server** (4 vCPU, 4GB) | ML-DSA-65 (PQC Cấp 3) | 0.724 | 690.61 | 46.62 | 1.14% | 37.85% | 0.00 | AN TOÀN (<60%) |
| **Server** (4 vCPU, 4GB) | ML-DSA-87 (PQC Cấp 5) | 0.897 | 557.41 | 49.21 | 1.20% | 50.05% | 0.00 | AN TOÀN (<60%) |
| **Edge** (1 vCPU, 512MB) | ECDSA (secp256k1) | 0.591 | 846.02 | 36.81 | 7.19% | 100.00% | 120.69 | AN TOÀN (<60%) |
| **Edge** (1 vCPU, 512MB) | ML-DSA-44 (PQC Cấp 2) | 0.811 | 616.52 | 43.12 | 8.42% | 100.00% | 433.38 | AN TOÀN (<60%) |
| **Edge** (1 vCPU, 512MB) | ML-DSA-65 (PQC Cấp 3) | 1.079 | 463.39 | 46.47 | 9.08% | 100.00% | 977.63 | AN TOÀN (<60%) |
| **Edge** (1 vCPU, 512MB) | ML-DSA-87 (PQC Cấp 5) | 1.792 | 279.02 | 49.21 | 9.61% | 100.00% | 4151.37 | AN TOÀN (<60%) |
| **IoT** (0.5 vCPU, 128MB) | ECDSA (secp256k1) | 1.124 | 444.84 | 36.68 | 28.66% | 100.00% | 1202.13 | AN TOÀN (<60%) |
| **IoT** (0.5 vCPU, 128MB) | ML-DSA-44 (PQC Cấp 2) | 1.677 | 298.15 | 42.99 | 33.59% | 100.00% | 2517.08 | AN TOÀN (<60%) |
| **IoT** (0.5 vCPU, 128MB) | ML-DSA-65 (PQC Cấp 3) | 1.959 | 255.23 | 46.48 | 36.31% | 100.00% | 4361.29 | AN TOÀN (<60%) |
| **IoT** (0.5 vCPU, 128MB) | ML-DSA-87 (PQC Cấp 5) | 3.176 | 157.43 | 49.13 | 38.38% | 100.00% | 10293.26 | AN TOÀN (<60%) |

*Biểu đồ kết quả đo đạc Kịch bản 1:*

**Hình 4.1: Biểu đồ đo lường giới hạn tài nguyên Node & cảnh báo ngưỡng OOM (3 panels: Peak RAM, Ingestion TPS, CPU Throttled ms).**

---

### 4.4.2. Kết quả Kịch bản 2: Quỹ đạo Bộ nhớ & Sự kiện OOM-Killer trên Node 60MB RAM
Bảng 4.2 ghi nhận quá trình tiêu thụ bộ nhớ Working Set thực tế từ thanh ghi cgroups v2 qua từng đợt nạp 50 giao dịch:

#### Bảng 4.2: Quỹ đạo tiêu thụ RAM thực tế & Sự kiện ngắt OOM-Killer trên Node 60MB RAM (1.500 Giao dịch)

| Mốc Giao dịch (Tx Count) | ECDSA RAM (MB) | ML-DSA-44 RAM (MB) | ML-DSA-65 RAM (MB) | ML-DSA-87 RAM (MB) | Ngưỡng Trần Linux (MB) | Ghi chú Sự kiện |
| :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Tx #50** | 35.70 | 36.66 | 36.94 | 37.14 | 60.00 | Khởi tạo Mempool cơ sở |
| **Tx #200** | 35.97 | 38.51 | 39.94 | 41.02 | 60.00 | Tích lũy tuyến tính theo Heap |
| **Tx #500** | 36.46 | 42.43 | 46.05 | 48.58 | 60.00 | Phân tầng rõ nét theo kích thước chữ ký |
| **Tx #800** | 36.78 | 46.30 | 52.05 | 55.98 | 60.00 | ML-DSA-87 chạm vùng rủi ro (>90% trần) |
| **Tx #950** | 36.93 | 48.21 | 55.07 | 58.69 | 60.00 | ML-DSA-87 tiệm cận sát trần 60MB |
| **Tx #1000** | 37.00 | 48.84 | 56.08 | **60.00 (OOM)** | 60.00 | **ML-DSA-87 OOM: Nhân Linux gửi SIGKILL Exit 137!** |
| **Tx #1150** | 37.18 | 50.67 | 57.96 | -- | 60.00 | ML-DSA-65 tiệm cận vùng nguy hiểm |
| **Tx #1250** | 37.66 | 52.24 | **60.00 (OOM)** | -- | 60.00 | **ML-DSA-65 OOM: Nhân Linux gửi SIGKILL Exit 137!** |
| **Tx #1400** | 37.80 | 54.10 | -- | -- | 60.00 | ML-DSA-44 tiếp tục duy trì ổn định |
| **Tx #1500** | **37.92** | **55.48** | -- | -- | 60.00 | **ECDSA & ML-DSA-44 SỐNG SÓT QUA 1.500 TXS** |

*Biểu đồ kết quả đo đạc Kịch bản 2:*

**Hình 4.2: Biểu đồ quỹ đạo bộ nhớ thực tế & sự kiện ngắt tiến trình Linux OOM-Killer trên Node IoT 60MB RAM.**

---

### 4.4.3. Kết quả Kịch bản 3: Đo kiểm Vĩ mô trong Mạng Live Mesh 6 Node
Bảng 4.3 thể hiện toàn bộ các chỉ số vận hành phân tán khi mạng chịu tải bão tin đồn Gossip và lan truyền khối qua giao thức WebSocket TLS 1.3:

#### Bảng 4.3: Ma trận hiệu năng vĩ mô Macro-Benchmark trong Mạng P2P Live Mesh 6 Node

| Chỉ số Vận hành Mạng Mesh | ECDSA (secp256k1) | ML-DSA-44 (PQC Cấp 2) | ML-DSA-65 (PQC Cấp 3) | ML-DSA-87 (PQC Cấp 5) |
| :--- | :---: | :---: | :---: | :---: |
| **Kích thước Dây mạng 1 Tx (Wire Bytes)** | 499 B | 7,711 B | 10,769 B | 14,685 B |
| **Kích thước Khối 100 Tx (Block Wire Size)** | 54.67 KB | 758.57 KB | 1,057.20 KB | 1,439.63 KB |
| **Xác thực 1 Tx trên Server / Edge / IoT (ms)** | 0.020 / 0.019 / 0.021 | 0.537 / 0.676 / 0.694 | 1.227 / 1.461 / 1.637 | 3.027 / 3.435 / 3.878 |
| **Xác thực Khối 100 Tx trên Server / Edge / IoT (ms)** | 2.62 / 2.76 / 3.15 | 54.33 / 68.40 / 70.47 | 123.34 / 146.89 / 164.73 | 303.34 / 344.37 / 388.90 |
| **Độ trễ Cam kết Khối Server / Edge / IoT (ms)** | **6.20 / 7.13 / 8.70** | **84.66 / 105.40 / 117.48** | **165.01 / 197.73 / 229.32** | **359.55 / 412.95 / 476.03** |
| **Thông lượng Nạp Gossip Server / Edge / IoT (TPS)** | **308.85 / 280.51 / 202.57** | **259.06 / 171.55 / 106.63** | **214.15 / 148.86 / 87.22** | **188.18 / 115.22 / 63.79** |
| **Bản sao Gossip Lọc bỏ (WS Dups Filtered)** | **400 / 400 / 400** | **400 / 400 / 400** | **400 / 400 / 400** | **400 / 400 / 400** |
| **Thời gian Bóp CPU Edge / IoT (Throttled ms)** | 147.05 / 833.48 | 760.26 / 2,037.86 | 831.94 / 2,896.59 | 1,571.61 / 5,820.86 |
| **Đỉnh RAM chiếm dụng Server / Edge / IoT (MB)** | 40.55 / 40.39 / 40.62 | 43.32 / 43.43 / 42.98 | 43.66 / 43.87 / 43.76 | 45.22 / 45.11 / 44.96 |
| **Tỷ lệ chiếm dụng RAM trên Thiết bị IoT (%)** | **31.73%** | **33.58%** | **34.19%** | **35.12%** |

*Biểu đồ kết quả đo đạc Kịch bản 3:*

**Hình 4.3: Biểu đồ Macro-Benchmark 4 panel đánh giá toàn diện DUT trong mạng Live Mesh 6 Node.**

---

## 4.5. Bình luận và giải thích chi tiết ở mỗi ảnh, mỗi kết quả (In-Depth Technical Analysis & Evaluation)

### 4.5.1. Phân tích Hình 4.1 & Bảng 4.1 (Baseline Hardware Matrix)
Quan sát biểu đồ 3 panel ở Hình 4.1 đối chiếu cùng Bảng 4.1, ta rút ra các kết luận then chốt về mặt kiến trúc hệ điều hành và mật mã học:

1. **Quy luật thứ bậc Thông lượng (Ingestion TPS):**
   * Thông lượng nạp giao dịch tuân thủ tuyệt đối quy luật phân tầng hai chiều:
     * Theo cấu hình phần cứng: **Server (4 vCPU) > Edge (1 vCPU) > IoT (0.5 vCPU)**
     * Theo thuật toán mật mã: **ECDSA > ML-DSA-44 > ML-DSA-65 > ML-DSA-87**
   * Trên cấu hình Server, ECDSA đạt đỉnh 950.57 tx/s, trong khi ML-DSA-44 đạt 781.25 tx/s, ML-DSA-65 đạt 690.61 tx/s và ML-DSA-87 đạt 557.41 tx/s. Khi chuyển dịch xuống thiết bị IoT (0.5 vCPU), thông lượng của ML-DSA-87 sụt giảm xuống còn 157.43 tx/s (giảm 71.7% so với Server).
   * Nguyên nhân là do cấu trúc toán học của chuẩn NIST FIPS 204: ML-DSA-87 yêu cầu ma trận đa thức bậc cao (k=8, l=7) với kích thước modulus q = 8,380,417. Trên chip IoT giới hạn 0.5 vCPU, việc không có tập lệnh vector hóa AVX-512 khiến các vòng lặp nhân đa thức NTT làm nghẽn năng lực tính toán của CPU.

2. **Hiện tượng Bóp nghẽn Chu kỳ CPU (CFS Quota Throttling):**
   * Panel 3 của Hình 4.1 ghi nhận thời gian bóp nghẽn CPU cực kỳ khốc liệt:
     - Trên **Server (4.0 vCPU)**: Thời gian bóp CPU bằng đúng **0.0 ms** cho mọi thuật toán do hạn mức thời gian hạn định của cgroups lớn hơn tải thực tế.
     - Trên **Edge (1.0 vCPU)**: Bắt đầu xuất hiện hiện tượng bóp nghẽn từ 120.69 ms (ECDSA) tăng vọt lên 4,151.37 ms (ML-DSA-87).
     - Trên **IoT (0.5 vCPU)**: Thời gian CPU bị bóp nghẽn của ML-DSA-87 lên tới **10,293.26 ms (hơn 10.2 giây)**! Điều này giải thích tại sao tổng thời gian hoàn thành 500 txs của ML-DSA-87 bị kéo dài lên 3.176 giây (trong khi Server chỉ mất 0.897 giây). Quá trình thực thi liên tục tiêu thụ hết quota CPU trong chu kỳ 100ms và bị nhân Linux cưỡng bức đưa vào trạng thái ngủ chờ chu kỳ quota tiếp theo.

3. **Tính Độc lập của Bộ nhớ Working Set so với Hạn mức Phần cứng:**
   * Panel 1 của Hình 4.1 cho thấy một đặc tính vật lý quan trọng: Đỉnh RAM chiếm dụng của từng thuật toán gần như tương đương nhau giữa các cấu hình phần cứng: ECDSA tiêu thụ xấp xỉ 36.8 MB, ML-DSA-44 tiêu thụ ~43.1 MB, ML-DSA-65 tiêu thụ ~46.5 MB và ML-DSA-87 tiêu thụ ~49.2 MB.
   * Giải thích: Dung lượng bộ nhớ Heap mà Python phân bổ để lưu trữ 500 cấu trúc dữ liệu giao dịch là mang tính tất định. Hạn mức phần cứng `--memory` của Docker là "trần cứng giám sát" (Ceiling), không phải dung tích mà tiến trình sẽ tự nở ra để chiếm dụng. Tuy nhiên, sự khác biệt sống còn nằm ở **Tỷ lệ chiếm dụng RAM theo hạn mức**: Trong khi trên Server 4GB, ML-DSA-87 chỉ chiếm 1.20% dung lượng, thì trên node IoT 128MB nó đã chiếm tới 38.38% tổng tài nguyên nhớ của thiết bị.

---

### 4.5.2. Phân tích Hình 4.2 & Bảng 4.2 (Extreme OOM Cliff trên Node 60MB RAM)
Biểu đồ Hình 4.2 tái hiện chân thực nhất quy luật tương tác giữa cấu trúc dữ liệu mật mã và cơ chế quản lý bộ nhớ của nhân Linux:

1. **Bản chất của Thời điểm Kích hoạt Linux Kernel OOM-Killer:**
   * Khác biệt hoàn toàn với các biểu đồ mô phỏng lý thuyết thường vẽ đường RAM chạm 60MB rồi đi ngang hoặc dao động răng cưa, kết quả đo thực nghiệm trên Docker cho thấy: **Ngay tại khoảnh khắc lượng trang nhớ ẩn danh (Anonymous Memory) và Working Set chạm đúng ngưỡng trần cứng 60.0 MB và nhân Linux không thể thu hồi thêm bộ nhớ, tín hiệu SIGKILL (Exit Code 137) được gửi tức thì, tiêu diệt tiến trình ngay tại đỉnh đầu tiên.**
   * **ML-DSA-87 (Cấp 5):** Do kích thước cặp khóa/chữ ký lên tới 7.22 KB/giao dịch, cộng thêm overhead cấu trúc đối tượng bậc cao của Python, đường tiêu thụ bộ nhớ có độ dốc lớn nhất (+0.024 MB/Tx). Tiến trình chạm mốc 58.69 MB tại Tx #950 và **bị OOM-Killer tiêu diệt chính xác tại Tx #1000 khi chạm 60.0 MB**.
   * **ML-DSA-65 (Cấp 3):** Có kích thước dữ liệu nhỏ hơn (~5.26 KB/giao dịch), độ dốc thoải hơn (+0.019 MB/Tx), tiến trình duy trì hoạt động đến Tx #1200 (58.93 MB) và **bị OOM-Killer tiêu diệt tại Tx #1250 khi chạm 60.0 MB**.

2. **Khả năng "Sống sót" và Biên độ An toàn của ML-DSA-44 (Cấp 2):**
   * Thuật toán ML-DSA-44 chứng minh khả năng tương thích tuyệt vời với phần cứng nhúng: Tại mốc kết thúc bài test (Tx #1500), lượng RAM chiếm dụng thực tế chỉ dừng lại ở **55.48 MB**.
   * Biên độ an toàn còn lại so với trần cứng 60.0 MB là **4.52 MB** (tương đương dung lượng đủ nạp thêm gần 300 giao dịch nữa). Kết quả này khẳng định ML-DSA-44 là ứng viên tối ưu nhất để triển khai trên các vi điều khiển hoặc board nhúng IoT có dung lượng RAM dưới 64MB.

3. **Tính Ổn định Tuyệt đối của ECDSA secp256k1:**
   * Đường biểu diễn của ECDSA gần như là một đường nằm ngang hoàn hảo: Tăng từ 35.70 MB (Tx #50) lên 37.92 MB (Tx #1500). Toàn bộ 1.500 giao dịch ECDSA chỉ làm tăng thêm vỏn vẹn 2.22 MB bộ nhớ (do chữ ký chỉ có 64 bytes và public key 33/65 bytes). Điều này lý giải tại sao các blockchain truyền thống như Bitcoin, Ethereum có thể chạy hàng chục nghìn giao dịch trong Mempool trên các máy chủ cấu hình rất thấp mà không lo tràn RAM.

---

### 4.5.3. Phân tích Hình 4.3 & Bảng 4.3 (Macro-Benchmark Mạng Live Mesh 6 Node)
Hình 4.3 phản ánh chân thực động lực học của một mạng Blockchain phân tán khi đối mặt với bão tin đồn giao dịch PQC và lan truyền khối qua kênh truyền bảo mật WebSocket TLS 1.3:

1. **Hiệu quả của Giao thức Lọc Trùng lặp (WS Dups Filtered = 400):**
   * Trong mô hình 6 node Full-Mesh, mỗi giao dịch phát tán từ 5 node nền tảng sẽ được gửi qua 5 kết nối WebSocket độc lập. Nhờ cơ chế chỉ mục băm O(1) `mempool_sigs` và `confirmed_sigs` trong Ledger, DUT lọc sạch chính xác tuyệt đối **400 bản tin dư thừa** (4 peers dư × 100 txs = 400) cho tất cả các thuật toán, bảo vệ Mempool khỏi tấn công từ chối dịch vụ (DoS).

2. **Bóc tách Độ trễ Cam kết Khối (Block Commit Latency Breakdown):**
   * Panel 1 của Hình 4.3 phân tách độ trễ cam kết khối thành hai thành phần trực quan:
     - **Chân cột đặc (Verify CPU Time):** Thời gian CPU node DUT thẩm định chữ ký 100 giao dịch trong khối. Với ECDSA chỉ mất 2.62 - 3.15 ms. Nhưng với ML-DSA-87, thời gian này chiếm tới 303.34 ms trên Server và 388.90 ms trên IoT.
     - **Phần gạch chéo (Wire Transit & TLS Record Delay):** Thời gian truyền tải gói tin nhị phân qua mạng TLS 1.3. Khối 100 giao dịch của ECDSA chỉ nặng 54.67 KB (transit mất 3.58 - 5.55 ms), trong khi khối của ML-DSA-87 phình to lên tới **1,439.63 KB (1.44 MB)**, khiến thời gian truyền tải và giải mã TLS tăng lên 56.21 - 87.13 ms.
   * Kết quả là tổng thời gian cam kết khối của ML-DSA-87 trên thiết bị IoT lên tới **476.03 ms (gần nửa giây cho một khối 100 txs)**, cao gấp 54.7 lần so với ECDSA (8.70 ms).

3. **Băng thông Tiếp nhận Dưới Bão Gossip (Ingress Bandwidth):**
   * Do kích thước wire payload của ML-DSA-87 là 14,685 bytes/tx, băng thông mạng nạp vào DUT trong giai đoạn bão Gossip đạt đỉnh **13.49 MB/s** trên Server. Trên thiết bị IoT, băng thông bị ghìm lại ở mức 4.57 MB/s do hàng đợi socket TCP và năng lực giải mã khung TLS 1.3 bị bóp nghẽn bởi CPU 0.5 vCPU.

---

### 4.5.4. Khuyến nghị Kiến trúc Triển khai Blockchain Hậu lượng tử
Từ các bằng chứng thực nghiệm cụ thể và định lượng trong kịch bản PERF-01, nhóm nghiên cứu đề xuất mô hình kiến trúc phân tầng tối ưu cho mạng Blockchain kháng lượng tử:
1. **Tầng Thiết bị Nhúng Cực Đoan (Smart Meters, IoT Sensors, RAM < 128MB):** Bắt buộc sử dụng chuẩn **ML-DSA-44 (NIST PQC Cấp 2)**. Đây là biến thể duy nhất đảm bảo an toàn tuyệt đối trước nguy cơ Linux Kernel OOM-Killer, đồng thời duy trì thông lượng nạp ở mức chấp nhận được (~300 tx/s).
2. **Tầng Trạm Cổng & Nút Chuyển Tiếp Biên (Edge Gateways, Raspberry Pi 4, RAM 512MB - 1GB):** Có thể triển khai chuẩn **ML-DSA-65 (NIST PQC Cấp 3)** với điều kiện cấu hình tham số dung lượng Mempool tối đa không vượt quá 1.000 giao dịch để tránh chạm trần OOM khi mạng xảy ra tắc nghẽn.
3. **Tầng Máy chủ Trung tâm & Nút Khai thác Mỏ (Cloud Validators / Mining Nodes, RAM ≥ 4GB, vCPU ≥ 4.0):** Triển khai toàn diện chuẩn **ML-DSA-87 (NIST PQC Cấp 5)** để đạt mức độ bảo mật mật mã học cao nhất, vì tài nguyên máy chủ hoàn toàn miễn nhiễm trước áp lực bóp nghẽn CPU và nguy cơ tràn bộ nhớ.
