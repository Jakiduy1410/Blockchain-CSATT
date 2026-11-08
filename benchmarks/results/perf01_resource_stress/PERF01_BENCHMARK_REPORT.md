# BÁO CÁO THỰC NGHIỆM ĐỒ ÁN MÔN HỌC: CƠ SỞ AN TOÀN THÔNG TIN
## PHẦN 2: TƯƠNG THÍCH PHẦN CỨNG & MẠNG
### KỊCH BẢN PERF-01: ĐO LƯỜNG GIỚI HẠN TÀI NGUYÊN NODE TRÊN PHẦN CỨNG YẾU (RESOURCE CONSTRAINED STRESS TEST)

---

**Thông tin chuyên đề:**
* **Học phần:** Cơ sở An toàn Thông tin / Blockchain Engineering
* **Hạng mục báo cáo:** Kịch bản thực nghiệm PERF-01 (Thành viên 4 phụ trách - Hardware Benchmark & DevOps)
* **Đối tượng kiểm thử:** Thuật toán chữ ký số Hậu lượng tử NIST FIPS 204 (ML-DSA-44, ML-DSA-65, ML-DSA-87) so sánh đối chuẩn với ECDSA (secp256k1)
* **Môi trường triển khai:** Linux Debian 12 Container (Docker, cgroups v2, Open Quantum Safe `liboqs` C-engine)

---

## MỤC LỤC

1. [ĐẶT VẤN ĐỀ & MỤC TIÊU CỦA KỊCH BẢN PERF-01](#1-đặt-vấn-đề--mục-tiêu-của-kịch-bản-perf-01)
2. [CÀI ĐẶT & THIẾT LẬP MÔI TRƯỜNG THỰC NGHIỆM](#2-cài-đặt--thiết-lập-môi-trường-thực-nghiệm)
   * [2.1. Đóng gói Container & Biên dịch Thư viện liboqs C Engine](#21-đóng-gói-container--biên-dịch-thư-viện-liboqs-c-engine)
   * [2.2. Định nghĩa 3 Cấu hình Phần cứng Cô lập qua Linux cgroups v2](#22-định-nghĩa-3-cấu-hình-phần-cứng-cô-lập-qua-linux-cgroups-v2)
   * [2.3. Hệ thống Giám sát Telemetry cgroups v2 & Triệt tiêu Nhiễu Cold-Start](#23-hệ-thống-giám-sát-telemetry-cgroups-v2--triệt-tiêu-nhiễu-cold-start)
3. [THIẾT KẾ KỊCH BẢN THỰC NGHIỆM](#3-thiết-kế-kịch-bản-thực-nghiệm)
   * [3.1. Kịch bản Chuẩn bị Tải: Bộ Dữ liệu Giao dịch Chuẩn hóa](#31-kịch-bản-chuẩn-bị-tải-bộ-dữ-liệu-giao-dịch-chuẩn-hóa)
   * [3.2. Kịch bản 1: Kiểm thử Vi mô Ma trận 3x4 (Micro-Benchmark 500 Txs)](#32-kịch-bản-1-kiểm-thử-vi-mô-ma-trận-3x4-micro-benchmark-500-txs)
   * [3.3. Kịch bản 2: Kiểm thử Cực hạn & Săn OOM-Killer (Extreme Stress Test 60MB RAM)](#33-kịch-bản-2-kiểm-thử-cực-hạn--săn-oom-killer-extreme-stress-test-60mb-ram)
   * [3.4. Kịch bản 3: Kiểm thử Vĩ mô Mạng P2P Mesh 6 Nodes (Macro-Benchmark Single DUT)](#34-kịch-bản-3-kiểm-thử-vĩ-mô-mạng-p2p-mesh-6-nodes-macro-benchmark-single-dut)
4. [TIẾN HÀNH THỰC NGHIỆM, KẾT QUẢ TỪNG BƯỚC & BÌNH LUẬN CHUYÊN SÂU](#4-tiến-hành-thực-nghiệm-kết-quả-từng-bước--bình-luận-chuyên-sâu)
   * [Bước 1: Xây dựng Docker Image & Kiểm tra Tính hợp lệ của liboqs](#bước-1-xây-dựng-docker-image--kiểm-tra-tính-hợp-lệ-của-liboqs)
   * [Bước 2: Sinh Bộ Dữ liệu Tải và Phân tích Tải trọng Mạng (Wire Overhead)](#bước-2-sinh-bộ-dữ-liệu-tải-và-phân-tích-tải-trọng-mạng-wire-overhead)
   * [Bước 3: Thực thi Kịch bản Vi mô 3x4 & Bình luận Biểu đồ Rủi ro OOM (Hình 1)](#bước-3-thực-thi-kịch-bản-vi-mô-3x4--bình-luận-biểu-đồ-rủi-ro-oom-hình-1)
   * [Bước 4: Thực thi Kịch bản Cực hạn 60MB RAM & Bắt sống Sự kiện OOM-Killer (Hình 2)](#bước-4-thực-thi-kịch-bản-cực-hạn-60mb-ram--bắt-sống-sự-kiện-oom-killer-hình-2)
   * [Bước 5: Thực thi Kịch bản Vĩ mô Mạng 6-Node Mesh & Bình luận Dashboard (Hình 3)](#bước-5-thực-thi-kịch-bản-vĩ-mô-mạng-6-node-mesh--bình-luận-dashboard-hình-3)
5. [TỔNG KẾT & KHUYẾN NGHỊ KIẾN TRÚC CHO HỆ THỐNG BLOCKCHAIN HẬU LƯỢNG TỬ](#5-tổng-kết--khuyến-nghị-kiến-trúc-cho-hệ-thống-blockchain-hậu-lượng-tử)
6. [ĐÓNG GÓP CỦA PERF-01 TRONG TỔNG THỂ ĐỒ ÁN](#6-đóng-góp-của-perf-01-trong-tổng-thể-đồ-án)

---

## 1. ĐẶT VẤN ĐỀ & MỤC TIÊU CỦA KỊCH BẢN PERF-01

Trong bối cảnh điện toán lượng tử phát triển nhanh chóng, các thuật toán mật mã khóa công khai truyền thống như RSA và ECDSA (đang được Bitcoin và Ethereum sử dụng) đứng trước nguy cơ bị bẻ gãy hoàn toàn bởi thuật toán Shor. Nhằm đảm bảo an toàn dài hạn, Viện Tiêu chuẩn và Công nghệ Quốc gia Hoa Kỳ (NIST) đã chính thức chuẩn hóa bộ tiêu chuẩn mật mã hậu lượng tử (PQC - Post-Quantum Cryptography), tiêu biểu là thuật toán chữ ký số dựa trên mạng tinh thể **ML-DSA (Module-Lattice-Based Digital Signature Algorithm - FIPS 204)**.

Tuy nhiên, việc nâng cấp chữ ký số từ ECDSA lên ML-DSA kéo theo sự gia tăng đột biến về kích thước dữ liệu:
* Chữ ký ECDSA (secp256k1) chỉ có kích thước **64 bytes** (khóa công khai 33–65 bytes).
* Chữ ký ML-DSA dao động từ **2,420 bytes** (ML-DSA-44), **3,309 bytes** (ML-DSA-65) đến **4,627 bytes** (ML-DSA-87), tức phình to gấp **37 đến 72 lần** so với chữ ký truyền thống. Khi đóng gói dưới định dạng JSON và mã hóa chuỗi Hex trong giao thức Blockchain, mỗi giao dịch nạp vào sổ cái chiếm từ **7.7 KB đến 14.7 KB** (gấp 15–29 lần so với 499 bytes của ECDSA).

```
+-------------------------------------------------------------------------------+
|                             THÁCH THỨC VẬN HÀNH PQC                           |
+-------------------------------------------------------------------------------+
|  Kích thước Chữ ký Lớn      |  Áp lực Lưu trữ Mempool     |  Độ trễ P2P Mesh  |
|  ML-DSA nặng gấp 15 - 29x   |  Nguy cơ cạn kiệt RAM IoT   |  Tải trọng Khối   |
|  (Giao dịch JSON: 7.7-14KB) |  Kernel OOM-Killer Exit 137 |  Lên tới 1.44 MB  |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                       MỤC TIÊU THỰC NGHIỆM CỦA PERF-01                        |
|  1. Xác định ranh giới chịu tải CPU (Saturation) và trần RAM (Peak Ceiling).  |
|  2. Bắt sống hiện tượng tràn bộ nhớ (Out-Of-Memory) bằng Linux cgroups v2.    |
|  3. Khảo sát độ trễ đồng thuận P2P TLS 1.3 và bóc tách CPU vs Network I/O.   |
|  4. Đưa ra khuyến nghị cấu hình phần cứng tối ưu cho IoT, Edge và Server.    |
+-------------------------------------------------------------------------------+
```

**Mục tiêu cốt lõi của kịch bản PERF-01:**
1. **Lượng hóa sự suy hao tài nguyên phần cứng:** Đo lường chính xác mức độ chiếm dụng CPU, đỉnh RAM (Peak RAM), thông lượng tiếp nhận giao dịch (Ingestion TPS) trên 3 cấp độ phần cứng đại diện: **Server** (Cloud/Datacenter), **Edge** (Gateway/Raspberry Pi 4) và **IoT** (Thiết bị nhúng/Smart Meter).
2. **Khảo sát ngưỡng OOM thực nghiệm (Extreme OOM Hunt):** Tìm ra ranh giới ngưỡng sập nguồn (Out-Of-Memory Crash) khi node nhúng bị quá tải Mempool bởi các giao dịch PQC cồng kềnh, phân tích cơ chế nhân Linux gửi tín hiệu hủy diệt tiến trình `SIGKILL (Exit Code 137)`.
3. **Đo lường độ trễ đồng thuận trong mạng lưới Mesh P2P thực tế (Macro-Benchmark):** Khảo sát hành vi của một Node bị giới hạn tài nguyên (DUT - Device Under Test) khi hòa mạng cùng cụm 5 Node nền (Background Nodes) giao tiếp qua kênh WebSocket bảo mật TLS 1.3 / ECDHE; bóc tách chính xác tỷ trọng giữa thời gian tính toán của CPU và thời gian trễ của đường truyền mạng.

---

## 2. CÀI ĐẶT & THIẾT LẬP MÔI TRƯỜNG THỰC NGHIỆM

Nhằm đảm bảo tính khách quan khoa học, loại bỏ yếu tố khác biệt giữa các hệ điều hành của các thành viên trong nhóm và tuân thủ nguyên tắc nghiên cứu thực nghiệm (*Ceteris Paribus* - mọi điều kiện môi trường được giữ nguyên, chỉ thay đổi thuật toán và giới hạn tài nguyên), toàn bộ môi trường kiểm thử được đóng gói hoàn toàn trong Docker Container và điều phối bằng Linux cgroups v2.

### 2.1. Đóng gói Container & Biên dịch Thư viện liboqs C Engine

Node Blockchain chạy trên nền Python 3.11 Debian Linux Slim. Điểm mấu chốt trong thiết kế môi trường là việc tích hợp thư viện **Open Quantum Safe (`liboqs`)**:
* Thư viện `liboqs` được biên dịch trực tiếp từ mã nguồn C thông qua `CMake` và `Ninja`, kích hoạt tối ưu hóa phần cứng x86_64 (`AVX2/SIMD`).
* Ứng dụng Python giao tiếp với `liboqs` qua wrapper C-extension `liboqs-python`. Khi thực hiện thẩm định chữ ký số PQC, Python **giải phóng khóa thông dịch toàn cục GIL (Global Interpreter Lock)**, cho phép các luồng worker HTTP xử lý song song thực sự trên đa nhân CPU.
* Ngược lại, thuật toán chuẩn đối chứng `ECDSA (secp256k1)` sử dụng thư viện `python-ecdsa`. Đây là thư viện thuần Python (Pure-Python), các vòng lặp toán học đường cong Elliptic bị thông dịch từng dòng bytecode và giữ chặt GIL.

**Trích dẫn Dockerfile tối ưu hóa môi trường (`perf/Dockerfile`):**
```dockerfile
FROM python:3.11-slim
WORKDIR /app

# 1. Cài đặt các công cụ biên dịch thiết yếu
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git cmake ninja-build libssl-dev curl procps \
    && rm -rf /var/lib/apt/lists/*

# 2. Biên dịch thư viện Hậu lượng tử C-engine liboqs (Open Quantum Safe)
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
       -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=ON \
    && cmake --build /tmp/liboqs/build \
    && cmake --install /tmp/liboqs/build \
    && ldconfig && rm -rf /tmp/liboqs

# 3. Cài đặt Python requirements & liboqs-python
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir liboqs-python

COPY . /app/
EXPOSE 5000 6000
CMD ["python", "blockchain/blockchain.py", "--host", "0.0.0.0", "-p", "5000"]
```

### 2.2. Định nghĩa 3 Cấu hình Phần cứng Cô lập qua Linux cgroups v2

Môi trường kiểm thử được chuẩn hóa thành 3 hồ sơ phần cứng (Profiles) thông qua file cấu hình `perf/docker-compose.yml`. Để đo lường chính xác nguy cơ tràn RAM vật lý, thiết lập quan trọng nhất là **vô hiệu hóa triệt để bộ nhớ ảo Swap** (`--memory-swap` bằng đúng `--memory`), buộc tiến trình phải đối mặt trực diện với bộ cấp phát bộ nhớ của nhân Linux:

* **Profile 1 – Server (Cloud / Datacenter Node):**
  * Hạn mức CPU: `4.0 vCPU` (tối đa 400% năng lực xử lý).
  * Hạn mức RAM: `4,096 MB` (4 GB), Swap: `4,096 MB` (Swap khả dụng = 0 MB).
  * Đại diện cho các Node đào (Miner), Full Node trên hạ tầng đám mây.
* **Profile 2 – Edge Gateway (Raspberry Pi 4 / Industrial PC):**
  * Hạn mức CPU: `1.0 vCPU` (tối đa 100% năng lực 1 nhân).
  * Hạn mức RAM: `512 MB`, Swap: `512 MB` (Swap khả dụng = 0 MB).
  * Đại diện cho các cổng biên công nghiệp, trạm trung chuyển dữ liệu cục bộ.
* **Profile 3 – IoT Embedded (Smart Meter / Sensor Node):**
  * Hạn mức CPU: `0.5 vCPU` (nhân Linux cấp hạn ngạch 50,000 $\mu s$ trong chu kỳ 100,000 $\mu s$).
  * Hạn mức RAM: `128 MB`, Swap: `128 MB` (Swap khả dụng = 0 MB).
  * Đại diện cho các vi điều khiển cao cấp, công tơ điện thông minh, cảm biến lưới điện.

```yaml
# Trích đoạn cấu hình giới hạn tài nguyên cgroups v2 (perf/docker-compose.yml)
deploy:
  resources:
    limits:
      cpus: '0.50'
      memory: 128M
mem_limit: 128M
memswap_limit: 128M   # Khóa cứng Swap = 0 để bắt sống OOM-Killer
```

### 2.3. Hệ thống Giám sát Telemetry cgroups v2 & Triệt tiêu Nhiễu Cold-Start

Trong các bài kiểm thử hiệu năng, việc sử dụng lệnh `docker stats` bên ngoài thường dẫn đến sai số nghiêm trọng do chu kỳ lấy mẫu chậm (1 giây/lần) và độ trễ phân tích JSON của Docker Daemon. Trong đồ án này, nhóm đã xây dựng module giám sát thời gian thực `CgroupTelemetryMonitor` đọc trực tiếp từ hệ thống tệp ảo của nhân Linux (**cgroups v2 interface**) với chu kỳ **80ms/mẫu**:

1. **Bộ nhớ RAM tức thời & Đỉnh phần cứng:** Đọc trực tiếp `/sys/fs/cgroup/memory.current` và `/sys/fs/cgroup/memory.peak` (thanh ghi phần cứng của kernel lưu đỉnh RAM thực tế, không bị bỏ sót giữa các chu kỳ trích mẫu).
2. **Thời gian tiêu thụ CPU:** Đọc trường `usage_usec` trong `/sys/fs/cgroup/cpu.stat`.
3. **Hiện tượng bóp xung nhịp do vượt Quota (CFS Throttling):** Đọc trường `throttled_usec` và `nr_throttled` trong `/sys/fs/cgroup/cpu.stat`.
4. **Sự kiện hủy diệt bộ nhớ:** Đọc trường `oom_kill` trong `/sys/fs/cgroup/memory.events`.

**Kỹ thuật xử lý triệt để nhiễu Cold-Start Page Cache:**
Khi khởi chạy container mới lần đầu, nhân Linux phải nạp toàn bộ file binary Python, glibc và thư viện động `liboqs.so` từ đĩa lưu trữ OverlayFS vào bộ đệm tệp (Page Cache). Điều này khiến RAM cgroup đo được bị đội ảo lên tới ~126 MB ngay từ lúc mới bật máy. Để khắc phục, kịch bản tự động kích hoạt một **Warm-up Container** chạy trước trong 2.5 giây nhằm nạp nóng Page Cache trên máy chủ Host. Nhờ đó, các lần đo chính thức phản ánh chính xác 100% bộ nhớ ẩn danh thực của tiến trình (**43.0 MB Baseline RAM**).

---

## 3. THIẾT KẾ KỊCH BẢN THỰC NGHIỆM

Quy trình đánh giá hiệu năng PERF-01 được cấu trúc thành **3 kịch bản liên hoàn**:

```
+-----------------------------------------------------------------------------------+
|                        QUY TRÌNH THỰC NGHIỆM PERF-01                              |
+-----------------------------------------------------------------------------------+
|  [Chuẩn bị]   Sinh bộ tải chuẩn hóa (generate_perf01_txs.py)                      |
|               - Tập 500 txs (chuẩn) & 2,000 txs (cực hạn) cho 4 thuật toán        |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  [Kịch bản 1] Micro-Benchmark Ma trận 3x4 (perf01_stress_test.py)                 |
|               - 3 Profile phần cứng (Server, Edge, IoT)                           |
|               - 4 Thuật toán (ECDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87)             |
|               - Bơm đồng thời 500 txs qua HTTP REST API (8 Worker Threads)        |
|               => Xuất: perf01_matrix.csv & perf01_oom_risk_chart.png               |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  [Kịch bản 2] Extreme Stress Test & OOM Hunt (perf01_stress_test.py)              |
|               - Ép trần cực hạn 60MB RAM trên chip 0.5 vCPU                       |
|               - Nạp liên tục 1,500 txs vào Mempool (từng đợt 50 txs)              |
|               - Săn lùng sự kiện Linux Kernel OOM-Killer (Exit Code 137)           |
|               => Xuất: perf01_extreme_oom_matrix.csv & perf01_extreme_oom_chart.png|
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  [Kịch bản 3] Macro-Benchmark Live P2P Mesh 6 Nodes (perf01_macro_stress.py)       |
|               - 1 DUT (Server / Edge / IoT) + 5 Background Nodes (Full Mesh)      |
|               - Giao tiếp Persistent WebSocket bọc TLS 1.3 / ECDHE                |
|               - Bơm bão Gossip 100 txs (sinh 600-1000 bản tin P2P) & Đào khối    |
|               - Bóc tách thời gian: Verify CPU vs Wire Transit vs Commit Delay    |
|               => Xuất: perf01_macro_matrix.csv & perf01_macro_chart.png           |
+-----------------------------------------------------------------------------------+
```

### 3.1. Kịch bản Chuẩn bị Tải: Bộ Dữ liệu Giao dịch Chuẩn hóa
Sử dụng script `perf/generate_perf01_txs.py` sinh trước toàn bộ các cặp khóa, ký số và đóng gói payload JSON chuẩn xác cho:
1. `txs_500_*.json`: Dùng cho bài đo vi mô 3x4 và kiểm tra tính hợp lệ của Mempool.
2. `txs_stress_*.json`: Tập 2,000 giao dịch độc lập dùng cho bài kiểm thử OOM cực hạn.
Việc sinh trước dữ liệu tải giúp loại bỏ hoàn toàn chi phí tạo chữ ký (Sign latency) của máy kiểm thử, đảm bảo node được đo thuần túy về **khả năng tiếp nhận, phân tích cú pháp JSON, thẩm định chữ ký và lưu trữ Mempool**.

### 3.2. Kịch bản 1: Kiểm thử Vi mô Ma trận 3x4 (Micro-Benchmark 500 Txs)
* **Số lượng phép thử:** 12 ca kiểm thử ($3 \text{ Profiles} \times 4 \text{ Thuật toán}$).
* **Phương thức nạp tải:** 8 luồng HTTP song song (`ThreadPoolExecutor`) gửi đồng loạt 500 yêu cầu `POST /transactions/new` vào Node đang được cô lập cgroups.
* **Chỉ số ghi nhận:** Thời gian nạp (Elapsed time), Thông lượng nạp (Ingestion TPS), RAM đỉnh (Peak RAM), Tỷ lệ chiếm dụng trần RAM (RAM Ceiling Usage %), CPU trung bình (Avg CPU %), CPU chuẩn hóa (Normalized CPU %) và Thời gian bóp xung nhịp (CPU Throttled ms).

### 3.3. Kịch bản 2: Kiểm thử Cực hạn & Săn OOM-Killer (Extreme Stress Test 60MB RAM)
* **Thiết lập:** Cấu hình container với mức RAM chạm đáy **60 MB** (`--memory=60m --memory-swap=60m`) và `0.5 vCPU`.
* **Mục tiêu:** Kiểm tra khả năng chịu đựng của hàng đợi Mempool khi bị tấn công bơm tải giao dịch (Transaction Flooding). Với RAM nền tĩnh của Python + Flask chiếm ~43 MB, khoảng đệm an toàn khả dụng (Memory Headroom) chỉ còn vỏn vẹn **17 MB**.
* **Tiến trình:** Bơm tuần tự từng lô 50 giao dịch cho đến khi đủ 1,500 giao dịch hoặc cho đến khi tiến trình bị hủy diệt hoàn toàn. Giám sát trạng thái cgroup sau mỗi lô để bắt thời điểm kích hoạt `oom_kill`.

### 3.4. Kịch bản 3: Kiểm thử Vĩ mô Mạng P2P Mesh 6 Nodes (Macro-Benchmark Single DUT)
* **Kiến trúc mạng:** Dựng cụm 6 container kết nối mạng Mesh qua WebSocket TLS 1.3 / ECDHE:
  * 5 Background Nodes (Node 1 là Miner, Node 2–5 là Relay/Validator) chạy không giới hạn tài nguyên.
  * 1 Device Under Test (DUT) chạy cổng 5000, tuần tự thay đổi giữa 3 profile: Server, Edge và IoT.
* **Tải thực nghiệm:**
  * Bão Gossip: Phát tán 100 giao dịch đồng thời từ các peer vào mạng mesh, DUT phải xử lý từ 600 đến 1,000 khung tin WebSocket dội về từ 5 kết nối đồng thời.
  * Đóng gói khối: Miner (Node 1) đào một khối chứa 100 giao dịch và phát sóng khối mới về DUT.
* **Chỉ số đo lường (8 Chỉ số Vàng):** Kích thước khối (Block Wire Size), Thời gian CPU thẩm định khối (Block Verify CPU ms), Thời gian truyền khối qua mạng (Block Transit Delay TLS ms), Tổng độ trễ cam kết (Commit Latency ms), Thông lượng nạp Mempool (Gossip Ingest TPS), Băng thông vào và số gói tin trùng lặp bị chặn (Ingress BW & Dups Filtered), Thời gian bóp nghẽn CPU (CFS Throttled ms) và Đỉnh RAM chiếm dụng trên IoT (Peak RAM & Util %).

---

## 4. TIẾN HÀNH THỰC NGHIỆM, KẾT QUẢ TỪNG BƯỚC & BÌNH LUẬN CHUYÊN SÂU

### Bước 1: Xây dựng Docker Image & Kiểm tra Tính hợp lệ của liboqs

#### 1. Thao tác dòng lệnh:
Từ thư mục gốc dự án, thực hiện biên dịch Docker Image:
```powershell
docker build -t blockchain-node:perf -f perf/Dockerfile .
```

#### 2. Kết quả Log Terminal ghi nhận:
```text
[+] Building 48.2s (14/14) FINISHED
 => [internal] load build definition from Dockerfile
 => => transferring dockerfile: 1.16kB done
 => [2/4] RUN apt-get update && apt-get install -y --no-install-recommends build-essential git cmake ninja-build ...
 => [3/4] RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs /tmp/liboqs ...
 => => cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja -DOQS_DIST_BUILD=ON
 => => ninja install & ldconfig
 => [4/4] RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir liboqs-python
 => exporting to image
 => => naming to docker.io/library/blockchain-node:perf done
```

Kiểm tra sự hiện diện của các thuật toán chữ ký NIST FIPS 204 bên trong container:
```powershell
docker run --rm blockchain-node:perf python -c "import oqs; print('Supported Sigs:', [s for s in oqs.get_enabled_sig_mechanisms() if 'Dilithium' in s or 'ML-DSA' in s])"
```
```text
Supported Sigs: ['Dilithium2', 'Dilithium3', 'Dilithium5', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']
```

#### 3. Nhận xét & Bình luận chuyên sâu:
* Quá trình biên dịch mã nguồn C của `liboqs` với cờ `-DOQS_DIST_BUILD=ON` và `-GNinja` diễn ra hoàn hảo.
* Việc nhận diện chính xác các cơ chế chữ ký `ML-DSA-44`, `ML-DSA-65` và `ML-DSA-87` (phiên bản chuẩn hóa chính thức của NIST FIPS 204) khẳng định hệ thống đã sẵn sàng cho các phép đo mật mã hậu lượng tử với hiệu năng C bản địa cao nhất.

---

### Bước 2: Sinh Bộ Dữ liệu Tải và Phân tích Tải trọng Mạng (Wire Overhead)

#### 1. Thao tác dòng lệnh:
Khởi chạy bộ sinh dữ liệu giao dịch bên trong môi trường Docker:
```powershell
docker run --rm -v "${PWD}:/app" blockchain-node:perf python perf/generate_perf01_txs.py
```

#### 2. Kết quả Log Terminal & Bảng Kích thước Tải trọng:
```text
======================================================================
  PERF-01: Bo Sinh Du Lieu Giao Dich Chuan Hoa (ECDSA vs PQC ML-DSA)
======================================================================
[*] Dang sinh 500 txs cho: ECDSA (secp256k1)...
    - Khoa Cong khai (Hex): 130 bytes
    - Chu ky (Hex): 142 bytes
    - Kich thuoc 1 giao dich JSON: 499 bytes
    -> Da ghi 500 txs vao data/txs_500_ecdsa.json (0.25 MB)

[*] Dang sinh 500 txs cho: ML-DSA-44 (NIST PQC Level 2)...
    - Khoa Cong khai (Hex): 2624 bytes
    - Chu ky (Hex): 4840 bytes
    - Kich thuoc 1 giao dich JSON: 7711 bytes
    -> Da ghi 500 txs vao data/txs_500_mldsa44.json (3.69 MB)

[*] Dang sinh 500 txs cho: ML-DSA-65 (NIST PQC Level 3)...
    - Khoa Cong khai (Hex): 3904 bytes
    - Chu ky (Hex): 6618 bytes
    - Kich thuoc 1 giao dich JSON: 10769 bytes
    -> Da ghi 500 txs vao data/txs_500_mldsa65.json (5.15 MB)

[*] Dang sinh 500 txs cho: ML-DSA-87 (NIST PQC Level 5)...
    - Khoa Cong khai (Hex): 5184 bytes
    - Chu ky (Hex): 9254 bytes
    - Kich thuoc 1 giao dich JSON: 14685 bytes
    -> Da ghi 500 txs vao data/txs_500_mldsa87.json (7.02 MB)
```

**Bảng 1: Phân tích Kích thước Tải trọng Mạng Giữa Mật mã Cổ điển & Hậu Lượng tử**

| Thuật Toán Chữ Ký | Cấp Độ An Toàn (NIST Level) | Public Key (Hex) | Chữ Ký (Hex) | Kích Thước 1 Txn (Wire Bytes) | Hệ Số Phình To (vs ECDSA) | Kích Thước Khối 100 Txns |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **ECDSA (secp256k1)** | Cổ điển (Không an toàn) | 130 B | 142 B | **499 Bytes** | **1.0x (Chuẩn)** | **54.7 KB** |
| **ML-DSA-44** | Cấp độ 2 (Tương đương SHA3-256) | 2,624 B | 4,840 B | **7,711 Bytes** | **15.5x** | **758.6 KB** |
| **ML-DSA-65** | Cấp độ 3 (Tương đương AES-192) | 3,904 B | 6,618 B | **10,769 Bytes** | **21.6x** | **1,057.2 KB** |
| **ML-DSA-87** | Cấp độ 5 (Tương đương AES-256) | 5,184 B | 9,254 B | **14,685 Bytes** | **29.4x** | **1,439.6 KB** |

#### 3. Nhận xét & Bình luận chuyên sâu:
* **Nguyên nhân toán học của sự gia tăng kích thước:** Chữ ký ML-DSA dựa trên bài toán Module Learning With Errors (M-LWE). Khóa công khai chứa ma trận các đa thức vành số nguyên $R_q$, còn chữ ký bao gồm vector các đa thức $z$ có hệ số bị chặn cùng với gợi ý khử nhiễu (hint vector $h$). Điều này khiến chữ ký nhị phân gốc đã chiếm tới 2.4 – 4.6 KB.
* **Phụ phí định dạng JSON + Hex (Double Overhead):** Trong kiến trúc hiện tại, các mảng byte nhị phân được mã hóa sang chuỗi ký tự thập lục phân (Hexadecimal string), làm tăng gấp đôi kích thước (mỗi byte dữ liệu cần 2 byte ký tự ASCII). Cộng thêm tiêu đề JSON (`sender_address`, `recipient_address`, `amount`, `nonce`), một giao dịch ML-DSA-87 phình to lên tới **14.69 KB**. Một khối gồm 100 giao dịch ML-DSA-87 sẽ chiếm **1.44 MB**, vượt qua trần MTU thông thường và tạo áp lực cực lớn lên tầng I/O mạng.

---

### Bước 3: Thực thi Kịch bản Vi mô 3x4 & Bình luận Biểu đồ Rủi ro OOM (Hình 1)

#### 1. Thao tác dòng lệnh:
Khởi chạy bộ kiểm thử vi mô tự động:
```powershell
python perf/perf01_stress_test.py
```

#### 2. Kết quả Log Terminal trích đoạn tiêu biểu:
```text
===========================================================================
  PROFILE: IoT Embedded (Smart Meter / Sensor)
  THUAT TOAN: ML-DSA-87 (NIST PQC Level 5)
  GIOI HAN: CPU=0.5 vCPU, RAM Limit=128m (Memswap=128m)
===========================================================================
[*] Dang khoi tao Node va kiem tra trang thai Healthcheck...
[*] Baseline Memory: 43.12 MB / 128 MB
[*] Bat dau ban dong thoi 500 giao dich vao mempool qua HTTP POST...
[*] Hoan tat 500 giao dich trong 2.405 giay.
    - Thanh cong: 500 / 500 | That bai: 0
    - Ingestion TPS: 207.90 tx/s
    - Peak RAM: 55.59 MB (43.43% tran cung 128MB)
    - Normalized CPU: 100.00% (Avg CPU: 57.12% / 0.5 vCPU)
    - CPU Throttled: 5,798.36 ms (Tiến trình bị ngắt nhịp do vượt Quota)
    - Trang thai OOM: AN TOAN (<60% tran)
```

**Bảng 2: Ma Trận Đầy Đủ Kết Quả Thực Nghiệm Vi Mô 3x4 (Trích xuất từ `perf01_matrix.csv`)**

| Cấu Hình Phần Cứng | Thuật Toán Chữ Ký | Thời Gian Xử Lý (s) | Ingestion TPS (tx/s) | Peak RAM (MB) | RAM Chiếm Dụng (%) | Avg CPU (%) | Normalized CPU (%) | CPU Throttled (ms) | Trạng Thái Rủi Ro OOM |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Server**<br>(4.0 vCPU, 4GB RAM) | **ECDSA (secp256k1)** | 1.160 s | 431.03 | 47.13 MB | 1.15% | 133.47% | 33.37% | 0.0 ms | AN TOÀN (<60%) |
| | **ML-DSA-44 (L2)** | 0.725 s | **689.66** | 51.94 MB | 1.27% | 150.93% | 37.73% | 0.0 ms | AN TOÀN (<60%) |
| | **ML-DSA-65 (L3)** | 0.763 s | **655.31** | 53.98 MB | 1.32% | 153.70% | 38.42% | 0.0 ms | AN TOÀN (<60%) |
| | **ML-DSA-87 (L5)** | 0.810 s | **617.28** | 54.89 MB | 1.34% | 152.35% | 38.09% | 0.0 ms | AN TOÀN (<60%) |
| **Edge**<br>(1.0 vCPU, 512MB RAM) | **ECDSA (secp256k1)** | 1.676 s | 298.33 | 48.82 MB | 9.54% | 99.19% | 99.19% | 680.86 ms | AN TOÀN (<60%) |
| | **ML-DSA-44 (L2)** | 1.010 s | **495.05** | 51.76 MB | 10.11% | 118.22% | 100.00% | 780.79 ms | AN TOÀN (<60%) |
| | **ML-DSA-65 (L3)** | 1.022 s | **489.24** | 53.30 MB | 10.41% | 114.54% | 100.00% | 855.14 ms | AN TOÀN (<60%) |
| | **ML-DSA-87 (L5)** | 1.141 s | **438.21** | 54.98 MB | 10.74% | 114.77% | 100.00% | 818.97 ms | AN TOÀN (<60%) |
| **IoT**<br>(0.5 vCPU, 128MB RAM) | **ECDSA (secp256k1)** | 3.365 s | 148.59 | 49.07 MB | 38.34% | 55.28% | 100.00% | 5,412.53 ms | AN TOÀN (<60%) |
| | **ML-DSA-44 (L2)** | 2.216 s | **225.63** | 54.60 MB | 42.66% | 57.77% | 100.00% | 4,931.10 ms | AN TOÀN (<60%) |
| | **ML-DSA-65 (L3)** | 2.320 s | **215.52** | 53.03 MB | 41.43% | 57.54% | 100.00% | 5,410.28 ms | AN TOÀN (<60%) |
| | **ML-DSA-87 (L5)** | 2.405 s | **207.90** | 55.59 MB | 43.43% | 57.12% | 100.00% | 5,798.36 ms | AN TOÀN (<60%) |

#### 3. Chụp kết quả trực quan (Hình 1):

![Biểu đồ Đánh giá Giới hạn Tài nguyên Node & Cảnh báo Ngưỡng OOM](results/perf01_oom_risk_chart.png)  
*Hình 1: Đánh giá Ranh giới Tài nguyên Node (Peak RAM, Ingestion TPS và Thời gian bóp nghẽn CPU CFS) khi tiếp nhận 500 giao dịch trên 3 Profile phần cứng.*

#### 4. Bình luận & Phân tích Học thuật Chi Tiết Cho Từng Biểu Đồ Con:

##### 4.1. Bình luận Đồ thị 1 (Góc trái - Đỉnh Trần Bộ Nhớ Peak RAM & Vùng OOM):
* **Hiện trạng an toàn ở quy mô 500 giao dịch:** Biểu đồ trực quan hóa mức chiếm dụng RAM so với ngưỡng an toàn bộ nhớ thiết bị nhúng: Đường nét đứt màu đỏ (IoT Ceiling: 128 MB). Ở tải nạp 500 giao dịch, cả 12 kịch bản đều nằm an toàn dưới ngưỡng cảnh báo 60% trần (76.8 MB).
* **Mức độ chiếm dụng thực tế:** Bộ nhớ RAM nền của Flask và các cấu trúc dữ liệu cơ bản chiếm khoảng ~43 MB. Sau khi nạp 500 giao dịch vào hàng đợi Mempool, mức RAM đỉnh của ECDSA đạt từ **47.13 MB đến 49.07 MB**, trong khi ML-DSA-87 đạt **54.89 MB đến 55.59 MB**. 
* **Tỷ trọng trần cứng:** Trên Server, mức này chỉ chiếm **1.34%** tổng dung lượng RAM 4GB; trên Edge chiếm **10.74%** của 512MB; nhưng trên thiết bị IoT, nó đã chiếm tới **43.43%** trần cứng 128MB. Điều này chỉ ra rằng 500 giao dịch chưa làm sập node nhúng, nhưng đã tiêu hao gần một nửa tổng tài nguyên bộ nhớ khả dụng.

##### 4.2. Bình luận Đồ thị 2 (Góc giữa - Nghịch Lý Thông Lượng Ingestion TPS):
* **Phát hiện nghịch lý thực nghiệm:** Mặc dù giao dịch ML-DSA có kích thước lớn gấp **15 đến 29 lần** so với ECDSA (ML-DSA-44 nặng 7.71 KB vs ECDSA 0.49 KB), thông lượng tiếp nhận (Ingestion TPS) của cả 3 biến thể ML-DSA lại **nhanh hơn đáng kể so với ECDSA trên tất cả các profile phần cứng**:
  * Trên Server: ML-DSA-44 đạt **689.66 tx/s**, nhanh hơn **1.60 lần** so với ECDSA (**431.03 tx/s**).
  * Trên Edge: ML-DSA-44 đạt **495.05 tx/s**, nhanh hơn **1.66 lần** so với ECDSA (**298.33 tx/s**).
  * Trên IoT: ML-DSA-44 đạt **225.63 tx/s**, nhanh hơn **1.52 lần** so với ECDSA (**148.59 tx/s**).
* **Bản chất khoa học giải thích nghịch lý (2 yếu tố cộng hưởng):**
  1. *Độ phức tạp thuật toán mật mã (NTT vs Phép nhân điểm Elliptic):* Quá trình xác thực chữ ký ECDSA yêu cầu thực hiện 2 phép nhân điểm vô hướng trên đường cong elliptic $s^{-1}(H(m)G + rQ)$ trên trường nguyên tố lớn 256-bit. Trong khi đó, việc thẩm định chữ ký ML-DSA bản chất là phép nhân ma trận đa thức trên vành số nguyên $R_q$. Nhờ thuật toán biến đổi số học **NTT (Number Theoretic Transform)**, độ phức tạp tính toán được tối ưu xuống $\mathcal{O}(n \log n)$ với toàn các phép toán số nguyên cơ bản, tốn ít chu kỳ ALU hơn nhiều so với phép nhân đường cong.
  2. *Kiến trúc thực thi C-Engine vs Pure-Python & Khóa GIL:* `liboqs` là thư viện C biên dịch bản địa, kích hoạt vector hóa AVX2 và **giải phóng Python GIL**. Khi 8 luồng HTTP nạp đồng thời, cả 4 nhân CPU của Server đều tham gia tính toán song song thực sự. Ngược lại, `python-ecdsa` là thư viện thuần Python, bị trói chặt bởi khóa GIL, khiến các luồng HTTP worker phải xếp hàng tuần tự để tranh giành CPU, biến CPU thành cổ chai nghiêm trọng. Phụ phí bóc tách JSON (+0.1ms) của PQC hoàn toàn bị khỏa lấp bởi tốc độ xác thực vượt trội của C-engine.

##### 4.3. Bình luận Đồ thị 3 (Góc phải - Áp Lực Quá Tải CPU & Thời Gian Bóp Nghẽn CFS Throttled):
* **Ý nghĩa học thuật của chỉ số Thời gian Bóp nghẽn CPU (`throttled_ms`):** Thay vì sử dụng phần trăm CPU tức thời dễ gây hiểu lầm giữa các cấu hình đa nhân và đơn nhân, thời gian bị bóp xung nhịp bởi bộ lập lịch Completely Fair Scheduler (CFS) của nhân Linux phản ánh chính xác 100% thời gian thực tế mà tiến trình bị "đóng băng" do tiêu thụ hết hạn ngạch cấp phát.
* **Sự phân hóa rõ rệt về áp lực quá tải giữa các cấu hình:**
  * **Server (4.0 vCPU):** Đạt mức **0.0 ms throttled** tuyệt đối trên cả 4 thuật toán. Năng lực 4 nhân giúp hệ thống hấp thụ hoàn toàn tải mà không một lần bị kernel ngắt nhịp.
  * **Edge (1.0 vCPU):** Tiến trình bắt đầu bị bóp từ **680.86 ms** (ECDSA) lên **780.79 – 855.14 ms** (ML-DSA).
  * **IoT (0.5 vCPU):** Áp lực bộc lộ gay gắt nhất. Nhân Linux đã bóp nghẹt xung nhịp tiến trình tới **4,931.10 ms đến 5,798.36 ms** (trong đó ML-DSA-87 bị bóp nặng nhất với 5.8 giây). Tiến trình bị treo chờ hạn ngạch CPU lâu hơn gấp đôi thời gian thực thi thực tế (2.4 giây), minh chứng rõ rệt cho sự quá tải của chip nhúng khi phải phân tích cú pháp và thẩm định giao dịch dồn dập.

---

### Bước 4: Thực thi Kịch bản Cực hạn 60MB RAM & Bắt sống Sự kiện OOM-Killer (Hình 2)

#### 1. Thao tác dòng lệnh:
Khởi chạy bài kiểm thử cực hạn săn lùng ngưỡng OOM trên chip IoT ép trần 60MB RAM:
```powershell
python perf/perf01_stress_test.py
# (Kịch bản tự động chuyển sang Part 2: Extreme OOM Hunt sau khi hoàn thành ma trận 3x4)
```

#### 2. Kết quả Log Terminal Ghi Nhận Sự Kiện Hủy Diệt Của Nhân Linux:
```text
===========================================================================
  PART 2: EXTREME OOM HUNT - TESTING MEMORY EXHAUSTION ON 60MB RAM NODE
  Hạn mức cgroups: memory.max = 60M, memory.swap.max = 0 (Swap = 0)
===========================================================================
[*] Dang ban giao dich theo tung batch 50 txs vao Node...
[Tx #500]  MLDSA87: 55.09 MB | MLDSA65: 53.00 MB | MLDSA44: 51.32 MB | ECDSA: 44.77 MB
[Tx #850]  MLDSA87: 59.50 MB | MLDSA65: 54.82 MB | MLDSA44: 51.68 MB | ECDSA: 45.62 MB
[Tx #900]  MLDSA87: 60.00 MB --> [!] CRITICAL: OOM-KILLER ACTIVATED!
           Container btc-extreme-hunt bi tieu diet boi Linux Kernel OOM!
           Exit Code: 137 (SIGKILL) | oom_kill counter: 1

[Tx #1250] MLDSA65: 60.00 MB | MLDSA44: 59.84 MB | ECDSA: 46.82 MB
[Tx #1300] MLDSA65: 60.00 MB --> [!] CRITICAL: OOM-KILLER ACTIVATED!
           Container btc-extreme-hunt bi tieu diet boi Linux Kernel OOM!
           Exit Code: 137 (SIGKILL) | oom_kill counter: 1

[Tx #1500] MLDSA44: 59.48 MB (SONG SOT AN TOAN!) | ECDSA: 46.77 MB (BINH AN)
```

**Bảng 3: Dữ Liệu Quỹ Đạo Bộ Nhớ RAM Thực Tế & Thời Điểm OOM-Killed (Trích từ `perf01_extreme_oom_matrix.csv`)**

| Mốc Giao Dịch Nạp | RAM ML-DSA-87 (MB) | RAM ML-DSA-65 (MB) | RAM ML-DSA-44 (MB) | RAM ECDSA (MB) | Ngưỡng Trần Cứng (MB) | Trạng Thái OOM ML-DSA-87 | Trạng Thái OOM ML-DSA-65 |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Tx #100** | 48.39 MB | 43.20 MB | 46.34 MB | 43.76 MB | 60.0 MB | Bình thường | Bình thường |
| **Tx #300** | 48.58 MB | 50.77 MB | 49.23 MB | 43.94 MB | 60.0 MB | Bình thường | Bình thường |
| **Tx #500** | 55.09 MB | 53.00 MB | 51.32 MB | 44.77 MB | 60.0 MB | Bình thường | Bình thường |
| **Tx #700** | 58.84 MB | 55.90 MB | 50.30 MB | 45.19 MB | 60.0 MB | Bình thường | Bình thường |
| **Tx #850** | 59.50 MB | 54.82 MB | 51.68 MB | 45.62 MB | 60.0 MB | Cận ngưỡng | Bình thường |
| **Tx #900** | **60.00 MB** | 59.12 MB | 56.06 MB | 45.17 MB | 60.0 MB | **OOM-KILLED (Exit 137)** | Bình thường |
| **Tx #1100** | *Đã chết* | 58.55 MB | 59.21 MB | 45.93 MB | 60.0 MB | - | Cận ngưỡng |
| **Tx #1250** | *Đã chết* | 60.00 MB | 59.84 MB | 46.82 MB | 60.0 MB | - | Chạm trần |
| **Tx #1300** | *Đã chết* | **60.00 MB** | 59.11 MB | 46.39 MB | 60.0 MB | - | **OOM-KILLED (Exit 137)** |
| **Tx #1500** | *Đã chết* | *Đã chết* | **59.48 MB** | **46.77 MB** | 60.0 MB | - | - |
| **Kết quả chung cuộc** | **Chết tại Tx #900** | **Chết tại Tx #1300** | **SỐNG SÓT 100%** | **SỐNG SÓT 100%** | - | **Thất bại hoàn toàn** | **Thất bại ở tải cao** |

#### 3. Chụp kết quả trực quan (Hình 2):

![Biểu đồ Bài Test Tải Cực Hạn & Sự Kiện Tràn Bộ Nhớ Linux OOM](results/perf01_extreme_oom_chart.png)  
*Hình 2: Quỹ đạo chiếm dụng bộ nhớ RAM và Bắt sống Sự kiện Kích hoạt Kernel OOM-Killer (Exit Code 137) trên Node IoT 60MB RAM.*

#### 4. Bình luận & Phân tích Học thuật Chi Tiết Cho Hình 2:

* **Bóc tách khoảng đệm bộ nhớ khả dụng (Memory Headroom):**
  * Tiến trình Python 3.11 cùng framework Flask và thư viện mật mã nạp vào bộ nhớ đã chiếm sẵn khoảng **43.0 MB** RAM nền tĩnh (Baseline).
  * Với trần cứng cgroups đặt tại **60.0 MB** và không có bộ nhớ ảo Swap, khoảng đệm thực tế còn lại cho Mempool là:
    $$\Delta_{\text{Headroom}} = 60.0\text{ MB} - 43.0\text{ MB} = 17.0\text{ MB}$$
* **Phân tích cơ chế suy sụp của ML-DSA-87 (Đường màu đỏ):**
  * Mỗi giao dịch ML-DSA-87 khi nằm trong RAM dưới dạng đối tượng Python `Transaction` chiếm tới khoảng **16.5 KB in-memory footprint**.
  * Đường cong màu đỏ tăng vọt dốc đứng. Đến mốc **Tx #900**, tổng dung lượng Mempool vượt quá 17.0 MB headroom, RAM chạm đúng đỉnh trần **60.0 MB**.
  * Ngay lập tức, bộ cấp phát trang nhớ của nhân Linux (`alloc_pages`) thất bại. Cơ chế OOM-Killer được kích hoạt, gửi tín hiệu `SIGKILL` tiêu diệt tiến trình ngay lập tức.
* **Phân tích cơ chế suy sụp của ML-DSA-65 (Đường màu cam):**
  * Với footprint khoảng **12.0 KB/tx**, ML-DSA-65 cầm cự tốt hơn, vượt qua mốc 1,000 giao dịch.
  * Tuy nhiên, khi tải tiếp tục tăng đến mốc **Tx #1300**, RAM chạm đỉnh 60.0 MB và kích hoạt **OOM-Killer thứ hai**.
* **Giải thích vì sao ML-DSA-44 sống sót ngoạn mục (Đường màu xanh lá):**
  * Giao dịch ML-DSA-44 chiếm khoảng **8.5 KB/tx**. Tại mốc Tx #1250, RAM đã chạm mức báo động cực kỳ nguy hiểm: **59.84 MB** (chiếm 99.73% trần cứng, chỉ cách cái chết đúng 0.16 MB).
  * Tuy nhiên, nhờ cơ chế thu gom rác (Garbage Collector) của Python thu hồi kịp thời các biến đệm tạm thời sau mỗi chu kỳ HTTP POST, dung lượng RAM được kéo lùi nhẹ về mức **59.48 MB**, giúp node vượt qua an toàn toàn bộ 1,500 giao dịch mà không bị sập nguồn.
* **Giải thích vì sao ECDSA hoàn toàn miễn nhiễm (Đường nét đứt màu xanh dương):**
  * Giao dịch ECDSA chỉ chiếm khoảng **0.5 KB in-memory**. Thêm 1,500 giao dịch vào hàng đợi chỉ tốn thêm vỏn vẹn $\approx 0.75\text{ MB}$ RAM.
  * Đường biểu diễn của ECDSA phẳng tuyệt đối và duy trì ổn định trong khoảng **44.0 MB đến 46.8 MB**, chứng minh mật mã truyền thống có khả năng phòng thủ cạn kiệt bộ nhớ vượt trội so với PQC.
* **Bản chất kỹ thuật của mã lỗi `Exit Code 137`:**
  * Theo chuẩn Linux POSIX, khi một tiến trình bị hệ điều hành tiêu diệt bằng tín hiệu bất khả kháng, mã thoát được tính bằng công thức:
    $$\text{Exit Code} = 128 + \text{Signal Number}$$
  * Tín hiệu mà OOM-Killer sử dụng là `SIGKILL` (Signal số 9):
    $$\text{Exit Code} = 128 + 9 = 137$$
  * Tín hiệu `SIGKILL` không thể bị bắt (*uncatchable*) hay bỏ qua (*unignorable*) bởi bất kỳ khối lệnh `try...except` nào trong mã nguồn Python, chứng minh tính bảo hộ tuyệt đối của tầng nhân hệ điều hành trước nguy cơ treo máy phần cứng.

---

### Bước 5: Thực thi Kịch bản Vĩ mô Mạng 6-Node Mesh & Bình luận Dashboard (Hình 3)

#### 1. Thao tác dòng lệnh:
Khởi chạy kịch bản Macro-Benchmark kiểm thử toàn diện Node DUT trong cụm mạng lưới Mesh sống:
```powershell
python perf/perf01_macro_stress.py
```

#### 2. Kết quả Log Terminal Ghi Nhận Quá Trình Bão Gossip & Đào Khối:
```text
========================================================================================
  MACRO-BENCHMARK: Single DUT in Live Mesh Network (1 DUT + 5 Background Nodes)
  DUT Profile: IoT DUT (0.5 vCPU, 128MB RAM) | Algorithm: ML-DSA-87 (NIST Level 5)
========================================================================================
[*] Dang khoi dong mang Mesh 6 Nodes qua WebSocket TLS 1.3...
[*] P2P Mesh hoan tat thiet lap: 15/15 kenh ket noi TLS 1.3 da thong suot.
[*] Phat song bao Gossip: 100 giao dich PQC dong thoi vao mang...
    - Tong so goi tin WebSocket DUT tiep nhan: 981 packets
    - So goi tin trung lap da loc nho seen_tx_hashes: 881 packets (Chặn 89.8%)
    - Bang thong Ingress dinh tren IoT: 5,600.29 KB/s (~5.6 MB/s)
    - Ingest Throughput: 39.81 TPS
[*] Miner Node 1 dao thanh cong Khoi #1 (100 txs ML-DSA-87, Kich thuoc: 1,439.63 KB)
[*] DUT tiep nhan va cam ket Khoi moi:
    - Thoi gian truyen khoi qua TLS 1.3 (Block Transit Delay): 74.00 ms
    - Thoi gian CPU verify 100 chu ky PQC: 18.68 ms
    - Tong do tre cam ket (Commit Latency): 95.46 ms
    - CFS Throttled Duration: 8,731.93 ms (Bị bóp 79.41% chu kỳ hoạt động)
    - Peak RAM tren IoT: 107.45 MB (83.95% tran cung 128MB)
```

**Bảng 4: Bảng 8 Chỉ Số Vàng Toàn Diện Macro-Benchmark (Trích xuất từ `perf01_macro_matrix.csv`)**

| Nhóm Đánh Giá | Chỉ Số Cốt Lõi (Core KPI) | ECDSA (secp256k1) | ML-DSA-44 (PQC L2) | ML-DSA-65 (PQC L3) | ML-DSA-87 (PQC L5) | Ý Nghĩa Học Thuật / Đánh Giá Thực Nghiệm |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **1. Tải Trọng Mạng** | **1. Kích thước 1 Txn / Khối 100 Txns** | 0.49 KB / **54.7 KB** | 7.71 KB / **758.6 KB** | 10.77 KB / **1,057.2 KB** | 14.69 KB / **1,439.6 KB** | Khối ML-DSA-87 phình to gấp **26.3 lần** so với ECDSA do cấu trúc chữ ký lattice và phụ phí Hex. |
| **2. Hiệu Năng Đồng Thuận Khối** | **2. Thời gian CPU Verify Khối (`dut_block_verify_ms`)**<br>*(Server / Edge / IoT)* | 115.0 / 124.7 / **193.1 ms** | 6.8 / 9.6 / **12.1 ms** | 14.2 / 19.0 / **14.2 ms** | 21.1 / 21.4 / **18.7 ms** | ML-DSA nhờ NTT của thư viện C `liboqs` nhanh gấp **10–16 lần** so với `python-ecdsa`. |
| | **3. Độ trễ Truyền Khối TLS 1.3 (`block_transit_ms`)**<br>*(Server / Edge / IoT)* | 3.7 / 4.4 / **4.6 ms** | 34.2 / 35.0 / **31.9 ms** | 49.1 / 50.6 / **54.3 ms** | 65.8 / 66.5 / **74.0 ms** | Ở PQC, **độ trễ truyền mạng chiếm tới 70%–80%** tổng thời gian; điểm nghẽn chuyển dịch từ CPU sang I/O Mạng. |
| | **4. Tổng Độ trễ Cam kết Khối (`commit_latency_ms`)**<br>*(Server / Edge / IoT)* | 118.9 / 129.5 / **197.9 ms** | 42.5 / 46.3 / **45.7 ms** | 65.5 / 72.0 / **71.7 ms** | 90.0 / 90.9 / **95.5 ms** | Tổng thời gian từ lúc Miner phát sóng qua WebSocket TLS 1.3 đến khi DUT xác thực và ghi sổ cái. |
| **3. Sức Chịu Tải Bão Gossip** | **5. Thông lượng Nạp Mempool (`ingest_throughput_tps`)**<br>*(Server / Edge / IoT)* | 146.7 / 154.1 / **103.1 TPS** | 176.1 / 121.9 / **63.4 TPS** | 165.4 / 108.0 / **55.8 TPS** | 140.3 / 97.4 / **39.8 TPS** | Tốc độ DUT hấp thụ 100 txs giữa bão tin nhắn. Trên IoT, thông lượng ML-DSA-87 giảm 2.6 lần so với ECDSA. |
| | **6. Băng thông Đỉnh & Lọc trùng (`ingress_bw` / `dups`)**<br>*(IoT Ingress BW / Gói tin trùng đã chặn)* | 351.5 KB/s<br>*(Chặn 600 gói)* | 4,295.0 KB/s<br>*(Chặn 800 gói)* | 5,869.8 KB/s<br>*(Chặn 900 gói)* | 5,600.3 KB/s<br>*(Chặn 881 gói)* | Thuật toán `seen_tx_hashes` hoạt động xuất sắc: chặn thành công 85%–90% gói tin dư thừa dội về từ 5 peers. |
| **4. Giới Hạn cgroups v2** | **7. Thời gian Bóp CPU (`total_throttled_ms` & `%`)**<br>*(Server / Edge / IoT)* | 0 / 322 / **1,627 ms**<br>*(0% / 46% / 69%)* | 0 / 1,051 / **3,932 ms**<br>*(0% / 57% / 74%)* | 0 / 1,447 / **5,259 ms**<br>*(0% / 56% / 76%)* | 0 / 1,624 / **8,732 ms**<br>*(0% / 59% / 79%)* | **Chỉ số đo áp lực tải thực tế:** Thời gian nhân Linux ngắt nhịp tiến trình. ML-DSA-87 đè nặng IoT gấp 5.3 lần ECDSA. |
| | **8. Đỉnh Bộ nhớ RAM & % Trần cứng IoT (`peak_ram` / `util%`)**<br>*(Server / Edge / IoT - Ngưỡng IoT: 128 MB)* | 50.5 / 50.2 / **50.1 MB**<br>*(IoT: **39.1%**)* | 57.2 / 69.6 / **78.9 MB**<br>*(IoT: **61.6%**)* | 75.0 / 80.3 / **85.9 MB**<br>*(IoT: **67.1%**)* | 79.2 / 91.2 / **107.5 MB**<br>*(IoT: **84.0%**)* | Chỉ với 100 txs, Mempool ML-DSA-87 đã chiếm tới **84.0% trần cứng 128MB của IoT**, cận kề vực thẳm OOM. |

#### 3. Chụp kết quả trực quan (Hình 3):

![Dashboard Kết Quả Macro-Benchmark Trong Mạng Live P2P Mesh](results/perf01_macro_chart.png)  
*Hình 3: Dashboard 4-Panel Đánh Giá Thực Nghiệm Toàn Diện Node DUT trong Mạng Lưới P2P Mesh 6 Nodes qua WebSocket TLS 1.3.*

#### 4. Bình luận & Phân tích Học thuật Chi Tiết Cho Từng Panel (Hình 3):

##### 4.1. Panel 1 (Góc trên trái - Thời Gian Cam Kết Khối Bóc Tách: Verify CPU vs Wire Transit):
* **Cấu trúc bóc tách:** Tổng thời gian cam kết khối được đo bằng công thức:
  $$\text{Commit Latency} = \text{Block Verify CPU Time} + \text{Wire Transit Delay TLS 1.3}$$
* **Sự chuyển dịch điểm nghẽn hệ thống (The Bottleneck Paradigm Shift):**
  * Với **ECDSA**: Hệ thống hoàn toàn là **CPU-bound**. Trên thiết bị IoT, thời gian truyền khối qua mạng chỉ mất **4.59 ms** (do khối chỉ nặng 54.7 KB), nhưng CPU mất tới **193.08 ms** để thẩm định 100 chữ ký đường cong Elliptic qua Python bytecode. Thời gian CPU verify chiếm tới **97.5%** tổng độ trễ.
  * Với **PQC (ML-DSA)**: Hệ thống chuyển dịch hoàn toàn sang **Network I/O-bound**. Nhờ thư viện C `liboqs`, CPU IoT chỉ mất **12.11 ms** để verify khối ML-DSA-44 và **18.68 ms** cho khối ML-DSA-87 (nhanh hơn ECDSA gấp 10–16 lần). Tuy nhiên, do khối nặng tới 0.76 – 1.44 MB, thời gian truyền tải socket TLS 1.3 chiếm tới **31.88 ms – 74.00 ms** (chiếm từ **70% đến 80%** tổng thời gian cam kết).
* **Giải thích hiện tượng độ trễ IoT (45.7ms) ngang bằng Edge (46.3ms) ở ML-DSA-44:**
  * Về mặt CPU thực tế, IoT (12.11 ms) vẫn chậm hơn Edge (9.57 ms) đúng theo tương quan phần cứng. Tuy nhiên, do thời gian truyền mạng chiếm tỷ trọng áp đảo (32–35 ms), độ dao động tự nhiên của socket TCP trên Docker bridge ($\pm 3\text{ ms}$) đã khỏa lấp mức chênh lệch CPU 2.5 ms, tạo nên độ trôi ngẫu nhiên nhỏ giữa hai cấu hình.

##### 4.2. Panel 2 (Góc trên phải - Tương Quan Giữa Tải Trọng Khối & Thông Lượng Nạp Mempool):
* **Tác động của bão Gossip đến thiết bị yếu:** Đường biểu diễn màu nâu cam thể hiện kích thước khối tăng vọt từ **54.7 KB** (ECDSA) lên **1,439.6 KB** (ML-DSA-87).
* Khi kích thước gói tin tăng, các cột thông lượng nạp (Ingest TPS) trên Node IoT (màu đỏ) suy giảm dốc đứng: từ **103.06 TPS** (ECDSA) tụt xuống **63.37 TPS** (ML-DSA-44), **55.81 TPS** (ML-DSA-65) và chạm đáy **39.81 TPS** (ML-DSA-87), tức suy giảm tới **61.4%**.
* Nguyên nhân là do nhân CPU yếu (0.5 vCPU) của IoT bị quá tải trong việc giải mã các gói tin khung WebSocket TLS 1.3 với lưu lượng dồn dập lên tới **5.6 MB/s – 5.8 MB/s**.
* Ngược lại, Node Server (4.0 vCPU) vẫn duy trì thông lượng ổn định từ **140 đến 176 TPS** nhờ năng lực xử lý I/O mạng đa luồng mạnh mẽ.
* **Đánh giá thuật toán lọc trùng lặp `seen_tx_hashes`:** Kịch bản ghi nhận DUT đã lọc và loại bỏ thành công từ **600 đến 900 gói tin giao dịch trùng lặp** do 5 peer trong mạng dội về liên tục, chứng minh cơ chế chống bão gossip của hệ thống hoạt động vô cùng hiệu quả, ngăn chặn nguy cơ cạn kiệt CPU do thẩm định lặp lại một giao dịch.

##### 4.3. Panel 3 (Góc dưới trái - Áp Lực Bóp Nghẽn CPU cgroups v2 Dưới Bão Gossip):
* **Khắc phục hạn chế của thông số CPU thông thường:** Trước đây, khi nhìn vào con số CPU 100%, người quan sát không thể biết được hệ thống bị quá tải ở mức độ nào. Chỉ số **Thời gian Bóp nghẽn CPU (CFS Throttled Duration)** từ cgroups v2 đã giải quyết triệt để vấn đề này.
* **Sự phân hóa rõ rệt giữa các cấu hình:**
  * Server (4 vCPU): Hoàn toàn không bị bóp nghẽn (**0.0 ms throttled**).
  * Edge (1 vCPU): Bị bóp từ **321.59 ms** (ECDSA) lên **1,624.21 ms** (ML-DSA-87), tỷ lệ chu kỳ bị ngắt nhịp là **58.8%**.
  * IoT (0.5 vCPU): Mức độ nghẽn tăng phi mã: ECDSA bị bóp **1,627.10 ms** (68.8% chu kỳ), nhưng khi chuyển sang ML-DSA-87, thời gian bị bóp nghẹt lên tới kỷ lục **8,731.93 ms**, chiếm tới **79.41%** tổng thời gian hoạt động. Điều này chứng minh thuật toán PQC cấp 5 đặt một gánh nặng tính toán và phân giải I/O vượt quá giới hạn thiết kế của các vi xử lý nhúng.

##### 4.4. Panel 4 (Góc dưới phải - Cảnh Báo Ngưỡng Bộ Nhớ RAM Trên IoT So Với Trần Cứng 128MB):
* **Trực quan hóa lằn ranh đỏ 128 MB:** Đường kẻ ngang màu đỏ thể hiện trần cứng cgroups của thiết bị nhúng IoT.
* **Nguy cơ OOM cận kề trong điều kiện vận hành thực tế:**
  * Với ECDSA, bộ nhớ RAM đỉnh của IoT chỉ đạt **50.05 MB**, tương đương **39.1%** trần cứng (còn dư hơn 77 MB an toàn).
  * Khi chuyển sang PQC, Mempool và bộ đệm WebSocket phình to nhanh chóng: ML-DSA-44 chiếm **78.90 MB (61.6%)**, ML-DSA-65 chiếm **85.91 MB (67.1%)**, và ML-DSA-87 đẩy mức chiếm dụng lên tới **107.45 MB**, tương đương **83.95%** trần cứng 128MB.
  * Chỉ với **100 giao dịch** trong mạng P2P, node IoT đã tiêu hao gần hết khoảng đệm an toàn và chỉ còn cách vực thẳm Linux OOM-Killer đúng **20.5 MB**. Nếu mạng lưới xảy ra ùn tắc giao dịch và số lượng giao dịch trong Mempool vượt quá 200–300, node IoT chắc chắn sẽ bị sập nguồn đột ngột.

---

## 5. TỔNG KẾT & KHUYẾN NGHỊ KIẾN TRÚC CHO HỆ THỐNG BLOCKCHAIN HẬU LƯỢNG TỬ

Dựa trên toàn bộ kết quả đo đạc định lượng từ 3 kịch bản thực nghiệm vi mô, cực hạn và vĩ mô, nhóm nghiên cứu đề xuất các khuyến nghị kiến trúc kỹ thuật chuẩn xác sau:

### 5.1. Bảng Khuyến Nghị Lựa Chọn Thuật Toán Theo Cấu Hình Phần Cứng

| Phân Khúc Thiết Bị | Thông Số Phần Cứng Mục Tiêu | Thuật Toán Khuyến Nghị | Thuật Toán Cần Tránh | Lý Do Kỹ Thuật & Giải Pháp Đi Kèm |
| :--- | :--- | :---: | :---: | :--- |
| **IoT / Cảm biến Nhúng**<br>*(Smart Meter, Sensor)* | CPU $\le 0.5$ vCPU<br>RAM $\le 128$ MB | **ML-DSA-44**<br>*(NIST Level 2)* | **ML-DSA-87** | ML-DSA-87 chiếm tới 84% RAM và gây nghẽn CPU tới 79%. ML-DSA-44 đảm bảo khả năng sống sót qua bão tải, RAM đỉnh chỉ 54–78 MB. Cần cấu hình giới hạn kích thước khối $\le 50$ txs. |
| **Edge Gateway**<br>*(Raspberry Pi 4, IPC)* | CPU $\approx 1.0$ vCPU<br>RAM $\approx 512$ MB | **ML-DSA-65**<br>*(NIST Level 3)* | - | ML-DSA-65 là "Điểm cân bằng vàng" (Sweet Spot): Đạt cấp an ninh AES-192, TPS nạp đạt ~489 tx/s, RAM đỉnh chỉ chiếm 10.4%–15.7% trần cứng. |
| **Cloud Server / Miner**<br>*(DataCenter, Validator)* | CPU $\ge 4.0$ vCPU<br>RAM $\ge 4096$ MB | **ML-DSA-65** hoặc **ML-DSA-87** | - | Server hoàn toàn không bị bóp nghẽn CPU (0 ms Throttled), RAM chiếm <2%, TPS đạt 617–690 tx/s. Đủ năng lực gánh các khối PQC dung lượng lớn. |

### 5.2. Đề Xuất Cải Tiến Kiến Trúc Hệ Thống (Future Work)

1. **Chuyển đổi tầng giao vận sang Chuẩn Nhị Phân (Binary Serialization):**
   * *Hạn chế hiện tại:* Việc biểu diễn chữ ký và khóa công khai dưới dạng chuỗi Text Hexadecimal làm phình gấp đôi kích thước dữ liệu (+100% overhead).
   * *Giải pháp:* Nâng cấp tầng giao vận WebSocket và lưu trữ khối sang định dạng nhị phân như **Protocol Buffers (Protobuf), CBOR hoặc MessagePack** (hoặc tối thiểu là Base64). Điều này sẽ giúp giảm ngay lập tức **40% đến 48% kích thước khối** (khối ML-DSA-87 giảm từ 1.44 MB xuống còn ~750 KB), triệt tiêu điểm nghẽn I/O mạng.
2. **Triển khai Cơ chế Giới hạn Mempool Theo Dung Lượng Byte (Byte-Bounded Mempool Eviction):**
   * *Hạn chế hiện tại:* Các node blockchain truyền thống thường giới hạn Mempool theo số lượng giao dịch cố định (ví dụ tối đa 5,000 txs). Với ECDSA, 5,000 txs chỉ tốn 2.5 MB RAM; nhưng với ML-DSA-87, nó sẽ ngốn tới **73.5 MB RAM**, ngay lập tức giết chết node IoT 128MB.
   * *Giải pháp:* Bắt buộc phải áp dụng chính sách giới hạn Mempool theo tổng số Megabyte (ví dụ: Node IoT chỉ cho phép Mempool tối đa **10 MB**). Khi hàng đợi đầy, node tự động loại bỏ (evict) các giao dịch có mức phí (gas fee) thấp nhất để bảo vệ an toàn tính mạng cho tiến trình.
3. **Tận dụng Thư viện C Bản Địa và Tối Ưu Hóa Vector Hóa (SIMD/AVX2):**
   * Kết quả thực nghiệm đã chứng minh sức mạnh vượt trội của `liboqs` C-engine so với Pure-Python. Mọi thành phần mật mã trong các hệ thống Blockchain thương mại bắt buộc phải được triển khai dưới dạng thư viện C bản địa hoặc Rust/Go để giải phóng khóa thông dịch và khai thác tối đa năng lực phần cứng.

---

## 6. ĐÓNG GÓP CỦA PERF-01 TRONG TỔNG THỂ ĐỒ ÁN

Kịch bản **PERF-01** đóng vai trò là chiếc cầu nối thực nghiệm vững chắc giữa lý thuyết mật mã trừu tượng và khả năng triển khai thực tế của toàn bộ đồ án:
* **Kết nối với Phần 1 (An ninh & Mật mã - SEC-01..04):** Trong khi các kịch bản SEC chứng minh tính an toàn tuyệt đối của ML-DSA trước các cuộc tấn công lật bit, phát lại và phân tích kênh kề thời gian thực thi (TVLA), PERF-01 đã chỉ ra rõ ràng "cái giá phải trả" về mặt tài nguyên tính toán, băng thông và bộ nhớ khi đưa các thuật toán này vào vận hành.
* **Kết nối với Phần 2 (Mạng P2P & Đồng thuận - NET-01..02):** Số liệu đo đạc tải trọng khối (1.44 MB/khối) và độ trễ truyền mạng TLS 1.3 của PERF-01 cung cấp trực tiếp dữ liệu đầu vào cho kịch bản NET-01 và NET-02 để giải thích hiện tượng phân mảnh gói tin TCP qua các ngưỡng MTU hẹp và tỷ lệ sinh nhánh phụ (Fork/Orphan blocks) khi mạng có độ trễ cao.
* **Tính thực tiễn và chuẩn mực DevOps:** Việc áp dụng kỹ thuật container hóa Docker, cơ chế giám sát kernel Linux cgroups v2, kỹ thuật khử nhiễu Warm-up Page Cache và mô phỏng mạng lưới P2P Mesh 6 nodes đã nâng tầm giá trị thực nghiệm của đồ án từ mô hình lý thuyết trên giấy thành một hệ thống kỹ thuật hoàn chỉnh, đáp ứng đầy đủ các tiêu chuẩn học thuật khắt khe.
