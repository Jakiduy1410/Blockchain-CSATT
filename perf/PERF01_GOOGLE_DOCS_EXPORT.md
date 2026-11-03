# BÁO CÁO KỸ THUẬT TOÀN DIỆN: KỊCH BẢN KIỂM THỬ PERF-01
# ĐO LƯỜNG GIỚI HẠN TÀI NGUYÊN NODE TRÊN PHẦN CỨNG YẾU (RESOURCE CONSTRAINED STRESS TEST)
## Tích Hợp Toàn Bộ Phổ Mật Mã Hậu Lượng Tử FIPS 204 (ML-DSA-44, ML-DSA-65, ML-DSA-87), Sự Kiện OOM-Killer Kép & So Sánh Micro vs Macro P2P

**Học phần:** Cơ sở An toàn Thông tin / Blockchain Engineering  
**Vai trò phụ trách:** Thành viên 4 (Hardware Benchmark & DevOps)  
**Mã kịch bản:** `PERF-01`  
**Tên kịch bản:** Đo lường Giới hạn Tài nguyên Node trên Phần cứng Yếu (Resource Constrained Stress Test)  
**Nền tảng kiểm thử:** Docker Desktop (WSL2 Linux Kernel 6.18, Cgroups v2)  
**Ngày thực hiện & Nghiệm thu:** 04/11/2026  

---

## MỤC LỤC
1. [Tổng Quan & Mục Tiêu Kịch Bản PERF-01](#1-tổng-quan--mục-tiêu-kịch-bản-perf-01)
2. [Thiết Kế Kiến Trúc DevOps & Giới Hạn Phần Cứng Docker](#2-thiết-kế-kiến-trúc-devops--giới-hạn-phần-cứng-docker)
3. [Chuẩn Hóa Mật Mã Hậu Lượng Tử: Bộ Ba FIPS 204 (ML-DSA-44 / 65 / 87)](#3-chuẩn-hóa-mật-mã-hậu-lượng-tử-bộ-ba-fips-204-ml-dsa-44--65--87)
4. [Thực Nghiệm Cấp Vi Mô (Micro-Benchmark): Ma Trận 3x4 Baseline](#4-thực-nghiệm-cấp-vi-mô-micro-benchmark-ma-trận-3x4-baseline)
   - 4.1. Bảng số liệu ma trận thực nghiệm 12 đợt
   - 4.2. Phân tích hiện tượng CPU Đa luồng trên Server (141% - 165%)
   - 4.3. Phân tích bão hòa CPU và CFS Throttling trên Edge và IoT
5. [Bài Test Tải Cực Hạn (Extreme Stress Test): Hiện Tượng OOM-Killer Kép (Exit 137)](#5-bài-test-tải-cực-hạn-extreme-stress-test-hiện-tượng-oom-killer-kép-exit-137)
   - 5.1. Thiết kế kịch bản bão hòa bộ nhớ trên Node 60MB RAM
   - 5.2. Kết quả đo đạc thực tế: ML-DSA-87 vs ML-DSA-65 vs ML-DSA-44 vs ECDSA
   - 5.3. Bằng chứng kích hoạt Linux Kernel OOM-Killer tại Tx #1050 và Tx #1350
6. [Thực Nghiệm Cấp Vĩ Mô (Macro-Benchmark): Mạng P2P Phân Cấp 3 Nodes](#6-thực-nghiệm-cấp-vĩ-mô-macro-benchmark-mạng-p2p-phân-cấp-3-nodes)
   - 6.1. Khái niệm và sự khác biệt cốt lõi giữa Micro vs Macro Benchmark
   - 6.2. Thiết lập mạng lưới phân cấp Heterogeneous (Server -> Edge -> IoT)
   - 6.3. Kết quả đo đạc độ trễ lan truyền khối (Block Propagation Delay) và Wire Payload
   - 6.4. Nút thắt cổ chai phần cứng (Hardware Bottleneck) trên Node IoT
7. [Hướng Dẫn Tái Lập Kết Quả (Reproducibility Guide)](#7-hướng-dẫn-tái-lập-kết-quả-reproducibility-guide)
8. [Khuyến Nghị Kiến Trúc DevOps & An Toàn Hệ Thống](#8-khuyến-nghị-kiến-trúc-devops--an-toàn-hệ-thống)
9. [Danh Mục Sản Phẩm Bàn Giao (Deliverables)](#9-danh-mục-sản-phẩm-bàn-giao-deliverables)

---

## 1. TỔNG QUAN & MỤC TIÊU KỊCH BẢN PERF-01

### 1.1. Bối cảnh Nghiên cứu
Trong kiến trúc bảo mật của hệ thống Blockchain hiện đại, việc chuyển đổi từ mật mã đường cong elliptic cổ điển (**ECDSA secp256k1**) sang **Mật mã Hậu lượng tử (Post-Quantum Cryptography - PQC)** là yêu cầu cấp thiết nhằm chống lại thuật toán Shor trên máy tính lượng tử tương lai. Tiêu chuẩn **NIST FIPS 204 (ML-DSA / Crystals-Dilithium)** được phê duyệt chính thức làm chuẩn chữ ký số hậu lượng tử toàn cầu.

Thay vì sử dụng thuật toán RSA (vốn không phản ánh mô hình chữ ký của blockchain thực tế), kịch bản đã chuẩn hóa toàn diện trên bộ tứ: **ECDSA (secp256k1)** làm mốc tham chiếu tiền lượng tử, kết hợp trọn bộ 3 cấp độ an toàn của FIPS 204: **ML-DSA-44 (Level 2)**, **ML-DSA-65 (Level 3 - Recommended Default)** và **ML-DSA-87 (Level 5)**.

### 1.2. Mục tiêu Trọng tâm của Kịch bản `PERF-01`
1. **Xác định ranh giới chịu tải (Hardware Boundary):** Đo lường mức tiêu thụ RAM đỉnh (**Peak RAM**), tỉ lệ trần bộ nhớ (**Memory Ceiling %**), mức độ bão hòa CPU (**CPU Saturation %**) và hiện tượng ngắt xung nhịp (**CFS CPU Throttling**) trên 3 hồ sơ phần cứng độc lập: **Server (4 vCPU, 4GB RAM)**, **Edge (1 vCPU, 512MB RAM)** và **IoT (0.5 vCPU, 128MB RAM)**.
2. **Khảo sát trọn vẹn dải PQC Spectrum (Levels 2, 3, 5):** Đánh giá tác động trực tiếp của từng cấp độ an toàn đến kích thước payload giao dịch (tăng từ 128 Bytes của ECDSA lên tới 7,219 Bytes của ML-DSA-87).
3. **Thực chứng sự kiện Tràn bộ nhớ OOM-Killed Kép (Exit Code 137):** Thiết lập ranh giới sinh tử trên Node IoT 60MB RAM để quan sát thời điểm Linux Kernel kích hoạt `SIGKILL` tiêu diệt tiến trình khi nạp 1,500 giao dịch.
4. **Mở rộng sang Cấp độ Vĩ mô (Heterogeneous Macro-Benchmark):** Triển khai mạng P2P đa node phân cấp kết nối qua mạng nội bộ Docker để đo đạc độ trễ lan truyền khối (**Block Propagation Delay**), dung lượng đường truyền (**Wire Payload**), và chứng minh nút thắt cổ chai khi node IoT yếu thẩm định khối từ node Server mạnh.

---

## 2. THIẾT KẾ KIẾN TRÚC DEVOPS & GIỚI HẠN PHẦN CỨNG DOCKER

Hệ thống được container hóa theo tiêu chuẩn DevOps cô lập cgroups v2 nghiêm ngặt:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               DOCKER CGROUPS V2 SUB-SYSTEM                             │
├──────────────────────────┬─────────────────────────────┬───────────────────────────────┤
│    PROFILE 1: SERVER     │       PROFILE 2: EDGE       │        PROFILE 3: IOT         │
│  • 4.0 vCPU Quota        │   • 1.0 vCPU Quota          │   • 0.5 vCPU Quota            │
│  • 4096 MB RAM Limit     │   • 512 MB RAM Limit        │   • 128 MB RAM Limit (60M OOM)│
│  • Memswap: 4096 MB      │   • Memswap: 512 MB         │   • Memswap: 128 MB           │
│  • Port: 5000            │   • Port: 5001              │   • Port: 5002                │
├──────────────────────────┴─────────────────────────────┴───────────────────────────────┤
│                                 NODE BLOCKCHAIN RUNTIME                                │
│  • Linux Kernel 6.18 (WSL2 Debian base, Python 3.11-slim)                              │
│  • Thư viện C liboqs (Open Quantum Safe FIPS 204 Engine: ML-DSA-44 / 65 / 87)         │
│  • Multithreaded RESTful API + Mempool Manager + P2P Block Propagation Engine          │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                           KERNEL TELEMETRY PROBES (TẦN SỐ CAO)                         │
│  • /sys/fs/cgroup/memory.peak: RAM đỉnh thực tế do nhân Linux ghi nhận                 │
│  • /sys/fs/cgroup/cpu.stat: usage_usec, nr_throttled, throttled_usec                   │
│  • /sys/fs/cgroup/memory.events: oom_kill counter & Docker inspect ExitCode 137        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> **Triệt tiêu Swap Memory (`--memory-swap = --memory`):** Toàn bộ các thử nghiệm đều áp đặt cờ khóa cứng trần bộ nhớ vật lý. Không có vùng đệm swap, bảo đảm khi bộ nhớ tiến trình chạm ngưỡng là Linux Kernel lập tức can thiệp, phản ánh chân thực môi trường vi điều khiển nhúng.

---

## 3. CHUẨN HÓA MẬT MÃ HẬU LƯỢNG TỬ: BỘ BA FIPS 204 (ML-DSA-44 / 65 / 87)

Bảng so sánh kích thước khóa và chữ ký số giữa các thuật toán trong bộ kiểm thử:

| Thuật toán Mật mã | Chuẩn Tiêu chuẩn | Cấp độ An toàn NIST | Kích thước Public Key | Kích thước Chữ ký (Signature) | Tổng Payload Mật mã thuần | Kích thước JSON Wire Giao dịch | Hệ số phình to so với ECDSA |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **ECDSA (secp256k1)** | Cổ điển (Bitcoin/ETH) | 128-bit (Tiền lượng tử) | 64 Bytes | 64 Bytes | **128 Bytes** | **~499 Bytes** | **1.0x (Baseline)** |
| **ML-DSA-44** | FIPS 204 (Category 2) | AES-128 Equivalent | 1,312 Bytes | 2,420 Bytes | **3,732 Bytes** | **~7,711 Bytes** | **15.5x** |
| **ML-DSA-65** | **FIPS 204 (Category 3)** | **AES-192 (Recommended Default)** | **1,952 Bytes** | **3,309 Bytes** | **5,261 Bytes** | **~10,769 Bytes** | **21.6x** |
| **ML-DSA-87** | **FIPS 204 (Category 5)** | **AES-256 Equivalent** | **2,592 Bytes** | **4,627 Bytes** | **7,219 Bytes** | **~14,685 Bytes** | **29.4x** |

---

## 4. THỰC NGHIỆM CẤP VI MÔ (MICRO-BENCHMARK): MA TRẬN 3X4 BASELINE

### 4.1. Bảng Số Liệu Ma Trận Thực Nghiệm 12 Đợt (500 Giao dịch Batch Ingestion)

| Cấu hình Phần cứng | vCPU | RAM Limit | Thuật toán Ký số | Số Tx Đạt | Thời gian (s) | Ingestion TPS | Baseline RAM | Peak RAM (MB) | % Đạt Trần RAM | Avg CPU (%) | Normalized CPU (% Quota) | CPU Throttled (ms) | Trạng thái OOM |
| :--- | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Server (Datacenter)** | **4.0** | **4096 MB** | ECDSA (secp256k1) | 500/500 | 1.200 s | **416.67 tx/s** | 43.50 MB | 46.50 MB | 1.14% | 141.79% | **35.45%** | 0.0 ms (0 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Server (Datacenter)** | **4.0** | **4096 MB** | **ML-DSA-44 (PQC L2)** | 500/500 | 0.702 s | **712.25 tx/s** | 43.95 MB | 54.44 MB | 1.33% | 161.54% | **40.38%** | 0.0 ms (0 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Server (Datacenter)** | **4.0** | **4096 MB** | **ML-DSA-65 (PQC L3)** | 500/500 | 0.695 s | **719.42 tx/s** | 42.88 MB | 53.53 MB | 1.31% | 164.04% | **41.01%** | 0.0 ms (0 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Server (Datacenter)** | **4.0** | **4096 MB** | **ML-DSA-87 (PQC L5)** | 500/500 | 0.754 s | **663.13 tx/s** | 43.54 MB | 57.21 MB | 1.40% | 165.43% | **41.36%** | 0.0 ms (0 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Edge Gateway** | **1.0** | **512 MB** | ECDSA (secp256k1) | 500/500 | 1.451 s | **344.59 tx/s** | 44.00 MB | 46.60 MB | 9.10% | 115.87% | **115.87%** | 543.2 ms (14 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Edge Gateway** | **1.0** | **512 MB** | **ML-DSA-44 (PQC L2)** | 500/500 | 0.926 s | **539.96 tx/s** | 43.72 MB | 52.50 MB | 10.25% | 124.23% | **124.23%** | 462.7 ms (12 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Edge Gateway** | **1.0** | **512 MB** | **ML-DSA-65 (PQC L3)** | 500/500 | 1.021 s | **489.72 tx/s** | 43.46 MB | 55.91 MB | 10.92% | 123.05% | **123.05%** | 625.6 ms (15 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **Edge Gateway** | **1.0** | **512 MB** | **ML-DSA-87 (PQC L5)** | 500/500 | 1.023 s | **488.76 tx/s** | 43.73 MB | 58.25 MB | 11.38% | 124.04% | **124.04%** | 697.4 ms (16 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **IoT Embedded** | **0.5** | **128 MB** | ECDSA (secp256k1) | 500/500 | 3.160 s | **158.23 tx/s** | 43.14 MB | 47.64 MB | 37.22% | 58.35% | **116.70%** | 5403.7 ms (32 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **IoT Embedded** | **0.5** | **128 MB** | **ML-DSA-44 (PQC L2)** | 500/500 | 1.999 s | **250.13 tx/s** | 43.81 MB | 54.37 MB | 42.48% | 62.94% | **125.88%** | 3883.4 ms (20 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **IoT Embedded** | **0.5** | **128 MB** | **ML-DSA-65 (PQC L3)** | 500/500 | 2.081 s | **240.27 tx/s** | 43.97 MB | 53.93 MB | 42.13% | 62.49% | **124.98%** | 3260.6 ms (21 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |
| **IoT Embedded** | **0.5** | **128 MB** | **ML-DSA-87 (PQC L5)** | 500/500 | 2.087 s | **239.58 tx/s** | 43.79 MB | 55.89 MB | 43.66% | 62.55% | **125.10%** | 4018.6 ms (21 events) | <span style="color:green;font-weight:bold;">AN TOÀN</span> (<60%) |

*Bảng dữ liệu trích xuất từ file: [`perf/results/perf01_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_matrix.csv) và [`perf/results/perf01_results.json`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_results.json)*

![Biểu đồ OOM Risk Matrix](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_oom_risk_chart.png)

---

### 4.2. Phân Tích Hiện Tượng CPU Đa Luồng Trên Server (141% - 165%)
Trên Node Server (4 vCPU = hạn ngạch 400%), CPU ghi nhận ở mức `141.79% - 165.43%`. Điều này chứng tỏ tiến trình Flask đa luồng đã tự động huy động xấp xỉ **1.4 đến 1.6 nhân CPU vật lý** để xử lý song song các tác vụ thẩm định chữ ký. Sau khi chuẩn hóa theo hạn ngạch 4 vCPU (**Normalized CPU**), máy chủ mới chỉ tiêu hao **~35% - 41%**, hoàn toàn không bị điều tiết xung nhịp (`throttled_ms = 0.0 ms`).

### 4.3. Phân Tích Bão Hòa CPU và CFS Throttling Trên Edge và IoT
- **Edge Gateway (1.0 vCPU):** Tiêu thụ 115% - 124% hạn ngạch đơn nhân $\rightarrow$ Linux Kernel CFS can thiệp ngắt xung nhịp từ **462 ms đến 697 ms** (12 - 16 chu kỳ ngắt).
- **IoT Embedded (0.5 vCPU):** Mức tải CPU đạt 116% - 126% so với hạn ngạch được cấp. Đặc biệt đối với **ECDSA**, do việc tính toán nghịch đảo modular và nhân điểm scalar trên đường cong tốn kém CPU, tổng thời gian bị đóng băng xung nhịp lên tới **5,403.7 ms** (hơn 5.4 giây), khiến TPS tiếp nhận của IoT tụt xuống chỉ còn **158.23 tx/s**. Trong khi đó, các thuật toán ML-DSA nhờ tối ưu hóa NTT xử lý nhẹ hơn đáng kể, đạt 240 - 250 tx/s.

---

## 5. BÀI TEST TẢI CỰC HẠN (EXTREME STRESS TEST): HIỆN TƯỢNG OOM-KILLER KÉP (EXIT 137)

### 5.1. Thiết Kế Kịch Bản Bão Hòa Bộ Nhớ Trên Node 60MB RAM
Để quan sát chính xác ranh giới sụp đổ của từng cấp độ PQC:
- **Hồ sơ Node IoT:** 0.5 vCPU, **Giới hạn cứng 60 MB RAM** (`-m=60m`, `--memory-swap=60m`).
- **Tải thử nghiệm:** Bơm liên tục **1,500 giao dịch** vào hàng đợi Mempool.
- **Đối chứng 4 nhánh:** ML-DSA-87 (Level 5) vs ML-DSA-65 (Level 3) vs ML-DSA-44 (Level 2) vs ECDSA.

### 5.2. Kết Quả Đo Đạc Thực Tế (1,500 Giao dịch trên Node 60MB RAM)

| Mốc Giao dịch (Tx Count) | ML-DSA-87 RAM (MB) | ML-DSA-65 RAM (MB) | ML-DSA-44 RAM (MB) | ECDSA RAM (MB) | Ngưỡng Trần | Trạng thái ML-DSA-87 | Trạng thái ML-DSA-65 | Trạng thái ML-DSA-44 | Trạng thái ECDSA |
| :---: | :---: | :---: | :---: | :---: | :---: | :--- | :--- | :--- | :--- |
| **0 txs (Idle)** | 42.50 MB | 42.60 MB | 42.25 MB | 42.60 MB | 60.0 MB | An toàn | An toàn | An toàn | An toàn |
| **250 txs** | 51.54 MB | 47.80 MB | 44.59 MB | 44.07 MB | 60.0 MB | Tăng nhanh | Tăng vừa | Vùng xanh | Ổn định phẳng |
| **500 txs** | 52.02 MB | 50.15 MB | 48.02 MB | 44.90 MB | 60.0 MB | Cảnh báo | Cảnh báo | Vùng xanh | Ổn định phẳng |
| **750 txs** | 59.85 MB | 53.40 MB | 50.92 MB | 45.59 MB | 60.0 MB | Cận kề trần | Tăng đều | Vùng xanh | Ổn định phẳng |
| **1,000 txs** | 59.99 MB | 55.80 MB | 54.10 MB | 45.98 MB | 60.0 MB | Chạm trần 100% | Cận kề trần | Vùng an toàn | Ổn định phẳng |
| **1,050 txs** | **60.00 MB** | 56.40 MB | 54.40 MB | 45.82 MB | 60.0 MB | <span style="color:red;font-weight:bold;">OOM-KILLER (#1050)</span> | Tăng tiếp | Vùng an toàn | Ổn định phẳng |
| **1,350 txs** | *Đã chết (Exit 137)* | **60.00 MB** | 57.20 MB | 46.10 MB | 60.0 MB | *Container đã dừng* | <span style="color:darkorange;font-weight:bold;">OOM-KILLER (#1350)</span> | Vùng an toàn | Ổn định phẳng |
| **1,500 txs** | *Đã chết (Exit 137)* | *Đã chết (Exit 137)* | **58.20 MB** | **46.20 MB** | **60.0 MB** | **Chết tại Tx #1050** | **Chết tại Tx #1350** | **SỐNG SÓT 100%** | **SỐNG SÓT 100%** |

*Bảng dữ liệu trích xuất từ file: [`perf/results/perf01_extreme_oom_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_extreme_oom_matrix.csv)*

![Biểu đồ Extreme OOM Cliff](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_extreme_oom_chart.png)

---

### 5.3. Bằng Chứng Kích Hoạt Linux Kernel OOM-Killer Tại Tx #1050 và Tx #1350
1. **ML-DSA-87 (Level 5):** Kích thước 14.7 KB/tx khiến Mempool bùng nổ, chạm trần 60MB tại giao dịch thứ **1050**. Nhân Linux can thiệp gửi `SIGKILL` (Exit 137) tiêu diệt tiến trình.
2. **ML-DSA-65 (Level 3):** Với kích thước trung gian 10.8 KB/tx, Mempool duy trì được lâu hơn nhưng vẫn chạm trần 60MB tại giao dịch thứ **1350**, kích hoạt sự kiện OOM-Killed thứ hai.
3. **ML-DSA-44 & ECDSA:** Nhờ kích thước nhỏ gọn hơn, ML-DSA-44 đạt đỉnh RAM 58.2 MB (dưới trần 60MB), sống sót trọn vẹn 1,500 giao dịch. ECDSA hoàn toàn phẳng ở mức 46.2 MB.

---

## 6. THỰC NGHIỆM CẤP VĨ MÔ (MACRO-BENCHMARK): MẠNG P2P PHÂN CẤP 3 NODES

### 6.1. Khái Niệm & Sự Khác Biệt Cốt Lõi Giữa Micro vs Macro Benchmark

| Tiêu chí So sánh | Thực nghiệm Cấp vi mô (Micro-Benchmark) | Thực nghiệm Cấp vĩ mô (Macro-Benchmark) |
| :--- | :--- | :--- |
| **Phạm vi Đo lường** | Cô lập trên 1 Node đơn lẻ (Component Isolation) | Mạng lưới P2P phân tán đa Node (End-to-End System) |
| **Môi trường Mạng** | Gọi trực tiếp qua loopback nội bộ (HTTP POST `/transactions/new`) | Kết nối mạng lưới qua **Docker Bridge Network (`perf-macro-net`)** |
| **Quy trình Nghiệp vụ** | Deserialization JSON $\rightarrow$ Xác thực Chữ ký $\rightarrow$ Lưu Mempool | Ingress $\rightarrow$ PoW Mining $\rightarrow$ P2P Block Propagation $\rightarrow$ Full Validation |
| **Mục đích Kỹ thuật** | Đo năng lực trần (Raw Capacity) của CPU & RAM khi nạp | Đo **Độ trễ lan truyền khối**, **Dung lượng đường truyền**, và **Nút thắt cổ chai** |

---

### 6.2. Thiết Lập Mạng Lưới Phân Cấp Heterogeneous (Server $\rightarrow$ Edge $\rightarrow$ IoT)
- **Node Server (btc-macro-server):** Profile Server (4 vCPU, 4096MB RAM, Port 5000) $\rightarrow$ Ingress Gateway & Miner.
- **Node Edge (btc-macro-edge):** Profile Edge (1 vCPU, 512MB RAM, Port 5001) $\rightarrow$ P2P Relay & Validator.
- **Node IoT (btc-macro-iot):** Profile IoT (0.5 vCPU, 128MB RAM, Port 5002) $\rightarrow$ Constrained Validator.

```
[ Client / Batch Txs ]
         │ (100 txs)
         ▼
┌──────────────────┐  P2P Propagation   ┌─────────────────┐  P2P Propagation   ┌────────────────┐
│   NODE SERVER    │ ═════════════════> │    NODE EDGE    │ ═════════════════> │    NODE IOT    │
│  (4 vCPU, 4GB)   │    Mined Block     │ (1 vCPU, 512MB) │    Mined Block     │(0.5 vCPU, 128M)│
│  [Ingress/Miner] │                    │ [P2P Relay]     │                    │ [Validator]    │
└──────────────────┘                    └─────────────────┘                    └────────────────┘
```

---

### 6.3. Kết Quả Đo Đạc Thực Nghiệm Macro-Benchmark (ECDSA vs ML-DSA-44 vs ML-DSA-65 vs ML-DSA-87)

| Chỉ số Đo lường Kỹ thuật | ECDSA (secp256k1) | ML-DSA-44 (NIST PQC Level 2) | ML-DSA-65 (NIST PQC Level 3) | ML-DSA-87 (NIST PQC Level 5) | Đánh giá Chênh lệch & Tác động |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Kích thước 1 Giao dịch trên dây mạng** | **499 Bytes** | 7,711 Bytes (~7.7 KB) | 10,769 Bytes (~10.8 KB) | 14,685 Bytes (~14.7 KB) | ML-DSA-65 gấp 21.6 lần ECDSA |
| **Tổng dung lượng gói 100 Giao dịch** | **48.73 KB** | 753.03 KB | 1,051.66 KB | 1,434.08 KB | Gói tin PQC phình to đáng kể |
| **Kích thước Khối đã đào (Block Wire Size)** | **27.30 KB** | 379.26 KB | 528.57 KB | 719.78 KB | Khối ML-DSA-87 lớn gấp 26.4x ECDSA |
| **Thời gian Server tiếp nhận 100 txs** | 0.244 s (409.8 tx/s) | 0.308 s (324.7 tx/s) | **0.150 s (666.7 tx/s)** | **0.138 s (724.6 tx/s)** | Server xử lý PQC cực nhanh nhờ NTT |
| **Thời gian Server đào khối (PoW)** | 0.098 s | 0.057 s | 0.134 s | 0.284 s | PoW biến thiên theo độ khó nonce |
| **Độ trễ Lan truyền & Thẩm định tới Edge** | 65.60 ms | 19.95 ms | **11.51 ms** | 15.80 ms | **ML-DSA-65 nhanh nhất tại trạm Edge** |
| **Độ trễ Lan truyền & Thẩm định tới IoT** | 77.56 ms | 32.72 ms | **11.18 ms** | 57.72 ms | **ML-DSA-65 đạt hiệu năng tối ưu trên IoT** |
| **Tổng thời gian End-to-End** | 0.485 s | 0.418 s | **0.307 s** | 0.496 s | **ML-DSA-65 nhanh nhất toàn trình** |
| **Thông lượng toàn mạng (E2E TPS)** | 206.19 tx/s | 239.23 tx/s | **325.73 tx/s** | 201.61 tx/s | **ML-DSA-65 đạt đỉnh 325.7 tx/s** |
| **Peak RAM Node Server** | 44.46 MB (1.09%) | 49.19 MB (1.20%) | 52.90 MB (1.29%) | 53.68 MB (1.31%) | Vận hành hoàn toàn ổn định |
| **Peak RAM Node Edge** | 44.11 MB (8.61%) | 45.57 MB (8.90%) | 49.49 MB (9.67%) | 47.89 MB (9.35%) | Vùng xanh an toàn |
| **Peak RAM Node IoT** | 43.27 MB (33.80%) | 48.81 MB (38.13%) | 46.51 MB (36.34%) | 48.77 MB (38.10%) | Vùng an toàn (<40% trần 128MB) |
| **Normalized CPU Node IoT** | 32.84% | 11.88% | 17.26% | 11.82% | PQC tiết kiệm CPU IoT hơn ECDSA |

*Bảng dữ liệu trích xuất từ file: [`perf/results/perf01_macro_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_macro_matrix.csv) và [`perf/results/perf01_macro_results.json`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_macro_results.json)*

![Biểu đồ Macro Benchmark](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_macro_chart.png)

---

### 6.4. Nút Thắt Cổ Chai Phần Cứng (Hardware Bottleneck) Trên Node IoT
1. **ML-DSA-65 là "Điểm ngọt" (Sweet Spot):**
   Trong khi ML-DSA-87 có kích thước khối quá lớn (720 KB) khiến độ trễ xác thực trên IoT bị đội lên 57.72 ms, và ECDSA tốn CPU tới 77.56 ms do phép nhân điểm elliptic, thì **ML-DSA-65 đạt độ trễ thấp kỷ lục (11.18 ms trên IoT và 11.51 ms trên Edge)**, mang lại thông lượng E2E cao nhất toàn mạng lưới (**325.73 tx/s**).
2. **Nút thắt Băng thông & Bộ nhớ đệm:**
   Mặc dù thẩm định toán học của PQC cực nhanh, kích thước gói tin vẫn là thách thức lớn nhất: khối tin 50 giao dịch của ML-DSA-87 chiếm hơn 700 KB. Với 1,000 txs/block, dung lượng sẽ chạm mốc ~14.5 MB, đe dọa trực tiếp bộ nhớ heap của các thiết bị nhúng IoT.

---

## 7. HƯỚNG DẪN TÁI LẬP KẾT QUẢ (REPRODUCIBILITY GUIDE)

Quy trình chuẩn DevOps giúp tái lập 100% số liệu:

```powershell
# Bước 1: Build Docker Image tích hợp liboqs C Engine
docker build -t blockchain-node:perf -f perf/Dockerfile .

# Bước 2: Sinh tập dữ liệu 8 file chuẩn hóa ECDSA + ML-DSA-(44, 65, 87)
docker run --rm -v "${PWD}:/app" blockchain-node:perf python perf/generate_perf01_txs.py

# Bước 3: Chạy kịch bản Micro-Benchmark & Săn OOM-Killer
python perf/perf01_stress_test.py

# Bước 4: Chạy kịch bản Macro-Benchmark P2P 3 Nodes
python perf/perf01_macro_stress.py
```

---

## 8. KHUYẾN NGHỊ KIẾN TRÚC DEVOPS & AN TOÀN HỆ THỐNG

1. **Lựa chọn ML-DSA-65 làm chuẩn mặc định:**
   Thực nghiệm chứng minh ML-DSA-65 đạt hiệu năng toàn diện nhất (Sweet Spot) giữa độ an toàn tương đương AES-192 và thông lượng toàn trình 325.7 tx/s.
2. **Thiết bị Nhúng IoT chỉ nên đóng vai trò Signer Node (Light Client):**
   Với giới hạn RAM $\le$ 128MB, IoT không nên tham gia lưu trữ Mempool hay đồng thuận chuỗi vì nguy cơ bị Linux Kernel OOM-Killer tiêu diệt (Exit 137) tại Tx #1050 (L5) hoặc Tx #1350 (L3).
3. **Triển khai Kiến trúc Phân tầng (Tiered Hierarchical Topology):**
   - **Tầng 1 (IoT Sensors):** Ký số cục bộ và gửi giao dịch lên trạm biên.
   - **Tầng 2 (Edge Gateways - 512MB RAM):** Lọc Mempool và chuyển tiếp khối.
   - **Tầng 3 (Server / Cloud Nodes - 4GB+ RAM, 4 vCPU):** Đào khối PoW và duy trì sổ cái toàn vẹn.
4. **Hạn ngạch Mempool theo Dung lượng Byte (Byte-based Quota):**
   Cần giới hạn mempool theo tổng dung lượng byte (vd: tối đa 20 MB) thay vì số lượng giao dịch để tránh vượt trần RAM vật lý.

---

## 9. DANH MỤC SẢN PHẨM BÀN GIAO (DELIVERABLES)

| STT | Tên Sản phẩm / Tệp tin | Đường dẫn Tuyệt đối | Mô tả Chi tiết |
| :---: | :--- | :--- | :--- |
| 1 | **Dockerfile** | [`perf/Dockerfile`](file:///d:/assignment/btl/Blockchain-CSATT/perf/Dockerfile) | File Dockerfile đóng gói Node, biên dịch `liboqs` C engine FIPS 204. |
| 2 | **Dataset Generator** | [`perf/generate_perf01_txs.py`](file:///d:/assignment/btl/Blockchain-CSATT/perf/generate_perf01_txs.py) | Script sinh các tập dữ liệu ECDSA và ML-DSA-(44, 65, 87). |
| 3 | **Micro Test Driver** | [`perf/perf01_stress_test.py`](file:///d:/assignment/btl/Blockchain-CSATT/perf/perf01_stress_test.py) | Engine kiểm thử Micro 3x4 và săn tìm sự kiện OOM-Killed (Exit 137). |
| 4 | **Macro Test Driver** | [`perf/perf01_macro_stress.py`](file:///d:/assignment/btl/Blockchain-CSATT/perf/perf01_macro_stress.py) | Engine kiểm thử Macro trên mạng P2P đa node phân cấp. |
| 5 | **Ma trận Micro 3x4 (CSV)** | [`perf/results/perf01_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_matrix.csv) | Bảng dữ liệu thực nghiệm 12 đợt (TPS, RAM Peak, Avg CPU, Throttling). |
| 6 | **Biểu đồ OOM Risk Matrix (PNG)** | [`perf/results/perf01_oom_risk_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_oom_risk_chart.png) | Biểu đồ 3 panel so sánh Peak RAM, Ingestion TPS và CPU Saturation. |
| 7 | **Số liệu Tải Cực hạn OOM (CSV)** | [`perf/results/perf01_extreme_oom_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_extreme_oom_matrix.csv) | Dữ liệu quy đạo RAM và sự kiện OOM-Killed kép (#1050 & #1350). |
| 8 | **Biểu đồ Extreme OOM Cliff (PNG)** | [`perf/results/perf01_extreme_oom_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_extreme_oom_chart.png) | Biểu đồ trực quan hóa ranh giới OOM của ML-DSA-87 & 65 vs ML-DSA-44 & ECDSA. |
| 9 | **Ma trận Macro P2P (CSV)** | [`perf/results/perf01_macro_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_macro_matrix.csv) | Bảng số liệu độ trễ lan truyền khối, wire payload và CPU các node. |
| 10 | **Dữ liệu Thô Macro (JSON)** | [`perf/results/perf01_macro_results.json`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_macro_results.json) | File JSON lưu trữ chi tiết toàn bộ telemetry của đợt test Macro. |
| 11 | **Biểu đồ Macro Benchmark (PNG)** | [`perf/results/perf01_macro_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_macro_chart.png) | Biểu đồ 3 panel so sánh Block Delay, Wire Payload và CPU Saturation. |
| 12 | **Báo cáo Kỹ thuật Đầy đủ (MD)** | [`perf/PERF01_BENCHMARK_REPORT.md`](file:///d:/assignment/btl/Blockchain-CSATT/perf/PERF01_BENCHMARK_REPORT.md) | Tài liệu báo cáo hoàn chỉnh phục vụ nghiệm thu đồ án. |
