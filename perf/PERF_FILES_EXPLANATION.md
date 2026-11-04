# TÀI LIỆU GIẢI THÍCH CHI TIẾT TẬP TIN DỮ LIỆU & KẾT QUẢ MODULE PERF-01
## Bóc Tách Cấu Trúc, Ý Nghĩa Chỉ Số và Mối Tương Quan Giữa Các Tệp JSON, CSV & PNG

> **Mã học phần:** Cơ sở An toàn Thông tin / Blockchain Engineering  
> **Chuyên mục:** Module PERF-01 (Hardware Benchmark & DevOps)  
> **Phạm vi tài liệu:** Giải thích chi tiết **16 tệp tin** gồm 8 tệp dữ liệu đầu vào (`perf/data/*.json`) và 8 tệp kết quả/biểu đồ thực nghiệm (`perf/results/*.csv`, `*.json`, `*.png`).

---

## MỤC LỤC TỔNG QUAN

1. [Sơ Đồ Phân Loại Tệp Tin Trong Module PERF](#1-sơ-đồ-phân-loại-tệp-tin-trong-module-perf)
2. [Chi Tiết Nhóm Dữ Liệu Đầu Vào (`perf/data/*.json`)](#2-chi-tiết-nhóm-dữ-liệu-đầu-vào-perfdatajson)
   - 2.1. Cấu trúc chuẩn của một giao dịch đã ký
   - 2.2. Nhóm Dataset Baseline 500 Giao Dịch
   - 2.3. Nhóm Dataset Stress Test 2,000 Giao Dịch
   - 2.4. Bảng so sánh dung lượng và kích thước chữ ký
3. [Chi Tiết Nhóm Bảng Số Liệu Thực Nghiệm (`perf/results/*.csv`)](#3-chi-tiết-nhóm-bảng-số-liệu-thực-nghiệm-perfresultscsv)
   - 3.1. `perf01_matrix.csv` (Ma trận vi mô 3x4)
   - 3.2. `perf01_extreme_oom_matrix.csv` (Săn OOM-Killer Kép 60MB RAM)
   - 3.3. `perf01_macro_matrix.csv` (Mạng P2P 3 Node phân cấp)
4. [Chi Tiết Nhóm Dữ Liệu Kết Quả Dạng Máy Đọc (`perf/results/*.json`)](#4-chi-tiết-nhóm-dữ-liệu-kết-quả-dạng-máy-đọc-perfresultsjson)
   - 4.1. `perf01_results.json` (Telemetry vi mô cgroups v2)
   - 4.2. `perf01_macro_results.json` (Telemetry mạng P2P đa tầng)
5. [Chi Tiết Nhóm Biểu Đồ Trực Quan Hóa (`perf/results/*.png`)](#5-chi-tiết-nhóm-biểu-đồ-trực-quan-hóa-perfresultspng)
   - 5.1. `perf01_oom_risk_chart.png` (Ma trận 3 Panel rủi ro tài nguyên)
   - 5.2. `perf01_extreme_oom_chart.png` (Biểu đồ vách đá OOM-Killer Kép)
   - 5.3. `perf01_macro_chart.png` (Biểu đồ vĩ mô P2P đa chỉ số)
6. [Bảng Ma Trận Tra Cứu Nhanh (Cheat Sheet)](#6-bảng-ma-trận-tra-cứu-nhanh-cheat-sheet)

---

## 1. SƠ ĐỒ PHÂN LOẠI TỆP TIN TRONG MODULE PERF

```text
perf/
├── data/                                 # [NHÓM 1: DỮ LIỆU ĐẦU VÀO]
│   ├── txs_500_ecdsa.json                # 500 txs ECDSA secp256k1 (266 KB)
│   ├── txs_500_mldsa44.json              # 500 txs ML-DSA-44 NIST Category 2 (3.87 MB)
│   ├── txs_500_mldsa65.json              # 500 txs ML-DSA-65 NIST Category 3 (5.40 MB)
│   ├── txs_500_mldsa87.json              # 500 txs ML-DSA-87 NIST Category 5 (7.36 MB)
│   ├── txs_stress_ecdsa.json             # 2,000 txs ECDSA cho test tải (1.07 MB)
│   ├── txs_stress_mldsa44.json           # 2,000 txs ML-DSA-44 cho test tải (15.49 MB)
│   ├── txs_stress_mldsa65.json           # 2,000 txs ML-DSA-65 cho test tải cực hạn (21.61 MB)
│   └── txs_stress_mldsa87.json           # 2,000 txs ML-DSA-87 cho test tải cực hạn (29.44 MB)
└── results/                              # [NHÓM 2: DỮ LIỆU & BIỂU ĐỒ ĐẦU RA]
    ├── perf01_matrix.csv                 # Bảng số liệu vi mô ma trận 3x4 (12 đợt đo)
    ├── perf01_results.json               # Dữ liệu vi mô đầy đủ kèm telemetry cgroups
    ├── perf01_oom_risk_chart.png         # Biểu đồ 3 panel phân tích rủi ro RAM & CPU
    ├── perf01_extreme_oom_matrix.csv     # Bảng theo dõi quỹ đạo RAM ép trần 60MB (4 thuật toán)
    ├── perf01_extreme_oom_chart.png      # Biểu đồ điểm rơi OOM-Killed Kép (#1050 & #1300)
    ├── perf01_macro_matrix.csv           # Bảng số liệu vĩ mô mạng P2P 3 node phân cấp
    ├── perf01_macro_results.json         # Dữ liệu vĩ mô chi tiết từng node (Server/Edge/IoT)
    └── perf01_macro_chart.png            # Biểu đồ 3 panel trễ lan truyền, payload & CPU
```

---

## 2. CHI TIẾT NHÓM DỮ LIỆU ĐẦU VÀO (`perf/data/*.json`)

Toàn bộ các tệp trong thư mục `perf/data/` được sinh tự động bởi script [`perf/generate_perf01_txs.py`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/generate_perf01_txs.py). Mỗi tệp chứa một mảng JSON các giao dịch đã được ký số hợp lệ bằng các thuật toán tương ứng.

### 2.1. Cấu Trúc Chuẩn Của Một Giao Dịch Đã Ký

```json
{
  "sender_address": "8963aaea29ab...",
  "recipient_address": "4d67538820a505b4...",
  "amount": "1.0",
  "nonce": 1,
  "signature": "3045022100...",
  "algorithm": "ECDSA"
}
```

* **`sender_address` (String Hex):** Khóa công khai (Public Key) của người gửi.
  * *ECDSA:* 64 bytes (128 hex chars) - uncompressed key.
  * *ML-DSA-44:* 1,312 bytes (2,624 hex chars) - FIPS 204 Category 2.
  * *ML-DSA-65:* 1,952 bytes (3,904 hex chars) - FIPS 204 Category 3.
  * *ML-DSA-87:* 2,592 bytes (5,184 hex chars) - FIPS 204 Category 5.
* **`recipient_address` (String Hex):** Địa chỉ ví của người nhận tiền.
* **`amount` (String):** Số lượng coin chuyển giao (`"1.0"`).
* **`nonce` (Integer):** Số thứ tự giao dịch tăng dần (`1, 2, ..., N`) nhằm chống Replay Attack.
* **`signature` (String Hex):** Chữ ký số mật mã do khóa riêng tư sinh ra.
* **`algorithm` (String):** Định danh giải thuật (`"ECDSA"`, `"ML-DSA-44"`, `"ML-DSA-65"`, `"ML-DSA-87"`).

---

### 2.2. Nhóm Dataset Baseline (500 Giao Dịch)

Dùng cho bài kiểm thử vi mô ma trận 3x4 trong [`perf/perf01_stress_test.py`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/perf01_stress_test.py):

| Tên Tệp | Dung Lượng | Số Tx | Thuật Toán & Chuẩn Ký | Kích Thước Chữ Ký | Mục Đích Sử Dụng |
| :--- | :---: | :---: | :--- | :---: | :--- |
| [`txs_500_ecdsa.json`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/data/txs_500_ecdsa.json) | 266 KB | 500 | ECDSA (đường cong `secp256k1`) | 64 bytes | Mốc đối chứng cổ điển (Baseline truyền thống, giống Bitcoin/Ethereum). |
| [`txs_500_mldsa44.json`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/data/txs_500_mldsa44.json) | 3.87 MB | 500 | ML-DSA-44 (NIST FIPS 204 Level 2) | 2,420 bytes | Đo đạc hiệu năng chuẩn PQC nhẹ nhất, sống sót qua trần 60MB RAM. |
| [`txs_500_mldsa65.json`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/data/txs_500_mldsa65.json) | 5.40 MB | 500 | ML-DSA-65 (NIST FIPS 204 Level 3) | 3,309 bytes | **Chuẩn khuyến nghị mặc định của NIST (Sweet Spot)**. |
| [`txs_500_mldsa87.json`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/data/txs_500_mldsa87.json) | 7.36 MB | 500 | ML-DSA-87 (NIST FIPS 204 Level 5) | 4,627 bytes | Đánh giá mức tiêu thụ tài nguyên tối đa của chuẩn PQC an toàn nhất. |

---

### 2.3. Nhóm Dataset Stress Test (2,000 Giao Dịch)

Dùng cho bài kiểm tra tải dồn dập và kịch bản săn tìm sự kiện tràn bộ nhớ Linux OOM-Killer:

| Tên Tệp | Dung Lượng | Số Tx | Thuật Toán | Điểm Đặc Biệt Trong Thực Nghiệm |
| :--- | :---: | :---: | :--- | :--- |
| [`txs_stress_ecdsa.json`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/data/txs_stress_ecdsa.json) | 1.07 MB | 2,000 | ECDSA | Dung lượng cực nhỏ, 2,000 txs chỉ chiếm 1MB bộ nhớ. Đối chứng an toàn trong bài test 60MB RAM. |
| [`txs_stress_mldsa44.json`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/data/txs_stress_mldsa44.json) | 15.49 MB | 2,000 | ML-DSA-44 | 2,000 giao dịch chiếm ~15.5 MB. Sống sót trọn vẹn 1,500 txs trên node IoT 60MB RAM. |
| [`txs_stress_mldsa65.json`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/data/txs_stress_mldsa65.json) | 21.61 MB | 2,000 | ML-DSA-65 | Chiếm ~21.6 MB. Kích nổ sự kiện Linux Kernel OOM-Killer tại **Tx #1300** trên node 60MB RAM. |
| [`txs_stress_mldsa87.json`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/data/txs_stress_mldsa87.json) | 29.44 MB | 2,000 | ML-DSA-87 | Dung lượng khổng lồ (~29.5 MB). Kích nổ sự kiện Linux Kernel OOM-Killer tại **Tx #900** trên node 60MB RAM. |

---

### 2.4. Bảng So Sánh Kích Thước Chữ Ký & Tải Trọng Mạng

| Thuật Toán | PK (Bytes) | Sig (Bytes) | 1 Tx Dây Mạng (Bytes) | 500 Txs JSON | Hệ Số Phình So Với ECDSA |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **ECDSA** | 64 | 64 | 499 | 266 KB | **$1.0\times$ (Mốc)** |
| **ML-DSA-44** | 1,312 | 2,420 | 7,711 | 3.87 MB | **$15.5\times$** |
| **ML-DSA-65** | 1,952 | 3,309 | 10,769 | 5.40 MB | **$21.6\times$** |
| **ML-DSA-87** | 2,592 | 4,627 | 14,685 | 7.36 MB | **$29.4\times$** |

---

## 3. CHI TIẾT NHÓM BẢNG SỐ LIỆU THỰC NGHIỆM (`perf/results/*.csv`)

### 3.1. Tệp `perf01_matrix.csv` (Ma Trận Vi Mô 3x4)
* **Đường dẫn:** [`perf/results/perf01_matrix.csv`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/results/perf01_matrix.csv)
* **Quy mô dữ liệu:** 13 dòng (1 tiêu đề + 12 dòng tương ứng với 3 Hardware Profiles $\times$ 4 Thuật toán).
* **Mục đích:** Lưu trữ kết quả đo lường vi mô khi nạp 500 giao dịch qua cổng HTTP REST API `/transactions/new`.

#### Ý Nghĩa Từng Cột:
1. `Hardware Profile`: Tên hồ sơ phần cứng Docker (`Server (DataCenter / Cloud)`, `Edge Gateway (Raspberry Pi 4)`, `IoT Embedded (Smart Meter / Sensor)`).
2. `vCPUs`: Số lượng nhân CPU ảo được cấp phát qua cgroups (`4.0`, `1.0`, `0.5`).
3. `RAM Limit (MB)`: Hạn mức RAM tối đa (`4096`, `512`, `128`).
4. `Signature Algorithm`: Thuật toán ký số kiểm thử.
5. `500 Txs Processed`: Tỉ lệ giao dịch xử lý thành công (`500/500`).
6. `Elapsed Time (s)`: Tổng thời gian (giây) nạp 500 giao dịch vào Mempool.
7. `Ingestion TPS (tx/s)`: Tốc độ nạp giao dịch trung bình ($\frac{500}{\text{Elapsed Time}}$).
8. `Baseline RAM (MB)`: RAM ở trạng thái tĩnh (idle) trước khi bắn tải.
9. `Peak RAM (MB)`: Đỉnh RAM cao nhất trong suốt quá trình tiếp nhận.
10. `RAM Ceiling Usage (%)`: Tỉ lệ phần trăm RAM đỉnh so với trần cgroups.
11. `Avg CPU (%)`: Mức tải CPU đo lường từ cgroups `cpu.stat`.
12. `Normalized CPU (%)`: Mức tải CPU đã chuẩn hóa về thang $0 - 100\%$ theo hạn ngạch.
13. `Peak CPU (%)`: Đỉnh CPU cao nhất ghi nhận được trong một cửa sổ đo telemetry.
14. `CPU Throttled (ms)`: Tổng thời gian Linux CFS Scheduler ép tiến trình tạm dừng hoạt động.
15. `OOM Risk Status`: Trạng thái cảnh báo rủi ro tràn bộ nhớ.

---

### 3.2. Tệp `perf01_extreme_oom_matrix.csv` (Săn OOM-Killer Kép 60MB RAM)
* **Đường dẫn:** [`perf/results/perf01_extreme_oom_matrix.csv`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/results/perf01_extreme_oom_matrix.csv)
* **Quy mô dữ liệu:** Theo dõi quỹ đạo tiêu thụ RAM của cả 4 thuật toán trên node IoT bị ép trần RAM xuống đúng **60 MB**.

#### Ý Nghĩa Từng Cột:
1. `Tx_Count`: Số lượng giao dịch tích lũy (`50, 100, ..., 1500`).
2. `MLDSA87_RAM_MB`: Dung lượng RAM của ML-DSA-87 tại mốc `Tx_Count`.
3. `MLDSA65_RAM_MB`: Dung lượng RAM của ML-DSA-65 tại mốc `Tx_Count`.
4. `MLDSA44_RAM_MB`: Dung lượng RAM của ML-DSA-44 tại mốc `Tx_Count`.
5. `ECDSA_RAM_MB`: Dung lượng RAM của ECDSA tại mốc `Tx_Count`.
6. `Ceiling_Limit_MB`: Trần cgroups cứng (`60.0 MB`).
7. `MLDSA87_OOM_Killed`: Chuyển thành `True` từ giao dịch **#1050** khi tiến trình chết vì `SIGKILL (Exit Code 137)`.
8. `MLDSA65_OOM_Killed`: Chuyển thành `True` từ giao dịch **#1300** khi tiến trình chết vì `SIGKILL (Exit Code 137)`.
9. `MLDSA44_OOM_Killed`: `False` xuyên suốt 1,500 txs (sống sót an toàn).
10. `ECDSA_OOM_Killed`: `False` xuyên suốt 1,500 txs (ổn định ở mức ~46 MB).

---

### 3.3. Tệp `perf01_macro_matrix.csv` (Mạng P2P 3 Node Phân Cấp)
* **Đường dẫn:** [`perf/results/perf01_macro_matrix.csv`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/results/perf01_macro_matrix.csv)
* **Quy mô dữ liệu:** 5 dòng (1 header + 4 dòng kết quả cho ECDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87).
* **Mục đích:** Lưu trữ kết quả đo đạc kiểm thử toàn diện vĩ mô (Macro End-to-End) trên cụm mạng P2P gồm 3 Node phân cấp (Server 5000 $\rightarrow$ Edge 5001 $\rightarrow$ IoT 5002).

---

## 4. CHI TIẾT NHÓM DỮ LIỆU KẾT QUẢ DẠNG MÁY ĐỌC (`perf/results/*.json`)

* **`perf01_results.json`:** Dữ liệu vi mô đầy đủ kèm telemetry cgroups phân cấp theo profile và thuật toán.
* **`perf01_macro_results.json`:** Dữ liệu vĩ mô chi tiết từng node (Server/Edge/IoT) với độ trễ lan truyền khối, wire payload và CPU chuẩn hóa.

---

## 5. CHI TIẾT NHÓM BIỂU ĐỒ TRỰC QUAN HÓA (`perf/results/*.png`)

### 5.1. Tệp `perf01_oom_risk_chart.png` (Ma Trận Vi Mô 3 Panel)
* **Đường dẫn:** [`perf/results/perf01_oom_risk_chart.png`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/results/perf01_oom_risk_chart.png)
* **Panel 1 (Peak RAM):** Trực quan hóa đỉnh RAM của 4 thuật toán trên 3 môi trường phần cứng so với trần 128MB (IoT) và 512MB (Edge).
* **Panel 2 (Ingestion TPS):** Tốc độ nạp mempool vượt trội của các thuật toán ML-DSA (đạt tới 719 tx/s trên Server) so với ECDSA (416 tx/s).
* **Panel 3 (CPU Saturation):** Mức tải CPU và hiện tượng ngắt xung nhịp CFS Throttling trên Edge và IoT.

---

### 5.2. Tệp `perf01_extreme_oom_chart.png` (Biểu Đồ Vách Đá OOM-Killer Kép)
* **Đường dẫn:** [`perf/results/perf01_extreme_oom_chart.png`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/results/perf01_extreme_oom_chart.png)
* **Ý nghĩa:** Trực quan hóa ranh giới sinh tử trên Node IoT 60MB RAM:
  * **Đường đỏ (ML-DSA-87 Level 5):** Chạm trần 60MB và bị Linux OOM-Killer gửi `SIGKILL (Exit 137)` tại **Tx #1050**.
  * **Đường cam (ML-DSA-65 Level 3):** Chạm trần 60MB và bị Linux OOM-Killer gửi `SIGKILL (Exit 137)` tại **Tx #1300**.
  * **Đường xanh lá (ML-DSA-44 Level 2):** Lượn sát dưới trần 60MB và sống sót trọn vẹn 1,500 txs.
  * **Đường xanh dương (ECDSA secp256k1):** Phẳng tuyệt đối ở mức 46 MB.

---

### 5.3. Tệp `perf01_macro_chart.png` (Biểu Đồ Vĩ Mô Mạng P2P 3 Node)
* **Đường dẫn:** [`perf/results/perf01_macro_chart.png`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/results/perf01_macro_chart.png)
* **Panel 1 (Block Propagation Delay):** Độ trễ lan truyền và thẩm định khối sang Edge và IoT. **ML-DSA-65 đạt độ trễ thấp nhất toàn tuyến (~11 ms)**.
* **Panel 2 (Network Wire Payload):** So sánh dung lượng 100 txs và dung lượng khối đã đào đóng gói.
* **Panel 3 (Normalized CPU):** Phân tích mức bão hòa CPU giữa Server và IoT.

---

## 6. BẢNG MA TRẬN TRA CỨU NHANH (CHEAT SHEET)

| Tên Tệp | Định Dạng | Vị Trí Lưu Trữ | Vai Trò Chính | Ứng Dụng Đọc Khuyến Nghị |
| :--- | :---: | :--- | :--- | :--- |
| `txs_500_*.json` | JSON | `perf/data/` | Dữ liệu giao dịch nạp vi mô (Baseline) | VSCode, Notepad++, Python `json.load()` |
| `txs_stress_*.json` | JSON | `perf/data/` | Dữ liệu nạp dồn dập săn OOM (Stress) | VSCode, Python `json.load()` |
| `perf01_matrix.csv` | CSV | `perf/results/` | Bảng số liệu vi mô ma trận 3x4 | Microsoft Excel, Google Sheets, Pandas |
| `perf01_results.json` | JSON | `perf/results/` | Telemetry vi mô chi tiết máy đọc | Web Dashboard, API, CI/CD Script |
| `perf01_oom_risk_chart.png` | PNG | `perf/results/` | Biểu đồ 3 panel rủi ro bộ nhớ & CPU | Trình xem ảnh, nhúng vào Slide/Báo cáo |
| `perf01_extreme_oom_matrix.csv`| CSV | `perf/results/` | Dữ liệu diễn biến RAM bài test 60MB | Microsoft Excel, Origin, R Studio |
| `perf01_extreme_oom_chart.png` | PNG | `perf/results/` | Biểu đồ bằng chứng OOM-Killed kép Exit 137 | Trình xem ảnh, nhúng vào Slide/Báo cáo |
| `perf01_macro_matrix.csv` | CSV | `perf/results/` | Bảng số liệu vĩ mô mạng P2P phân cấp | Microsoft Excel, Google Sheets, Pandas |
| `perf01_macro_results.json` | JSON | `perf/results/` | Telemetry vĩ mô chi tiết từng node | Web Dashboard, Monitoring Log |
| `perf01_macro_chart.png` | PNG | `perf/results/` | Biểu đồ 3 panel độ trễ, payload & CPU | Trình xem ảnh, nhúng vào Slide/Báo cáo |

---
> **Ghi chú bảo trì:** Toàn bộ hệ thống kiểm thử đã được chuẩn hóa trọn vẹn theo chuẩn **NIST FIPS 204** (ML-DSA-44, ML-DSA-65, ML-DSA-87) và ECDSA secp256k1 trên nền tảng cgroups v2.
