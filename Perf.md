# BÁO CÁO KỸ THUẬT KỊCH BẢN PERF-01
## ĐO LƯỜNG GIỚI HẠN TÀI NGUYÊN NODE TRÊN PHẦN CỨNG YẾU (RESOURCE CONSTRAINED STRESS TEST)
### So Sánh Toàn Diện: ECDSA vs ML-DSA-44 vs ML-DSA-65 vs ML-DSA-87 (NIST FIPS 204 PQC Spectrum)

> [!NOTE]
> **Tài liệu đầy đủ & Báo cáo hoàn chỉnh:**
> 👉 **Báo cáo Kỹ thuật Đầy đủ (10 Chương):** [`perf/PERF01_BENCHMARK_REPORT.md`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/PERF01_BENCHMARK_REPORT.md)  
> 👉 **Bản xuất cho Google Docs (Đầy đủ bảng biểu & sơ đồ):** [`perf/PERF01_GOOGLE_DOCS_EXPORT.md`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/PERF01_GOOGLE_DOCS_EXPORT.md)  
> 👉 **Báo cáo Trực tuyến trên Google Docs:** [Google Docs PERF-01 (heading=h.m3dzhewaqa7b)](https://docs.google.com/document/d/11TLElp3ceeBPXwJGntcr8gvw5fgNlUeG/edit#heading=h.m3dzhewaqa7b)  
> 👉 **Cẩm nang Hỏi - Đáp & Bảo vệ Đồ án:** [`perf/note.md`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/note.md)  
> 👉 **Giải thích 16 Tệp tin Dữ liệu Đầu vào & Đầu ra:** [`perf/PERF_FILES_EXPLANATION.md`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/PERF_FILES_EXPLANATION.md)  
> 👉 **Hướng dẫn Vận hành Docker DevOps:** [`perf/README.md`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/README.md)  

---

## 1. Tóm Tắt Kết Quả Then Chốt (Executive Summary)

Kịch bản **PERF-01** do **Thành viên 4 (Hardware Benchmark & DevOps)** thiết kế và triển khai nhằm đánh giá tính khả thi, độ an toàn bộ nhớ và mức tiêu hao tài nguyên khi đưa toàn bộ dải chữ ký số hậu lượng tử **NIST FIPS 204 (ML-DSA-44 / ML-DSA-65 / ML-DSA-87)** vào mạng lưới Blockchain thực tế với các thiết bị biên hạn chế tài nguyên (Edge / IoT), đối chứng cùng chuẩn cổ điển **ECDSA (secp256k1)**.

### 1.1. Ma Trận Vi Mô 3x4 (Server, Edge, IoT x 4 Thuật Toán)
* **Server Node (4.0 vCPU, 4096MB RAM):** Không gặp bất kỳ hiện tượng nghẽn nào (`CFS Throttled = 0.0 ms`). Nhờ thuật toán biến đổi số học NTT (*Number Theoretic Transform*) kết hợp C-extension `liboqs` nhả khóa Python GIL, **ML-DSA-44** đạt thông lượng tiếp nhận cao nhất **689.66 tx/s (0.725s)**, kế đó là **ML-DSA-65** đạt **655.31 tx/s (0.763s)** và **ML-DSA-87** đạt **617.28 tx/s (0.810s)**, vượt trội 43% - 60% so với **ECDSA (431.03 tx/s)**.
* **Edge Node (1.0 vCPU, 512MB RAM):** ML-DSA-44 đạt 495.05 tx/s, ML-DSA-65 đạt 489.24 tx/s, ML-DSA-87 đạt 438.21 tx/s, vượt trội so với ECDSA (298.33 tx/s). Đỉnh RAM của cả 4 thuật toán đều nằm trong vùng an toàn (48.8 - 55.0 MB, chiếm <11% hạn mức).
* **IoT Node (0.5 vCPU, 128MB RAM):** CPU đơn nhân bị bão hòa triệt để (110% - 116% quota cgroups). ECDSA mất 3.365s và bị Linux Kernel can thiệp bóp xung nhịp (CFS CPU Throttled) tới **5,412.53 ms** (TPS tiếp nhận đạt 148.59 tx/s). Các thuật toán ML-DSA xử lý nhanh hơn (2.2s - 2.4s, đạt 208 - 226 tx/s) do chi phí thẩm định trên vành đa thức nhẹ hơn phép nhân điểm elliptic vô hướng trên chip yếu.

### 1.2. Bài Test Tải Cực Hạn & Hiện Tượng OOM-Killer Kép (60MB RAM Hard Limit)
Khi dồn dập nạp **1,500 giao dịch** vào hàng đợi Mempool của Node IoT bị ép trần RAM xuống **60.0 MB cứng** (cấm Swap):
* **ML-DSA-87 (NIST Level 5 - 7,219 B/tx):** Chữ ký lớn nhất khiến Mempool phình to cực nhanh. Tại **Giao dịch #900**, RAM chạm 60.0 MB $\rightarrow$ **Linux Kernel cgroups OOM-Killer lập tức gửi tín hiệu `SIGKILL` (Exit 137)** tiêu diệt tiến trình.
* **ML-DSA-65 (NIST Level 3 - 5,261 B/tx):** Đóng vai trò là "điểm gãy trung gian", kích thước payload ~10.8 KB/wire khiến Mempool chạm trần 60MB tại **Giao dịch #1300** $\rightarrow$ **Kích hoạt sự kiện OOM-Killed thứ hai (Exit 137)**.
* **ML-DSA-44 (NIST Level 2 - 3,732 B/tx):** Nhờ payload gọn hơn, đỉnh RAM đạt xấp xỉ 59.84 MB (99.7% trần), **sống sót trọn vẹn 1,500 giao dịch**.
* **ECDSA (secp256k1 - 128 B/tx):** Chữ ký siêu nhỏ (64 bytes), RAM duy trì ổn định tuyệt đối ở mức **~46.8 MB**.

### 1.3. Macro-Benchmark Mạng P2P Phân Cấp (Server -> Edge -> IoT)
* **Độ trễ lan truyền & xác thực khối (Block Propagation Delay cho 100 txs):**
  * **ML-DSA-44:** Nhanh nhất trên toàn tuyến (**23.79 ms** tại Edge, **22.25 ms** tại IoT).
  * **ML-DSA-65:** Độ trễ là **29.55 ms** tại Edge và **36.00 ms** tại IoT.
  * **ML-DSA-87:** Khối đào 100 txs phình to lên **1,439.42 KB**, độ trễ thẩm định trên IoT là **33.59 ms** (vẫn nhanh hơn nhiều so với ECDSA).
  * **ECDSA:** Dù khối siêu nhẹ (54.46 KB), nhưng thuật toán xác thực ECDSA thuần Python trên chip yếu 0.5 vCPU tốn thời gian tới **237.83 ms** (chậm gấp 10.7 lần ML-DSA-44).
* **Dung lượng đường truyền (Wire Payload cho 100 txs):**
  * ECDSA: 48.73 KB $\rightarrow$ ML-DSA-44: 753.03 KB $\rightarrow$ ML-DSA-65: 1,051.66 KB $\rightarrow$ ML-DSA-87: 1,434.08 KB (phình to gấp 29.4 lần).
* **Thông lượng toàn trình (E2E TPS):**
  * ML-DSA-44 (227.79 tx/s) $\rightarrow$ ML-DSA-65 (192.31 tx/s) $\rightarrow$ ML-DSA-87 (163.40 tx/s) $\rightarrow$ ECDSA (118.20 tx/s).

---

## 2. Danh Mục Sản Phẩm & Kết Quả Bàn Giao (Deliverables)

Tất cả dữ liệu thô, ma trận kết quả và biểu đồ được sinh tự động và lưu trữ tại thư mục [`perf/`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/):

| Hạng mục | Đường dẫn tệp | Mô tả |
| :--- | :--- | :--- |
| **Bản xuất Google Docs** | [`perf/PERF01_GOOGLE_DOCS_EXPORT.md`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/PERF01_GOOGLE_DOCS_EXPORT.md) | Tài liệu định dạng chuẩn để dán trực tiếp vào Google Docs. |
| **Báo cáo chuyên sâu** | [`perf/PERF01_BENCHMARK_REPORT.md`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/PERF01_BENCHMARK_REPORT.md) | Báo cáo kỹ thuật chi tiết 10 chương đầy đủ bảng biểu số liệu. |
| **Biểu đồ OOM Risk** | [`perf/results/perf01_oom_risk_chart.png`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/results/perf01_oom_risk_chart.png) | Trực quan hóa ma trận vi mô 3x4 và vùng nguy cơ OOM. |
| **Biểu đồ Extreme OOM** | [`perf/results/perf01_extreme_oom_chart.png`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/results/perf01_extreme_oom_chart.png) | Ranh giới sinh tử: Điểm rơi OOM của ML-DSA-87 (#900), ML-DSA-65 (#1300) vs ML-DSA-44 & ECDSA. |
| **Biểu đồ Macro P2P** | [`perf/results/perf01_macro_chart.png`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/results/perf01_macro_chart.png) | Độ trễ lan truyền, wire payload và mức tải CPU trên 3 node mạng. |
| **Số liệu Ma trận 3x4** | [`perf/results/perf01_matrix.csv`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/results/perf01_matrix.csv) | Kết quả chi tiết 12 đợt đo đạc vi mô. |
| **Số liệu Extreme OOM** | [`perf/results/perf01_extreme_oom_matrix.csv`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/results/perf01_extreme_oom_matrix.csv) | Nhật ký dung lượng RAM qua 30 mốc đo kiểm tra OOM. |
| **Số liệu Macro P2P** | [`perf/results/perf01_macro_matrix.csv`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/results/perf01_macro_matrix.csv) | Độ trễ, payload kích thước và CPU bão hòa vĩ mô. |
| **Cẩm nang Q&A & Bảo vệ** | [`perf/note.md`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/note.md) | Giải thích nghịch lý hiệu năng và chuẩn bị bảo vệ đồ án. |
| **Mã nguồn thực thi** | [`perf/perf01_stress_test.py`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/perf01_stress_test.py) <br> [`perf/perf01_macro_stress.py`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/perf01_macro_stress.py) | Engine kiểm thử tự động, telemetry cgroups v2 và vẽ đồ thị. |
| **Cấu hình Docker** | [`perf/Dockerfile`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/Dockerfile) <br> [`perf/docker-compose.yml`](file:///c:/Feixiao/Code/btl/Blockchain-CSATT/perf/docker-compose.yml) | Đóng gói C engine `liboqs` FIPS 204 và thiết lập hạn mức phần cứng. |

---

## 3. Lệnh Tái Lập Nhanh (Quick Start)

```powershell
# 1. Build Docker image
docker build -t blockchain-node:perf -f perf/Dockerfile .

# 2. Sinh tập dữ liệu 8 file chuẩn hóa ECDSA + ML-DSA-(44, 65, 87)
docker run --rm -v "${PWD}:/app" blockchain-node:perf python perf/generate_perf01_txs.py

# 3. Chạy kiểm thử vi mô & săn OOM-Killer
python perf/perf01_stress_test.py

# 4. Chạy kiểm thử vĩ mô mạng P2P 3 node
python perf/perf01_macro_stress.py
```
