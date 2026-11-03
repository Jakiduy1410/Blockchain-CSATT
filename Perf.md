# BÁO CÁO KỸ THUẬT KỊCH BẢN PERF-01
## ĐO LƯỜNG GIỚI HẠN TÀI NGUYÊN NODE TRÊN PHẦN CỨNG YẾU (RESOURCE CONSTRAINED STRESS TEST)
### So Sánh Toàn Diện: ECDSA vs ML-DSA-44 vs ML-DSA-65 vs ML-DSA-87 (NIST FIPS 204 PQC Spectrum)

> [!NOTE]
> **Tài liệu đầy đủ:** Toàn bộ báo cáo học thuật chuyên sâu 350+ dòng, số liệu thống kê chi tiết từng đợt chạy và phân tích kiến trúc được lưu trữ chính thức tại:
> 👉 **[`perf/PERF01_BENCHMARK_REPORT.md`](file:///d:/assignment/btl/Blockchain-CSATT/perf/PERF01_BENCHMARK_REPORT.md)**  
> 👉 Hướng dẫn vận hành Docker & chạy kịch bản: **[`perf/README.md`](file:///d:/assignment/btl/Blockchain-CSATT/perf/README.md)**  
> 👉 Giải thích chi tiết từng tệp JSON, CSV, PNG: **[`perf/PERF_FILES_EXPLANATION.md`](file:///d:/assignment/btl/Blockchain-CSATT/perf/PERF_FILES_EXPLANATION.md)**  
> 👉 **Bản báo cáo trực tuyến trên Google Docs:** [Báo Cáo Kỹ Thuật PERF-01 (Google Docs)](https://docs.google.com/document/d/1YHpdUAUFGrS151Kh72IDlp3UYkOmPeqvztNUNy0YSmE/edit)

---

## 1. Tóm Tắt Kết Quả Then Chốt (Executive Summary)

Kịch bản **PERF-01** do **Thành viên 4 (Hardware Benchmark & DevOps)** thiết kế và triển khai nhằm đánh giá tính khả thi, độ an toàn bộ nhớ và mức tiêu hao tài nguyên khi đưa toàn bộ dải chữ ký số hậu lượng tử **NIST FIPS 204 (ML-DSA-44 / ML-DSA-65 / ML-DSA-87)** vào mạng lưới Blockchain thực tế với các thiết bị biên hạn chế tài nguyên (Edge / IoT), đối chứng cùng chuẩn cổ điển **ECDSA (secp256k1)**.

### 1.1. Ma Trận Vi Mô 3x4 (Server, Edge, IoT x 4 Thuật Toán)
* **Server Node (4 vCPU, 4GB RAM):** Không gặp bất kỳ hiện tượng nghẽn nào. Nhờ biến đổi số học NTT (*Number Theoretic Transform*), **ML-DSA-65** đạt thông lượng tiếp nhận cao nhất **719.42 tx/s (0.695s)**, kế đó là **ML-DSA-44** đạt **712.25 tx/s (0.702s)** và **ML-DSA-87** đạt **663.13 tx/s (0.754s)**, nhanh gần gấp đôi **ECDSA (416.67 tx/s)**.
* **Edge Node (1 vCPU, 512MB RAM):** ML-DSA-44 duy trì độ ổn định cao nhất (0.926s, 539.96 tx/s). ML-DSA-65 và ML-DSA-87 đạt xấp xỉ ~489 tx/s. Đỉnh RAM của cả 4 thuật toán đều nằm trong vùng an toàn (46.6 - 58.3 MB, chiếm <12% hạn mức).
* **IoT Node (0.5 vCPU, 128MB RAM):** CPU đơn nhân bị bão hòa triệt để (116% - 126% quota cgroups). ECDSA mất tới 3.16s và bị Linux Kernel can thiệp "bóp" xung nhịp (CFS CPU Throttled) tới **5,403.7 ms**. Các thuật toán ML-DSA xử lý nhanh hơn (chỉ mất ~2.0s) do chi phí thẩm định trên vành đa thức nhẹ hơn phép nhân điểm elliptic vô hướng trên chip yếu.

### 1.2. Bài Test Tải Cực Hạn & Hiện Tượng OOM-Killer Kép (60MB RAM Ceiling)
Khi dồn dập nạp **1,500 giao dịch** vào Mempool của Node IoT bị ép trần RAM xuống **60 MB cứng**:
* **ML-DSA-87 (NIST Level 5 - 7,219 B/tx):** Chữ ký lớn nhất khiến Mempool phình to cực nhanh. Tại **Giao dịch #1050**, RAM chạm 60.1 MB $\rightarrow$ **Linux Kernel cgroups OOM-Killer lập tức gửi tín hiệu `SIGKILL` (Exit 137)** tiêu diệt tiến trình.
* **ML-DSA-65 (NIST Level 3 - 5,261 B/tx):** Đóng vai trò là "điểm gãy trung gian", kích thước payload ~10.8 KB/wire khiến Mempool chạm trần 60MB tại **Giao dịch #1350** $\rightarrow$ **Kích hoạt sự kiện OOM-Killed thứ hai (Exit 137)**.
* **ML-DSA-44 (NIST Level 2 - 3,732 B/tx):** Nhờ payload gọn hơn, đỉnh RAM đạt xấp xỉ 54-58 MB, **sống sót trọn vẹn 1,500 giao dịch**.
* **ECDSA (secp256k1 - 128 B/tx):** Chữ ký siêu nhỏ (64 bytes), RAM duy trì ổn định tuyệt đối ở mức **~46 MB**.

### 1.3. Macro-Benchmark Mạng P2P Phân Cấp (Server -> Edge -> IoT)
* **Độ trễ lan truyền & xác thực khối (Block Propagation Delay):**
  * **ML-DSA-65:** Đạt hiệu năng tối ưu nhất trên toàn tuyến (**11.51 ms** tại Edge, **11.18 ms** tại IoT) do thời gian xác thực cực nhanh bù đắp hoàn toàn phụ phí truyền dẫn mạng.
  * **ML-DSA-44:** Độ trễ tại Edge là 19.95 ms, IoT là 32.72 ms.
  * **ML-DSA-87:** Do dung lượng khối đào phình to lên tới **719.8 KB**, độ trễ xác thực trên Node IoT bị đội lên **57.72 ms**.
  * **ECDSA:** Dù khối siêu nhẹ (27.3 KB), nhưng thuật toán xác thực ECDSA trên chip yếu 0.5 vCPU tốn CPU tới **77.56 ms**.
* **Dung lượng đường truyền (Wire Payload cho 100 txs):**
  * ECDSA: 48.73 KB $\rightarrow$ ML-DSA-44: 753.03 KB $\rightarrow$ ML-DSA-65: 1,051.66 KB $\rightarrow$ ML-DSA-87: 1,434.08 KB (phình to gấp 29.4 lần).

---

## 2. Danh Mục Sản Phẩm & Kết Quả (Deliverables)

Tất cả dữ liệu thô, ma trận kết quả và biểu đồ được sinh tự động và lưu trữ tại thư mục [`perf/`](file:///d:/assignment/btl/Blockchain-CSATT/perf/):

| Hạng mục | Đường dẫn tệp | Mô tả |
| :--- | :--- | :--- |
| **Báo cáo chuyên sâu** | [`perf/PERF01_BENCHMARK_REPORT.md`](file:///d:/assignment/btl/Blockchain-CSATT/perf/PERF01_BENCHMARK_REPORT.md) | Báo cáo kỹ thuật chi tiết 9 chương đầy đủ bảng biểu số liệu. |
| **Biểu đồ OOM Risk** | [`perf/results/perf01_oom_risk_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_oom_risk_chart.png) | Trực quan hóa ma trận vi mô 3x4 và vùng nguy cơ OOM. |
| **Biểu đồ Extreme OOM** | [`perf/results/perf01_extreme_oom_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_extreme_oom_chart.png) | Ranh giới sinh tử: Điểm rơi OOM của ML-DSA-87 (#1050), ML-DSA-65 (#1350) vs ML-DSA-44 & ECDSA. |
| **Biểu đồ Macro P2P** | [`perf/results/perf01_macro_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_macro_chart.png) | Độ trễ lan truyền, wire payload và mức tải CPU trên 3 node mạng. |
| **Số liệu Ma trận 3x4** | [`perf/results/perf01_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_matrix.csv) | Kết quả chi tiết 12 đợt đo đạc vi mô. |
| **Số liệu Extreme OOM** | [`perf/results/perf01_extreme_oom_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_extreme_oom_matrix.csv) | Nhật ký dung lượng RAM theo từng block 50 giao dịch cho 4 thuật toán. |
| **Số liệu Macro P2P** | [`perf/results/perf01_macro_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_macro_matrix.csv) | Độ trễ, payload kích thước và CPU bão hòa vĩ mô. |
| **Mã nguồn thực thi** | [`perf/perf01_stress_test.py`](file:///d:/assignment/btl/Blockchain-CSATT/perf/perf01_stress_test.py) <br> [`perf/perf01_macro_stress.py`](file:///d:/assignment/btl/Blockchain-CSATT/perf/perf01_macro_stress.py) | Engine kiểm thử tự động, telemetry cgroups v2 và vẽ đồ thị. |
| **Cấu hình Docker** | [`perf/Dockerfile`](file:///d:/assignment/btl/Blockchain-CSATT/perf/Dockerfile) <br> [`perf/docker-compose.yml`](file:///d:/assignment/btl/Blockchain-CSATT/perf/docker-compose.yml) | Đóng gói C engine `liboqs` FIPS 204 và thiết lập hạn mức phần cứng. |

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
