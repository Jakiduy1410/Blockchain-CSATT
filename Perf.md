# BÁO CÁO KỸ THUẬT KỊCH BẢN PERF-01
## ĐO LƯỜNG GIỚI HẠN TÀI NGUYÊN NODE TRÊN PHẦN CỨNG YẾU (RESOURCE CONSTRAINED STRESS TEST)
### So Sánh Toàn Diện: ECDSA vs RSA-2048 vs ML-DSA-44 vs ML-DSA-87 (NIST FIPS 204 PQC)

> [!NOTE]
> **Tài liệu đầy đủ:** Toàn bộ báo cáo học thuật chuyên sâu 350+ dòng, số liệu thống kê chi tiết từng đợt chạy và phân tích kiến trúc được lưu trữ chính thức tại:
> 👉 **[`perf/PERF01_BENCHMARK_REPORT.md`](file:///d:/assignment/btl/Blockchain-CSATT/perf/PERF01_BENCHMARK_REPORT.md)**  
> 👉 Hướng dẫn vận hành Docker & chạy kịch bản: **[`perf/README.md`](file:///d:/assignment/btl/Blockchain-CSATT/perf/README.md)**

---

## 1. Tóm Tắt Kết Quả Then Chốt (Executive Summary)

Kịch bản **PERF-01** do **Thành viên 4 (Hardware Benchmark & DevOps)** thiết kế và triển khai nhằm đánh giá tính khả thi, độ an toàn bộ nhớ và mức tiêu hao tài nguyên khi đưa chuẩn chữ ký số hậu lượng tử **FIPS 204 (ML-DSA)** vào mạng lưới Blockchain thực tế với các thiết bị biên hạn chế tài nguyên (Edge / IoT).

### 1.1. Ma Trận Vi Mô 3x4 (Server, Edge, IoT x 4 Thuật Toán)
* **Server Node (4 vCPU, 4GB RAM):** Không gặp bất kỳ hiện tượng nghẽn nào. ML-DSA-44 xử lý 500 giao dịch chỉ trong 0.96 giây (đạt 520.8 tx/s), nhanh gấp đôi ECDSA nhờ thuật toán biến đổi số học NTT (Number Theoretic Transform).
* **Edge Node (1 vCPU, 512MB RAM):** ML-DSA-44 duy trì độ ổn định cao (1.83 giây, 273.2 tx/s). ML-DSA-87 tiêu tốn 4.09 giây và RAM chạm 54.8 MB.
* **IoT Node (0.5 vCPU, 128MB RAM):** CPU bị bão hòa triệt để (100% quota cgroups). ML-DSA-87 mất tới 7.94 giây cho 500 txs.

### 1.2. Bài Test Tải Cực Hạn & Sự Kiện OOM-Killer (60MB RAM Ceiling)
* Khi dồn dập bơm hàng nghìn giao dịch vào Mempool của Node IoT bị ép RAM xuống **60 MB**:
  * **ML-DSA-87 (NIST Level 5):** Chữ ký lớn (4,627 bytes) khiến Mempool phình to vượt giới hạn. Tại **Giao dịch #1050**, RAM chạm 60.1 MB $\rightarrow$ **Linux Kernel cgroups OOM-Killer lập tức gửi tín hiệu `SIGKILL` (Exit 137)** tiêu diệt tiến trình Node.
  * **ML-DSA-44 (NIST Level 2):** Nhờ kích thước chữ ký chỉ 2,420 bytes, đỉnh RAM đạt **59.54 MB** (sát trần 60MB nhưng không vượt qua), **sống sót trọn vẹn 1,500 giao dịch**.
  * **ECDSA (secp256k1):** Chữ ký siêu nhỏ (71 bytes), RAM ổn định tuyệt đối ở mức **46.2 MB**.

### 1.3. Macro-Benchmark Mạng P2P Phân Cấp (Server -> Edge -> IoT)
* **Độ trễ lan truyền & xác thực khối (Block Propagation Delay):**
  * **ML-DSA-44:** Nhanh nhất toàn mạng lưới (**11.4 ms** tại Edge, **31.3 ms** tại IoT) do thời gian xác thực siêu nhanh của thuật toán mạng tinh thể bù đắp hoàn toàn phụ phí truyền dẫn mạng.
  * **ML-DSA-87:** Dung lượng khối lớn (719.8 KB) khiến độ trễ tăng lên 36.8 ms (Edge) và 45.1 ms (IoT).
  * **ECDSA:** Do xác thực đường cong elliptic tốn CPU trên chip IoT yếu, độ trễ bị đội lên tới **106.5 ms**.

---

## 2. Danh Mục Sản Phẩm & Kết Quả (Deliverables)

Tất cả dữ liệu thô, ma trận kết quả và biểu đồ được sinh tự động và lưu trữ tại thư mục [`perf/`](file:///d:/assignment/btl/Blockchain-CSATT/perf/):

| Hạng mục | Đường dẫn tệp | Mô tả |
| :--- | :--- | :--- |
| **Báo cáo chuyên sâu** | [`perf/PERF01_BENCHMARK_REPORT.md`](file:///d:/assignment/btl/Blockchain-CSATT/perf/PERF01_BENCHMARK_REPORT.md) | Báo cáo kỹ thuật chi tiết 9 chương đầy đủ bảng biểu số liệu. |
| **Biểu đồ OOM Risk** | [`perf/results/perf01_oom_risk_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_oom_risk_chart.png) | Trực quan hóa ma trận vi mô 3x4 và vùng nguy cơ OOM. |
| **Biểu đồ Extreme OOM** | [`perf/results/perf01_extreme_oom_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_extreme_oom_chart.png) | Điểm rơi OOM-Killed của ML-DSA-87 tại Tx #1050 vs ML-DSA-44 & ECDSA. |
| **Biểu đồ Macro P2P** | [`perf/results/perf01_macro_chart.png`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_macro_chart.png) | Độ trễ lan truyền, wire payload và mức tải CPU trên 3 node mạng. |
| **Số liệu Ma trận 3x4** | [`perf/results/perf01_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_matrix.csv) | Kết quả chi tiết 12 đợt đo đạc vi mô. |
| **Số liệu Extreme OOM** | [`perf/results/perf01_extreme_oom_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_extreme_oom_matrix.csv) | Nhật ký dung lượng RAM theo từng block 50 giao dịch. |
| **Số liệu Macro P2P** | [`perf/results/perf01_macro_matrix.csv`](file:///d:/assignment/btl/Blockchain-CSATT/perf/results/perf01_macro_matrix.csv) | Độ trễ, payload kích thước và CPU bão hòa vĩ mô. |
| **Mã nguồn thực thi** | [`perf/perf01_stress_test.py`](file:///d:/assignment/btl/Blockchain-CSATT/perf/perf01_stress_test.py) <br> [`perf/perf01_macro_stress.py`](file:///d:/assignment/btl/Blockchain-CSATT/perf/perf01_macro_stress.py) | Engine kiểm thử tự động, telemetry cgroups v2 và vẽ đồ thị. |
| **Cấu hình Docker** | [`perf/Dockerfile`](file:///d:/assignment/btl/Blockchain-CSATT/perf/Dockerfile) <br> [`perf/docker-compose.yml`](file:///d:/assignment/btl/Blockchain-CSATT/perf/docker-compose.yml) | Đóng gói C engine `liboqs` FIPS 204 và thiết lập hạn mức phần cứng. |

---

## 3. Lệnh Tái Lập Nhanh (Quick Start)

```powershell
# 1. Build Docker image
docker build -t blockchain-node:perf -f perf/Dockerfile .

# 2. Sinh tập dữ liệu 7 file chuẩn hóa (nếu cần tạo mới)
docker run --rm -v "${PWD}:/app" blockchain-node:perf python perf/generate_perf01_txs.py

# 3. Chạy kiểm thử vi mô & săn OOM-Killer
python perf/perf01_stress_test.py

# 4. Chạy kiểm thử vĩ mô mạng P2P 3 node
python perf/perf01_macro_stress.py
```
