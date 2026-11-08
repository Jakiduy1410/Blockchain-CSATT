# Module PERF-01: DevOps, Docker & Hardware Benchmark

Thư mục này chứa toàn bộ cấu hình **Docker**, bộ dữ liệu tải thực nghiệm, mã nguồn đo lường giới hạn tài nguyên phần cứng (**PERF-01 Stress Test & Macro-Benchmark**) và tài liệu hướng dẫn kỹ thuật chuyên sâu.

---

## 1. Cấu Trúc Thư Mục `perf/`

```text
perf/
├── Dockerfile                  # Đóng gói Node Python 3.11 + liboqs C engine (FIPS 204 ML-DSA-44, 65 & 87)
├── docker-compose.yml          # Định nghĩa 3 profile phần cứng: Server, Edge, IoT
├── generate_perf01_txs.py      # Sinh dữ liệu tải 500 txs (chuẩn) & 2,000 txs (cực hạn)
├── perf01_stress_test.py       # Engine kiểm thử vi mô ma trận 3x4 & Extreme OOM Hunt (60MB RAM)
├── perf01_macro_stress.py      # Engine kiểm thử vĩ mô mạng P2P Single DUT Mesh (1 DUT + 5 Background Nodes)
├── note.md                     # Cẩm nang hỏi - đáp chuyên sâu và bảo vệ đồ án
├── data/                       # Chứa các bộ dataset giao dịch chuẩn hóa (.json)
│   ├── txs_500_ecdsa.json
│   ├── txs_500_mldsa44.json
│   ├── txs_500_mldsa65.json
│   ├── txs_500_mldsa87.json
│   ├── txs_stress_ecdsa.json
│   ├── txs_stress_mldsa44.json
│   ├── txs_stress_mldsa65.json
│   └── txs_stress_mldsa87.json
└── results/                    # Kết quả đo đạc thực nghiệm (CSV, JSON, PNG)
    ├── perf01_matrix.csv
    ├── perf01_results.json
    ├── perf01_oom_risk_chart.png
    ├── perf01_extreme_oom_matrix.csv
    ├── perf01_extreme_oom_chart.png
    ├── perf01_macro_matrix.csv
    ├── perf01_macro_results.json
    └── perf01_macro_chart.png
```

> 📄 **Bản báo cáo trực tuyến trên Google Docs:** [Báo Cáo Kỹ Thuật PERF-01 (Google Docs)](https://docs.google.com/document/d/11TLElp3ceeBPXwJGntcr8gvw5fgNlUeG/edit#heading=h.m3dzhewaqa7b)  

---

## 2. Hướng Dẫn Sử Dụng Nhanh

### Bước 1: Build Docker Image
Từ thư mục gốc dự án:
```powershell
docker build -t blockchain-node:perf -f perf/Dockerfile .
```
Hoặc từ bên trong thư mục `perf/`:
```powershell
docker compose build
```

### Bước 2: Sinh Dữ Liệu Giao Dịch (Nếu cần tạo mới)
```powershell
# Chạy qua Docker container (để dùng thư viện liboqs cho ML-DSA-44, ML-DSA-65 & ML-DSA-87):
docker run --rm -v "${PWD}:/app" blockchain-node:perf python perf/generate_perf01_txs.py
```

### Bước 3: Chạy Kịch Bản Stress Test Vi Mô & Săn OOM-Killer
```powershell
python perf/perf01_stress_test.py
```
*Script sẽ tự động khởi động các container theo từng profile phần cứng (Server / Edge / IoT), bắn tải 500 giao dịch (ECDSA / ML-DSA-44 / ML-DSA-65 / ML-DSA-87), giám sát RAM / CPU qua cgroups v2 và kích hoạt Extreme OOM Hunt (60MB RAM).*

Để chỉ xuất lại biểu đồ và bảng CSV từ kết quả đã có mà không cần chạy lại container:
```powershell
python perf/perf01_stress_test.py --plot-only
```

### Bước 4: Chạy Kịch Bản Macro-Benchmark P2P 6 Nodes (1 DUT + 5 Background Nodes)
```powershell
python perf/perf01_macro_stress.py
```
*Script sẽ khởi chạy cụm 6 node mạng Mesh qua WebSocket TLS 1.3 (1 DUT phân cấp Server/Edge/IoT + 5 Background Nodes), đo độ trễ lan truyền khối, lọc trùng bão gossip, wire payload và bão hòa CPU.*

Để chỉ vẽ lại biểu đồ Macro và xuất bảng CSV từ kết quả có sẵn:
```powershell
python perf/perf01_macro_stress.py --plot-only
```

### Bước 5: Chạy Độc Lập 1 Profile Cụ Thể (Tùy Chọn)
Nếu muốn tự tay bật 1 node với cấu hình bị ép để tương tác:
```powershell
# Khởi chạy node-iot (0.5 vCPU, 128MB RAM)
docker compose -f perf/docker-compose.yml --profile iot up -d

# Khởi chạy node-edge (1.0 vCPU, 512MB RAM)
docker compose -f perf/docker-compose.yml --profile edge up -d

# Khởi chạy node-server (4.0 vCPU, 4GB RAM)
docker compose -f perf/docker-compose.yml --profile server up -d
```
