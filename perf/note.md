# CẨM NANG HỎI - ĐÁP VÀ BẢO VỆ ĐỒ ÁN PERF-01
## Các Câu Hỏi Phản Biện Chuyên Sâu, Nghịch Lý Hiệu Năng & Bản Chất Kỹ Thuật Đằng Sau Số Liệu Benchmark

> **Mã học phần:** Cơ sở An toàn Thông tin / Blockchain Engineering  
> **Chuyên đề:** Module PERF-01 (Hardware Benchmark & DevOps - Thành viên 4)  
> **Mục tiêu tệp:** Trang bị đầy đủ cơ sở lý luận, giải thích bản chất kiến trúc và dữ liệu thực nghiệm để tự tin trả lời bất kỳ câu hỏi phản biện nào của Giảng viên hướng dẫn và Hội đồng chấm đồ án.

---

### MỤC LỤC

1. [Nghịch Lý 1: Vì Sao Chữ Ký PQC Nặng Gấp 15–29 Lần Mà TPS Lại Nhanh Hơn ECDSA?](#1-nghịch-lý-1-vì-sao-chữ-ký-pqc-nặng-gấp-1529-lần-mà-tps-lại-nhanh-hơn-ecdsa)
2. [Nghịch Lý 2: Vì Sao Server Có 4 vCPU Mà Mức Tải CPU Đo Được Lại Là ~150%?](#2-nghịch-lý-2-vì-sao-server-có-4-vcpu-mà-mức-tải-cpu-đo-được-lại-là-150)
3. [Hiện Tượng OOM-Killer Kép: Cơ Chế Nhân Linux SIGKILL (Exit 137) Hoạt Động Như Thế Nào?](#3-hiện-tượng-oom-killer-kép-cơ-chế-nhân-linux-sigkill-exit-137-hoạt-động-như-thế-nào)
4. [Sự Khác Biệt Giữa Micro-Benchmark (Đơn Lẻ) Và Macro-Benchmark (Mạng P2P 3-Node)](#4-sự-khác-biệt-giữa-micro-benchmark-đơn-lẻ-và-macro-benchmark-mạng-p2p-3-node)
5. [Phương Pháp Đo Lường cgroups v2, Hiện Tượng Cold-Start Cache & Cách Xử Lý Nhiễu](#5-phương-pháp-đo-lường-cgroups-v2-hiện-tượng-cold-start-cache--cách-xử-lý-nhiễu)
6. [Bảng Tra Cứu Nhanh Câu Hỏi Phản Biện Của Thầy Cô (Quick Defense Flashcards)](#6-bảng-tra-cứu-nhanh-câu-hỏi-phản-biện-của-thầy-cô-quick-defense-flashcards)
7. [Bảng 8 Chỉ Số Vàng & Tổng Hợp Cốt Lõi Macro-Benchmark (Dùng Viết Báo Cáo Với Thầy)](#7-bảng-8-chỉ-số-vàng--tổng-hợp-cốt-lõi-macro-benchmark-dùng-viết-báo-cáo-với-thầy)

---

### 1. NGHỊCH LÝ 1: VÌ SAO CHỮ KÝ PQC NẶNG GẤP 15–29 LẦN MÀ TPS LẠI NHANH HƠN ECDSA?

#### Câu hỏi của Giảng viên:
> *"Tại sao chữ ký ML-DSA lớn hơn ECDSA rất nhiều (ML-DSA-44 nặng 7.7 KB/tx, ML-DSA-87 nặng 14.7 KB/tx so với ECDSA chỉ 499 Bytes/tx), truyền qua mạng tốn băng thông và phân tích JSON nặng hơn, mà thông lượng tiếp nhận (Ingestion TPS) của ML-DSA lại cao hơn ECDSA trên cả 3 cấu hình Server, Edge và IoT (ví dụ Server: ML-DSA-65 đạt 446.8 tx/s trong khi ECDSA chỉ đạt 300.5 tx/s)?"*

#### Câu trả lời chuẩn xác & Bản chất kỹ thuật:
Hiện tượng này là kết quả cộng hưởng từ **2 yếu tố then chốt**: Thuật toán toán học và Kiến trúc thực thi mã nguồn.

```mermaid
flowchart TD
    subgraph ML_DSA["1. ML-DSA (NIST FIPS 204)"]
        A1["Thuật toán: Lattice-based (M-LWE)"] --> B1["Phép toán: Nhân đa thức vành R_q qua NTT (O(n log n))"]
        B1 --> C1["Thực thi: Thư viện C bản địa (liboqs C-extension)"]
        C1 --> D1["SIMD/AVX2 + Giải phóng Python GIL"]
        D1 --> E1["==> Tốc độ xác thực cực nhanh (Hàng chục ngàn ops/s)"]
    end

    subgraph ECDSA_PATH["2. ECDSA (secp256k1)"]
        A2["Thuật toán: Elliptic Curve Cryptography"] --> B2["Phép toán: Nhân vô hướng điểm Elliptic Curve s^-1(Hm.G + r.Q)"]
        B2 --> C2["Thực thi: Thư viện Pure-Python (python-ecdsa)"]
        C2 --> D2["Chạy bytecode Python + Tranh chấp Python GIL"]
        D2 --> E2["==> Cổ chai khóa luồng GIL, xử lý đa luồng bị nghẽn"]
    end
```

1. **Về mặt toán học mật mã (Algorithmic Complexity):**
   * **ECDSA (secp256k1):** Xác thực chữ ký yêu cầu thực hiện **2 phép nhân điểm vô hướng (scalar point multiplications)** trên đường cong elliptic:
     $$s^{-1} \cdot H(m) \cdot G + s^{-1} \cdot r \cdot Q$$
     Phép toán này đòi hỏi hàng trăm phép cộng và nhân đôi điểm trên trường hữu hạn nguyên tố lớn ($GF(p)$ với $p \approx 2^{256}$), tiêu tốn rất nhiều chu kỳ xử lý ALU.
   * **ML-DSA (Dilithium - FIPS 204):** Dựa trên bài toán mạng tinh thể M-LWE (*Module Learning With Errors*). Việc thẩm định chữ ký bản chất là **phép nhân ma trận đa thức trên vành số nguyên** $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$ với $q = 8,380,417$ (số nguyên tố 23-bit).
   * Nhờ thuật toán biến đổi số học **NTT (*Number Theoretic Transform*)**, phép nhân đa thức bậc $n=256$ được chuyển đổi từ độ phức tạp $\mathcal{O}(n^2)$ về chỉ còn $\mathcal{O}(n \log n)$ với toàn các phép toán cộng/nhân số nguyên cơ bản. Do đó, về mặt lý thuyết thuần túy, thẩm định chữ ký ML-DSA tốn ít chu kỳ CPU hơn nhiều so với phép nhân điểm elliptic.

2. **Về mặt kiến trúc thực thi mã nguồn (Native C vs Pure-Python & GIL):**
   * Trong mã nguồn [`blockchain/core/crypto.py`](file:///d:/assignment/btl/Blockchain-CSATT/blockchain/core/crypto.py):
     * **ML-DSA** được thẩm định thông qua thư viện `oqs` (`liboqs`). Đây là **thư viện C biên dịch bản địa (Compiled Native C Extension)** có kích hoạt tập lệnh vector hóa vi xử lý (AVX2/NEON). Khi gọi hàm xác thực C, Python **nhả khóa toàn cục GIL (Global Interpreter Lock)**, cho phép 8 luồng HTTP worker chạy song song thực sự trên các nhân CPU.
     * **ECDSA** được thẩm định bằng thư viện `python-ecdsa` (`from ecdsa import VerifyingKey`). Đây là thư viện **thuần Python (Pure-Python)**. Mọi phép nhân đường cong elliptic đều được thông dịch bằng Python Bytecode và **giữ chặt khóa GIL**. Dù máy chủ Flask có mở 8 worker threads, các worker vẫn phải xếp hàng tuần tự để tranh giành GIL, tạo thành điểm nghẽn nghiêm trọng (Thread Contention).

> **Kết luận cho Giảng viên:** Dung lượng JSON của ML-DSA tuy lớn hơn, nhưng phụ phí phân tích chuỗi (JSON parsing overhead ~0.1ms) hoàn toàn bị khỏa lấp bởi tốc độ xác thực của thư viện C `liboqs` chạy NTT nhanh gấp hàng chục lần so với vòng lặp Pure-Python của `ecdsa`.

---

### 2. NGHỊCH LÝ 2: VÌ SAO SERVER CÓ 4 vCPU MÀ MỨC TẢI CPU ĐO ĐƯỢC LẠI LÀ ~150%?

#### Câu hỏi của Giảng viên:
> *"Tại sao trong bảng kết quả, cột `Avg CPU (%)` của Server lại lên đến `138.92%` đến `154.82%`? Tại sao không phải là dưới 100%?"*

#### Câu trả lời:
* Trong Linux kernel và hệ thống quản lý tài nguyên cgroups v2:
  * **$100\%$ CPU tương đương với 1 nhân CPU vật lý (hoặc 1 vCPU) hoạt động hết công suất.**
  * Server được cấp phát `--cpus=4.0`, nghĩa là hạn mức trần của Server là **$400\%$**.
  * Mức tải `154.82%` thể hiện tiến trình Python/Flask đang khai thác đồng thời khoảng **$1.55$ nhân CPU** trong tổng số 4 nhân được cấp phát để giải mã và xác thực đồng thời 8 luồng giao dịch nạp vào.
* Để thầy cô dễ đối chiếu, đồ án đã bổ sung thêm cột **`Normalized CPU (%)`**:
  $$\text{Normalized CPU} = \min\left(100.0\%, \; \frac{\text{Avg CPU}}{\text{Allocated vCPUs}}\right) = \frac{154.82\%}{4.0} = 38.70\%$$
  Nghĩa là Server chỉ mới sử dụng hết **$38.7\%$** hạn mức điện toán tối đa của nó. Với các node chịu tải bão hòa (Edge, IoT), chỉ số này đạt trần tối đa **$100.0\%$** (theo chuẩn học thuật quốc tế), và mức độ quá tải thực tế được lượng hóa chính xác qua chỉ số **`CPU Throttled (ms)`** từ Linux CFS Quota.
* **Nguyên tắc toán học đảm bảo tính đúng đắn:**
  $$\text{Peak CPU (\%)} \ge \text{Avg CPU (\%)} \ge \text{Baseline CPU (\%)} \ge 0$$
  Tất cả các bản ghi trong ma trận số liệu đều tuân thủ tuyệt đối quy tắc này.

---

### 3. HIỆN TƯỢNG OOM-KILLER KÉP: CƠ CHẾ NHÂN LINUX SIGKILL (EXIT 137) HOẠT ĐỘNG NHƯ THẾ NÀO?

#### Câu hỏi của Giảng viên:
> *"Bài test ép trần 60MB RAM (Extreme OOM Hunt) nhằm chứng minh điều gì? Tại sao ML-DSA-87 bị OOM ở giao dịch #900, ML-DSA-65 bị OOM ở #1300, còn ML-DSA-44 và ECDSA lại sống sót qua 1,500 giao dịch?"*

#### Bản chất kỹ thuật & Phân tích cơ chế:

```mermaid
stateDiagram-v2
    [*] --> Baseline_43MB: Khởi động Flask Node
    Baseline_43MB --> Nạp_Mempool: Tiếp nhận giao dịch HTTP
    
    state Nạp_Mempool {
        ECDSA: ECDSA (+0.5 KB/tx) -> Đỉnh 46 MB (Bình an)
        MLDSA44: ML-DSA-44 (+8.5 KB/tx) -> Đỉnh 59.86 MB (Sống sót)
        MLDSA65: ML-DSA-65 (+12 KB/tx) -> Chạm 60.0 MB tại Tx #1300
        MLDSA87: ML-DSA-87 (+16 KB/tx) -> Chạm 60.0 MB tại Tx #900
    }

    MLDSA65 --> SIGKILL_137: Vượt cgroup memory.max (60MB)
    MLDSA87 --> SIGKILL_137: Vượt cgroup memory.max (60MB)
    SIGKILL_137 --> Process_Terminated: Linux Kernel OOM-Killer tiêu diệt (Exit 137)
```

1. **Bộ nhớ tĩnh (Baseline RAM):**
   * Một container chạy Python 3.11 + Flask runtime + các thư viện mật mã nạp vào bộ nhớ đã chiếm sẵn khoảng **$42.5 - 43.5\text{ MB}$** RAM nền tĩnh.
   * Trần cứng cgroups đặt ở mức **$60.0\text{ MB}$**, kèm thiết lập `--memory-swap=60m` (cấm triệt để dùng bộ nhớ ảo Swap).
   * **Khoảng đệm an toàn khả dụng (Headroom)** thực tế cho Mempool chỉ còn lại:
     $$\Delta_{\text{Headroom}} = 60.0\text{ MB} - 43.0\text{ MB} = 17.0\text{ MB}$$

2. **Dung lượng lưu giữ trên RAM của mỗi giao dịch (In-Memory Footprint):**
   Mỗi giao dịch không chỉ tốn dung lượng JSON trên đường truyền mạng, mà khi nằm trong RAM nó là một đối tượng Python `Transaction` chứa các chuỗi hex `OrderedDict`:
   * **ECDSA:** $\approx 0.5\text{ KB/tx}$ $\rightarrow$ 1,500 giao dịch chỉ tốn thêm $\approx 0.75\text{ MB}$ RAM $\rightarrow$ RAM đỉnh chỉ đạt $46.4\text{ MB}$ (còn dư hơn 13 MB an toàn).
   * **ML-DSA-44:** $\approx 8.5\text{ KB/tx}$ in-memory $\rightarrow$ 1,500 giao dịch tốn thêm $\approx 12.8\text{ MB}$ RAM $\rightarrow$ RAM đỉnh chạm $59.86\text{ MB}$ ($99.8\%$ trần), lượn sát mép vực nhưng **chưa chạm đỉnh 60MB**, do đó sống sót an toàn!
   * **ML-DSA-65:** $\approx 12\text{ KB/tx}$ in-memory $\rightarrow$ Tại mốc **Tx #1300**, tổng RAM giao dịch vượt quá 17 MB headroom $\rightarrow$ RAM chạm $60.0\text{ MB}$ $\rightarrow$ **Kích hoạt OOM-Killer thứ nhất**.
   * **ML-DSA-87:** $\approx 16.5\text{ KB/tx}$ in-memory $\rightarrow$ Tại mốc **Tx #900**, RAM chạm $60.0\text{ MB}$ $\rightarrow$ **Kích hoạt OOM-Killer sớm nhất**.

3. **Vì sao mã lỗi thoát là `137`?**
   * Theo chuẩn Linux POSIX, khi một tiến trình bị nhân Linux hủy diệt bằng tín hiệu (*Signal*), mã thoát của tiến trình sẽ bằng:
     $$\text{Exit Code} = 128 + \text{Signal Number}$$
   * Tín hiệu mà OOM-Killer sử dụng là `SIGKILL` (Signal số 9):
     $$\text{Exit Code} = 128 + 9 = 137$$
   * Tín hiệu `SIGKILL` không thể bị bắt (*uncatchable*), không thể bỏ qua (*unignorable*) bởi bất kỳ khối lệnh `try...except` nào trong Python, chứng minh tính bảo hộ tuyệt đối của tầng hệ điều hành.

---

### 4. SỰ KHÁC BIỆT GIỮA MICRO-BENCHMARK (ĐƠN LẺ) VÀ MACRO-BENCHMARK (MẠNG P2P SINGLE DUT MESH)

#### Câu hỏi của Giảng viên:
> *"Tại sao cần cả bài đo Micro (3x4 đơn lẻ) và bài đo Macro (1 DUT + 5 Background Nodes)? Tại sao không dùng mô hình chuỗi tuyến tính 3 node đơn giản mà phải dựng mạng mesh 6 node?"*

#### Câu trả lời:
* **Micro-Benchmark (Kiểm thử vi mô 3x4):**
  * *Mục tiêu:* Cô lập từng node riêng biệt để tìm giới hạn cực đại của tài nguyên tính toán (CPU Saturation) và bộ nhớ (Peak RAM) khi tiếp nhận liên tục 500 giao dịch vào Mempool qua REST API.
  * *Ý nghĩa:* Trả lời câu hỏi: *"Một thiết bị phần cứng cụ thể (Server, Edge, IoT) có thể chịu tải nạp giao dịch ở tốc độ bao nhiêu?"*
* **Macro-Benchmark (Kiểm thử vĩ mô mạng P2P Single DUT in Live Mesh Network):**
  * *Hạn chế của mô hình chuỗi tuyến tính cũ (Server -> Edge -> IoT):* Thiếu tính thực tế vì trong mạng Blockchain không node nào kết nối độc đạo kiểu dây chuyền; không tạo ra được áp lực bão tin nhắn P2P; không đo được khả năng khử trùng lặp gossip.
  * *Ưu thế vượt trội của mô hình Single DUT in Live Mesh Network (1 DUT + 5 Background Nodes):*
    * **Phản ánh chính xác thực tế:** 5 node nền unconstrained tạo thành mạng lưới sống, liên tục gossip giao dịch và đào khối. 1 node DUT (Server / Edge / IoT) được "thả" vào mạng để kiểm tra xem thiết bị yếu có theo kịp nhịp đồng thuận hay sẽ bị nghẽn mạng và sập nguồn.
    * **Kiểm tra sức đề kháng bão Gossip (Gossip Storm Stress):** DUT nhận đồng thời 500 - 900 gói tin WebSocket P2P từ 5 peers, chứng minh hiệu quả của thuật toán khử trùng lặp `seen_tx_hashes` (lọc thành công 400 - 800 gói tin dư thừa).
    * **Chứng minh thực nghiệm Nghịch lý độ trễ (The Latency Paradox):**
      * Khối đào đóng gói 100 txs: ECDSA ($54.5	ext{ KB}$), ML-DSA-44 ($758.4	ext{ KB}$), ML-DSA-65 ($1,057.0	ext{ KB}$), ML-DSA-87 ($1,439.4	ext{ KB}$).
      * **Độ trễ thẩm định trên IoT yếu (0.5 vCPU):** Với ML-DSA-65, dù khối nặng hơn 19 lần, nhờ NTT của thư viện C `liboqs`, độ trễ thẩm định khối chỉ mất **$53.54	ext{ ms}$**. Ngược lại, ECDSA dù khối siêu nhẹ nhưng chạy Pure-Python trên CPU yếu khiến độ trễ bị đội lên tới **$223.98	ext{ ms}$** (chậm gấp 4.2 lần!).

---

### 5. PHƯƠNG PHÁP ĐO LƯỜNG cgroups v2, HIỆN TƯỢNG COLD-START CACHE & CÁCH XỬ LÝ NHIỄU

#### Câu hỏi của Giảng viên:
> *"Các em đo số liệu CPU và RAM bằng cách nào? Liệu việc gọi `docker stats` từ bên ngoài có gây sai lệch kết quả do phụ phí của Docker daemon không?"*

#### Câu trả lời:
* Đồ án **không dùng `docker stats`** vì lệnh này lấy mẫu chậm ($1\text{s}/lần$) và có độ trễ cao. Thay vào đó, toàn bộ công cụ telemetry được xây dựng trực tiếp trên giao diện kernel **Linux cgroups v2**:
  1. **RAM thời gian thực:** Đọc trực tiếp pseudo-file `/sys/fs/cgroup/memory.current`.
  2. **Đỉnh RAM phần cứng:** Đọc trực tiếp `/sys/fs/cgroup/memory.peak` (thanh ghi nội tại của nhân Linux lưu lại đỉnh sử dụng cao nhất của cgroup kể từ khi container khởi chạy, không bao giờ bị bỏ sót do tần số lấy mẫu).
  3. **Thời gian tiêu thụ CPU:** Đọc trường `usage_usec` trong `/sys/fs/cgroup/cpu.stat`.
  4. **Hiện tượng bóp xung nhịp (CFS Throttling):** Đọc trường `throttled_usec` và `nr_throttled` trong `cpu.stat`.
* **Hiện tượng Cold-Start Page Cache và cách nhóm xử lý triệt để:**
  * Trong lần chạy đầu tiên, nhân Linux phải nạp toàn bộ file binary Python và thư viện liên kết động (`liboqs.so`, `libc.so`) từ đĩa OverlayFS vào bộ đệm cgroup file cache, khiến RAM đo được bị nhảy vọt lên $\sim 126\text{ MB}$ (dù tiến trình chỉ dùng 43 MB anon memory).
  * *Biện pháp kỹ thuật đã xử lý:* Trước khi bước vào vòng lặp đo chính thức, kịch bản tự động khởi chạy một container mồi (**Warm-up Container**) trong 2.5 giây để nạp nóng kernel page cache trên máy chủ Host. Nhờ đó, tất cả các lần đo sau đều đo đúng bộ nhớ thực (**$43.3\text{ MB}$ Baseline** và **$48.0\text{ MB}$ Peak RAM** cho ECDSA Server).

---

### 6. BẢNG TRA CỨU NHANH CÂU HỎI PHẢN BIỆN CỦA THẦY CÔ (QUICK DEFENSE FLASHCARDS)

| # | Câu Hỏi Thường Gặp | Từ Khóa Trả Lời Ngay (Key Points) |
|---|---|---|
| **1** | *"Kích thước chữ ký ML-DSA lớn như vậy có khả thi trên IoT không?"* | **Khả thi về CPU/RAM với ML-DSA-44/65 (chỉ tốn ~49MB RAM, verify 22ms). Điểm nghẽn duy nhất là băng thông truyền dẫn không dây (LoRa/BLE). Khuyến nghị dùng ML-DSA-44.** |
| **2** | *"Vì sao không thử nghiệm RSA trong bài test tải này?"* | **Khóa công khai RSA-3072/4096 quá cồng kềnh, chữ ký 384–512 bytes, không có khả năng kháng lượng tử (bị giải bởi thuật toán Shor), và đã bị NIST FIPS loại bỏ khỏi danh mục tiêu chuẩn hậu lượng tử PQC 2024.** |
| **3** | *"Tại sao ML-DSA-65 được NIST khuyến nghị là Default Standard thay vì 44 hay 87?"* | **ML-DSA-65 đạt Cấp độ an ninh 3 (NIST Level 3 - tương đương AES-192), là điểm cân bằng hoàn hảo ("Sweet Spot") giữa độ an toàn mã hóa chống máy tính lượng tử và phụ phí kích thước chữ ký (3,309 bytes).** |
| **4** | *"Nếu Mempool trên Node IoT bị kẻ tấn công bơm ngập giao dịch ML-DSA-87 thì làm sao chống OOM?"* | **Cần triển khai cơ chế lọc mempool thông minh (Mempool Eviction Policy): giới hạn dung lượng hàng đợi Mempool theo Byte (ví dụ tối đa 10 MB) thay vì theo số lượng giao dịch, đồng thời ưu tiên giao dịch có phí (Gas fee) cao hơn.** |
| **5** | *"Docker giới hạn CPU 0.5 nhân hoạt động ra sao?"* | **Sử dụng cơ chế CFS (Completely Fair Scheduler) Quota của Linux: Trong mỗi chu kỳ chu kỳ quota $100,000\mu s$ (period), tiến trình chỉ được cấp phép chạy tối đa $50,000\mu s$ thời gian CPU. Nếu dùng quá, nhân kernel sẽ bóp ngắt (CFS Throttle) tiến trình.** |

---
> **Lời khuyên khi thuyết trình:** Hãy luôn tự tin chỉ ra rằng đồ án không chỉ dừng lại ở việc so sánh lý thuyết trên giấy, mà đã thực sự **triển khai Docker hóa, ép trần tài nguyên cgroups v2, bắt sống hiện tượng Kernel OOM-Killer thực tế và đo đạc luồng P2P đa tầng**. Đây là điểm cộng thực nghiệm rất lớn trong mắt hội đồng!


---

### 7. BẢNG 8 CHỈ SỐ VÀNG & TỔNG HỢP CỐT LÕI MACRO-BENCHMARK (DÙNG VIẾT BÁO CÁO VỚI THẦY)

#### 7.1. Bảng Ma Trận 8 Chỉ Số Cốt Lõi (Core KPIs) Trích Xuất Từ Thực Nghiệm 1-DUT
> **Mục tiêu:** Bảng số liệu chuẩn hóa, cô đọng từ 53 cột CSV thành 8 chỉ số có giá trị học thuật cao nhất, phân chia theo 4 góc độ đánh giá hệ thống, sẵn sàng đưa vào báo cáo Word/Docs.

| Nhóm Đánh Giá | Chỉ Số Cốt Lõi (Core KPI) | ECDSA (secp256k1) | ML-DSA-44 (PQC L2) | ML-DSA-65 (PQC L3) | ML-DSA-87 (PQC L5) | Ý Nghĩa Học Thuật / Đánh Giá Thực Nghiệm |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **1. Tải Trọng Mạng (Wire Overhead)** | **1. Kích thước 1 Txn / Khối 100 Txns** | 0.49 KB / **54.7 KB** | 7.71 KB / **758.6 KB** | 10.77 KB / **1,057.2 KB** | 14.69 KB / **1,439.6 KB** | Khối ML-DSA-87 phình gấp **26.3 lần** ECDSA do cấu trúc chữ ký lattice và mã hóa JSON+Hex. |
| **2. Hiệu Năng Đồng Thuận Khối (Consensus Latency)** | **2. Thời gian CPU Verify Khối (`dut_block_verify_ms`)**<br>*(Server / Edge / IoT)* | 115.0 / 124.7 / **193.1 ms** | 6.8 / 9.6 / **12.1 ms** | 14.2 / 19.0 / **14.2 ms** | 21.1 / 21.4 / **18.7 ms** | ML-DSA nhờ NTT của thư viện C `liboqs` nhanh gấp **10–16 lần** `python-ecdsa`. CPU IoT verify vẫn chậm hơn Edge đúng tương quan phần cứng. |
| | **3. Độ trễ Truyền Khối qua TLS 1.3 (`block_transit_ms`)**<br>*(Server / Edge / IoT)* | 3.7 / 4.4 / **4.6 ms** | 34.2 / 35.0 / **31.9 ms** | 49.1 / 50.6 / **54.3 ms** | 65.8 / 66.5 / **74.0 ms** | Ở PQC, **Độ trễ truyền mạng chiếm tới 70%–80%** tổng thời gian commit; điểm nghẽn đã chuyển dịch hoàn toàn từ CPU sang I/O Mạng. |
| | **4. Tổng Độ trễ Cam kết Khối (`commit_latency_ms`)**<br>*(Server / Edge / IoT)* | 118.9 / 129.5 / **197.9 ms** | 42.5 / 46.3 / **45.7 ms** | 65.5 / 72.0 / **71.7 ms** | 90.0 / 90.9 / **95.5 ms** | Tổng thời gian toàn trình từ lúc Miner phát sóng qua WebSocket TLS 1.3 đến khi DUT kiểm tra xong và ghi vào sổ cái. |
| **3. Sức Chịu Tải Bão Gossip (Gossip Ingestion)** | **5. Thông lượng Nạp Mempool (`ingest_throughput_tps`)**<br>*(Server / Edge / IoT)* | 146.7 / 154.1 / **103.1 TPS** | 176.1 / 121.9 / **63.4 TPS** | 165.4 / 108.0 / **55.8 TPS** | 140.3 / 97.4 / **39.8 TPS** | Tốc độ DUT hấp thụ 100 giao dịch giữa bão 700–1,000 gói tin PQC. Trên IoT, thông lượng ML-DSA-87 giảm 2.6 lần so với ECDSA. |
| | **6. Băng thông Đỉnh & Lọc trùng lặp (`ingress_bw` / `dups`)**<br>*(IoT Ingress BW / Gói tin trùng đã chặn)* | 351.5 KB/s<br>*(Chặn 600–800 gói)* | 4,295.0 KB/s<br>*(Chặn 600–800 gói)* | 5,869.8 KB/s<br>*(Chặn 800–900 gói)* | 5,600.3 KB/s<br>*(Chặn 800–900 gói)* | Thuật toán `seen_tx_hashes` hoạt động xuất sắc: chặn thành công 85%–90% gói tin trùng lặp dội từ 5 peer trong mesh. |
| **4. Giới Hạn Phần Cứng cgroups v2 (CPU & RAM)** | **7. Thời gian Bóp nghẽn CPU (`total_throttled_ms` & `%`)**<br>*(Server / Edge / IoT)* | 0 / 322 / **1,627 ms**<br>*(0% / 46% / 69%)* | 0 / 1,051 / **3,932 ms**<br>*(0% / 57% / 74%)* | 0 / 1,447 / **5,259 ms**<br>*(0% / 56% / 76%)* | 0 / 1,624 / **8,732 ms**<br>*(0% / 59% / 79%)* | **Chỉ số thay thế hoàn hảo cho cột CPU 100%:** Đo thời gian nhân Linux ngắt nhịp tiến trình do vượt quota vCPU. ML-DSA-87 đè nặng IoT gấp 5.3 lần ECDSA. |
| | **8. Đỉnh Bộ nhớ RAM & % Trần cứng IoT (`peak_ram` / `util%`)**<br>*(Server / Edge / IoT - Ngưỡng IoT: 128 MB)* | 50.5 / 50.2 / **50.1 MB**<br>*(IoT: **39.1%**)* | 57.2 / 69.6 / **78.9 MB**<br>*(IoT: **61.6%**)* | 75.0 / 80.3 / **85.9 MB**<br>*(IoT: **67.1%**)* | 79.2 / 91.2 / **107.5 MB**<br>*(IoT: **84.0%**)* | Chỉ với 100 giao dịch, Mempool ML-DSA-87 đã chiếm tới **84.0% trần cứng 128MB của IoT**, chứng minh nguy cơ OOM cận kề trên thiết bị nhúng. |

---

#### 7.2. Luận Điểm Khoa Học Giải Thích Cho Biểu Đồ Dashboard 4-Panel (`perf01_macro_chart.png`)

1. **Panel 1 (Góc trên trái): Giải thích vì sao ML-DSA-44 trên IoT (45.7ms) lại ngang bằng hoặc nhanh hơn Edge (46.3ms):**
   * **Bóc tách thành phần:** $\text{Commit Latency} = \text{Block Verify CPU Time} + \text{Wire Transit Delay TLS 1.3}$.
   * **Sự thật phần cứng:** CPU Verify thực tế của IoT ($12.11\text{ ms}$) **vẫn chậm hơn** Edge ($9.57\text{ ms}$) đúng theo quy luật.
   * **Bản chất kỹ thuật:** Do khối PQC nặng $758.6\text{ KB}$, thời gian truyền mạng chiếm tới $70\% - 80\%$ ($32 - 35\text{ ms}$). Độ dao động tự nhiên của socket TCP trên Docker bridge ($\pm 3\text{ ms}$) đã khỏa lấp mức chênh lệch CPU $2.5\text{ ms}$, tạo ra độ trôi ngẫu nhiên $0.58\text{ ms}$.
   * **Kết luận học thuật:** Trên Blockchain PQC, **điểm nghẽn hệ thống đã dịch chuyển từ CPU sang I/O Mạng (Network-bound thay vì CPU-bound)**.

2. **Panel 2 (Góc trên phải): Mối tương quan giữa Kích thước Khối và Sự suy giảm Thông lượng Nạp Mempool:**
   * Khi kích thước khối tăng từ $54.7\text{ KB}$ (ECDSA) lên $1,439.6\text{ KB}$ (ML-DSA-87), thông lượng Ingest của IoT giảm từ **$103.1\text{ TPS}$ xuống $39.8\text{ TPS}$** (suy giảm 61.4%).
   * Ngược lại, Node Server (4 vCPU) vẫn duy trì thông lượng ổn định từ $140 - 176\text{ TPS}$ nhờ khả năng xử lý song song đa luồng TLS 1.3.

3. **Panel 3 (Góc dưới trái): Thay thế cột CPU 100% bằng Thời Gian Bóp Nghẽn CPU (CFS Throttled Duration):**
   * Việc hiển thị $100\%$ CPU trước đây là do hàm kẹp trần $\min(100\%, \dots)$ khi vCPU đơn nhân bị khai thác kịch trần.
   * Sử dụng **CFS Throttled Duration** chứng minh sự phân hóa rõ rệt: Server hoàn toàn không bị bóp ($0\text{ ms}$), Edge bị bóp từ $322\text{ ms} \rightarrow 1,624\text{ ms}$, và IoT bị bóp nghẹt từ $1,627\text{ ms}$ lên kỷ lục **$8,732\text{ ms}$** ($79.4\%$ tổng thời gian chạy).

4. **Panel 4 (Góc dưới phải): Cảnh báo Ngưỡng Bộ Nhớ RAM trên IoT (Trần cứng 128 MB):**
   * Đường kẻ ngang màu đỏ $128\text{ MB}$ trực quan hóa ranh giới an toàn của cgroups.
   * Trong khi ECDSA chỉ ngốn $50.1\text{ MB}$ ($39.1\%$), ML-DSA-87 đẩy mức chiếm dụng lên tới **$107.5\text{ MB}$ ($84.0\%$)**, chỉ còn cách vực thẳm OOM-Killer đúng $20.5\text{ MB}$.

5. **Tính Nhất Quán Phương Pháp Luận & Khuyến Nghị Tương Lai (Ceteris Paribus & Binary Serialization):**
   * Toàn bộ hệ thống ở tất cả các nhánh git (`master`, `perf-01`, `mldsa-*`) đều chạy đồng nhất trên nền **JSON + HEX**.
   * Với ECDSA, phụ phí Hex (+100%) chỉ tốn thêm vài trăm bytes; nhưng với PQC, nó làm phình đôi khối dữ liệu ($373\text{ KB} \rightarrow 753\text{ KB}$).
   * **Khuyến nghị kiến trúc (Future Work):** Đối với các mạng IoT thực tế, bắt buộc phải nâng cấp tầng giao vận sang **Binary Serialization (Protobuf, CBOR, MessagePack)** hoặc tối thiểu là **Base64** (+33% thay vì +100% của Hex) để tiết kiệm băng thông.
