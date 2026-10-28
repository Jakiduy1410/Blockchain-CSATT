# BÁO CÁO KỸ THUẬT: KỊCH BẢN SEC-01 & SEC-02
## HARVEST NOW, DECRYPT LATER (HNDL) & TẤN CÔNG HẠ CẤP GIAO THỨC (MITM DOWNGRADE)

**Học phần:** Cơ sở An toàn Thông tin / Blockchain Engineering  
**Vai trò phụ trách:** Thành viên 1 (Network & TLS Security)  
**Mã kịch bản:** `SEC-01` & `SEC-02`  
**File bắt gói mẫu:** `benchmarks/results/sec01_hndl_mitm/pqc_p2p_capture.pcap`  
**Cấu hình OpenSSL PQC:** `configs/pqc_openssl.cnf`  

---

## 1. MỤC TIÊU KỊCH BẢN

### 1.1. SEC-01: Chống tấn công "Thu hoạch hôm nay, Giải mã tương lai" (Harvest Now, Decrypt Later - HNDL)
* Kẻ tấn công thu thập toàn bộ lưu lượng mã hóa P2P truyền giữa các node blockchain và lưu trữ. Khi máy tính lượng tử đủ mạnh (CRQC), kẻ tấn công dùng thuật toán Shor để giải mã khóa trao đổi cổ điển (ECDHE / RSA).
* **Giải pháp**: Nâng cấp kênh truyền WebSocket P2P lên **Hybrid Key Exchange X25519 + ML-KEM-768 (Group ID 0x11ec)** theo chuẩn TLS 1.3. Khóa phiên được bảo vệ bởi bài toán ML-KEM chống lại cả máy tính cổ điển và lượng tử.

### 1.2. SEC-02: Chống tấn công Hạ cấp Giao thức (MitM Downgrade Attack)
* Kẻ trung gian (Man-in-the-Middle) chặn gói tin bắt tay `TLS 1.3 Client Hello`, loại bỏ extension PQC (cắt bỏ byte `0x11ec`) nhằm ép server và client lùi về dùng đường cong cổ điển (X25519 hoặc P-256).
* **Giải pháp**: Cơ chế Zero-Trust tại tầng mạng. Khi gói tin Client Hello bị can thiệp biến dạng byte hoặc cắt bỏ extension PQC bắt buộc, kết nối lập tức bị Server ngắt (`DROP_CONNECTION`) và bắn cảnh báo `CRITICAL` vào hộp đen kiểm toán (`/api/audit/alert`).

---

## 2. HƯỚNG DẪN MỞ VÀ KIỂM TRA TRÊN WIRESHARK (WINDOWS / LINUX)

### 2.1. Xem bắt gói tin mẫu:
1. Mở phần mềm **Wireshark**.
2. Chọn `File` -> `Open` -> Trỏ đến file `pqc_p2p_capture.pcap` trong thư mục này.
3. Trên thanh filter gõ `tls` hoặc `tcp.port == 6000`.
4. Chọn gói tin **Client Hello**:
   - Mở rộng nhánh: `Transport Layer Security -> TLSv1.3 Record Layer -> Handshake Protocol: Client Hello`.
   - Xem mục `Extension: supported_groups (len=8)`:
     + Xuất hiện nhóm: **`x25519_kyber768` hoặc `x25519_mlkem768` (0x11ec)**.
   - Xem mục `Extension: key_share (len=1252)`:
     + Chứa khóa chia sẻ **ML-KEM Key Share (độ dài 1216 bytes)**.

### 2.2. Giải mã dữ liệu phiên với SSLKEYLOGFILE:
1. Trong file `blockchain/network/tls_helper.py`, hệ thống tự động kiểm tra biến môi trường `SSLKEYLOGFILE`.
2. Khi chạy node, set biến môi trường:
   ```cmd
   set SSLKEYLOGFILE=C:\path\to\sslkeys.log
   ```
3. Trong Wireshark: Vào `Edit` -> `Preferences` -> `Protocols` -> `TLS` -> `(Pre)-Master-Secret log filename` -> Chọn file `sslkeys.log`.
4. Wireshark sẽ giải mã toàn bộ dữ liệu trao đổi WebSocket P2P được bọc trong TLS 1.3.

---

## 3. CÔNG CỤ THỰC NGHIỆM ĐI KÈM
* **Proxy đánh chặn MitM**: `tests/sec01_sec02_network/mitm_proxy.py` (Lắng nghe 6500, forward 6000, lột bỏ byte PQC `\x11\xec` thành `\x00\x00` và trigger audit alert).
* **Gửi bắt tay Hybrid PQC thủ công**: `tests/sec01_sec02_network/send_pqc_handshake.py` (Tạo bản tin Client Hello chứa extension `0x11ec` và key share 1216B).
* **Unit Test tự động**: `tests/sec01_sec02_network/test_sec01_sec02_network.py`.
