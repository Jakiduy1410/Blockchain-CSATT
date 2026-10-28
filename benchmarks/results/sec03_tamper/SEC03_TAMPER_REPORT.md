# BÁO CÁO KỸ THUẬT: KỊCH BẢN SEC-03
## TẤN CÔNG GIẢ MẠO CHỮ KÝ (FORGERY/MALLEABILITY) & PHÁT LẠI GIAO DỊCH (REPLAY ATTACK)

**Học phần:** Cơ sở An toàn Thông tin / Blockchain Engineering  
**Vai trò phụ trách:** Thành viên 2 (Signature Integrity & Anti-Tampering)  
**Mã kịch bản:** `SEC-03`  
**Công cụ kiểm thử:** `tests/sec03_signature_integrity/attack_sec03.py`  
**Thư mục lưu log kết quả:** `benchmarks/results/sec03_tamper/`  

---

## 1. MỤC TIÊU KIỂM THỬ
1. **Toàn vẹn Chữ ký Số (Signature Integrity)**: Khẳng định chữ ký Hậu lượng tử ML-DSA-44 (2.420 bytes) đạt tính toàn vẹn tuyệt đối. Bất kỳ sự can thiệp lật ngẫu nhiên bit (Bit-flipping) nào trên đường truyền cũng khiến thuật toán `Verify` từ chối 100%.
2. **Chống giả mạo Payload (Anti-Tampering / Malleability)**: Khi kẻ tấn công giữ nguyên chữ ký hợp lệ nhưng sửa đổi số tiền (`value`/`amount`) hoặc địa chỉ người nhận (`recipient`), hệ thống lập tức phát hiện băm không khớp và từ chối.
3. **Chống tấn công phát lại (Anti-Replay Attack)**: Khi kẻ tấn công bắt gói tin giao dịch hợp lệ và phát lại hàng loạt vào các node (cùng chữ ký, cùng nonce), cơ chế kiểm tra `nonce > current_nonce` của `ledger.py` và `mempool` loại bỏ toàn bộ 100% các giao dịch phát lại.

---

## 2. THIẾT KẾ BỘ KIỂM THỬ (1.000 POST ATTEMPTS)
Bộ kiểm thử tự động sinh 1.000 ca kiểm thử phân bổ ngẫu nhiên vào 6 Node P2P (port 5000 - 5005):
* **334 Ca Bit-Flipping**: Chọn ngẫu nhiên vị trí byte và bit trong chữ ký ML-DSA để đảo bit (`sig[idx] ^= (1 << bit)`).
* **333 Ca Payload Mutation**: Thay đổi giá trị chuyển tiền hoặc địa chỉ nhận nhưng giữ nguyên chữ ký gốc.
* **1 Ca Baseline**: Gửi giao dịch gốc hợp lệ để xác nhận trạng thái mạng hoạt động chuẩn.
* **332 Ca Replay Attack**: Bắn lại chính xác giao dịch Baseline vào 6 node với cùng Nonce và chữ ký.

---

## 3. KẾT QUẢ VÀ BẰNG CHỨNG THỰC NGHIỆM
* **Tỷ lệ chặn Bit-flipping**: 334/334 (100% BLOCKED).
* **Tỷ lệ chặn Payload Mutation**: 333/333 (100% BLOCKED).
* **Tỷ lệ chặn Replay Attack**: 332/332 (100% BLOCKED).
* **Tổng số giao dịch độc hại lọt qua**: **0 / 999** (Tỷ lệ an toàn: 100%).
