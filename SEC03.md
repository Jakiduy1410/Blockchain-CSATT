# SEC-03 — nhánh thực nghiệm 5 thuật toán

## Chạy toàn bộ

Windows: dùng Python 3.11+ 64-bit và nhấp đúp `run_test.bat`.

Kali: chuẩn bị `python3-venv`, `git`, `cmake`, `build-essential`, `libssl-dev`, sau đó chạy `bash run_test.sh`.
Lần đầu cần Internet để pip cài thư viện. Linux cần liboqs native; liboqs-python tự tải và build khi chưa có thư viện này. Windows dùng DLL liboqs 0.16.0 đi kèm ZIP master của nhóm.

Nếu đã có môi trường: `python run_all_attacks.py`.
Chỉ kiểm tra lệnh: `python run_all_attacks.py --dry-run` (bước này cũng dựng các file runtime).
Chỉ chạy một thuật toán: `python run_all_attacks.py --project ML-DSA-44`.

## Cấu trúc

- Các thư mục `blockchain/`, `blockchain_client/`, `benchmarks/` và các test khác lấy từ ZIP master của nhóm.
- `tests/sec03_signature_integrity/attack_sec03.py` là một bản dùng chung, giữ nguyên byte từ thư mục thực hành cá nhân.
- `tests/sec03_signature_integrity/runtime_sources/` lưu mã Python và hai cấu hình cần thiết của năm mạng đang dùng. `manifest.json` ghi SHA-256 của từng file.
- `prepare_runtime.py` tự dựng `Blockchain-CSATT-rsa`, `Blockchain-CSATT-ecdsa`, `Blockchain-CSATT-mldsa44`, `Blockchain-CSATT-mldsa65`, `Blockchain-CSATT-mldsa87` khi bắt đầu. Các thư mục này được Git bỏ qua.
- SEC-03 dùng các snapshot trên để bảo toàn phiên bản thực nghiệm. Chương trình blockchain ở gốc vẫn là bản master của nhóm.

Mỗi thuật toán gửi 1.450 yêu cầu: bit-flip 300 lỗi + 300 hợp lệ (75 mỗi mức bit), mutation 300 lỗi + 300 hợp lệ (100 mỗi trường), replay 50 gốc + 200 phát lại. Tổng cả 5 thuật toán là 7.250 yêu cầu.

Sau PASS, runner xuất batch JSON và ba ảnh so sánh `sec03_comparison_{chart,mutation,bitflip}.png` ở gốc. Mỗi runtime có summary, terminal log và các ảnh bit-flip, mutation, replay. Công thức đo và cách phân loại giữ nguyên bản thực hành.

## Kết quả tham chiếu và kiểm thử

`benchmarks/results/sec03_tamper/reference/` chứa nguyên bản batch JSON và ảnh từ lần chạy đã có trong workspace. Đây là dữ liệu tham chiếu, không phải một lần đo mới. Đường dẫn Kali trong batch tham chiếu giữ nguyên; `compare.py --batch <đường-dẫn-batch>` đọc số liệu được lưu sẵn trong JSON.

Thời gian TB/P95 được đo lại trên máy chạy, do đó không có cam kết trùng các con số latency lịch sử. Số lượng ca và định dạng báo cáo được bảo toàn.

Kiểm thử hồi quy:

```sh
python tests/sec03_signature_integrity/prepare_runtime.py
python -m unittest -q test_sec03_wallets test_sec03_atomic_outputs
```

Các khóa trong snapshot là ví mô phỏng đi kèm bài thực hành, chỉ dùng cho mạng thử nghiệm này.

## Đưa lên nhánh GitHub

Checkout nhánh mới `sec03` trong clone repo nhóm rồi chép nội dung gói này vào thư mục repo.
Các output cũ và dữ liệu stress lớn từ master không nằm trong gói; bộ kết quả SEC-03 tham chiếu được giữ riêng.
Kiểm tra `git status` trước commit để thấy chỉ có mã nguồn, snapshot nhỏ và báo cáo tham chiếu. Thư mục venv, runtime, log và cache được bỏ qua bởi `.gitignore`.
