# SEC03new — kiểm thử đầy đủ với ECDSA OpenSSL và ba ML-DSA

Nhánh này dùng bố cục mã nguồn của `Blockchain-CSATT-master.zip`, nhưng chạy bộ
SEC-03 đầy đủ của `Blockchain-CSATT-sec03.zip`. Điểm khởi động là `run_test.bat`
hoặc `run_test.sh` ở gốc; không dùng launcher demo của master cho lượt đo này.

## Chạy trên Windows

Cài Python 3.11+ 64-bit, giải nén rồi nhấp đúp `run_test.bat`.
Script tự tạo môi trường, cài thư viện, dựng và chạy lần lượt cả bốn mạng,
tổng hợp batch JSON và ba biểu đồ so sánh. Lần đầu cần Internet để cài thư viện.
DLL liboqs 0.16.0 của master được giữ nguyên trong gói.

## Chạy trên Kali Linux

Chuẩn bị công cụ hệ thống một lần:

```sh
sudo apt update
sudo apt install python3 python3-venv python3-dev git cmake build-essential libssl-dev
```

Mở terminal tại thư mục đã giải nén và chạy:

```sh
bash run_test.sh --keep-raw-logs
```

Script tạo venv riêng, cài `requirements.txt` và chạy toàn bộ. `liboqs-python`
cần thư viện liboqs native; nếu chưa có, wrapper có thể tải và biên dịch liboqs,
vì vậy lần đầu cần Internet và các công cụ bên trên. `oqs.dll` chỉ dùng trên
Windows. Kết quả thời gian của Kali phải lấy từ lần chạy Kali thực tế.

## Số lượng và cách kiểm thử

| Mỗi thuật toán | Tấn công | Hợp lệ | Tổng yêu cầu |
|---|---:|---:|---:|
| Bit-flipping: 75 mẫu mỗi mức 1–4 bit | 300 | 300 | 600 |
| Mutation: 100 Amount, 100 Receiver, 100 Sender | 300 | 300 | 600 |
| Replay: 50 giao dịch gốc, mỗi giao dịch phát lại 4 lần | 200 | 50 | 250 |
| Tổng | 800 | 650 | 1.450 |

Bốn thuật toán: ECDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87.
Toàn đợt có **5.800 yêu cầu = 3.200 lượt tấn công + 2.600 giao dịch hợp lệ**.
Hai pha đầu trộn mẫu, mặc định 6 worker; Replay giữ cách gửi tuần tự của bộ SEC-03.
RSA không còn nằm trong danh sách chạy hay biểu đồ so sánh của nhánh này.

## Phạm vi cập nhật ECDSA

- Sinh khóa và ký bằng `cryptography`/OpenSSL: secp256k1, SHA-256, chữ ký raw64
  `r || s`, cùng cách làm của master.
- Hàm xác minh ECDSA lấy từ master, gồm cả nhánh SHA-1 tương thích chữ ký cũ.
  Chữ ký lỗi có thể đi qua cả hai phép thử hash như master.
- Giữ nguyên cấu trúc giao dịch ba trường và cơ chế chống phát lại của bộ
  SEC-03 đầy đủ. Không chuyển cả mạng sang giao thức nonce của bản demo master.
- File `attack_sec03.py` và toàn bộ ba snapshot ML-DSA giữ nguyên byte so với
  ZIP SEC-03 cũ; công thức TB/P95, điều kiện PASS và số lượng mẫu giữ nguyên.
- Dependency `ecdsa` vẫn được giữ vì các snapshot ML-DSA cũ có đường xác minh
  tương thích sử dụng nó. Mạng ECDSA chạy trong nhánh này dùng OpenSSL.

`tests/sec03_signature_integrity/runtime_sources/` chứa các snapshot nguồn.
`prepare_runtime.py` tự dựng bốn thư mục `Blockchain-CSATT-*` khi chạy; các thư
mục sinh ra này được Git bỏ qua. `SOURCE_PROVENANCE.json` ghi nguồn và hash.

## Kết quả để viết báo cáo

```sh
python run_all_attacks.py --keep-raw-logs
```

Lệnh này dùng khi đã có môi trường. Giữ JSONL sẽ thuận tiện kiểm tra số liệu.
Nếu bỏ `--keep-raw-logs`, chỉ JSONL của lượt PASS được dọn sau khi lưu kết quả.

Ở gốc sẽ có `sec03_batch_*.json` và:

- `sec03_comparison_chart.png`
- `sec03_comparison_mutation.png`
- `sec03_comparison_bitflip.png`

Mỗi runtime có summary JSON, terminal log và ba ảnh bit-flip, mutation, replay.
Để coi đợt chạy thành công, kiểm tra từng summary: 1.450 yêu cầu quan sát được;
số tấn công bị chặn theo pha `[300, 300, 200]`; số giao dịch hợp lệ trong block
`[300, 300, 50]`; không có mẫu lọt qua hoặc kết quả chưa xác định.

Các số ms phải lấy từ batch mới, không ghép số ECDSA mới với số ML-DSA lịch sử.
TB/P95 SEC-03 là độ trễ phản hồi HTTP của yêu cầu tấn công bị chặn; chúng không
phải thời gian Verify thuần. Cùng mã ML-DSA có thể cho latency khác giữa các lần chạy.

`benchmarks/micro_benchmark.py` giữ bản master và là phép đo riêng. Muốn chạy
phép đo này, cài thêm `numpy scipy` vào môi trường rồi xem tùy chọn `--help`;
nó không được tự động chạy trong SEC-03 và không thay thế số liệu SEC-03.

## Đưa lên nhánh GitHub

Giải nén, chép **nội dung** thư mục `Blockchain-CSATT-sec03new` vào clone của
repo nhóm trên nhánh mới. Kiểm tra `git status` rồi commit mã nguồn. Không đẩy
venv, runtime sinh ra, cache hay log thô. Gói không chứa kết quả lịch sử của bản
ECDSA Python. Bằng chứng kiểm tra gói nằm trong `validation/` nếu đi kèm.

Các khóa ví mẫu chỉ phục vụ mạng thử nghiệm cục bộ.
