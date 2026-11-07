# SEC-03 — dữ liệu tham chiếu của bài thực hành

Phiên bản trong nhánh này chạy 5 thuật toán: RSA, ECDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87.
Mỗi thuật toán có 1.450 yêu cầu: 300 bit-flip + 300 normal; 300 mutation + 300 normal; 50 gốc + 200 replay.
Bit-flip chia 75 ca cho mỗi mức 1–4 bit. Mutation chia 100 ca Amount, 100 Receiver, 100 Sender.

Thư mục `reference/` lưu nguyên bản kết quả đã chạy trong workspace cá nhân, gồm batch JSON, summary và các PNG.
Đây là bằng chứng của lần đo lịch sử. Runner tính lại mọi số liệu khi chạy mới, không nạp các giá trị tham chiếu vào bài test.

Chạy `run_test.bat` hoặc `bash run_test.sh` từ gốc dự án. Chi tiết tại `SEC03.md`.
