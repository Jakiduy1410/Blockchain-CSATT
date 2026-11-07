# NET-01 và NET-02 — mã thực nghiệm và kết quả đã lưu

Bộ mã này đi cùng báo cáo NET ngày 07/11/2026. Nền là nhánh
`B24DCCE080-NET01-NET02`, commit `56d5ccb25c716b2f363f18f68d9b63bbb3904eb7`.
Hai bản sửa `miner.py` và `ledger.py` cùng kiểm thử đã dùng trong loạt đo được giữ nguyên.
Đợt đóng gói chỉ chỉnh đường dẫn, tham số chạy và cách lưu tệp; không chạy lại ma trận mạng.

## Chọn đúng thao tác

| Muốn làm gì | Tệp sử dụng | Có mở node/đào/truyền mạng không? |
|---|---|---|
| Xem bảng số liệu trong báo cáo | `show_results.py` | Không |
| Đối soát số lượt và mã băm bằng chứng | `check_evidence.py` | Không |
| Kiểm thử lỗi đào và chữ ký ML-DSA trong bộ nhớ | `tests/test_mining_races.py` ở gốc repo | Không |
| Tính lại bảng từ log/packet CSV đã lưu | `analyze.py` | Không |
| Vẽ lại biểu đồ từ bảng đã lưu | `charts.py` | Không |
| Xác minh PoW/chữ ký trong log cũ | `verify_blocks.py` | Không |
| Chủ động chạy một loạt thí nghiệm mới | `run_lab.py` và `node_lab.py` | Có; cần Linux/WSL root |

## Demo ngắn trên Windows

Đứng ở thư mục gốc repo, nơi có các thư mục `blockchain`, `tests`, `benchmarks`:

```powershell
python -B benchmarks/net01_net02_lab/show_results.py
```

Lệnh chỉ đọc CSV đã commit; bảng hiện ra là kết quả cũ, không phải phép đo trực tiếp.
Không cần node, Clumsy, Wireshark, Docker hoặc quyền Administrator.
Trong thư mục bàn giao trên Desktop, kiểm tra thêm bằng chứng đã giải nén:

```powershell
python -B benchmarks/net01_net02_lab/check_evidence.py --data-root ../bang-chung --verify-hashes
```

Nếu chỉ clone GitHub, lấy gói `Bang_chung_NET01_NET02_GOC.zip` từ thành viên 5,
giải nén riêng rồi thay `--data-root` bằng thư mục chứa `evidence_seg_final`, `evidence_net2`, `analysis`.
Gói gốc không đặt vào Git: file ZIP khoảng 152 MB, vượt giới hạn 100 MiB cho một tệp GitHub thông thường.

## Kiểm thử ngắn trên môi trường đã có liboqs

```powershell
python -B -m unittest -v tests.test_mining_races tests.test_consensus_security
```

Có 13 test. Hai test thích hợp để trình bày nhanh:

```powershell
python -B -m unittest -v tests.test_mining_races.MiningRaceTests.test_real_mldsa_block_accepted_by_peer
python -B -m unittest -v tests.test_mining_races.MiningRaceTests.test_peer_block_during_pow_restarts_with_new_parent
```

`OK` xác nhận các điều kiện của test đạt; thời gian `Ran ... in ...` là thời gian chạy
test, không phải độ trễ truyền block. Các test không chứng minh tốc độ mạng.
Test ML-DSA cần thư viện C liboqs có ML-DSA-44 và binding `liboqs-python`.
Trong lần đóng gói, 13/13 test đã chạy đạt trên runtime WSL có sẵn, Python 3.14.4/liboqs 0.16.0.

## Tính lại kết quả từ bằng chứng cũ

Chạy ở gốc repo; đầu ra mới để riêng, không ghi đè bảng gốc:

```powershell
python -B benchmarks/net01_net02_lab/analyze.py --data-root ../bang-chung --output-dir ../kiem-tra/analysis_rebuilt
python -B benchmarks/net01_net02_lab/charts.py --analysis-dir ../kiem-tra/analysis_rebuilt --output-dir ../kiem-tra/figures_rebuilt
```

`analyze.py` ưu tiên đọc `packets.csv` đã có. Khi cần đối soát lại trực tiếp PCAP,
thêm `--decode-pcap --tshark "C:/Program Files/Wireshark/tshark.exe"`.
CSV được giải mã lại lưu dưới output mới, không sửa bằng chứng.
Vẽ biểu đồ cần `matplotlib`. `requirements.txt` khai báo thư viện cần cho bộ lab;
`requirements_recorded.txt` giữ nguyên danh sách package của runtime đo cũ, không phải trình cài liboqs C.

Xác minh chữ ký và PoW của block cũ trên runtime có liboqs:

```bash
python -B benchmarks/net01_net02_lab/verify_blocks.py --data-root /duong/dan/bang-chung --output /duong/dan/kiem-tra/block_validation_rebuilt.json
```

Đối soát trong lần đóng gói: 60 lượt, 2040 block, tất cả có PoW/chữ ký hợp lệ và đúng 4 giao dịch người dùng.

## Chạy một loạt MỚI khi thực sự cần

Không cần mục này để trình bày báo cáo hoặc kiểm tra kết quả đã lưu.
Cần Linux/WSL, Python >= 3.12 (`os.setns`), `iproute2`, `ethtool`, `tcpdump`,
liboqs C có ML-DSA-44 và các package trong `requirements.txt`.
Thư viện C phải được nạp đúng qua cấu hình loader/`OQS_INSTALL_PATH` của máy.
Máy khác cần chuẩn bị môi trường tương ứng; chỉ clone repo chưa đủ để chạy full lab.

Đứng ở gốc repo, dùng đường dẫn Python của venv đã chuẩn bị, với quyền root:

```bash
python -B benchmarks/net01_net02_lab/run_lab.py --n1-only --data-root /duong/dan/lo-do-moi --capture-root /duong/dan/linux-native/pcap-moi
python -B benchmarks/net01_net02_lab/run_lab.py --n2-only --data-root /duong/dan/lo-do-moi --capture-root /duong/dan/linux-native/pcap-moi
```

Chạy tuần tự. Dùng đường dẫn mới; không trỏ tới bộ bằng chứng đã bàn giao.
Capture tạm nên nằm trên filesystem Linux, rồi được sao chép ra output sau khi tcpdump dừng.
Driver giữ MTU 1500/576; NET-01 100 tx/lượt, ba lượt/cấu hình; NET-02 34 block/lượt,
ba lượt/cấu hình, baseline và delay 50 ms/jitter 10 ms với loss 0/5/10/15%.
Driver dùng chính Python đang gọi (`sys.executable`), tạo bản sao runtime và ví thử tách riêng
trong `<data-root>/.runtime`, không thay `configs/wallets.json` đã theo dõi bởi Git.
Không tự xóa namespace có sẵn. Chỉ dọn namespace do chính lượt chạy đó tạo.
Lượt đã có result/PCAP/JSONL hợp lệ được bỏ qua; lượt dở dang được giữ và báo lỗi.

## Đọc đúng kết quả

- NET-01: 12 lượt, 1200 giao dịch. ECDSA 1/2 đoạn TCP mỗi giao dịch tại MTU 1500/576;
  ML-DSA 6/15 đoạn. Đây là số đo từ batch trong capture, không phải quy luật cho mọi ứng dụng.
- NET-02: 60 lượt, 2040 block đào; 58/60 lượt cùng tip tại thời điểm chốt.
- Chỉ 1758/2040 block có cặp timestamp gửi/nhận P2P trong cửa sổ đo.
  Không tính block chưa thấy là độ trễ 0; median/P95 có thiên lệch quan sát khi loss cao.
- Hai lượt chưa hội tụ vẫn giữ nguyên: `N2_1500_loss10_ECDSA_3`, `N2_576_loss5_ML-DSA_3`.
- F/M là block có anh em cùng parent / block đào; stale tính trên các lượt đã hội tụ.
  Không dùng số lần gọi `resolve_conflicts()` thay cho số fork.
- TLS của loạt NET là TLS 1.3 ECDHE trên bản NET nền; không lấy kết quả Hybrid TLS của SEC làm kết quả NET.
- Các CSV cũ ở `benchmarks/results/net01_*`, `net02_*` và bộ script NET phiên bản trước vẫn được giữ.
  Báo cáo mới lấy kết quả ở `benchmarks/net01_net02_lab/results`, không trộn hai loạt.

## Tệp sửa trong code chung

- `blockchain/consensus/miner.py`: chụp nhất quán parent/giao dịch trước PoW, tuần tự hóa lời gọi đào tại cùng node và thử lại khi candidate hết hiệu lực.
- `blockchain/core/ledger.py`: chỉ commit đúng candidate đã giải, kiểm tra lại parent/PoW trước khi đổi chain/mempool.
- `tests/test_mining_races.py`: bảy test hồi quy, trong đó có chữ ký ML-DSA thật.
- `tests/test_consensus_security.py`: sáu test hiện có được chỉnh fixture để block hợp lệ thật sự có PoW đúng.

Không đổi độ khó, quy tắc longest-chain hoặc thuật toán chữ ký để làm số liệu đẹp hơn.
Nhánh PERF cũng thay `ledger.py`; người gộp nhánh cần kết hợp từng thay đổi, không chép đè nguyên file lên master.

Trong lần đóng gói đã kiểm tra test hồi quy, đọc lại log, dựng bảng và vẽ biểu đồ.
Chế độ tạo thí nghiệm mạng mới chỉ được kiểm tra cú pháp/CLI; không khởi chạy lại toàn ma trận.
Kết quả một lần đo mới có thể biến động do lịch luồng, PoW và mất gói ngẫu nhiên;
không cam kết lặp lại nguyên từng con số của loạt đã ghi.
