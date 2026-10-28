import csv
import math
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "benchmarks" / "results"
SUMMARY_CSV = RESULT_DIR / "net01_net02_summary.csv"
RAW_CSV = RESULT_DIR / "net01_net02_results.csv"

SEGMENT_CSV = RESULT_DIR / "net01_tcp_segmentation.csv"
SEGMENT_PNG = RESULT_DIR / "tcp_segmentation_mtu.png"
PROP_PNG = RESULT_DIR / "propagation_delay.png"
FORK_PNG = RESULT_DIR / "fork_orphan_rate.png"
REPORT = ROOT / "NET01_NET02_REPORT.md"

FINAL_LABELS = [
    "mtu576_loss5_lag100",
    "mtu576_loss15_lag100",
]

with open(SUMMARY_CSV, "r", encoding="utf-8") as f:
    summary_rows = list(csv.DictReader(f))

final_rows = [
    r for r in summary_rows
    if r["label"] in FINAL_LABELS
]

if len(final_rows) < 4:
    raise RuntimeError(
        f"Chi tim thay {len(final_rows)} dong final trong summary CSV."
    )

lookup = {
    (r["label"], r["algorithm"]): r
    for r in final_rows
}

# ============================================================
# NET-01: TCP segmentation / header overhead
# ============================================================

ecdsa_payload = round(sum(
    float(r["avg_tx_json_bytes"])
    for r in final_rows
    if r["algorithm"] == "ECDSA"
) / 2)

mldsa_payload = round(sum(
    float(r["avg_tx_json_bytes"])
    for r in final_rows
    if r["algorithm"] == "ML-DSA"
) / 2)

# IPv4 header 20 B + TCP header 20 B.
IP_TCP_HEADER = 40

segment_rows = []

for mtu in [1500, 576]:
    mss = mtu - IP_TCP_HEADER

    for algorithm, payload in [
        ("ECDSA", ecdsa_payload),
        ("ML-DSA", mldsa_payload),
    ]:
        segments = math.ceil(payload / mss)
        header_bytes = segments * IP_TCP_HEADER
        wire_bytes = payload + header_bytes

        overhead_wire = (
            header_bytes / wire_bytes * 100.0
            if wire_bytes
            else 0.0
        )

        overhead_payload = (
            header_bytes / payload * 100.0
            if payload
            else 0.0
        )

        segment_rows.append({
            "algorithm": algorithm,
            "mtu_bytes": mtu,
            "mss_bytes": mss,
            "representative_tx_json_bytes": payload,
            "tcp_segments_theoretical": segments,
            "ip_tcp_header_bytes": header_bytes,
            "estimated_wire_bytes": wire_bytes,
            "header_overhead_percent_of_wire":
                round(overhead_wire, 3),
            "header_overhead_percent_of_payload":
                round(overhead_payload, 3),
        })

with open(
    SEGMENT_CSV,
    "w",
    newline="",
    encoding="utf-8"
) as f:
    fields = list(segment_rows[0].keys())
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(segment_rows)

# Chart segmentation
mtus = [1500, 576]

ecdsa_segments = [
    next(
        r["tcp_segments_theoretical"]
        for r in segment_rows
        if r["algorithm"] == "ECDSA"
        and r["mtu_bytes"] == mtu
    )
    for mtu in mtus
]

mldsa_segments = [
    next(
        r["tcp_segments_theoretical"]
        for r in segment_rows
        if r["algorithm"] == "ML-DSA"
        and r["mtu_bytes"] == mtu
    )
    for mtu in mtus
]

x = list(range(len(mtus)))
width = 0.35

fig, ax = plt.subplots(figsize=(8, 5))
ax.bar(
    [i - width / 2 for i in x],
    ecdsa_segments,
    width,
    label="ECDSA"
)
ax.bar(
    [i + width / 2 for i in x],
    mldsa_segments,
    width,
    label="ML-DSA"
)
ax.set_xticks(x)
ax.set_xticklabels([f"MTU {m}" for m in mtus])
ax.set_ylabel("Estimated TCP payload segments / transaction")
ax.set_title("NET-01: TCP Segmentation vs MTU")
ax.legend()
ax.grid(axis="y", alpha=0.25)
fig.tight_layout()
fig.savefig(SEGMENT_PNG, dpi=180)
plt.close(fig)

# ============================================================
# NET-02: propagation delay
# ============================================================

loss_labels = [
    ("mtu576_loss5_lag100", "Loss 5%"),
    ("mtu576_loss15_lag100", "Loss 15%"),
]

ecdsa_prop = [
    float(lookup[(key, "ECDSA")]["avg_propagation_ms"])
    for key, _ in loss_labels
]

mldsa_prop = [
    float(lookup[(key, "ML-DSA")]["avg_propagation_ms"])
    for key, _ in loss_labels
]

x = list(range(len(loss_labels)))

fig, ax = plt.subplots(figsize=(8, 5))
ax.bar(
    [i - width / 2 for i in x],
    ecdsa_prop,
    width,
    label="ECDSA"
)
ax.bar(
    [i + width / 2 for i in x],
    mldsa_prop,
    width,
    label="ML-DSA"
)
ax.set_xticks(x)
ax.set_xticklabels([name for _, name in loss_labels])
ax.set_ylabel("Average propagation delay (ms)")
ax.set_title("NET-02: Block Propagation Delay at MTU 576")
ax.legend()
ax.grid(axis="y", alpha=0.25)
fig.tight_layout()
fig.savefig(PROP_PNG, dpi=180)
plt.close(fig)

# ============================================================
# NET-02: fork / orphan
# ============================================================

conditions = [
    ("mtu576_loss5_lag100", "ECDSA", "5% ECDSA"),
    ("mtu576_loss5_lag100", "ML-DSA", "5% ML-DSA"),
    ("mtu576_loss15_lag100", "ECDSA", "15% ECDSA"),
    ("mtu576_loss15_lag100", "ML-DSA", "15% ML-DSA"),
]

fork_rates = []
orphan_rates = []

for label, algo, _ in conditions:
    row = lookup[(label, algo)]
    rounds = int(row["rounds"])

    fork_rate = float(row["fork_rate_percent"])

    orphan_rate = (
        int(row["orphan_blocks_delta"]) / rounds * 100.0
        if rounds
        else 0.0
    )

    fork_rates.append(fork_rate)
    orphan_rates.append(orphan_rate)

x = list(range(len(conditions)))

fig, ax = plt.subplots(figsize=(10, 5))
ax.bar(
    [i - width / 2 for i in x],
    fork_rates,
    width,
    label="Fork rate"
)
ax.bar(
    [i + width / 2 for i in x],
    orphan_rates,
    width,
    label="Orphan rate"
)
ax.set_xticks(x)
ax.set_xticklabels(
    [name for _, _, name in conditions],
    rotation=15
)
ax.set_ylabel("Rate (%)")
ax.set_ylim(0, 110)
ax.set_title("NET-02: Fork / Orphan Rate under Network Impairment")
ax.legend()
ax.grid(axis="y", alpha=0.25)
fig.tight_layout()
fig.savefig(FORK_PNG, dpi=180)
plt.close(fig)

# ============================================================
# Build markdown report
# ============================================================

def get_seg(algo, mtu):
    return next(
        r for r in segment_rows
        if r["algorithm"] == algo
        and r["mtu_bytes"] == mtu
    )

e1500 = get_seg("ECDSA", 1500)
e576 = get_seg("ECDSA", 576)
m1500 = get_seg("ML-DSA", 1500)
m576 = get_seg("ML-DSA", 576)

loss5_e = lookup[("mtu576_loss5_lag100", "ECDSA")]
loss5_m = lookup[("mtu576_loss5_lag100", "ML-DSA")]
loss15_e = lookup[("mtu576_loss15_lag100", "ECDSA")]
loss15_m = lookup[("mtu576_loss15_lag100", "ML-DSA")]

report = f"""# NET-01 / NET-02 Network Experiment Report

**Sinh viên:** Lê Ngọc Trường Giang  
**Mã sinh viên:** B24DCCE080

## 1. Mục tiêu

NET-01 đánh giá tác động của kích thước giao dịch hậu lượng tử ML-DSA lên TCP segmentation khi MTU giảm từ 1500 byte xuống 576 byte.

NET-02 đánh giá block propagation delay, số lần xử lý `resolve_conflicts()`, fork và orphan block khi Node 1 và Node 2 đào cạnh tranh trong điều kiện mạng có packet loss và delay biến thiên.

## 2. Môi trường thực nghiệm

- Python 3.11
- Blockchain P2P WebSocket TLS chạy trên localhost.
- Node 1 HTTP/P2P: 5000 / 6000.
- Node 2 HTTP/P2P: 5001 / 6001.
- Wireshark bắt traffic trên Npcap Loopback Adapter.
- Windows `netsh` cấu hình Loopback MTU 1500 và 576.
- Clumsy giả lập packet loss 5% và 15%.
- Lag cấu hình 100 ms trên outbound traffic P2P.
- Hai miner được kích hoạt gần đồng thời để tạo điều kiện cạnh tranh block.

## 3. Kích thước chữ ký và transaction

Kích thước ML-DSA-44 đo trực tiếp bằng liboqs:

| Thành phần | Kích thước |
|---|---:|
| ML-DSA public key | 1312 B |
| ML-DSA secret key | 2560 B |
| ML-DSA signature | 2420 B |
| Public key + signature | 3732 B |

Transaction JSON quan sát trong benchmark:

- ECDSA: khoảng **{ecdsa_payload} B/tx**
- ML-DSA: khoảng **{mldsa_payload} B/tx**
- ML-DSA lớn hơn khoảng **{mldsa_payload / ecdsa_payload:.2f} lần**.

## 4. NET-01 - TCP segmentation và header overhead

Giả sử IPv4 header 20 B và TCP header 20 B:

- MTU 1500 -> MSS xấp xỉ 1460 B.
- MTU 576 -> MSS xấp xỉ 536 B.

| Algorithm | MTU | MSS | Payload | TCP segments | Header bytes | Header overhead / wire |
|---|---:|---:|---:|---:|---:|---:|
| ECDSA | 1500 | {e1500['mss_bytes']} | {e1500['representative_tx_json_bytes']} | {e1500['tcp_segments_theoretical']} | {e1500['ip_tcp_header_bytes']} | {e1500['header_overhead_percent_of_wire']}% |
| ECDSA | 576 | {e576['mss_bytes']} | {e576['representative_tx_json_bytes']} | {e576['tcp_segments_theoretical']} | {e576['ip_tcp_header_bytes']} | {e576['header_overhead_percent_of_wire']}% |
| ML-DSA | 1500 | {m1500['mss_bytes']} | {m1500['representative_tx_json_bytes']} | {m1500['tcp_segments_theoretical']} | {m1500['ip_tcp_header_bytes']} | {m1500['header_overhead_percent_of_wire']}% |
| ML-DSA | 576 | {m576['mss_bytes']} | {m576['representative_tx_json_bytes']} | {m576['tcp_segments_theoretical']} | {m576['ip_tcp_header_bytes']} | {m576['header_overhead_percent_of_wire']}% |

![TCP segmentation](benchmarks/results/tcp_segmentation_mtu.png)

### Lưu ý về Wireshark trên Windows Loopback

Raw capture được lưu cục bộ ở:

- `mldsa_mtu1500.pcapng`
- `mldsa_mtu576.pcapng`

Trên Npcap Loopback, Wireshark quan sát một số TCP payload lớn hơn MTU do vị trí capture/offload/coalescing của Windows. Vì vậy số `Displayed` trong capture không được coi trực tiếp là số TCP segment vật lý.

Bảng phía trên sử dụng **payload transaction thực đo** và MSS suy ra từ MTU để tính số TCP payload segment lý thuyết. Capture Wireshark được dùng để xác nhận traffic P2P và payload lớn, không dùng để bịa số segment từ packet đã bị coalesced.

## 5. NET-02 - Propagation delay

### Loss 5%, Lag 100 ms, MTU 576

| Algorithm | Avg delay | Min | Max | Samples |
|---|---:|---:|---:|---:|
| ECDSA | {float(loss5_e['avg_propagation_ms']):.3f} ms | {float(loss5_e['min_propagation_ms']):.3f} | {float(loss5_e['max_propagation_ms']):.3f} | {loss5_e['propagation_samples']} |
| ML-DSA | {float(loss5_m['avg_propagation_ms']):.3f} ms | {float(loss5_m['min_propagation_ms']):.3f} | {float(loss5_m['max_propagation_ms']):.3f} | {loss5_m['propagation_samples']} |

### Loss 15%, Lag 100 ms, MTU 576

| Algorithm | Avg delay | Min | Max | Samples |
|---|---:|---:|---:|---:|
| ECDSA | {float(loss15_e['avg_propagation_ms']):.3f} ms | {float(loss15_e['min_propagation_ms']):.3f} | {float(loss15_e['max_propagation_ms']):.3f} | {loss15_e['propagation_samples']} |
| ML-DSA | {float(loss15_m['avg_propagation_ms']):.3f} ms | {float(loss15_m['min_propagation_ms']):.3f} | {float(loss15_m['max_propagation_ms']):.3f} | {loss15_m['propagation_samples']} |

![Propagation delay](benchmarks/results/propagation_delay.png)

## 6. Fork, orphan và resolve_conflicts()

| Loss | Algorithm | Fork rate | Orphan blocks | resolve_conflicts() |
|---|---|---:|---:|---:|
| 5% | ECDSA | {loss5_e['fork_rate_percent']}% | {loss5_e['orphan_blocks_delta']} | {loss5_e['resolve_conflicts_delta']} |
| 5% | ML-DSA | {loss5_m['fork_rate_percent']}% | {loss5_m['orphan_blocks_delta']} | {loss5_m['resolve_conflicts_delta']} |
| 15% | ECDSA | {loss15_e['fork_rate_percent']}% | {loss15_e['orphan_blocks_delta']} | {loss15_e['resolve_conflicts_delta']} |
| 15% | ML-DSA | {loss15_m['fork_rate_percent']}% | {loss15_m['orphan_blocks_delta']} | {loss15_m['resolve_conflicts_delta']} |

![Fork and orphan rate](benchmarks/results/fork_orphan_rate.png)

Trong kịch bản competitive mining hiện tại, Node 1 và Node 2 được gọi mine gần đồng thời. Do đó fork/orphan đạt trạng thái bão hòa 100% ở cả ECDSA và ML-DSA trong các round mạng suy hao.

Kết quả này **không chứng minh ML-DSA có fork rate cao hơn ECDSA** trong cấu hình hiện tại. Nó chứng minh cơ chế instrumentation phát hiện được fork, orphan và `resolve_conflicts()`, đồng thời cho thấy mạng có delay/loss mở rộng cửa sổ cạnh tranh block.

## 7. Kết luận

1. ML-DSA tạo transaction lớn hơn ECDSA rất nhiều trong cùng hệ thống.
2. Khi MTU giảm từ 1500 xuống 576, số TCP payload segment lý thuyết của ML-DSA tăng đáng kể và tỷ lệ header overhead tăng theo.
3. Packet loss và lag làm block propagation delay tăng mạnh so với baseline localhost.
4. Cơ chế đo đã ghi nhận được fork candidate, orphan block và số lần gọi `resolve_conflicts()`.
5. Trong bài test competitive mining 5 round/case, fork/orphan bão hòa ở 100% cho cả hai thuật toán; vì vậy không được diễn giải dữ liệu hiện tại thành bằng chứng ML-DSA có fork rate cao hơn ECDSA.
6. Để định lượng xác suất fork khác biệt giữa hai thuật toán chính xác hơn, cần random hóa thời điểm mining hoặc chạy nhiều round mà không ép hai miner mine đồng thời tuyệt đối.

## 8. File kết quả

- `benchmarks/results/net01_net02_results.csv`
- `benchmarks/results/net01_net02_summary.csv`
- `benchmarks/results/net01_tcp_segmentation.csv`
- `benchmarks/results/tcp_segmentation_mtu.png`
- `benchmarks/results/propagation_delay.png`
- `benchmarks/results/fork_orphan_rate.png`

Raw `.pcapng` được giữ local làm evidence và không bắt buộc commit vào Git.
"""

REPORT.write_text(report, encoding="utf-8")

print("=== DA SINH FILE KET QUA ===")
print(SEGMENT_CSV)
print(SEGMENT_PNG)
print(PROP_PNG)
print(FORK_PNG)
print(REPORT)
