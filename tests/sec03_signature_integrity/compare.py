#!/usr/bin/env python3
"""
So sánh và trực quan hóa độ trễ đánh chặn tấn công SEC-03 giữa 4 thuật toán:
Classical ECDSA, Post-Quantum ML-DSA-44, ML-DSA-65, ML-DSA-87.
Tự động xuất 3 biểu đồ so sánh:
1. sec03_comparison_chart.png (Toàn bộ 3 kịch bản)
2. sec03_comparison_mutation.png (Phân rã theo trường bị sửa: Amount, Recipient, Sender)
3. sec03_comparison_bitflip.png (Phân rã theo số bit bị lật: 1, 2, 3, 4 bit)
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent
if ROOT.name == "sec03_signature_integrity":
    ROOT = ROOT.parents[1]
BENCHMARK_DIR = ROOT / "benchmarks" / "results" / "sec03_tamper"

SCHEMES = {
    "ECDSA": "ecdsa",
    "ML-DSA-44": "mldsa44",
    "ML-DSA-65": "mldsa65",
    "ML-DSA-87": "mldsa87",
}

SCENARIOS = ("Bit-flipping", "Payload mutation", "Replay")

SCENARIO_MAP = {
    "Bit-Flipping Integrity": "Bit-flipping",
    "Bit-flipping": "Bit-flipping",
    "Payload Mutation / Anti-Tamper": "Payload mutation",
    "Payload mutation": "Payload mutation",
    "Anti-Replay Defense": "Replay",
    "Replay": "Replay",
}

DETAIL_GROUPS = {
    "Bit-flipping": ("bit_flips", {str(bits): f"{bits} bit" for bits in range(1, 5)}),
    "Payload mutation": ("mutation_field", {
        "amount": "Amount", "recipient_address": "Receiver", "sender_address": "Sender",
    }),
}


def find_latest_summaries(search_dir: Path) -> dict[str, Path]:
    """Tìm các file summary json mới nhất cho từng thuật toán."""
    found: dict[str, Path] = {}
    if not search_dir.is_dir():
        return found

    for summary_path in search_dir.glob("*.summary.json"):
        try:
            data = json.loads(summary_path.read_text(encoding="utf-8"))
            raw_scheme = (data.get("scheme") or "").lower()
            for label, scheme_key in SCHEMES.items():
                if raw_scheme == scheme_key:
                    if label not in found or summary_path.stat().st_mtime > found[label].stat().st_mtime:
                        found[label] = summary_path
                    break
        except Exception:
            continue
    return found


def analyze_log_file(jsonl_path: Path) -> dict:
    """Đọc và bóc tách dữ liệu thống kê từ 1 file log jsonl."""
    times = {kind: [] for kind in SCENARIOS}
    group_times = {kind: {key: [] for key in labels} for kind, (_, labels) in DETAIL_GROUPS.items()}
    sent = {kind: 0 for kind in SCENARIOS}
    blocked = {kind: 0 for kind in SCENARIOS}

    with jsonl_path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                raw_scenario = row.get("scenario", "")
                kind = SCENARIO_MAP.get(raw_scenario, raw_scenario)
                if kind not in times:
                    continue

                is_attack = row.get("is_attack")
                if is_attack is None:
                    is_attack = (row.get("group") == "attack")
                if not is_attack:
                    continue

                sent[kind] += 1
                res = (row.get("classified_result") or row.get("result") or "").lower()
                if "block" not in res and res != "pass":
                    continue

                lat = row.get("elapsed_ms")
                if lat is None:
                    continue
                lat = float(lat)
                if lat < 0 or not math.isfinite(lat):
                    continue

                blocked[kind] += 1
                times[kind].append(lat)

                if kind == "Bit-flipping":
                    flips = str(row.get("bit_flips") or "")
                    if flips in group_times[kind]:
                        group_times[kind][flips].append(lat)
                elif kind == "Payload mutation":
                    field = str(row.get("mutation_field") or "")
                    if field in group_times[kind]:
                        group_times[kind][field].append(lat)
            except Exception:
                continue

    result = {}
    for kind in SCENARIOS:
        lats = times[kind]
        lats_sorted = sorted(lats)
        n = len(lats)
        p95 = lats_sorted[min(n - 1, int(math.ceil(0.95 * n)) - 1)] if n else None
        mean = (math.fsum(lats) / n) if n else None
        total = math.fsum(lats) if n else 0.0
        result[kind] = {
            "attack_sent": sent[kind],
            "blocked": blocked[kind],
            "mean_ms": mean,
            "p95_ms": p95,
            "total_ms": total,
            "group_mean_ms": {}
        }

    for kind, groups in group_times.items():
        for key, values in groups.items():
            if values:
                result[kind]["group_mean_ms"][key] = math.fsum(values) / len(values)

    return result


def analyze_summary_file(summary_path: Path) -> dict:
    """Đọc dữ liệu từ file .summary.json đã tính toán trước."""
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    lat_stats = data.get("latency_stats", {})
    bf_detail = data.get("bit_flip_detail", {})
    mut_detail = data.get("mutation_detail", {})

    def get_mean(d):
        return d.get("mean") if isinstance(d, dict) else None

    def get_p95(d):
        return d.get("p95") if isinstance(d, dict) else None

    result = {
        "Bit-flipping": {
            "attack_sent": lat_stats.get("bitflip", {}).get("count", 0),
            "blocked": lat_stats.get("bitflip", {}).get("count", 0),
            "mean_ms": get_mean(lat_stats.get("bitflip", {})),
            "p95_ms": get_p95(lat_stats.get("bitflip", {})),
            "total_ms": 0.0,
            "group_mean_ms": {k: get_mean(v) for k, v in bf_detail.items() if get_mean(v) is not None}
        },
        "Payload mutation": {
            "attack_sent": lat_stats.get("mutation", {}).get("count", 0),
            "blocked": lat_stats.get("mutation", {}).get("count", 0),
            "mean_ms": get_mean(lat_stats.get("mutation", {})),
            "p95_ms": get_p95(lat_stats.get("mutation", {})),
            "total_ms": 0.0,
            "group_mean_ms": {k: get_mean(v) for k, v in mut_detail.items() if get_mean(v) is not None}
        },
        "Replay": {
            "attack_sent": lat_stats.get("replay", {}).get("count", 0),
            "blocked": lat_stats.get("replay", {}).get("count", 0),
            "mean_ms": get_mean(lat_stats.get("replay", {})),
            "p95_ms": get_p95(lat_stats.get("replay", {})),
            "total_ms": 0.0,
            "group_mean_ms": {}
        }
    }
    return result


def print_benchmark_table(results: dict):
    def num(val):
        return "N/A" if val is None else f"{val:.2f}"

    header = f"{'Thuật toán':<14} {'Kịch bản':<22} {'Chặn/Gửi':>10} {'TB (ms)':>11} {'P95 (ms)':>11}"
    sep = "-" * len(header)
    print("\n" + "=" * len(header))
    print("      BẢNG TỔNG HỢP SO SÁNH ĐỘ TRỄ ĐÁNH CHẶN SEC-03")
    print("=" * len(header))
    print(header)
    print(sep)

    for alg in SCHEMES:
        if alg not in results:
            continue
        for kind in SCENARIOS:
            data = results[alg].get(kind, {})
            print(f"{alg:<14} {kind:<22} "
                  f"{data.get('blocked', 0):>4}/{data.get('attack_sent', 0):<5} "
                  f"{num(data.get('mean_ms')):>11} "
                  f"{num(data.get('p95_ms')):>11}")
        print(sep)


def save_grouped_chart(values_by_algorithm: dict, groups: dict, filename: str, title: str):
    """Vẽ biểu đồ cột nhóm (Grouped Bar Chart) cho 4 thuật toán."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        colors = ("#ad651d", "#158379", "#2563eb", "#8154a4")
        width = 0.18
        fig, ax = plt.subplots(figsize=(10.5, 5.2))

        active_algs = [a for a in SCHEMES if a in values_by_algorithm]
        if not active_algs:
            return False

        for index, alg in enumerate(active_algs):
            color = colors[index % len(colors)]
            data = values_by_algorithm.get(alg, {})
            offset = (index - (len(active_algs) - 1) / 2) * width
            positions, values = [], []

            for g_idx, key in enumerate(groups):
                pos = g_idx + offset
                val = data.get(key)
                if val is None or not math.isfinite(val):
                    ax.text(pos, 0.05, "N/A", ha="center", color=color, fontsize=8)
                else:
                    positions.append(pos)
                    values.append(val)

            if positions and values:
                bars = ax.bar(positions, values, width * 0.9, color=color, label=alg)
                ax.bar_label(bars, fmt="%.2f", padding=3, fontsize=8)

        ax.set_xticks(range(len(groups)))
        ax.set_xticklabels(list(groups.values()), fontweight="bold")
        ax.set_xlim(-0.6, len(groups) - 0.4)
        ax.set_ylim(bottom=0)
        ax.margins(y=0.20)
        ax.set_ylabel("Thời gian chặn trung bình (ms)", fontsize=10)
        ax.set_title(title, pad=15, fontsize=12, fontweight="bold")
        ax.set_axisbelow(True)
        ax.grid(axis="y", alpha=0.25, linestyle="--")
        handles, labels = ax.get_legend_handles_labels()
        if handles:
            ax.legend(handles, labels, ncol=min(5, len(handles)), loc="upper center", bbox_to_anchor=(0.5, -0.12))
        fig.tight_layout()

        # Lưu vào thư mục benchmark kết quả
        dest_paths = [BENCHMARK_DIR / filename]
        for dest in dest_paths:
            dest.parent.mkdir(parents=True, exist_ok=True)
            fig.savefig(dest, dpi=180)
            print(f"[CHART] Đã lưu: {dest}")

        plt.close(fig)
        return True
    except Exception as e:
        print(f"[CHART] Lỗi vẽ biểu đồ {filename}: {e}", file=sys.stderr)
        return False


def save_comparison_charts(results: dict) -> bool:
    """Tạo 3 biểu đồ so sánh: Tổng quan kịch bản, Sửa Payload, Lật bit."""
    # 1. Biểu đồ tổng quan cả 3 kịch bản
    overall = {
        alg: {kind: data.get(kind, {}).get("mean_ms") for kind in SCENARIOS}
        for alg, data in results.items()
    }
    s1 = save_grouped_chart(
        overall,
        {kind: kind for kind in SCENARIOS},
        "sec03_comparison_chart.png",
        "SEC-03: So Sánh Độ Trễ Chặn Tấn Công Giữa Các Thuật Toán (PQC vs Classical)"
    )

    # 2. Biểu đồ Payload Mutation theo trường bị sửa
    _, mut_groups = DETAIL_GROUPS["Payload mutation"]
    mutation_vals = {
        alg: data.get("Payload mutation", {}).get("group_mean_ms", {})
        for alg, data in results.items()
    }
    s2 = save_grouped_chart(
        mutation_vals,
        mut_groups,
        "sec03_comparison_mutation.png",
        "SEC-03: Payload Mutation · So Sánh Độ Trễ Theo Trường Bị Sửa (Amount / Receiver / Sender)"
    )

    # 3. Biểu đồ Bit-Flipping theo số bit bị lật
    _, bit_groups = DETAIL_GROUPS["Bit-flipping"]
    bit_vals = {
        alg: data.get("Bit-flipping", {}).get("group_mean_ms", {})
        for alg, data in results.items()
    }
    s3 = save_grouped_chart(
        bit_vals,
        bit_groups,
        "sec03_comparison_bitflip.png",
        "SEC-03: Bit-Flipping · So Sánh Độ Trễ Theo Số Bit Bị Lật (1, 2, 3, 4 bit)"
    )
    return s1 and s2 and s3


def generate_batch_json(results: dict, batch_path: Path) -> Path:
    """Xuất file batch JSON tổng hợp các kết quả kiểm thử."""
    batch_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "algorithms": list(results.keys()),
        "benchmark": results
    }
    batch_path.write_text(json.dumps(batch_data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[BATCH] Đã xuất Batch JSON tổng hợp: {batch_path}")
    return batch_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, help="Đường dẫn tới file Batch JSON có sẵn để phân tích")
    parser.add_argument("--dir", type=Path, default=BENCHMARK_DIR, help="Thư mục quét tìm file log/summary")
    parser.add_argument("--out-batch", action="store_true", default=True, help="Tự động xuất tệp sec03_batch_<timestamp>.json")
    args = parser.parse_args()

    results: dict = {}

    if args.batch and args.batch.is_file():
        report = json.loads(args.batch.read_text(encoding="utf-8"))
        results = report.get("benchmark", {})
    else:
        # Tìm các file summary mới nhất trong thư mục
        summaries = find_latest_summaries(args.dir)
        for alg, path in summaries.items():
            results[alg] = analyze_summary_file(path)

        # Nếu thiếu summary, tìm các file jsonl tương ứng
        for jsonl_path in args.dir.glob("sec03_*.jsonl"):
            try:
                # 1. Đoán qua tên file: sec03_ecdsa_... hoặc sec03_mldsa44_...
                name_parts = jsonl_path.stem.split("_")
                alg_guess = None
                if len(name_parts) >= 2 and name_parts[1].lower() in SCHEMES.values():
                    scheme_k = name_parts[1].lower()
                    for lbl, sk in SCHEMES.items():
                        if sk == scheme_k:
                            alg_guess = lbl
                            break

                # 2. Nếu chưa đoán được, đọc sender_name trong dòng đầu
                if not alg_guess:
                    with jsonl_path.open(encoding="utf-8", errors="ignore") as f:
                        line = f.readline()
                        if line:
                            first = json.loads(line)
                            sender = first.get("sender_name", "")
                            if "MLDSA87" in sender:
                                alg_guess = "ML-DSA-87"
                            elif "MLDSA65" in sender:
                                alg_guess = "ML-DSA-65"
                            elif "PQC" in sender:
                                alg_guess = "ML-DSA-44"
                            elif sender in ("Alice", "Bob", "Charlie", "Dave", "Perf_ECDSA"):
                                alg_guess = "ECDSA"

                if alg_guess and alg_guess not in results:
                    results[alg_guess] = analyze_log_file(jsonl_path)
            except Exception:
                pass

    if not results:
        print("[!] Không tìm thấy log kiểm thử SEC-03 nào. Vui lòng chạy attack_sec03.py hoặc run_all_attacks.py trước.")
        return 1

    print_benchmark_table(results)
    save_comparison_charts(results)

    if args.out_batch:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        batch_file = BENCHMARK_DIR / f"sec03_batch_{stamp}.json"
        generate_batch_json(results, batch_file)

    return 0


if __name__ == "__main__":
    sys.exit(main())
