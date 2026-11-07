#!/usr/bin/env python3
"""So sánh độ trễ các yêu cầu tấn công bị chặn trong SEC-03."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import tempfile
from pathlib import Path, PureWindowsPath

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent
PROJECTS = {
    "RSA": "Blockchain-CSATT-rsa",
    "ECDSA": "Blockchain-CSATT-ecdsa",
    "ML-DSA-44": "Blockchain-CSATT-mldsa44",
    "ML-DSA-65": "Blockchain-CSATT-mldsa65",
    "ML-DSA-87": "Blockchain-CSATT-mldsa87",
}
SCENARIOS = ("Bit-flipping", "Payload mutation", "Replay")
DETAIL_GROUPS = {
    "Bit-flipping": ("bit_flips", {str(bits): f"{bits} bit" for bits in range(1, 5)}),
    "Payload mutation": ("mutation_field", {
        "amount": "Amount", "recipient_address": "Receiver", "sender_address": "Sender",
    }),
}


def latest_logs():
    selected = {}
    for algorithm, directory in PROJECTS.items():
        files = list((ROOT / directory).glob("sec03_*.jsonl"))
        if files:
            selected[algorithm] = max(files, key=lambda path: path.stat().st_mtime)
    return selected


def percentile_95(values):
    ordered = sorted(values)
    return ordered[math.ceil(0.95 * len(ordered)) - 1]


def saved_benchmarks():
    """Load comparison rows saved by the runner before raw log cleanup."""
    for batch in sorted(ROOT.glob("sec03_batch_*.json")):
        try:
            report = json.loads(batch.read_text(encoding="utf-8"))
            benchmark = report["benchmark"]
            runs = report["runs"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if not isinstance(benchmark, dict) or not isinstance(runs, list):
            continue
        for run in runs:
            if not isinstance(run, dict):
                continue
            algorithm = run.get("algorithm")
            path = run.get("log")
            mtime = run.get("log_mtime_ns")
            if (isinstance(algorithm, str) and algorithm in benchmark
                    and isinstance(path, str) and isinstance(mtime, int)):
                yield algorithm, Path(path), mtime, benchmark[algorithm]


def analyze_logs(log_paths=None):
    paths = latest_logs() if log_paths is None else log_paths
    results = {}
    if log_paths is None:
        newest = {algorithm: path.stat().st_mtime_ns
                  for algorithm, path in paths.items()}
        for algorithm, _, mtime, data in saved_benchmarks():
            if mtime > newest.get(algorithm, -1):
                newest[algorithm] = mtime
                results[algorithm] = data
        paths = {algorithm: path for algorithm, path in paths.items()
                 if algorithm not in results}

    for algorithm, path in paths.items():
        path = Path(path)
        if not path.is_file():
            for saved_algorithm, saved_path, _, data in saved_benchmarks():
                if saved_algorithm == algorithm and saved_path.resolve() == path.resolve():
                    results[algorithm] = data
                    break
            else:
                raise FileNotFoundError(f"Không thấy log: {path}")
            continue

        times = {kind: [] for kind in SCENARIOS}
        group_times = {kind: {key: [] for key in labels}
                       for kind, (_, labels) in DETAIL_GROUPS.items()}
        sent = {kind: 0 for kind in SCENARIOS}
        blocked = {kind: 0 for kind in SCENARIOS}
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                    kind = row.get("scenario")
                    group = row.get("group")
                    if group is None:
                        group = ("normal" if kind == "Replay"
                                 and row.get("baseline") else "attack")
                    if kind not in times or group != "attack":
                        continue
                    sent[kind] += 1
                    if (row.get("result") != "blocked"
                            or row.get("evidence_type") == "assumption"):
                        continue
                    value = float(row["elapsed_ms"])
                    if not math.isfinite(value) or value < 0:
                        continue
                    blocked[kind] += 1
                    times[kind].append(value)
                    if kind in DETAIL_GROUPS:
                        field, _ = DETAIL_GROUPS[kind]
                        key = str(row.get(field))
                        if key in group_times[kind]:
                            group_times[kind][key].append(value)
                except (ValueError, TypeError, KeyError):
                    continue

        summary_path = path.with_suffix(".summary.json")
        phase_seconds = {}
        if summary_path.is_file():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                phase_seconds = {
                    item["scenario"]: item.get("phase_wall_seconds")
                    for item in summary.get("scenarios", [])
                }
            except (OSError, ValueError, KeyError, TypeError):
                pass

        results[algorithm] = {
            kind: {
                "attack_sent": sent[kind],
                "blocked": blocked[kind],
                "mean_ms": (math.fsum(times[kind]) / len(times[kind])
                            if times[kind] else None),
                "p95_ms": (percentile_95(times[kind])
                           if times[kind] else None),
                "total_ms": math.fsum(times[kind]),
                "phase_wall_seconds": phase_seconds.get(kind),
            }
            for kind in SCENARIOS
        }
        for kind, groups in group_times.items():
            results[algorithm][kind]["group_mean_ms"] = {
                key: math.fsum(values) / len(values)
                for key, values in groups.items() if values
            }
    return results


def print_benchmark(results):
    def number(value):
        return "N/A" if value is None else f"{value:.2f}"

    header = (f"{'Thuật toán':<12} {'Kịch bản':<17} {'Chặn/gửi':>10} "
              f"{'TB (ms)':>11} {'P95 (ms)':>11} {'Tổng (ms)':>12} "
              f"{'Pha (s)':>10}")
    print("\nSO SÁNH THỜI GIAN CHẶN TẤN CÔNG SEC-03")
    print(header)
    print("-" * len(header))
    for algorithm in PROJECTS:
        if algorithm not in results:
            continue
        for kind in SCENARIOS:
            data = results[algorithm][kind]
            print(f"{algorithm:<12} {kind:<17} "
                  f"{data['blocked']:>4}/{data['attack_sent']:<5} "
                  f"{number(data['mean_ms']):>11} "
                  f"{number(data['p95_ms']):>11} "
                  f"{number(data['total_ms']):>12} "
                  f"{number(data['phase_wall_seconds']):>10}")
    print("TB/P95: độ trễ phản hồi của riêng yêu cầu tấn công bị chặn. "
          "Pha: thời gian chạy cả kịch bản, gồm gửi và xác nhận block.")


def analyze_batch(path):
    report = json.loads(path.read_text(encoding="utf-8"))
    # New batches retain the original comparison values after JSONL cleanup.
    results = dict(report.get("benchmark", {}))
    logs = {}
    for run in report["runs"]:
        algorithm = run.get("algorithm")
        original = run.get("log")
        if algorithm not in PROJECTS or not original:
            continue
        saved = results.get(algorithm, {})
        if all("group_mean_ms" in saved.get(kind, {}) for kind in DETAIL_GROUPS):
            continue
        name = PureWindowsPath(original).name
        candidates = (
            path.parent / original,
            path.parent / PROJECTS[algorithm] / name,
            ROOT / PROJECTS[algorithm] / name,
        )
        log = next((candidate for candidate in candidates if candidate.is_file()), None)
        if log is not None:
            logs[algorithm] = log
    for algorithm, data in analyze_logs(logs).items():
        saved = results.setdefault(algorithm, data)
        for kind in DETAIL_GROUPS:
            saved.setdefault(kind, data[kind]).setdefault(
                "group_mean_ms", data[kind]["group_mean_ms"]
            )
    return results


def save_grouped_chart(values_by_algorithm, groups, filename, title,
                       pending_outputs=None):
    path = ROOT / filename
    temporary = None
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        colors = ("#516174", "#ad651d", "#158379", "#3169b0", "#8154a4")
        width = 0.15
        fig, ax = plt.subplots(figsize=(12, 5.8))
        try:
            for index, (algorithm, color) in enumerate(zip(PROJECTS, colors)):
                data = values_by_algorithm.get(algorithm, {})
                offset = (index - (len(PROJECTS) - 1) / 2) * width
                positions, values = [], []
                for group, key in enumerate(groups):
                    position = group + offset
                    value = data.get(key)
                    if value is None:
                        ax.text(position, 0.015, "N/A", ha="center", color=color,
                                fontsize=8, transform=ax.get_xaxis_transform())
                    else:
                        positions.append(position)
                        values.append(value)
                bars = ax.bar(positions, values, width * 0.9, color=color, label=algorithm)
                ax.bar_label(bars, fmt="%.2f", padding=3, fontsize=8)
            ax.set_xticks(range(len(groups)), list(groups.values()))
            ax.set_xlim(-0.5, len(groups) - 0.5)
            ax.set_ylim(bottom=0)
            ax.margins(y=0.18)
            ax.set_ylabel("Thời gian chặn trung bình (ms)")
            ax.set_title(title, pad=15)
            if not any(value is not None for data in values_by_algorithm.values()
                       for value in data.values()):
                ax.text(0.5, 0.5, "Không có số liệu cho các nhóm trong log đã chọn",
                        ha="center", va="center", transform=ax.transAxes)
            ax.set_axisbelow(True)
            ax.grid(axis="y", alpha=0.22)
            ax.legend(ncol=len(PROJECTS), loc="upper center", bbox_to_anchor=(0.5, -0.10))
            fig.tight_layout()
            with tempfile.NamedTemporaryFile(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
            fig.savefig(temporary, format="png", dpi=180)
        finally:
            plt.close(fig)
        if pending_outputs is None:
            os.replace(temporary, path)
        else:
            pending_outputs.append((temporary, path))
        temporary = None
    except Exception as exc:
        print(f"[CHART] Không lưu được {path}: {exc}", file=sys.stderr)
        return False
    else:
        print(f"[CHART] {path}")
        return True
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def save_comparison_chart(results, pending_outputs=None):
    staged = []
    overall = {algorithm: {kind: row["mean_ms"] for kind, row in data.items()}
               for algorithm, data in results.items()}
    try:
        succeeded = save_grouped_chart(
            overall, {kind: kind for kind in SCENARIOS},
            "sec03_comparison_chart.png", "SEC-03 · So sánh thời gian chặn tấn công",
            pending_outputs=staged,
        )
        for kind, filename, title in (
            ("Payload mutation", "sec03_comparison_mutation.png",
             "SEC-03 · Payload mutation theo trường bị sửa"),
            ("Bit-flipping", "sec03_comparison_bitflip.png",
             "SEC-03 · Bit-flipping theo số bit bị lật"),
        ):
            _, groups = DETAIL_GROUPS[kind]
            values = {algorithm: data.get(kind, {}).get("group_mean_ms", {})
                      for algorithm, data in results.items()}
            saved = save_grouped_chart(values, groups, filename, title,
                                       pending_outputs=staged)
            succeeded = saved and succeeded
        if not succeeded:
            return False
        if pending_outputs is None:
            for temporary, path in staged:
                os.replace(temporary, path)
        else:
            pending_outputs.extend(staged)
            staged = []
        return True
    finally:
        for temporary, _ in staged:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def report_comparison(results, pending_outputs=None):
    if not results:
        return False
    print_benchmark(results)
    return save_comparison_chart(results, pending_outputs=pending_outputs)


def report_batch(path, pending_outputs=None, source_path=None):
    results = analyze_batch(path if source_path is None else source_path)
    print(f"[BATCH] {path}")
    return report_comparison(results, pending_outputs=pending_outputs)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--batch", type=Path, help="Chọn file báo cáo batch SEC-03.")
    source.add_argument(
        "--log", action="append", default=[], metavar="ALGORITHM=PATH",
        help="Chọn log cụ thể; có thể lặp lại cho 5 thuật toán.",
    )
    args = parser.parse_args()
    if not args.log:
        return args.batch, None
    paths = {}
    for item in args.log:
        algorithm, separator, raw_path = item.partition("=")
        if not separator or algorithm not in PROJECTS or not raw_path:
            parser.error("--log cần dạng RSA=path hoặc ML-DSA-44=path")
        path = Path(raw_path).resolve()
        paths[algorithm] = path
    return None, paths


if __name__ == "__main__":
    batch, paths = parse_args()
    if batch is None and paths is None:
        batch = max(ROOT.glob("sec03_batch_*.json"),
                    key=lambda path: path.stat().st_mtime_ns, default=None)
    try:
        found = (report_batch(batch.resolve()) if batch is not None
                 else report_comparison(analyze_logs(paths)))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise SystemExit(str(exc)) from exc
    if not found:
        raise SystemExit("Không tìm thấy log SEC-03.")
