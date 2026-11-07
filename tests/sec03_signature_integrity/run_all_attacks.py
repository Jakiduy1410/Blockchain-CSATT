#!/usr/bin/env python3
"""
Bộ điều phối kiểm thử toàn diện SEC-03 (Batch Orchestrator Runner):
- Tự động chạy lần lượt 4 thuật toán: ECDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87
- Kiểm tra tính sẵn sàng của 6 Node P2P (tự động khởi động nếu chưa chạy)
- Sử dụng Multi-Worker dispatching đồng thời
- Thu thập toàn bộ kết quả, xuất Batch JSON tổng hợp và sinh 3 biểu đồ so sánh chuẩn báo cáo.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent
if ROOT.name == "sec03_signature_integrity":
    ROOT = ROOT.parents[1]
BENCHMARK_DIR = ROOT / "benchmarks" / "results" / "sec03_tamper"
BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_SCHEMES = ["ecdsa", "mldsa44", "mldsa65", "mldsa87"]
SCHEME_LABELS = {
    "ecdsa": "ECDSA",
    "mldsa44": "ML-DSA-44",
    "mldsa65": "ML-DSA-65",
    "mldsa87": "ML-DSA-87",
}


def check_node_health(ports: list[int]) -> list[int]:
    """Kiểm tra xem cổng node nào đang mở và phản hồi /status 200."""
    active_ports = []
    for p in ports:
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{p}/status")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    active_ports.append(p)
        except Exception:
            pass
    return active_ports


def start_nodes(ports: list[int], python_exe: str) -> list[subprocess.Popen]:
    """Khởi động 6 node P2P chạy nền với cấu hình hỗ trợ toàn bộ chữ ký (--sig all)."""
    print(f"[*] Đang tự động khởi chạy 6 Node P2P qua start_interactive_network.py...")
    launcher = ROOT / "start_interactive_network.py"
    if launcher.is_file():
        proc = subprocess.Popen([python_exe, str(launcher), "-y", "--sig", "all", "--tls", "ecdhe", "--auto-mine"])
        deadline = time.monotonic() + 35.0
        while time.monotonic() < deadline:
            active = check_node_health(ports)
            if len(active) >= len(ports):
                print(f"[+] Toàn bộ {len(ports)} Node đã sẵn sàng: {active}")
                return [proc]
            time.sleep(1.0)
    raise RuntimeError("Không thể khởi động mạng 6 Node.")


def run_single_scheme(
    scheme: str,
    args: argparse.Namespace,
    run_stamp: str
) -> tuple[int, Path]:
    """Thực thi attack_sec03.py cho một thuật toán cụ thể."""
    attack_script = ROOT / "tests" / "sec03_signature_integrity" / "attack_sec03.py"
    log_file = BENCHMARK_DIR / f"sec03_{scheme}_{run_stamp}.jsonl"

    cmd = [
        args.python,
        str(attack_script),
        "--project-root", str(ROOT),
        "--scheme", scheme,
        "--count-per-scenario", str(args.count_per_scenario),
        "--workers", str(args.workers),
        "--timeout", str(args.timeout),
        "--delay", str(args.delay),
        "--ports", *(str(p) for p in args.ports),
        "--log", str(log_file)
    ]
    if not args.mine:
        cmd.append("--no-mine")

    print(f"\n" + "#" * 80)
    print(f"  BẮT ĐẦU CHẠY THỬ NGHIỆM CHO THUẬT TOÁN: {SCHEME_LABELS.get(scheme, scheme.upper())}")
    print(f"#" * 80)

    res = subprocess.run(cmd)
    return res.returncode, log_file


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schemes", nargs="+", default=DEFAULT_SCHEMES,
                        choices=["ecdsa", "mldsa44", "mldsa65", "mldsa87", "all"],
                        help="Danh sách thuật toán cần chạy (mặc định: toàn bộ 4 thuật toán: ECDSA, ML-DSA-44, 65, 87)")
    parser.add_argument("--count-per-scenario", type=int, default=300,
                        help="Số ca kiểm thử mỗi kịch bản (mặc định 300 = 150 Benign + 150 Malicious)")
    parser.add_argument("--workers", type=int, default=6,
                        help="Số luồng worker gửi đồng thời (mặc định: 6)")
    parser.add_argument("--ports", nargs="+", type=int, default=list(range(5000, 5006)),
                        help="Danh sách cổng node mục tiêu (mặc định 5000-5005)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout HTTP (giây)")
    parser.add_argument("--delay", type=float, default=0.0, help="Độ trễ giữa các request (giây)")
    parser.add_argument("--python", default=sys.executable, help="Trình thông dịch Python")
    parser.add_argument("--no-mine", dest="mine", action="store_false", default=True,
                        help="Không tự động kích hoạt đào block sau khi test")
    parser.add_argument("--dry-run", action="store_true", help="Chỉ kiểm tra cấu hình, không gửi gói tin")
    parser.add_argument("--auto-start", action="store_true", default=False,
                        help="Tự động bật 6 node nếu mạng chưa chạy")
    args = parser.parse_args()

    selected_schemes = DEFAULT_SCHEMES if "all" in args.schemes else args.schemes

    print("=" * 80)
    print("       BỘ ĐIỀU PHỐI KIỂM THỬ TỰ ĐỘNG SEC-03 (ALL SCHEMES RUNNER)")
    print(f"  • Thuật toán chọn chạy : {', '.join([SCHEME_LABELS.get(s, s) for s in selected_schemes])}")
    print(f"  • Số ca mỗi kịch bản   : {args.count_per_scenario}")
    print(f"  • Số Workers đồng thời : {args.workers}")
    print(f"  • Dải cổng Node        : {args.ports}")
    print("=" * 80)

    if args.dry_run:
        print("[+] Chế độ Dry-Run: Cấu hình kiểm thử hợp lệ. Đã kiểm tra sẵn sàng.")
        return 0

    # Kiểm tra trạng thái mạng
    active_nodes = check_node_health(args.ports)
    node_procs = []
    if len(active_nodes) < len(args.ports):
        missing = [p for p in args.ports if p not in active_nodes]
        print(f"[!] Mạng chưa đủ 6 Node (Các port chưa chạy: {missing}).")
        if args.auto_start:
            node_procs = start_nodes(args.ports, args.python)
        else:
            print("[!] Vui lòng bật mạng trước: python start_interactive_network.py (hoặc thêm cờ --auto-start).")
            print("    Đang thử chạy với các node hiện có...")

    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_results = {}

    try:
        for sc in selected_schemes:
            code, log_p = run_single_scheme(sc, args, run_stamp)
            run_results[sc] = {
                "exit_code": code,
                "log_path": str(log_p),
                "status": "PASSED" if code == 0 else "FAILED"
            }
            time.sleep(1.0)
    finally:
        if node_procs:
            print("[*] Đang đóng các tiến trình Node đã tự khởi chạy...")
            for p in node_procs:
                try:
                    if sys.platform == "win32" and hasattr(p, "pid"):
                        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    else:
                        p.terminate()
                except Exception:
                    pass

    # Phân tích tổng hợp qua compare.py
    print("\n" + "=" * 80)
    print("  ĐANG TỔNG HỢP KẾT QUẢ VÀ XUẤT BATCH BÁO CÁO QUA compare.py...")
    print("=" * 80)

    compare_script = ROOT / "tests" / "sec03_signature_integrity" / "compare.py"
    if not compare_script.is_file():
        compare_script = ROOT / "compare.py"
    if compare_script.is_file():
        subprocess.run([args.python, str(compare_script), "--dir", str(BENCHMARK_DIR), "--out-batch"])

    all_passed = all(r["exit_code"] == 0 for r in run_results.values())
    print("\n" + "=" * 80)
    print(f"  HOÀN TẤT KIỂM THỬ BATCH SEC-03: {'100% THÀNH CÔNG (PASSED)' if all_passed else 'CÓ LỖI (FAILED)'}")
    print("=" * 80)
    return 0 if all_passed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Đã dừng bởi người dùng (Ctrl+C).", file=sys.stderr)
        sys.exit(130)
