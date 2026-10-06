"""
Unified Benchmark Suite Entrypoint
Usage:
  python benchmarks/run_benchmarks.py --micro
  python benchmarks/run_benchmarks.py --macro
  python benchmarks/run_benchmarks.py --all
"""

import argparse
import sys
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


def main():
    parser = argparse.ArgumentParser(description="Blockchain Benchmark Suite Runner")
    parser.add_argument('--micro', action='store_true', help="Chạy Micro-Benchmark (Đo lường thuật toán mật mã)")
    parser.add_argument('--macro', action='store_true', help="Chạy Macro-Benchmark (Đo lường mạng lưới P2P E2E)")
    parser.add_argument('--all', action='store_true', help="Chạy toàn bộ cả Micro và Macro Benchmark")
    parser.add_argument('-n', '--iterations', type=int, default=0, help="Số lần lặp (Micro) hoặc số transaction (Macro)")
    parser.add_argument('-c', '--config', type=str, default="", help="Đường dẫn file cấu hình JSON")
    parser.add_argument('-o', '--output-dir', type=str, default="", help="Thư mục xuất kết quả")
    args = parser.parse_args()

    # Default to --all if no specific mode selected
    run_all = args.all or (not args.micro and not args.macro)

    if args.micro or run_all:
        from benchmarks.micro_benchmark import main as run_micro
        print("\n" + "=" * 80)
        print("  KHOI DONG PHAN 1: MICRO-BENCHMARK (CRYPTOGRAPHIC PRIMITIVES)")
        print("=" * 80)
        micro_args = []
        if args.iterations > 0:
            micro_args.extend(['-n', str(args.iterations)])
        if args.config:
            micro_args.extend(['-c', args.config])
        if args.output_dir:
            micro_args.extend(['-o', args.output_dir])
        sys.argv = [sys.argv[0]] + micro_args
        run_micro()

    if args.macro or run_all:
        from benchmarks.macro_benchmark import main as run_macro
        print("\n" + "=" * 80)
        print("  KHOI DONG PHAN 2: MACRO-BENCHMARK (END-TO-END P2P NETWORK)")
        print("=" * 80)
        macro_args = []
        if args.iterations > 0:
            macro_args.extend(['-n', str(args.iterations)])
        if args.config:
            macro_args.extend(['-c', args.config])
        if args.output_dir:
            macro_args.extend(['-o', args.output_dir])
        sys.argv = [sys.argv[0]] + macro_args
        run_macro()


if __name__ == '__main__':
    main()
