"""
Pytest integration wrapper for SEC-06 Nonce Clone Benchmark
"""
import os
import sys
from pathlib import Path

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tests.sec06_nonce_clone.sec06_nonce_reuse_benchmark import NonceReuseBenchmark


def test_sec06_nonce_reuse_exploit_and_defense():
    benchmark = NonceReuseBenchmark()
    summary = benchmark.run_all_cases()
    assert summary['ecdsa']['key_recovery_rate_percent'] == 100.0
    assert summary['mldsa']['key_recovery_rate_percent'] == 0.0
    assert summary['ecdsa']['forged_transactions_accepted'] == 5


if __name__ == "__main__":
    test_sec06_nonce_reuse_exploit_and_defense()
    print("[v] SEC-06 Test Passed Successfully!")
