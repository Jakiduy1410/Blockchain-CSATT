"""
Pytest integration wrapper for SEC-05 ML-DSA TVLA Benchmark
"""
import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tests.sec05_tvla_ml_dsa.sec05_mldsa_tvla_benchmark import MLDSATimingTVLABenchmark


def test_sec05_tvla_mldsa_constant_time():
    benchmark = MLDSATimingTVLABenchmark(samples_per_set=500)
    benchmark.setup()
    benchmark.run_benchmark()
    results = benchmark.analyze_results()
    assert results['is_constant_time'] is True, f"Rò rỉ kênh kề: |t| = {results['abs_t_statistic']}"


if __name__ == "__main__":
    test_sec05_tvla_mldsa_constant_time()
    print("[v] SEC-05 Test Passed Successfully!")
