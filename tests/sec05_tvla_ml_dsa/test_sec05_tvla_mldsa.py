"""
Unit and Integration test wrapper for SEC-05 ML-DSA TVLA Benchmark.
Compatible with both python -m unittest and pytest.
"""
import os
import sys
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tests.sec05_tvla_ml_dsa.sec05_mldsa_tvla_benchmark import MLDSATimingTVLABenchmark


class TestSec05TvlaMldsa(unittest.TestCase):
    def test_sec05_tvla_mldsa_constant_time(self):
        benchmark = MLDSATimingTVLABenchmark(samples_per_set=500)
        benchmark.setup()
        benchmark.run_benchmark()
        results = benchmark.analyze_results()
        self.assertTrue(results['is_constant_time'], f"Ro ri kenh ke: |t| = {results['abs_t_statistic']}")


if __name__ == "__main__":
    unittest.main()
