"""
Unit and Integration test wrapper for SEC-06 Nonce Clone Benchmark.
Compatible with both python -m unittest and pytest.
"""
import os
import sys
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tests.sec06_nonce_clone.sec06_nonce_reuse_benchmark import NonceReuseBenchmark


class TestSec06NonceClone(unittest.TestCase):
    def test_sec06_nonce_reuse_exploit_and_defense(self):
        benchmark = NonceReuseBenchmark()
        summary = benchmark.run_all_cases()
        self.assertEqual(summary['ecdsa']['key_recovery_rate_percent'], 100.0)
        self.assertEqual(summary['mldsa']['key_recovery_rate_percent'], 0.0)
        self.assertEqual(summary['ecdsa']['forged_transactions_accepted'], 5)


if __name__ == "__main__":
    unittest.main()
