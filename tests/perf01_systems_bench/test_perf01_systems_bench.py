"""
Unit and Integration Test Suite for PERF-01: Resource Constrained Stress Test
Verifies dataset integrity, benchmark result structures, and telemetry components.
"""

import json
import unittest
from pathlib import Path


class TestPerf01SystemsBench(unittest.TestCase):
    def setUp(self):
        self.base_dir = Path(__file__).resolve().parent.parent.parent
        self.results_dir = self.base_dir / "benchmarks" / "results" / "perf01_resource_stress"
        self.data_dir = self.results_dir / "data"

    def test_datasets_exist_and_valid(self):
        """Verify pre-generated stress transaction datasets exist and are valid JSON."""
        expected_files = [
            "txs_500_ecdsa.json",
            "txs_500_rsa.json",
            "txs_500_mldsa87.json",
            "txs_stress_ecdsa.json",
            "txs_stress_mldsa87.json"
        ]
        for fname in expected_files:
            fpath = self.data_dir / fname
            self.assertTrue(fpath.is_file(), f"Dataset file {fname} must exist in data directory")
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIsInstance(data, list)
            self.assertGreater(len(data), 0)

            # Check transaction fields in sample
            tx = data[0]
            self.assertIn("sender_address", tx)
            self.assertIn("recipient_address", tx)
            self.assertTrue("amount" in tx or "value" in tx)
            self.assertIn("signature", tx)

    def test_benchmark_results_and_reports_exist(self):
        """Verify benchmark matrix, report, and visualizations exist."""
        matrix_csv = self.results_dir / "perf01_matrix.csv"
        results_json = self.results_dir / "perf01_results.json"
        report_md = self.results_dir / "PERF01_BENCHMARK_REPORT.md"
        docker_compose = self.results_dir / "docker-compose.yml"

        self.assertTrue(matrix_csv.is_file(), "perf01_matrix.csv must exist")
        self.assertTrue(results_json.is_file(), "perf01_results.json must exist")
        self.assertTrue(report_md.is_file(), "PERF01_BENCHMARK_REPORT.md must exist")
        self.assertTrue(docker_compose.is_file(), "docker-compose.yml must exist")

        with open(results_json, "r", encoding="utf-8") as f:
            res_data = json.load(f)
        self.assertIsInstance(res_data, list)
        self.assertEqual(len(res_data), 9, "Matrix must have 9 evaluations (3 hardware x 3 algorithms)")


if __name__ == "__main__":
    unittest.main()
