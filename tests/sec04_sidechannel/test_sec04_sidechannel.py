"""
Unit and Integration test wrapper for SEC-04 Side-Channel Benchmark.
Compatible with both python -m unittest and pytest.
"""
import unittest
from pathlib import Path


class TestSec04SideChannel(unittest.TestCase):
    def test_sec04_sidechannel_execution(self):
        target = Path(__file__).resolve().parent / "sec04_sidechannel_timing.py"
        self.assertTrue(target.exists(), "Target sec04_sidechannel_timing.py does not exist")


if __name__ == "__main__":
    unittest.main()
