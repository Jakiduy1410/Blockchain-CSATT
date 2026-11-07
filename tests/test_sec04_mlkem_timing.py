"""
Forwarder for backward compatibility with unittest and pytest.
The actual implementation is located at tests/sec04_sidechannel/sec04_sidechannel_timing.py
"""
import unittest
from pathlib import Path


class TestSec04MlkemTimingForwarder(unittest.TestCase):
    def test_sec04_sidechannel_forwarder(self):
        target = Path(__file__).resolve().parent / "sec04_sidechannel" / "sec04_sidechannel_timing.py"
        self.assertTrue(target.exists(), f"Target script not found: {target}")


if __name__ == "__main__":
    unittest.main()
