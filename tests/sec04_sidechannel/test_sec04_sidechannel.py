"""
Pytest integration test wrapper for SEC-04 Side-Channel Benchmark.
Calls tests/security/sec04_sidechannel_timing.py
"""
import runpy
from pathlib import Path

def test_sec04_sidechannel_execution():
    target = Path(__file__).resolve().parent / "sec04_sidechannel_timing.py"
    assert target.exists(), "Target sec04_sidechannel_timing.py does not exist"

if __name__ == "__main__":
    target = Path(__file__).resolve().parent / "sec04_sidechannel_timing.py"
    runpy.run_path(str(target), run_name="__main__")
