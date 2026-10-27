"""
Forwarder for backward compatibility.
The actual implementation is now located at tests/sec04_sidechannel/sec04_sidechannel_timing.py
"""
import runpy
from pathlib import Path

def test_sec04_sidechannel_forwarder():
    target = Path(__file__).resolve().parent / "sec04_sidechannel" / "sec04_sidechannel_timing.py"
    assert target.exists(), f"Target script not found: {target}"

if __name__ == "__main__":
    target = Path(__file__).resolve().parent / "sec04_sidechannel" / "sec04_sidechannel_timing.py"
    runpy.run_path(str(target), run_name="__main__")
