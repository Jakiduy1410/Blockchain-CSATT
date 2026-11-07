"""Print the recorded report tables; this does not run an experiment."""
import csv
from pathlib import Path

root = Path(__file__).resolve().parent/'results'/'analysis'
print('RECORDED NET-01/NET-02 RESULTS - 2026-11-07 (not a live network test)')
print('\nNET-01: transaction size and TCP segmentation')
print(f'{"Algorithm":<10} {"MTU":>5} {"n":>5} {"JSON B":>10} {"P2P JSON B":>11} {"seg/tx":>8} {"header B/tx":>12}')
for r in csv.DictReader((root/'net01_summary.csv').open()):
    print(f'{r["algorithm"]:<10} {r["mtu"]:>5} {r["n"]:>5} {float(r["json_bytes"]):10.2f} {float(r["ws_json_bytes"]):11.2f} {float(r["segments_per_tx"]):8.2f} {float(r["header_per_tx"]):12.2f}')
print('\nNET-02: application-level block propagation (observed samples only)')
print(f'{"Algorithm":<10} {"MTU":>5} {"Network":<8} {"Samples":>7} {"Median ms":>11} {"P95 ms":>11} {"Sync runs":>10}')
for r in csv.DictReader((root/'net02_summary.csv').open()):
    print(f'{r["algorithm"]:<10} {r["mtu"]:>5} {r["profile"]:<8} {r["samples"]:>7} {float(r["median_ms"]):11.2f} {float(r["p95_ms"]):11.2f} {r["synced_runs"]:>8}/{r["runs"]}')
print('\n58/60 runs converged. 1758/2040 blocks have paired P2P timestamps.')
print('At high loss, slower blocks may be unobserved before cutoff. Compare sample coverage too.')
