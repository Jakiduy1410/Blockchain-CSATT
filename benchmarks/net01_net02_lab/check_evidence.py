"""Read-only checks on recorded evidence; no nodes, networking, or mining."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--data-root', type=Path, required=True)
parser.add_argument('--verify-hashes', action='store_true')
args = parser.parse_args()
root = args.data_root.resolve()
one = sorted((root/'evidence_seg_final').glob('N1_*/result.json'))
two = sorted((root/'evidence_net2').glob('N2_*/result.json'))
assert len(one) == 12, f'Expected 12 NET-01 runs, found {len(one)}'
assert len(two) == 60, f'Expected 60 NET-02 runs, found {len(two)}'
txs = blocks = synced = 0
for p in one:
    r = json.loads(p.read_text())
    assert r['n'] == r['received'] == 100, p.parent.name
    txs += r['n']
for p in two:
    r = json.loads(p.read_text())
    assert len(r['mined']) == 34 and all(s['valid'] for s in r['final']), p.parent.name
    blocks += len(r['mined'])
    synced += int(r['synced'])
for p in one + two:
    for name in ['traffic.pcap', 'eventsA.jsonl', 'eventsB.jsonl']:
        assert (p.parent/name).is_file(), str(p.parent/name)
all_data = json.loads((root/'analysis/all.json').read_text())
samples = sum(row['samples'] for row in all_data['net02'])
assert (txs, blocks, synced, samples) == (1200, 2040, 58, 1758)
print(f'NET-01: {len(one)} runs, {txs} transactions, all received')
print(f'NET-02: {len(two)} runs, {blocks} mined blocks, {synced}/60 converged at cutoff')
print(f'P2P timestamp pairs: {samples}/2040; missing pairs are not zero delay')
for row in all_data['runs']:
    if not row['synced']:
        print('Unconverged (preserved):', row['run'])
if args.verify_hashes:
    checked = 0
    for line in (root/'manifest.sha256').read_text().splitlines():
        expected, name = line.split('  ', 1)
        p = (root/name).resolve()
        assert p.is_relative_to(root)
        if p.is_file():
            assert hashlib.sha256(p.read_bytes()).hexdigest() == expected, name
            checked += 1
    assert checked > 300, f'Incomplete evidence extraction: {checked} files'
    print('Original manifest hashes verified:', checked, 'extracted files')
print('PASS: recorded evidence checks; no experiment was rerun')
