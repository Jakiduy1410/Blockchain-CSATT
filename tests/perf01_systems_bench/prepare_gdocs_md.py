import re
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent.parent
RESULTS_DIR = BASE_DIR / 'benchmarks' / 'results' / 'perf01_resource_stress'
src = RESULTS_DIR / 'BAO_CAO_PERF01.md'
dst = RESULTS_DIR / 'BAO_CAO_PERF01_GDOCS.md'

with open(src, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace LaTeX expressions
latex_replacements = [
    (r'$\mathcal{O}(n \log n)$', 'O(n log n)'),
    (r'$\mathcal{O}(n^2)$', 'O(n²)'),
    (r'$R_q$', 'R_q'),
    (r'$R_q = \mathbb{Z}_q[X]/(X^{256}+1)$', 'R_q = Z_q[X]/(X²⁵⁶+1)'),
    (r'$q = 8,380,417$', 'q = 8,380,417'),
    (r'$GF(p)$', 'GF(p)'),
    (r'$p \approx 2^{256}$', 'p ≈ 2²⁵⁶'),
    (r'$n=256$', 'n = 256'),
    (r'$s^{-1}(H(m)G + rQ)$', 's⁻¹(H(m)G + rQ)'),
    (r'$s^{-1} \cdot H(m) \cdot G + s^{-1} \cdot r \cdot Q$', 's⁻¹ · H(m) · G + s⁻¹ · r · Q'),
    (r'$$\Delta_{\text{Headroom}} = 60.0\text{ MB} - 43.0\text{ MB} = 17.0\text{ MB}$$', '> Δ_Headroom = 60.0 MB - 43.0 MB = 17.0 MB'),
    (r'$\Delta_{\text{Headroom}} = 60.0\text{ MB} - 43.0\text{ MB} = 17.0\text{ MB}$', 'Δ_Headroom = 60.0 MB - 43.0 MB = 17.0 MB'),
    (r'$$\text{Commit Latency} = \text{Block Verify CPU Time} + \text{Wire Transit Delay TLS 1.3}$$', '> Commit Latency = Block Verify CPU Time + Wire Transit Delay TLS 1.3'),
    (r'$\text{Commit Latency} = \text{Block Verify CPU Time} + \text{Wire Transit Delay TLS 1.3}$', 'Commit Latency = Block Verify CPU Time + Wire Transit Delay TLS 1.3'),
    (r'$$\text{Exit Code} = 128 + \text{Signal Number}$$', '> Exit Code = 128 + Signal Number'),
    (r'$$\text{Exit Code} = 128 + 9 = 137$$', '> Exit Code = 128 + 9 = 137'),
    (r'$\text{Exit Code} = 128 + \text{Signal Number}$', 'Exit Code = 128 + Signal Number'),
    (r'$\text{Exit Code} = 128 + 9 = 137$', 'Exit Code = 128 + 9 = 137'),
    (r'$$\text{Normalized CPU} = \min\left(100.0\%, \; \frac{\text{Avg CPU}}{\text{Allocated vCPUs}}\right) = \frac{154.82\%}{4.0} = 38.70\%$$', '> Normalized CPU = min(100.0%, Avg CPU / Allocated vCPUs) = 154.82% / 4.0 = 38.70%'),
    (r'$\pm 3\text{ ms}$', '±3 ms'),
    (r'$\approx 0.75\text{ MB}$', '≈ 0.75 MB'),
    (r'$\approx 0.5\text{ KB/tx}$', '≈ 0.5 KB/tx'),
    (r'$\approx 8.5\text{ KB/tx}$', '≈ 8.5 KB/tx'),
    (r'$\approx 12\text{ KB/tx}$', '≈ 12 KB/tx'),
    (r'$\approx 16.5\text{ KB/tx}$', '≈ 16.5 KB/tx'),
    (r'$\le 50$', '≤ 50'),
    (r'$\le 128\text{ MB}$', '≤ 128 MB'),
    (r'$\le 0.5\text{ vCPU}$', '≤ 0.5 vCPU'),
    (r'$\approx 1.0\text{ vCPU}$', '≈ 1.0 vCPU'),
    (r'$\approx 512\text{ MB}$', '≈ 512 MB'),
    (r'$\ge 4.0\text{ vCPU}$', '≥ 4.0 vCPU'),
    (r'$\ge 4096\text{ MB}$', '≥ 4096 MB'),
    (r'50,000 $\mu s$', '50,000 µs'),
    (r'100,000 $\mu s$', '100,000 µs'),
    (r'$3 \text{ Profiles} \times 4 \text{ Thuật toán}$', '3 Profiles × 4 Thuật toán'),
    (r'\rightarrow', '→'),
    (r'$z$', 'z'),
    (r'$h$', 'h'),
    (r'$\le 0.5$', '≤ 0.5'),
    (r'$\le 128$', '≤ 128'),
    (r'$\approx 1.0$', '≈ 1.0'),
    (r'$\approx 512$', '≈ 512'),
    (r'$\ge 4.0$', '≥ 4.0'),
    (r'$\ge 4096$', '≥ 4096'),
]

for old, new in latex_replacements:
    content = content.replace(old, new)

# Update image paths to absolute posix path
results_dir = RESULTS_DIR
p1 = (results_dir / 'perf01_oom_risk_chart.png').as_posix()
p2 = (results_dir / 'perf01_extreme_oom_chart.png').as_posix()
p3 = (results_dir / 'perf01_macro_chart.png').as_posix()

content = content.replace('(results/perf01_oom_risk_chart.png)', f'({p1})')
content = content.replace('(results/perf01_extreme_oom_chart.png)', f'({p2})')
content = content.replace('(results/perf01_macro_chart.png)', f'({p3})')

# Clean file:/// links if any
content = re.sub(r'\[(.*?)\]\(file:///[^)]+\)', r'\1', content)

# Check remaining dollars
remaining_dollars = re.findall(r'\$[^$\n]+\$', content)
print('Remaining inline LaTeX dollars:', len(remaining_dollars))
for d in remaining_dollars:
    print('  ', repr(d))

with open(dst, 'w', encoding='utf-8') as f:
    f.write(content)
print('Successfully written BAO_CAO_PERF01_GDOCS.md')
