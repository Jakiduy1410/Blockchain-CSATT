from pathlib import Path
import json,statistics,csv,argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
parser=argparse.ArgumentParser(description='Draw charts from saved summary tables, without rerunning experiments.')
parser.add_argument('--analysis-dir',type=Path,default=Path(__file__).resolve().parent/'results'/'analysis')
parser.add_argument('--output-dir',type=Path,required=True)
args=parser.parse_args();A=args.analysis_dir.resolve();F=args.output_dir.resolve();F.mkdir(parents=True,exist_ok=True)
D=json.loads((A/'all.json').read_text())
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10})
colors=['#265C91','#D07930'];algos=['ECDSA','ML-DSA']
fig,axes=plt.subplots(1,2,figsize=(10,3.8))
for j,(key,ylabel) in enumerate([('segments_per_tx','TCP data segments / giao dich'),('header_per_tx','Byte header IPv4 + TCP / giao dich')]):
 for k,algo in enumerate(algos):
  vals=[next(r[key] for r in D['net01'] if r['algorithm']==algo and r['mtu']==mtu) for mtu in [1500,576]]
  bars=axes[j].bar([i+(k-.5)*.34 for i in [0,1]],vals,.34,label=algo,color=colors[k]);axes[j].bar_label(bars,fmt='%.1f',padding=3)
 axes[j].set_xticks([0,1],['MTU 1500','MTU 576']);axes[j].set_ylabel(ylabel);axes[j].grid(axis='y',alpha=.2);axes[j].set_axisbelow(True);axes[j].margins(y=.18)
axes[0].legend();fig.tight_layout();fig.savefig(F/'net01.png',dpi=200);plt.close(fig)
if D['net02']:
 profiles=['base','delay','loss5','loss10','loss15'];labels=['Baseline','Delay jitter','Loss 5%','Loss 10%','Loss 15%']
 fig,axes=plt.subplots(2,2,figsize=(10,6.2))
 for row,mtu in enumerate([1500,576]):
  for col,key in enumerate(['median_ms','p95_ms']):
   ax=axes[row,col]
   for k,algo in enumerate(algos):
    vals=[next((r[key] for r in D['net02'] if r['algorithm']==algo and r['mtu']==mtu and r['profile']==p),float('nan')) for p in profiles]
    ax.plot(range(5),vals,'o-',label=algo,color=colors[k]);ax.set_xticks(range(5),labels,rotation=15);ax.set_title(f'MTU {mtu}  |  '+('Median' if key=='median_ms' else 'P95'));ax.set_ylabel('ms');ax.grid(alpha=.2)
 axes[0,0].legend();fig.tight_layout();fig.savefig(F/'propagation.png',dpi=200);plt.close(fig)
 fig,axes=plt.subplots(1,2,figsize=(10,4))
 for ax,mtu in zip(axes,[1500,576]):
  for k,algo in enumerate(algos):
   g=[next((r for r in D['net02'] if r['algorithm']==algo and r['mtu']==mtu and r['profile']==p),{}) for p in profiles]
   vals=[r.get('stale_pct',float('nan')) or 0 for r in g];ax.bar([i+(k-.5)*.36 for i in range(5)],vals,.36,label=algo,color=colors[k])
  ax.set_xticks(range(5),labels,rotation=20);ax.set_title(f'MTU {mtu}');ax.set_ylabel('Stale / khoi da dao da chot (%)');ax.set_ylim(0,100);ax.grid(axis='y',alpha=.2);ax.set_axisbelow(True)
 axes[0].legend();fig.tight_layout();fig.savefig(F/'stale.png',dpi=200);plt.close(fig)
print('Charts ready')
