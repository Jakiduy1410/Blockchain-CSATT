import json,csv,subprocess,statistics,math,collections,argparse,shutil
from pathlib import Path
parser=argparse.ArgumentParser(description='Rebuild tables from saved evidence, without starting nodes or changing evidence.')
parser.add_argument('--data-root',required=True,type=Path)
parser.add_argument('--output-dir',required=True,type=Path)
parser.add_argument('--tshark',default=shutil.which('tshark') or r'C:/Program Files/Wireshark/tshark.exe')
parser.add_argument('--decode-pcap',action='store_true',help='Decode PCAP again instead of using its existing packets.csv')
args=parser.parse_args();ROOT=args.data_root.resolve();A=args.output_dir.resolve();TS=args.tshark
if A==ROOT/'analysis':raise SystemExit('Choose a separate output directory; delivered analysis is preserved.')
A.mkdir(parents=True,exist_ok=True)
def csvsave(name,rows):
 if not rows:return
 with open(A/name,'w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def quant(v,p):
 if not v:return None
 v=sorted(v);k=(len(v)-1)*p;lo=int(k);return v[lo]+(v[min(lo+1,len(v)-1)]-v[lo])*(k-lo)
def read_events(d):
 return [json.loads(s) for p in d.glob('events*.jsonl') for s in p.read_text().splitlines()]
n1=[];n2=[];prop=[]
for d in sorted(list((ROOT/'evidence_seg_final').glob('N1_*'))+list((ROOT/'evidence_net2').glob('N2_*'))):
 if not (d/'result.json').exists():continue
 r=json.loads((d/'result.json').read_text());events=read_events(d)
 if d.name.startswith('N1_'):
  if r['repeat']==0:continue
  fields=['frame.number','frame.time_epoch','ip.src','ip.len','ip.hdr_len','tcp.hdr_len','tcp.len','tcp.seq_raw','tcp.stream','tcp.options.mss_val','ip.flags.mf','ip.frag_offset','tcp.analysis.retransmission']
  if (d/'packets.csv').exists() and not args.decode_pcap:
   packets=list(csv.DictReader((d/'packets.csv').open(encoding='utf-8')))
  else:
   out=subprocess.check_output([TS,'-r',str(d/'traffic.pcap'),'-T','fields','-E','header=y','-E','separator=,','-E','quote=d']+sum((['-e',f] for f in fields),[]),text=True)
   cache=A/'packet_csv';cache.mkdir(exist_ok=True);(cache/(d.name+'.csv')).write_text(out);packets=list(csv.DictReader(out.splitlines()))
  selected=[p for p in packets if p['ip.src']==r.get('source_ip','10.203.7.1') and int(p['tcp.len'] or 0)>0 and r['start']/1e9<=float(p['frame.time_epoch'])<=r['finish']/1e9]
  hdr=sum(int(p['ip.hdr_len'])+int(p['tcp.hdr_len']) for p in selected);pay=sum(int(p['tcp.len']) for p in selected)
  ws=[e['bytes'] for e in events if e['node']=='A' and e['kind']=='send' and e['type']=='TRANSACTION']
  n1.append(dict(run=d.name,algorithm=r['algorithm'],mtu=r['mtu'],repeat=r['repeat'],n=r['n'],received=r['received'],json_bytes=statistics.mean(r['tx_bytes']),ws_json_bytes=statistics.mean(ws),signature_bytes=r['signature_bytes'],pk_bytes=r['public_key_bytes'],segments=len(selected),segments_per_tx=len(selected)/r['n'],tcp_payload=pay,tcp_payload_per_tx=pay/r['n'],header=hdr,header_per_tx=hdr/r['n'],overhead_pct=100*hdr/(pay+hdr),ack_count=sum(int(p['tcp.len'] or 0)==0 for p in packets),max_ip=max(int(p['ip.len'] or 0) for p in packets),max_tcp=max(int(p['tcp.len'] or 0) for p in packets),mss=','.join(sorted(set(p['tcp.options.mss_val'] for p in packets if p['tcp.options.mss_val']))),retrans=sum(bool(p['tcp.analysis.retransmission']) for p in selected),fragments=sum(p['ip.flags.mf']=='1' or int(p['ip.frag_offset'] or 0)>0 for p in packets)))
 else:
  mined={e['hash']:e for e in events if e['kind']=='mined'};sends={}
  for e in events:
   if e['kind']=='send' and e.get('type')=='BLOCK' and e['hash'] in mined and e['node']==mined[e['hash']]['node']:sends[e['hash']]=min(sends.get(e['hash'],e['t']),e['t'])
  delays=[];verifies=[];seen=set()
  for e in sorted(events,key=lambda e:e['t']):
   h=e.get('hash')
   if e['kind']=='recv' and e.get('type')=='BLOCK' and h in sends and e['node']!=mined[h]['node'] and h not in seen:
    dt=(e['t']-sends[h])/1e6
    if dt>=0:delays.append(dt);seen.add(h);prop.append(dict(run=d.name,hash=h,origin=mined[h]['node'],receiver=e['node'],send_ns=sends[h],recv_ns=e['t'],propagation_ms=dt))
   if e['kind']=='processed' and e.get('type')=='BLOCK':verifies.append(e['duration_ms'])
  chains=json.loads((d/'chains.json').read_text());tipsets=[]
  def bh(b):
   import hashlib
   return hashlib.sha256(json.dumps({k:b[k] for k in ['block_number','timestamp','transactions','nonce','previous_hash']},sort_keys=True).encode()).hexdigest()
  canonical={bh(b) for b in chains[0][1:]};groups=collections.defaultdict(set)
  for h,m in mined.items():groups[m['parent']].add(h)
  siblings=[v for v in groups.values() if len(v)>1];forked=set().union(*siblings) if siblings else set()
  import re
  tc_drops=0;tc_sent=0
  for text in r['qdisc_final']:
   for chunk in text.split('qdisc netem ')[1:]:
    m=re.search(r'Sent (\d+) bytes (\d+) pkt \(dropped (\d+)',chunk)
    if m:tc_sent+=int(m[2]);tc_drops+=int(m[3])
  sync=r['synced'];stale=len(set(mined)-canonical) if sync else None
  n2.append(dict(run=d.name,algorithm=r['algorithm'],mtu=r['mtu'],profile=r['profile'],repeat=r['repeat'],tc_sent=tc_sent,tc_dropped=tc_drops,mined=len(mined),canonical=len(set(mined)&canonical) if sync else None,stale=stale,unresolved=0 if sync else len(mined),synced=sync,valid=all(s['valid'] for s in r['final']),competing_parents=len(siblings),forked_blocks=len(forked),fork_block_pct=100*len(forked)/len(mined),stale_pct=100*stale/len(mined) if sync else None,resolve_calls=sum(e['kind']=='resolve' for e in events),reorganizations=sum(e['kind']=='resolve' and e.get('changed') for e in events),samples=len(delays),median_ms=statistics.median(delays) if delays else None,p95_ms=quant(delays,.95),mean_ms=statistics.mean(delays) if delays else None,processing_median_ms=statistics.median(verifies) if verifies else None))
csvsave('net01_runs.csv',n1);csvsave('net02_runs.csv',n2);csvsave('propagation_raw.csv',prop)
s1=[];s2=[]
for mtu in [1500,576]:
 for algo in ['ECDSA','ML-DSA']:
  g=[r for r in n1 if r['mtu']==mtu and r['algorithm']==algo]
  if g:
   h=sum(r['header'] for r in g);p=sum(r['tcp_payload'] for r in g);n=sum(r['n'] for r in g)
   s1.append(dict(algorithm=algo,mtu=mtu,runs=len(g),n=n,json_bytes=statistics.mean(r['json_bytes'] for r in g),ws_json_bytes=statistics.mean(r['ws_json_bytes'] for r in g),segments=sum(r['segments'] for r in g),segments_per_tx=sum(r['segments'] for r in g)/n,header_per_tx=h/n,tcp_bytes_per_tx=p/n,overhead_pct=h/(h+p)*100,mss=g[0]['mss'],max_ip=max(r['max_ip'] for r in g),max_tcp=max(r['max_tcp'] for r in g),retrans=sum(r['retrans'] for r in g),fragments=sum(r['fragments'] for r in g)))
  for profile in ['base','delay','loss5','loss10','loss15']:
   g=[r for r in n2 if r['mtu']==mtu and r['algorithm']==algo and r['profile']==profile]
   if not g:continue
   ids={r['run'] for r in g};v=[r['propagation_ms'] for r in prop if r['run'] in ids];m=sum(r['mined'] for r in g);stale=sum(r['stale'] or 0 for r in g);fork=sum(r['forked_blocks'] for r in g);resolved=sum(r['mined'] for r in g if r['synced'])
   s2.append(dict(algorithm=algo,mtu=mtu,profile=profile,runs=len(g),tc_sent=sum(r['tc_sent'] for r in g),tc_dropped=sum(r['tc_dropped'] for r in g),mined=m,synced_runs=sum(r['synced'] for r in g),samples=len(v),median_ms=statistics.median(v),p95_ms=quant(v,.95),forked=fork,fork_pct=fork/m*100,canonical=sum(r['canonical'] or 0 for r in g),stale=stale,stale_denominator=resolved,stale_pct=stale/resolved*100 if resolved else None,unresolved=sum(r['unresolved'] for r in g),resolve_calls=sum(r['resolve_calls'] for r in g),reorgs=sum(r['reorganizations'] for r in g)))
csvsave('net01_summary.csv',s1);csvsave('net02_summary.csv',s2)
(A/'all.json').write_text(json.dumps(dict(net01=s1,net02=s2,runs=n2),indent=2))
print('N1 runs',len(n1),'N2 runs',len(n2));print(json.dumps(s1,indent=2));print(json.dumps(s2,indent=2))
