import sys,os,json,time,random,subprocess,signal,contextlib,argparse,tempfile,shutil
from pathlib import Path
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
ROOT=Path(__file__).resolve().parent
SOURCE_REPO=ROOT.parents[1]
parser=argparse.ArgumentParser(description="NET lab: explicitly start NEW Linux/WSL network experiments. Existing evidence is not required for the short demo.")
mode=parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--n1-only',action='store_true')
mode.add_argument('--n2-only',action='store_true')
parser.add_argument('--data-root',type=Path,required=True,help='Output directory for a new/resumed experiment, never the delivered evidence directory')
parser.add_argument('--capture-root',type=Path,help='Optional Linux-native temporary PCAP directory')
ARGS=parser.parse_args()
DATA=ARGS.data_root.expanduser().resolve()
if DATA == (SOURCE_REPO.parent/'bang-chung').resolve():
 raise SystemExit('Delivered evidence is read-only. Choose a new --data-root.')
DATA.mkdir(parents=True,exist_ok=True)
OUT=DATA/('evidence_seg_final' if ARGS.n1_only else 'evidence_net2');OUT.mkdir(exist_ok=True)
# Run a source snapshot with disposable wallets, rather than modifying tracked configs/wallets.json.
runtime_parent=DATA/'.runtime';runtime_parent.mkdir(exist_ok=True)
RUNTIME=tempfile.TemporaryDirectory(prefix='repo-',dir=runtime_parent)
REPO=Path(RUNTIME.name)
shutil.copytree(SOURCE_REPO/'blockchain',REPO/'blockchain',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
shutil.copytree(SOURCE_REPO/'configs',REPO/'configs',ignore=shutil.ignore_patterns('wallets.json','*.key','*.pem'))
os.environ['NET_LAB_REPO']=str(REPO)
os.environ['NET_LAB_DATA_ROOT']=str(DATA)
CAPTURE_ROOT=ARGS.capture_root.expanduser().resolve() if ARGS.capture_root else Path(tempfile.gettempdir())/('net-pcap-'+str(os.getpid()))
CREATED=[]
sys.path.insert(0,str(REPO))
import requests,oqs,ecdsa
S=requests.Session();S.trust_env=False
NS=['cxnetA','cxnetB'];IPS=['10.203.7.1','10.203.7.2'];PY=sys.executable
def cmd(a):return subprocess.check_output(a,stderr=subprocess.STDOUT,text=True)
def ns(i,a):return ['ip','netns','exec',NS[i]]+a
def rpc(i,path,tx=None):
 url=f'http://{IPS[i]}:{5000+i}'+path
 r=S.get(url,timeout=60) if tx is None else S.post(url,json=tx,timeout=60)
 r.raise_for_status();return r.json()
def setup():
 for n in NS:
  cmd(['ip','netns','add',n]);CREATED.append(n)
 cmd(['ip','link','add','cxa','type','veth','peer','name','cxb'])
 for i,dev in enumerate(['cxa','cxb']):
  cmd(['ip','link','set',dev,'netns',NS[i]]);cmd(ns(i,['ip','link','set',dev,'name','lab0']))
  cmd(ns(i,['ip','addr','add',IPS[i]+'/30','dev','lab0']));cmd(ns(i,['ip','link','set','lo','up']));cmd(ns(i,['ip','link','set','lab0','up']))
  cmd(ns(i,['ethtool','-K','lab0','tso','off','gso','off','gro','off','lro','off']))
def network(mtu,loss=0,delay=0,jitter=0):
 cfg=[]
 for i in range(2):
  cmd(ns(i,['ip','link','set','lab0','mtu',str(mtu)]));subprocess.run(ns(i,['tc','qdisc','del','dev','lab0','root']),capture_output=True)
  if delay or loss:
   cmd(ns(i,['tc','qdisc','add','dev','lab0','root','handle','1:','prio','bands','3']))
   a=['tc','qdisc','add','dev','lab0','parent','1:3','handle','30:','netem','limit','10000']
   if delay:a+=['delay',f'{delay}ms',f'{jitter}ms']
   if loss:a+=['loss','random',f'{loss}%']
   cmd(ns(i,a))
   for match in ['sport','dport']:
    for port in [6000,6001]:cmd(ns(i,['tc','filter','add','dev','lab0','parent','1:','protocol','ip','prio','1','u32','match','ip','protocol','6','0xff','match','ip',match,str(port),'0xffff','flowid','1:3']))
  cfg.append(dict(node=NS[i],ip=cmd(ns(i,['ip','-j','addr','show','lab0'])),offload=cmd(ns(i,['ethtool','-k','lab0'])),qdisc=cmd(ns(i,['tc','-s','qdisc','show','dev','lab0']))))
 return cfg
def wallet():
 if (REPO/'configs/wallets.json').exists():
  old=json.loads((REPO/'configs/wallets.json').read_text())
  if set(old)=={'E','R','M'}:return old
 w={}
 for name in ['E','R']:
  sk=ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1);w[name]=dict(public_key=sk.verifying_key.to_string().hex(),private_key=sk.to_string().hex(),initial_balance=100000,name=name)
 with oqs.Signature('ML-DSA-44') as s:
  pk=s.generate_keypair();w['M']=dict(public_key=pk.hex(),private_key=s.export_secret_key().hex(),initial_balance=100000,name='M')
 (REPO/'configs/wallets.json').write_text(json.dumps(w));return w
def txs(algo,n):
 w=W['E' if algo=='ECDSA' else 'M'];out=[]
 for nonce in range(1,n+1):
  value=f'{.01+nonce/100000:.5f}';d=OrderedDict(sender_address=w['public_key'],recipient_address=W['R']['public_key'],value=value)
  if algo=='ECDSA':
   d['nonce']=str(nonce);sig=ecdsa.SigningKey.from_string(bytes.fromhex(w['private_key']),curve=ecdsa.SECP256k1).sign(str(d).encode())
  else:
   with oqs.Signature('ML-DSA-44',secret_key=bytes.fromhex(w['private_key'])) as s:sig=s.sign(str(d).encode())
  out.append(dict(sender_address=w['public_key'],recipient_address=W['R']['public_key'],amount=value,nonce=nonce,signature=sig.hex()))
 return out
@contextlib.contextmanager
def nodes(run):
 procs=[];files=[]
 try:
  for i in range(2):
   f=open(OUT/run/f'node{NS[i][-1]}.log','w');files.append(f)
   procs.append(subprocess.Popen(ns(i,[PY,str(ROOT/'node_lab.py'),NS[i][-1],IPS[i],f'{IPS[1-i]}:{5001-i}',run]),cwd=REPO,stdout=f,stderr=subprocess.STDOUT))
  deadline=time.monotonic()+30
  while True:
   try:
    st=[rpc(i,'/lab') for i in range(2)]
    if all(s['connections']==1 for s in st):break
   except Exception:pass
   if time.monotonic()>deadline:raise RuntimeError('nodes not connected '+run)
   time.sleep(.2)
  (OUT/run/'initial.json').write_text(json.dumps(st,indent=2));yield
 finally:
  for p in procs:p.terminate()
  for p in procs:
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:p.kill();p.wait()
  for f in files:f.close()
@contextlib.contextmanager
def capture(run):
 local=CAPTURE_ROOT/run;local.mkdir(exist_ok=True,parents=True)
 f=open(OUT/run/'tcpdump.log','w');p=subprocess.Popen(ns(1,['tcpdump','--immediate-mode','-i','lab0','-U','-s','0','-w',str(local/'traffic.pcap'),'tcp port 6000 or tcp port 6001']),stdout=f,stderr=f);time.sleep(.25)
 try:yield
 finally:time.sleep(.3);p.send_signal(signal.SIGINT);p.wait(timeout=10);f.close();__import__('shutil').copy2(local/'traffic.pcap',OUT/run/'traffic.pcap')
def save(run,obj):(OUT/run/'result.json').write_text(json.dumps(obj,indent=2))
def complete(run):
 p=OUT/run/'result.json'
 if not p.exists():return False
 r=json.loads(p.read_text())
 files=all((OUT/run/f).exists() for f in ['traffic.pcap','eventsA.jsonl','eventsB.jsonl'])
 valid=(r.get('n')==100 and r.get('received')==100) if run.startswith('N1_') else (len(r.get('mined',[]))==34 and all(x.get('valid') for x in r.get('final',[])))
 if files and valid:print('SKIP completed',run,flush=True);return True
 raise RuntimeError('Existing incomplete result retained: '+run)
def n1(algo,mtu,rep):
 run=f'N1_{mtu}_{algo}_{rep}'
 if complete(run):return
 (OUT/run).mkdir(exist_ok=True);cfg=network(mtu);(OUT/run/'config.json').write_text(json.dumps(cfg,indent=2));transactions=txs(algo,100)
 with capture(run),nodes(run):
  start=time.time_ns()
  for k,tx in enumerate(transactions):
   rpc(0,'/transactions/new',tx);deadline=time.monotonic()+5
   while rpc(1,'/lab')['mem']<k+1:
    if time.monotonic()>deadline:raise RuntimeError('missing tx')
   time.sleep(.012)
  finish=time.time_ns();state=rpc(1,'/lab')
 save(run,dict(run=run,algorithm=algo,mtu=mtu,repeat=rep,n=100,start=start,finish=finish,received=state['mem'],source_ip=IPS[0],tx_bytes=[len(json.dumps(t,separators=(',',':')).encode()) for t in transactions],signature_bytes=len(bytes.fromhex(transactions[0]['signature'])),public_key_bytes=len(bytes.fromhex(transactions[0]['sender_address']))));print('DONE',run,flush=True)
def n2(algo,mtu,profile,rep):
 run=f'N2_{mtu}_{profile}_{algo}_{rep}'
 if complete(run):return
 (OUT/run).mkdir(exist_ok=True);loss,delay,jitter={'base':(0,0,0),'delay':(0,50,10),'loss5':(5,50,10),'loss10':(10,50,10),'loss15':(15,50,10)}[profile];cfg=network(mtu);(OUT/run/'config.json').write_text(json.dumps(cfg,indent=2));transactions=txs(algo,140);seed=711000+rep;rng=random.Random(seed)
 with capture(run),nodes(run):
  with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(lambda tx:rpc(0,'/transactions/new',tx),transactions))
  deadline=time.monotonic()+35
  while rpc(1,'/lab')['mem']<140 and time.monotonic()<deadline:time.sleep(.1)
  preload=[rpc(i,'/lab') for i in range(2)]
  if any(x['mem']!=140 for x in preload):raise RuntimeError('preload mismatch')
  cfg=network(mtu,loss,delay,jitter);(OUT/run/'config.json').write_text(json.dumps(cfg,indent=2))
  time.sleep(.2)
  schedule=[]
  for i in range(2):
   t=0
   for k in range(17):t+=rng.expovariate(1/.4);schedule.append((t,i))
  begin=time.monotonic()
  def mine(entry):
   due,i=entry;time.sleep(max(0,begin+due-time.monotonic()));return dict(node=i,response=rpc(i,'/lab/mine'))
  with ThreadPoolExecutor(max_workers=6) as pool:results=list(pool.map(mine,sorted(schedule)))
  time.sleep(1)
  for k in range(3):
   for i in range(2):rpc(i,'/nodes/resolve')
   time.sleep(.2)
  chains=[rpc(i,'/chain')['chain'] for i in range(2)];state=[rpc(i,'/lab') for i in range(2)]
  (OUT/run/'chains.json').write_text(json.dumps(chains));q=[cmd(ns(i,['tc','-s','qdisc','show','dev','lab0'])) for i in range(2)]
  save(run,dict(run=run,algorithm=algo,mtu=mtu,profile=profile,repeat=rep,seed=seed,preload=preload,schedule=schedule,mined=results,final=state,synced=state[0]['tip']==state[1]['tip'],qdisc_final=q))
 print('DONE',run,flush=True)
if __name__=='__main__':
 if sys.platform != 'linux' or os.geteuid()!=0:raise SystemExit('Use Linux/WSL as root for the full experiment, not for the short demo.')
 for name in ['ip','tc','ethtool','tcpdump']:
  if not shutil.which(name):raise SystemExit('Missing Linux command: '+name)
 if ARGS.n1_only:NS=['cxsegA','cxsegB'];IPS=['10.203.8.1','10.203.8.2']
 present={line.split()[0] for line in cmd(['ip','netns','list']).splitlines() if line.strip()}
 if present.intersection(NS):raise SystemExit('Lab namespaces already exist; stop the other lab first. No existing namespace was deleted.')
 if '--n1-only' in sys.argv:NS=['cxsegA','cxsegB'];IPS=['10.203.8.1','10.203.8.2']
 try:
  setup();os.setns(os.open('/var/run/netns/'+NS[0],os.O_RDONLY),0);W=wallet();(OUT/'environment.json').write_text(json.dumps(dict(kernel=cmd(['uname','-a']),python=sys.version,openssl=__import__('ssl').OPENSSL_VERSION,oqs=oqs.oqs_version(),packages=cmd([PY,'-m','pip','freeze']),cpu=cmd(['lscpu']),mem=cmd(['free','-b']),utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())),indent=2))
  n1('ECDSA',576,0) if '--pilot' in sys.argv else None
  if '--pilot' not in sys.argv:
   for rep in ([] if '--n2-only' in sys.argv else [1,2,3]):
    for mtu in [1500,576]:
     for algo in (['ECDSA','ML-DSA'] if rep%2 else ['ML-DSA','ECDSA']):n1(algo,mtu,rep)
   for rep in ([] if '--n1-only' in sys.argv else [1,2,3]):
    for mtu in [1500,576]:
     for profile in ['base','delay','loss5','loss10','loss15']:
      for algo in (['ECDSA','ML-DSA'] if rep%2 else ['ML-DSA','ECDSA']):n2(algo,mtu,profile,rep)
 finally:
  for n in CREATED:subprocess.run(['ip','netns','del',n],capture_output=True)
  RUNTIME.cleanup()

