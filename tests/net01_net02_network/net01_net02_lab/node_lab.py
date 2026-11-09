import sys,os,json,time,threading,logging
from pathlib import Path
from flask import jsonify,request
ROOT=Path(__file__).resolve().parent
REPO=Path(os.environ['NET_LAB_REPO']).resolve()
DATA=Path(os.environ['NET_LAB_DATA_ROOT']).resolve()
sys.path.insert(0,str(REPO))
from blockchain.server import create_app
from blockchain.config import NodeConfig
from blockchain.network import p2p
from blockchain.network.tls_helper import TLSManager
from blockchain.core.crypto import calculate_block_hash
import ssl
node,ip,peer,run=sys.argv[1:]
out=DATA/('evidence_seg_final' if ip.startswith('10.203.8.') else 'evidence_net2')/run;out.mkdir(exist_ok=True,parents=True)
lock=threading.Lock(); events=[]
def log(kind,**kw):
 e=dict(kind=kind,t=time.time_ns(),node=node,**kw)
 with lock:
  events.append(e)

import signal
def finish(signum,frame):
 with lock:(out/f'events{node}.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
 os._exit(0)
signal.signal(signal.SIGTERM,finish)
# Bind a real interface; exactly one duplex P2P connection and no compression.
serve0=p2p.ws_serve;connect0=p2p.ws_connect
def serve(*a,**k):k.update(host=ip,compression=None);return serve0(*a,**k)
def connect(*a,**k):k['compression']=None;return connect0(*a,**k)
p2p.ws_serve=serve;p2p.ws_connect=connect
if node=='B':p2p.P2PNetwork._maintain_peer_connections_loop=lambda self:None
for name in ['create_server_ssl_context','create_client_ssl_context']:
 original=getattr(TLSManager,name)
 def ctx(fn=original):
  c=fn();c.minimum_version=c.maximum_version=ssl.TLSVersion.TLSv1_3;return c
 setattr(TLSManager,name,ctx)
c=NodeConfig();c.host=ip;c.port=5000 if node=='A' else 5001;c.peers=[peer];c.difficulty=2
app,ledger,net,miner=create_app(c)
send0=net._send_ws_payload
def send(p):
 data=p['data'];h=calculate_block_hash(data) if p['type']=='BLOCK' else data['tx_id']
 log('send',type=p['type'],hash=h,bytes=len(json.dumps(p).encode()))
 return send0(p)
net._send_ws_payload=send
recv0=net._process_ws_message
def recv(raw):
 p=json.loads(raw);data=p.get('data',{});typ=p.get('type');h=calculate_block_hash(data) if typ=='BLOCK' else data.get('tx_id')
 log('recv',type=typ,hash=h)
 t=time.time_ns();r=recv0(raw);log('processed',type=typ,hash=h,duration_ms=(time.time_ns()-t)/1e6);return r
net._process_ws_message=recv
resolve0=net.resolve_conflicts
def resolve():
 old=calculate_block_hash(ledger.get_last_block());r=resolve0();log('resolve',changed=r,old=old,new=calculate_block_hash(ledger.get_last_block()));return r
net.resolve_conflicts=resolve
@app.get('/lab')
def state():
 with lock:count=len([e for e in events if e['kind']=='recv' and e.get('type')=='TRANSACTION'])
 return jsonify(dict(rx=count,mem=len(ledger.get_mempool()),tip=calculate_block_hash(ledger.get_last_block()),height=len(ledger.chain),connections=len(net.outgoing_sockets)+len(net.incoming_sockets),valid=ledger.valid_chain(ledger.get_chain())))
@app.get('/lab/mine')
def mine():
 b=miner.mine_block(max_txs=int(request.args.get('max','5')));h=calculate_block_hash(b)
 log('mined',hash=h,parent=b['previous_hash'],height=b['block_number'],block=b)
 return jsonify(dict(hash=h,height=b['block_number']))
logging.getLogger('werkzeug').setLevel(logging.ERROR)
app.run(host=ip,port=c.port,threaded=True,use_reloader=False)
