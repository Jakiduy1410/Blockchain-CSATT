from pathlib import Path
import json,sys,argparse
parser=argparse.ArgumentParser(description='Verify PoW and signatures in existing event logs; never mine or send transactions.')
parser.add_argument('--data-root',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args();r=args.data_root.resolve();sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
args.output.parent.mkdir(parents=True,exist_ok=True)
from blockchain.core.block import Block
from blockchain.core.transaction import Transaction
summary=[]
for d in sorted((r/'evidence_net2').glob('N2*')):
 valid=[]
 for p in d.glob('events*.jsonl'):
  for l in p.read_text().splitlines():
   e=json.loads(l)
   if e['kind']=='mined':
    b=e['block'];tx=[t for t in b['transactions'] if t['sender_address']!='THE BLOCKCHAIN'];valid.append(Block.valid_proof(tx,b['previous_hash'],b['nonce'],2) and all(Transaction.from_dict(t).is_valid() for t in tx) and len(tx)==4)
 summary.append(dict(run=d.name,blocks=len(valid),all_pow_signatures_and_4_txs=all(valid)))
args.output.write_text(json.dumps(summary,indent=2));print(len(summary),sum(s['blocks'] for s in summary),all(s['all_pow_signatures_and_4_txs'] for s in summary))
