import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from collections import OrderedDict
import binascii
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
import threading
import time as t_time

MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2

class Blockchain:
    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '')
        self.create_block(0, '00')

    def register_node(self, node_url):
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('URL không hợp lệ')

    def verify_transaction_signature(self, sender_address, signature, transaction):
        transaction_ordered = OrderedDict([
            ('sender_address', transaction['sender_address']),
            ('recipient_address', transaction['recipient_address']),
            ('value', transaction['value'])
        ])
        transaction_string = str(transaction_ordered).encode('utf8')
        try:
            signature_bytes = bytes.fromhex(signature)
            public_key_bytes = bytes.fromhex(sender_address)
            vk = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
            return vk.verify(signature_bytes, transaction_string)
        except (BadSignatureError, ValueError):
            return False
        except Exception:
            return False

    def submit_transaction(self, sender_address, recipient_address, value, signature):
        transaction = OrderedDict([
            ('sender_address', sender_address),
            ('recipient_address', recipient_address),
            ('value', value)
        ])
        if sender_address == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            if self.verify_transaction_signature(sender_address, signature, transaction):
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False

    def create_block(self, nonce, previous_hash):
        block = {
            'block_number': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.transactions,
            'nonce': nonce,
            'previous_hash': previous_hash
        }
        self.transactions = []
        self.chain.append(block)
        return block

    def hash(self, block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self):
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)
        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1
        return nonce

    def valid_proof(self, transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block):
                return False
            last_block = block
            current_index += 1
        return True

    def resolve_conflicts(self):
        neighbors = self.nodes
        new_chain = None
        max_length = len(self.chain)
        for node in neighbors:
            try:
                response = requests.get(f'http://{node}/chain', timeout=2)
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']
                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except Exception:
                continue
        if new_chain:
            self.chain = new_chain
            return True
        return False


app = Flask(__name__)
CORS(app)
blockchain = Blockchain()

# ==========================================
# CÁC API RENDER GIAO DIỆN WEB (FIX LỖI 404)
# ==========================================
@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/configure')
def configure():
    return render_template('./configure.html')

# ==========================================
# CÁC API BLOCKCHAIN CORE
# ==========================================
@app.route('/status', methods=['GET'])
def get_status():
    return jsonify({
        'chain_length': len(blockchain.chain),
        'mempool_count': len(blockchain.transactions),
        'peers': list(blockchain.nodes)
    }), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json() or request.form
    required = ['sender_address', 'recipient_address', 'amount', 'signature']
    if not all(k in values for k in required):
        return jsonify({'message': 'Thiếu dữ liệu giao dịch'}), 400

    transaction_result = blockchain.submit_transaction(
        values['sender_address'], 
        values['recipient_address'], 
        values['amount'], 
        values['signature']
    )
    if transaction_result == False:
        return jsonify({'message': 'Giao dịch không hợp lệ / Sai chữ ký số ECDSA!'}), 406
    else:
        return jsonify({'message': f'Giao dịch sẽ được đưa vào Block số {transaction_result}'}), 201

@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    return jsonify({'transactions': blockchain.transactions}), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    return jsonify({
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }), 200

@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()
    blockchain.submit_transaction(sender_address=MINING_SENDER, recipient_address=blockchain.node_id, value=MINING_REWARD, signature="")
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)
    return jsonify({
        'message': "Đã đào thành công Block mới!",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form or request.get_json()
    nodes_raw = values.get('nodes')
    if not nodes_raw:
        return "Lỗi: Vui lòng cung cấp danh sách node hợp lệ", 400
    nodes = nodes_raw.replace(" ", "").split(',')
    for node in nodes:
        blockchain.register_node(node)
    return jsonify({
        'message': 'Đã thêm thành công các Node mới vào mạng lưới',
        'total_nodes': list(blockchain.nodes),
    }), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        return jsonify({
            'message': 'Chuỗi của node đã được thay thế (Đồng thuận thành công)',
            'new_chain': blockchain.chain
        }), 200
    else:
        return jsonify({
            'message': 'Chuỗi của node hiện tại đã là chuẩn và dài nhất',
            'chain': blockchain.chain
        }), 200

def main():
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('--miner', action='store_true', help='auto mine flag')
    parser.add_argument('--peers', default='', type=str, help='comma separated peer list')
    args = parser.parse_args()
    
    if args.peers:
        for p_peer in args.peers.split(','):
            if p_peer.strip():
                blockchain.register_node(p_peer.strip())

    if args.miner:
        def auto_miner_loop():
            while True:
                t_time.sleep(3)
                if len(blockchain.transactions) > 0:
                    try:
                        last_block = blockchain.chain[-1]
                        nonce = blockchain.proof_of_work()
                        blockchain.submit_transaction(sender_address=MINING_SENDER, recipient_address=blockchain.node_id, value=MINING_REWARD, signature="")
                        previous_hash = blockchain.hash(last_block)
                        blockchain.create_block(nonce, previous_hash)
                    except Exception:
                        pass
        threading.Thread(target=auto_miner_loop, daemon=True).start()

    app.run(host='127.0.0.1', port=args.port)

if __name__ == '__main__':
    main()
