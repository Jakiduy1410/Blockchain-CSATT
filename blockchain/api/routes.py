"""
API Routes & Controller
"""

from flask import Blueprint, jsonify, request, render_template

try:
    from ..core.ledger import BlockchainLedger
    from ..core.transaction import Transaction
    from ..core.crypto import calculate_block_hash
    from ..network.p2p import P2PNetwork
    from ..consensus.miner import Miner
except ImportError:
    from core.ledger import BlockchainLedger
    from core.transaction import Transaction
    from core.crypto import calculate_block_hash
    from network.p2p import P2PNetwork
    from consensus.miner import Miner


def create_api_blueprint(ledger: BlockchainLedger, network: P2PNetwork, miner: Miner, port: int) -> Blueprint:
    api = Blueprint('blockchain_api', __name__)

    # --- Web UI Routes ---
    @api.route('/')
    def index():
        return render_template('./index.html')

    @api.route('/configure')
    def configure():
        return render_template('./configure.html')

    @api.route('/visualizer')
    def visualizer():
        return render_template('./visualizer.html')

    @api.route('/wallets/sample', methods=['GET'])
    def sample_wallets():
        import json, os
        root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        wallets_file = os.path.join(root_dir, 'configs', 'wallets.json')
        if not os.path.exists(wallets_file):
            wallets_file = os.path.join(root_dir, 'wallets.json')
        if os.path.exists(wallets_file):
            with open(wallets_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return jsonify(data), 200
        return jsonify({}), 404

    # --- Audit Log Route (Hộp đen kiểm toán) ---
    @api.route('/audit/logs', methods=['GET'])
    def get_audit_logs():
        limit = request.args.get('limit', default=50, type=int)
        logs = ledger.audit.get_logs(limit=limit)
        return jsonify({'logs': logs, 'count': len(logs)}), 200

    # --- Node Status Route (Cho Visualizer & Monitoring) ---
    @api.route('/status', methods=['GET'])
    def get_status():
        mempool = ledger.get_mempool()
        chain = ledger.get_chain()
        balances = ledger.get_all_balances()
        response = {
            'node_id': ledger.node_id,
            'port': port,
            'is_miner': miner.auto_mine,
            'mempool_count': len(mempool),
            'mempool': mempool,
            'chain_length': len(chain),
            'peers': list(network.peers),
            'balances': balances,
            'stack_threshold': 3
        }
        return jsonify(response), 200

    # --- Account Balances & Nonce Route ---
    @api.route('/accounts/balance', methods=['GET'])
    def get_accounts_balance():
        balances = ledger.get_all_balances()
        return jsonify({
            'balances': balances,
            'mempool_queue': len(ledger.get_mempool()),
            'stack_threshold': 3
        }), 200

    @api.route('/accounts/nonce', methods=['GET'])
    def get_account_nonce():
        address = request.args.get('address', '').strip()
        if not address:
            return jsonify({'message': 'Thiếu địa chỉ ví (address)'}), 400
        next_nonce = ledger.get_next_nonce(address)
        return jsonify({'address': address, 'next_nonce': next_nonce}), 200

    # --- Live Packet Inspector Route (Phân tích gói tin đa tầng) ---
    @api.route('/packet/inspect', methods=['GET', 'POST'])
    def inspect_packet():
        import json, os, hashlib
        from collections import OrderedDict
        import ecdsa
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        wallets_file = os.path.join(root_dir, 'configs', 'wallets.json')
        wallets = {}
        if os.path.exists(wallets_file):
            with open(wallets_file, 'r', encoding='utf-8') as f:
                wallets = json.load(f)

        alice = wallets.get('Alice', {})
        bob = wallets.get('Bob', {})
        alice_pub = alice.get('public_key', '04' + 'a' * 126)
        bob_pub = bob.get('public_key', '04' + 'b' * 126)
        alice_priv = alice.get('private_key', 'c' * 64)

        # 1. Sinh giao dịch mẫu có chữ ký ECDSA và Nonce
        next_nonce = ledger.get_next_nonce(alice_pub)
        amount_str = "10.0"
        tx_dict = OrderedDict([
            ('sender_address', alice_pub),
            ('recipient_address', bob_pub),
            ('value', amount_str),
            ('nonce', str(next_nonce))
        ])

        try:
            sk = ecdsa.SigningKey.from_string(bytes.fromhex(alice_priv), curve=ecdsa.SECP256k1)
            sig = sk.sign(str(tx_dict).encode('utf-8')).hex()
        except Exception:
            sig = "3045022100" + "ab" * 30 + "0220" + "cd" * 31

        tx_obj = Transaction(alice_pub, bob_pub, amount_str, sig, nonce=next_nonce)
        p2p_payload = {
            'type': 'TRANSACTION',
            'origin': f"127.0.0.1:{port}",
            'data': tx_obj.to_full_dict()
        }
        plaintext_bytes = json.dumps(p2p_payload, indent=2).encode('utf-8')

        # 2. Mô phỏng đóng gói TLS 1.3 Record (RFC 8446)
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        tls_nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(tls_nonce, plaintext_bytes, None)
        record_len = len(ciphertext)
        tls_header = bytes([0x17, 0x03, 0x03, (record_len >> 8) & 0xFF, record_len & 0xFF])
        full_wire_record = tls_header + ciphertext

        # Tạo định dạng Wireshark Hex Dump
        hex_dump_lines = []
        for i in range(0, min(len(full_wire_record), 256), 16):
            chunk = full_wire_record[i:i + 16]
            hex_part = ' '.join(f"{b:02x}" for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_dump_lines.append(f"{i:08x}  {hex_part:<48}  |{ascii_part}|")
        if len(full_wire_record) > 256:
            hex_dump_lines.append(f"... (con tiep {len(full_wire_record) - 256} bytes da duoc ma hoa)")
        hex_dump_str = '\n'.join(hex_dump_lines)

        # 3. Chuẩn bị mẫu băm khối Block Hash Commit
        latest_block = ledger.get_last_block()
        prev_hash = calculate_block_hash(latest_block)
        coinbase_tx = {
            'sender_address': ledger.mining_sender,
            'recipient_address': ledger.node_id,
            'value': str(ledger.mining_reward),
            'nonce': 0,
            'signature': ''
        }
        sample_block = {
            'block_number': len(ledger.chain) + 1,
            'timestamp': 1700000000.0 + len(ledger.chain) * 10,
            'transactions': [coinbase_tx, tx_obj.to_full_dict()],
            'nonce': 12345,
            'previous_hash': prev_hash
        }
        block_canonical_str = json.dumps(sample_block, sort_keys=True, indent=2)
        block_hash = hashlib.sha256(json.dumps(sample_block, sort_keys=True).encode('utf-8')).hexdigest()

        response = {
            'application_layer': {
                'title': 'Tầng 1: P2P Broadcast JSON (Nội dung truyền giữa các Node)',
                'summary': 'Nội dung dữ liệu phẳng sau khi giải mã, được truyền qua đường ống WebSocket mở sẵn.',
                'payload_json': p2p_payload,
                'json_string': json.dumps(p2p_payload, indent=2),
                'payload_bytes': len(plaintext_bytes)
            },
            'tls_transport_layer': {
                'title': 'Tầng 2: Vỏ bọc TLS 1.3 ECDHE (Kẻ nghe lén trên dây mạng nhìn thấy gì)',
                'summary': 'Gói tin được bọc trong khung TLS Record tiêu chuẩn RFC 8446 với mã hóa AES-256-GCM và trao đổi khóa ECDHE (prime256v1).',
                'protocol': 'TLSv1.3 (RFC 8446)',
                'cipher_suite': 'TLS_AES_256_GCM_SHA384 (256-bit Key)',
                'key_exchange': 'ECDHE (Curve: prime256v1 / secp256r1)',
                'record_header_hex': tls_header.hex(),
                'record_header_breakdown': {
                    'content_type': '0x17 (Application Data)',
                    'version': '0x0303 (TLS 1.2/1.3 Legacy Wire Format)',
                    'payload_length': f'{record_len} bytes'
                },
                'auth_tag_hex': ciphertext[-16:].hex(),
                'total_wire_bytes': len(full_wire_record),
                'wireshark_hex_dump': hex_dump_str
            },
            'block_hash_layer': {
                'title': 'Tầng 3: Cấu trúc tính toán Block Hash (SHA-256 Commitment)',
                'summary': 'Công thức toán học biến toàn bộ dữ liệu giao dịch, số dư và Nonce PoW thành hàm băm bất biến.',
                'canonical_json': block_canonical_str,
                'nonce_pow': sample_block['nonce'],
                'previous_hash': prev_hash,
                'resulting_hash': block_hash,
                'formula': f"SHA-256(canonical_json) -> {block_hash}"
            }
        }
        return jsonify(response), 200

    # --- Transaction Routes ---
    @api.route('/transactions/new', methods=['POST'])
    def new_transaction():
        values = request.form if request.form else request.get_json(silent=True)
        if not values:
            return jsonify({'message': 'Thiếu dữ liệu giao dịch'}), 400

        required = ['sender_address', 'recipient_address', 'amount', 'signature']
        if not all(k in values for k in required):
            return jsonify({'message': 'Thiếu các trường bắt buộc (sender_address, recipient_address, amount, signature)'}), 400

        tx = Transaction.from_dict(values)

        ledger.audit.log(
            category="API",
            title=f"Nhan Transaction truc tiep tu Client qua Ingress Node (Port {port})",
            details={'amount': tx.value, 'recipient': f"{tx.recipient_address[:20]}..."},
            status="INFO"
        )

        success = network.gossip_transaction(tx)
        if not success:
            return jsonify({'message': 'Giao dịch bị từ chối! Chữ ký không hợp lệ hoặc Số dư khả dụng của người gửi không đủ.'}), 406

        return jsonify({
            'message': f'Transaction accepted and gossiped to network! TX_ID: {tx.tx_id[:10]}...'
        }), 201

    @api.route('/transactions/get', methods=['GET'])
    def get_transactions():
        return jsonify({'transactions': ledger.get_mempool()}), 200

    # --- P2P Network Gossip Routes ---
    @api.route('/p2p/transactions/receive', methods=['POST'])
    def p2p_receive_transaction():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'status': 'ignored'}), 400

        tx = Transaction(
            sender_address=data.get('sender_address', ''),
            recipient_address=data.get('recipient_address', ''),
            value=data.get('value', '0'),
            signature=data.get('signature', '')
        )

        network.gossip_transaction(tx)
        return jsonify({'status': 'acknowledged'}), 200

    @api.route('/p2p/blocks/receive', methods=['POST'])
    def p2p_receive_block():
        data = request.get_json(silent=True)
        if not data or 'block' not in data:
            return jsonify({'status': 'invalid'}), 400

        block = data['block']
        accepted = network.handle_incoming_block(block)
        return jsonify({'accepted': accepted}), 200

    # --- Blockchain Chain & Mining Routes ---
    @api.route('/chain', methods=['GET'])
    def get_chain():
        chain = ledger.get_chain()
        return jsonify({
            'chain': chain,
            'length': len(chain)
        }), 200

    @api.route('/mine', methods=['GET'])
    def manual_mine():
        max_txs = request.args.get('max_txs', default=50, type=int)
        block = miner.mine_block(max_txs=max_txs)
        return jsonify({
            'message': 'New Block Forged',
            'block': block,
            'block_number': block['block_number'],
            'timestamp': block['timestamp'],
            'transactions': block['transactions'],
            'nonce': block['nonce'],
            'previous_hash': block['previous_hash']
        }), 200

    # --- Node Peer Registration & Consensus ---
    @api.route('/nodes/register', methods=['POST'])
    def register_nodes():
        values = request.form if request.form else request.get_json(silent=True)
        if not values or 'nodes' not in values:
            return "Error: Please supply a valid list of nodes", 400

        raw_nodes = values.get('nodes')
        if isinstance(raw_nodes, list):
            nodes = raw_nodes
        else:
            nodes = raw_nodes.replace(" ", "").split(',')

        network.register_peers_bulk(nodes)

        return jsonify({
            'message': 'New nodes have been added',
            'total_nodes': list(network.peers)
        }), 201

    @api.route('/nodes/get', methods=['GET'])
    def get_nodes():
        return jsonify({'nodes': list(network.peers)}), 200

    @api.route('/nodes/resolve', methods=['GET'])
    def consensus():
        replaced = network.resolve_conflicts()
        chain = ledger.get_chain()
        if replaced:
            response = {'message': 'Our chain was replaced', 'new_chain': chain}
        else:
            response = {'message': 'Our chain is authoritative', 'chain': chain}
        return jsonify(response), 200

    return api
