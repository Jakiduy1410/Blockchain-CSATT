"""
API Routes & Controller
"""

from flask import Blueprint, jsonify, request, render_template

try:
    from ..core.ledger import BlockchainLedger
    from ..core.transaction import Transaction
    from ..network.p2p import P2PNetwork
    from ..consensus.miner import Miner
except ImportError:
    from core.ledger import BlockchainLedger
    from core.transaction import Transaction
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
        response = {
            'node_id': ledger.node_id,
            'port': port,
            'is_miner': miner.auto_mine,
            'mempool_count': len(mempool),
            'mempool': mempool,
            'chain_length': len(chain),
            'peers': list(network.peers)
        }
        return jsonify(response), 200

    # --- Transaction Routes ---
    @api.route('/transactions/new', methods=['POST'])
    def new_transaction():
        values = request.form if request.form else request.get_json(silent=True)
        if not values:
            return jsonify({'message': 'Missing data'}), 400

        required = ['sender_address', 'recipient_address', 'amount', 'signature']
        if not all(k in values for k in required):
            return jsonify({'message': 'Missing required fields'}), 400

        tx = Transaction.from_dict(values)

        ledger.audit.log(
            category="API",
            title=f"Nhan Transaction truc tiep tu Client qua Ingress Node (Port {port})",
            details={'amount': tx.value, 'recipient': f"{tx.recipient_address[:20]}..."},
            status="INFO"
        )

        success = network.gossip_transaction(tx)
        if not success:
            return jsonify({'message': 'Invalid Transaction! Signature verification failed.'}), 406

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
        block = miner.mine_block()
        return jsonify({
            'message': 'New Block Forged',
            'block_number': block['block_number'],
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
