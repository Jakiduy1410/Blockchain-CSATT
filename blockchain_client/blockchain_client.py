import os
import json
from collections import OrderedDict
import binascii
from ecdsa import SigningKey, SECP256k1
import requests
from flask import Flask, jsonify, request, render_template

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class Transaction:
    def __init__(self, sender_address, sender_private_key, recipient_address, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'recipient_address': self.recipient_address,
                            'value': self.value})

    def sign_transaction(self):
        """Sign transaction with ECDSA SECP256k1 private key"""
        private_key_bytes = bytes.fromhex(self.sender_private_key)
        sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        
        transaction_string = str(self.to_dict()).encode('utf8')
        signature_bytes = sk.sign(transaction_string)
        return signature_bytes.hex()


app = Flask(__name__)

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')

@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    # Tạo cặp khóa bằng thuật toán ECDSA
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    
    response = {
        'private_key': sk.to_string().hex(),
        'public_key': vk.to_string().hex()
    }
    return jsonify(response), 200

@app.route('/wallets/sample', methods=['GET'])
def sample_wallets():
    wallets_file = os.path.join(root_dir, 'configs', 'wallets.json')
    if not os.path.exists(wallets_file):
        wallets_file = os.path.join(root_dir, 'wallets.json')
    if os.path.exists(wallets_file):
        with open(wallets_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify(data), 200
    return jsonify({'message': 'Không tìm thấy file ví mẫu configs/wallets.json'}), 404

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_address = request.form.get('sender_address', '').strip()
    sender_private_key = request.form.get('sender_private_key', '').strip()
    recipient_address = request.form.get('recipient_address', '').strip()
    value = request.form.get('amount', '').strip()

    if not sender_address or not sender_private_key or not recipient_address or not value:
        return jsonify({'message': 'Vui lòng điền đầy đủ các trường: Người gửi, Khóa bí mật, Người nhận và Số tiền.'}), 400

    try:
        transaction = Transaction(sender_address, sender_private_key, recipient_address, value)
        response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}
        return jsonify(response), 200
    except ValueError:
        return jsonify({'message': 'Lỗi ký số: Khóa bí mật không hợp lệ hoặc sai định dạng Hex.'}), 400
    except Exception as e:
        return jsonify({'message': f'Lỗi ký số: {str(e)}'}), 400


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)
