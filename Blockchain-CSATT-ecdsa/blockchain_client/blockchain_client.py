import os
import json
from collections import OrderedDict
import binascii
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
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
        """Ký ECDSA secp256k1/SHA-256 qua OpenSSL, xuất raw r||s như master."""
        priv_int = int(self.sender_private_key, 16)
        sk = ec.derive_private_key(priv_int, ec.SECP256K1())
        transaction_bytes = str(self.to_dict()).encode('utf-8')
        der_sig = sk.sign(transaction_bytes, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        sig_bytes = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        return sig_bytes.hex()


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
    # Cùng cách sinh khóa và biểu diễn hex với master.
    sk = ec.generate_private_key(ec.SECP256K1())
    priv_num = sk.private_numbers().private_value
    pub_num = sk.public_key().public_numbers()
    response = {
        'private_key': f'{priv_num:064x}',
        'public_key': f'{pub_num.x:064x}{pub_num.y:064x}'
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
