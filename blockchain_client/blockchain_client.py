import os
import json
from collections import OrderedDict
import binascii
import requests
from flask import Flask, jsonify, request, render_template

# Sử dụng chuẩn ECDSA (secp256k1) cho giao dịch theo cấu hình tinh gọn
import ecdsa

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    oqs = None

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Transaction:
    def __init__(self, sender_address, sender_private_key, recipient_address, value, nonce=1):
        self.sender_address = str(sender_address)
        self.sender_private_key = str(sender_private_key)
        self.recipient_address = str(recipient_address)
        self.value = str(value)
        try:
            self.nonce = int(nonce) if nonce is not None and str(nonce).strip() != '' else 1
        except (ValueError, TypeError):
            self.nonce = 1

    def to_dict(self):
        d = OrderedDict([
            ('sender_address', self.sender_address),
            ('recipient_address', self.recipient_address),
            ('value', self.value)
        ])
        if self.nonce is not None:
            d['nonce'] = str(self.nonce)
        return d

    def sign_transaction(self):
        """Ký số giao dịch bằng ECDSA (secp256k1) hoặc ML-DSA nếu khóa dài"""
        try:
            # Nếu khóa có độ dài lớn (> 1000) và oqs khả dụng -> ML-DSA
            if len(self.sender_private_key) > 1000 and OQS_AVAILABLE:
                private_key_bytes = bytes.fromhex(self.sender_private_key)
                transaction_string = str(self.to_dict()).encode('utf8')
                with oqs.Signature("ML-DSA-44", secret_key=private_key_bytes) as signer:
                    signature_bytes = signer.sign(transaction_string)
                return signature_bytes.hex()

            # Mặc định chuẩn: Ký số ECDSA (secp256k1)
            sk_bytes = bytes.fromhex(self.sender_private_key)
            sk = ecdsa.SigningKey.from_string(sk_bytes, curve=ecdsa.SECP256k1)
            transaction_bytes = str(self.to_dict()).encode('utf-8')
            signature_bytes = sk.sign(transaction_bytes)
            return signature_bytes.hex()
        except Exception as e:
            raise ValueError(f"Lỗi trong quá trình ký số giao dịch: {str(e)}")


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
    # Tạo cặp khóa ECDSA secp256k1
    try:
        sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        response = {
            'private_key': sk.to_string().hex(),
            'public_key': vk.to_string().hex(),
            'algorithm': 'ECDSA-secp256k1'
        }
        return jsonify(response), 200
    except Exception as e:
        return jsonify({'message': f'Lỗi tạo ví: {str(e)}'}), 500


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
    nonce = request.form.get('nonce', '1').strip()

    if not sender_address or not sender_private_key or not recipient_address or not value:
        return jsonify({'message': 'Vui lòng điền đầy đủ các trường: Người gửi, Khóa bí mật, Người nhận và Số tiền.'}), 400

    try:
        transaction = Transaction(sender_address, sender_private_key, recipient_address, value, nonce=nonce)
        response = {
            'transaction': transaction.to_dict(),
            'signature': transaction.sign_transaction(),
            'nonce': transaction.nonce
        }
        return jsonify(response), 200
    except ValueError as ve:
        return jsonify({'message': f'Lỗi ký số: Khóa bí mật không hợp lệ hoặc sai định dạng. Chi tiết: {str(ve)}'}), 400
    except Exception as e:
        return jsonify({'message': f'Lỗi hệ thống: {str(e)}'}), 500


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)
