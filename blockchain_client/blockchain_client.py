import os
import json
from collections import OrderedDict
import binascii
import requests
from flask import Flask, jsonify, request, render_template

# Sử dụng chuẩn ECDSA (secp256k1) bằng C-backend OpenSSL qua cryptography
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
import ecdsa

try:
    if os.name == 'nt' and hasattr(os, 'add_dll_directory'):
        dll_dirs = [
            os.path.abspath('.'),
            os.path.abspath('liboqs'),
            os.path.abspath('liboqs/build/bin'),
            os.path.abspath('liboqs/build/bin/Release'),
            os.path.abspath('liboqs/build/bin/Debug'),
            os.path.abspath('build/bin/Release'),
            os.path.abspath('build/bin'),
            os.path.expanduser('~/_oqs/bin')
        ]
        liboqs_env = os.environ.get('LIBOQS_DIR')
        if liboqs_env:
            dll_dirs.extend([liboqs_env, os.path.join(liboqs_env, 'bin')])
        for d in dll_dirs:
            if os.path.isdir(d):
                try:
                    os.add_dll_directory(d)
                except Exception:
                    pass
    import oqs
    OQS_AVAILABLE = True
except (ImportError, Exception):
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
            # Nếu khóa có độ dài lớn (> 1000) và oqs khả dụng -> ML-DSA (ML-DSA-44 hoặc ML-DSA-87)
            if len(self.sender_private_key) > 1000 and OQS_AVAILABLE:
                private_key_bytes = bytes.fromhex(self.sender_private_key)
                transaction_string = str(self.to_dict()).encode('utf8')
                if len(private_key_bytes) >= 4800:
                    alg_name = "ML-DSA-87"
                elif len(private_key_bytes) >= 3500:
                    alg_name = "ML-DSA-65"
                else:
                    alg_name = "ML-DSA-44"
                with oqs.Signature(alg_name, secret_key=private_key_bytes) as signer:
                    signature_bytes = signer.sign(transaction_string)
                return signature_bytes.hex()

            # Mặc định chuẩn: Ký số ECDSA (secp256k1) qua C-backend OpenSSL
            priv_int = int(self.sender_private_key, 16)
            sk = ec.derive_private_key(priv_int, ec.SECP256K1())
            transaction_bytes = str(self.to_dict()).encode('utf-8')
            der_sig = sk.sign(transaction_bytes, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(der_sig)
            sig_bytes = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
            return sig_bytes.hex()
        except Exception as e:
            raise ValueError(f"Lỗi trong quá trình ký số giao dịch: {str(e)}")


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/make/transaction')
def make_transaction():
    default_sig = app.config.get('DEFAULT_SIG_MODE', os.environ.get('BLOCKCHAIN_SIG_MODE', 'all'))
    return render_template('./make_transaction.html', default_sig_mode=default_sig)


@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')


@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    # Tạo cặp khóa ECDSA secp256k1 qua C-Engine OpenSSL
    try:
        sk = ec.generate_private_key(ec.SECP256K1())
        priv_num = sk.private_numbers().private_value
        priv_hex = f"{priv_num:064x}"
        pub_num = sk.public_key().public_numbers()
        pub_hex = f"{pub_num.x:064x}{pub_num.y:064x}"
        response = {
            'private_key': priv_hex,
            'public_key': pub_hex,
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
    parser.add_argument('--sig', default=os.environ.get('BLOCKCHAIN_SIG_MODE', 'all'), type=str, help='Default signature mode (ecdsa, mldsa44, all)')
    args = parser.parse_args()
    port = args.port
    app.config['DEFAULT_SIG_MODE'] = args.sig

    app.run(host='127.0.0.1', port=port)
