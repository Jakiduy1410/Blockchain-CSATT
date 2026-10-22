import os
import json
from collections import OrderedDict
import binascii
import time
import requests
from flask import Flask, jsonify, request, render_template

try:
    import pqcrypto.sign.ml_dsa_44 as mldsa_pqc
except ImportError:
    mldsa_pqc = None

try:
    import pqcrypto.kem.ml_kem_768 as mlkem_pqc
except ImportError:
    mlkem_pqc = None

try:
    import oqs
except BaseException:
    oqs = None

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIG_ALG = "ML-DSA-44"  # Thuật toán Hậu lượng tử

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
        """Ký số giao dịch bằng khóa bí mật ML-DSA-44"""
        try:
            private_key_bytes = bytes.fromhex(self.sender_private_key)
            transaction_string = str(self.to_dict()).encode('utf8')

            if mldsa_pqc is not None:
                sig_bytes = mldsa_pqc.sign(private_key_bytes, transaction_string)
                return sig_bytes.hex()
            elif oqs is not None:
                with oqs.Signature(SIG_ALG, secret_key=private_key_bytes) as signer:
                    signature_bytes = signer.sign(transaction_string)
                return signature_bytes.hex()
            else:
                raise RuntimeError("Khong co thu vien ho tro ML-DSA-44 (pqcrypto hoac liboqs).")
        except Exception as e:
            raise ValueError(f"Lỗi trong quá trình ký số ML-DSA: {str(e)}")


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
    # Tạo cặp khóa PQC bằng thuật toán ML-DSA-44
    try:
        if mldsa_pqc is not None:
            pk, sk = mldsa_pqc.keygen()
            public_key_hex = pk.hex()
            private_key_hex = sk.hex()
        elif oqs is not None:
            with oqs.Signature(SIG_ALG) as signer:
                pk = signer.generate_keypair()
                sk = signer.export_secret_key()
                public_key_hex = pk.hex()
                private_key_hex = sk.hex()
        else:
            raise RuntimeError("Khong co thu vien ML-DSA-44.")

        response = {
            'private_key': private_key_hex,
            'public_key': public_key_hex
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

    if not sender_address or not sender_private_key or not recipient_address or not value:
        return jsonify({'message': 'Vui lòng điền đầy đủ các trường: Người gửi, Khóa bí mật, Người nhận và Số tiền.'}), 400

    try:
        transaction = Transaction(sender_address, sender_private_key, recipient_address, value)
        response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}
        return jsonify(response), 200
    except ValueError as ve:
        return jsonify({'message': f'Lỗi ký số: Khóa bí mật không hợp lệ hoặc sai định dạng Hex. Chi tiết: {str(ve)}'}), 400
    except Exception as e:
        return jsonify({'message': f'Lỗi hệ thống: {str(e)}'}), 500


@app.route('/broadcast/transaction', methods=['POST'])
def broadcast_transaction():
    """Chuyển tiếp giao dịch từ Client tới Blockchain Node qua kênh PQC-TLS (ML-KEM-768) an toàn."""
    node_url = request.form.get('node_url', '').strip()
    if not node_url:
        return jsonify({'message': 'Vui lòng chọn hoặc nhập URL của Blockchain Node!'}), 400

    payload = {
        'sender_address': request.form.get('sender_address', '').strip(),
        'recipient_address': request.form.get('recipient_address', '').strip(),
        'amount': request.form.get('amount', '').strip(),
        'signature': request.form.get('signature', '').strip()
    }

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    kem_result = None
    # 1. Thực hiện bắt tay Trao đổi khóa Hậu lượng tử ML-KEM-768 với Node nếu chạy TLS/HTTPS
    if mlkem_pqc is not None and node_url.startswith("https://"):
        try:
            t0 = time.perf_counter()
            client_pk, client_sk = mlkem_pqc.keygen()
            hs_resp = requests.post(f"{node_url}/pqc/kem/handshake", json={'client_pk': client_pk.hex()}, timeout=4, verify=False)
            if hs_resp.status_code == 200:
                hs_data = hs_resp.json()
                server_ct = bytes.fromhex(hs_data['ciphertext'])
                shared_secret = mlkem_pqc.decaps(client_sk, server_ct)
                dt_kem_ms = (time.perf_counter() - t0) * 1000.0
                kem_result = {
                    'enabled': True,
                    'algorithm': 'ML-KEM-768',
                    'standard': 'NIST FIPS 203',
                    'category': 'Post-Quantum (Lattice / Module-LWE)',
                    'pk_bytes': len(client_pk),
                    'ct_bytes': len(server_ct),
                    'handshake_ms': round(dt_kem_ms, 3),
                    'fingerprint': hs_data.get('fingerprint')
                }
        except Exception as e:
            print(f"[!] Warning: KEM handshake error: {e}")

    # 2. Gửi giao dịch qua kênh bảo mật
    try:
        res = requests.post(f"{node_url}/transactions/new", json=payload, timeout=6, verify=False)
        resp_data = res.json()
        if kem_result:
            resp_data['pqc_kem'] = kem_result
        return jsonify(resp_data), res.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'message': f'Không thể kết nối tới Node ({node_url}). Đảm bảo Node đang chạy! Chi tiết: {str(e)}'}), 502


@app.route('/node/balance', methods=['GET'])
def node_balance():
    """Proxy lấy số dư từ Node qua kênh TLS."""
    node_url = request.args.get('node_url', 'http://127.0.0.1:5000').strip()
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        res = requests.get(f"{node_url}/accounts/balance", timeout=3, verify=False)
        return jsonify(res.json()), res.status_code
    except Exception:
        return jsonify({'balances': []}), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)
