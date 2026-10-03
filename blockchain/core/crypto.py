"""
Crypto Module
Trách nhiệm:
- Thẩm định chữ ký số RSA (PKCS#1 v1.5 với SHA-1/SHA-256)
- Tính toán hàm băm mật mã SHA-256 chuẩn cho khối (block) và giao dịch (transaction)
"""

import binascii
import hashlib
import json
from collections import OrderedDict
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


def verify_rsa_signature(sender_public_key_hex: str, signature_hex: str, transaction_dict: dict) -> bool:
    """
    Xác thực chữ ký số RSA của người gửi.
    - Zero-Trust: Nếu public key, signature hoặc định dạng dữ liệu sai lệch -> Từ chối ngay.
    """
    try:
        if not sender_public_key_hex or not signature_hex:
            return False

        public_key_bytes = binascii.unhexlify(sender_public_key_hex)
        signature_bytes = binascii.unhexlify(signature_hex)

        public_key = RSA.importKey(public_key_bytes)
        verifier = PKCS1_v1_5.new(public_key)

        # Đảm bảo thứ tự trường trong transaction để hash luôn đồng nhất
        ordered_tx = OrderedDict([
            ('sender_address', transaction_dict.get('sender_address', '')),
            ('recipient_address', transaction_dict.get('recipient_address', '')),
            ('value', transaction_dict.get('value', ''))
        ])

        tx_hash = SHA.new(str(ordered_tx).encode('utf-8'))
        return verifier.verify(tx_hash, signature_bytes)
    except Exception:
        return False


def calculate_sha256(data: str) -> str:
    """Tính SHA-256 cho chuỗi ký tự."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def calculate_block_hash(block: dict) -> str:
    """
    Tính SHA-256 cho Block.
    Sắp xếp key (sort_keys=True) để đảm bảo tính toàn vẹn và bất biến.
    """
    block_copy = {
        'block_number': block['block_number'],
        'timestamp': block['timestamp'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash']
    }
    block_string = json.dumps(block_copy, sort_keys=True).encode('utf-8')
    return hashlib.sha256(block_string).hexdigest()
