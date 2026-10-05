"""
Crypto Module
Trách nhiệm:
- Thẩm định chữ ký số ECDSA (secp256k1) và RSA (PKCS#1 v1.5)
- Tính toán hàm băm mật mã SHA-256 chuẩn cho khối (block) và giao dịch (transaction)
"""

import binascii
import hashlib
import json
from collections import OrderedDict

try:
    from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
except ImportError:
    VerifyingKey = None

from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


def verify_ecdsa_signature(sender_public_key_hex: str, signature_hex: str, transaction_dict: dict) -> bool:
    """
    Xác thực chữ ký số ECDSA (đường cong secp256k1).
    Zero-Trust: từ chối ngay nếu định dạng hoặc chữ ký sai lệch.
    """
    if VerifyingKey is None:
        return False
    try:
        if not sender_public_key_hex or not signature_hex:
            return False

        public_key_bytes = bytes.fromhex(sender_public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        vk = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)

        ordered_tx = OrderedDict([
            ('sender_address', str(transaction_dict.get('sender_address', ''))),
            ('recipient_address', str(transaction_dict.get('recipient_address', ''))),
            ('value', str(transaction_dict.get('value', '')))
        ])
        tx_bytes = str(ordered_tx).encode('utf-8')
        return vk.verify(signature_bytes, tx_bytes)
    except Exception:
        return False


def verify_rsa_signature(sender_public_key_hex: str, signature_hex: str, transaction_dict: dict) -> bool:
    """Xác thực chữ ký số RSA của người gửi."""
    try:
        if not sender_public_key_hex or not signature_hex:
            return False

        public_key_bytes = binascii.unhexlify(sender_public_key_hex)
        signature_bytes = binascii.unhexlify(signature_hex)

        public_key = RSA.importKey(public_key_bytes)
        verifier = PKCS1_v1_5.new(public_key)

        ordered_tx = OrderedDict([
            ('sender_address', str(transaction_dict.get('sender_address', ''))),
            ('recipient_address', str(transaction_dict.get('recipient_address', ''))),
            ('value', str(transaction_dict.get('value', '')))
        ])

        tx_hash = SHA.new(str(ordered_tx).encode('utf-8'))
        return verifier.verify(tx_hash, signature_bytes)
    except Exception:
        return False


def verify_signature(sender_public_key_hex: str, signature_hex: str, transaction_dict: dict) -> bool:
    """
    Hàm xác thực chữ ký số tổng quát:
    Tự động thẩm định theo ECDSA trước, nếu không khớp kiểm tra RSA.
    """
    if verify_ecdsa_signature(sender_public_key_hex, signature_hex, transaction_dict):
        return True
    return verify_rsa_signature(sender_public_key_hex, signature_hex, transaction_dict)


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
