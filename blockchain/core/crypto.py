"""
Crypto Module
Trách nhiệm:
- Thẩm định chữ ký số Hậu lượng tử ML-DSA-44 (FIPS 204), ECDSA (secp256k1) và RSA (PKCS#1 v1.5)
- Tính toán hàm băm mật mã SHA-256 chuẩn cho khối (block) và giao dịch (transaction)
"""

import binascii
import hashlib
import json
from collections import OrderedDict

import os
import sys

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
        for dll_dir in dll_dirs:
            if os.path.isdir(dll_dir):
                try:
                    os.add_dll_directory(dll_dir)
                except Exception:
                    pass
    import oqs
except (ImportError, Exception):
    oqs = None

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.exceptions import InvalidSignature
except (ImportError, Exception):
    ec = None

from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


def verify_mldsa_signature(sender_public_key_hex: str, signature_hex: str, transaction_dict: dict) -> bool:
    """
    Xác thực chữ ký số Hậu lượng tử ML-DSA-44 (FIPS 204).
    Zero-Trust: nếu public key, signature hoặc định dạng dữ liệu sai -> từ chối ngay.
    """
    if oqs is None:
        return False
    try:
        if not sender_public_key_hex or not signature_hex:
            return False

        public_key_bytes = bytes.fromhex(sender_public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)

        ordered_tx = OrderedDict([
            ('sender_address', str(transaction_dict.get('sender_address', ''))),
            ('recipient_address', str(transaction_dict.get('recipient_address', ''))),
            ('value', str(transaction_dict.get('value', '')))
        ])
        if 'nonce' in transaction_dict and transaction_dict['nonce'] is not None and str(transaction_dict['nonce']) != '':
            ordered_tx['nonce'] = str(transaction_dict['nonce'])
        tx_bytes = str(ordered_tx).encode('utf-8')

        if len(public_key_bytes) >= 2592 or len(signature_bytes) >= 4627:
            alg_name = "ML-DSA-87"
        elif len(public_key_bytes) >= 1952 or len(signature_bytes) >= 3309:
            alg_name = "ML-DSA-65"
        else:
            alg_name = "ML-DSA-44"

        with oqs.Signature(alg_name) as verifier:
            return verifier.verify(tx_bytes, signature_bytes, public_key_bytes)
    except Exception:
        return False


def verify_ecdsa_signature(sender_public_key_hex: str, signature_hex: str, transaction_dict: dict) -> bool:
    """
    Xác thực chữ ký số ECDSA (đường cong secp256k1) thuần túy bằng C-Engine (OpenSSL qua cryptography).
    Tuyệt đối không sử dụng thư viện Pure-Python; đảm bảo tính minh bạch và công bằng 100% với PQC (liboqs C-core).
    """
    if ec is None or not sender_public_key_hex or not signature_hex:
        return False

    try:
        ordered_tx = OrderedDict([
            ('sender_address', str(transaction_dict.get('sender_address', ''))),
            ('recipient_address', str(transaction_dict.get('recipient_address', ''))),
            ('value', str(transaction_dict.get('value', '')))
        ])
        if 'nonce' in transaction_dict and transaction_dict['nonce'] is not None and str(transaction_dict['nonce']) != '':
            ordered_tx['nonce'] = str(transaction_dict['nonce'])

        tx_bytes = str(ordered_tx).encode('utf-8')
        public_key_bytes = bytes.fromhex(sender_public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)

        # 1. Đọc Public Key bằng OpenSSL C-Engine (hỗ trợ raw 64B x||y, compressed 33B, hoặc 65B 0x04)
        if len(public_key_bytes) == 64:
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b'\x04' + public_key_bytes)
        elif len(public_key_bytes) in (33, 65):
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)
        else:
            pk = serialization.load_der_public_key(public_key_bytes)

        # 2. Đọc Signature (chuẩn raw r||s 64B hoặc chuẩn DER ASN.1)
        if len(signature_bytes) == 64:
            r = int.from_bytes(signature_bytes[:32], 'big')
            s = int.from_bytes(signature_bytes[32:], 'big')
            der_sig = encode_dss_signature(r, s)
        else:
            der_sig = signature_bytes

        # 3. Thẩm định hoàn toàn bằng C native OpenSSL (ưu tiên SHA-256, hỗ trợ SHA-1 legacy)
        try:
            pk.verify(der_sig, tx_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            try:
                pk.verify(der_sig, tx_bytes, ec.ECDSA(hashes.SHA1()))
                return True
            except InvalidSignature:
                return False
    except Exception:
        return False


def verify_rsa_signature(sender_public_key_hex: str, signature_hex: str, transaction_dict: dict) -> bool:
    """Xác thực chữ ký số RSA PKCS#1 v1.5."""
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
    Tự động thẩm định theo ML-DSA-44 (PQC), ECDSA hoặc RSA.
    """
    if not sender_public_key_hex or not signature_hex:
        return False

    # 1. Nếu độ dài phù hợp ML-DSA-44 (khóa pub >= 1312 bytes hoặc sig >= 2420 bytes)
    if len(signature_hex) > 1000 or len(sender_public_key_hex) > 1000:
        return verify_mldsa_signature(sender_public_key_hex, signature_hex, transaction_dict)

    # 2. Thẩm định ECDSA
    if verify_ecdsa_signature(sender_public_key_hex, signature_hex, transaction_dict):
        return True

    # 3. Thẩm định RSA
    if verify_rsa_signature(sender_public_key_hex, signature_hex, transaction_dict):
        return True

    # 4. Fallback thử lại ML-DSA-44 nếu có
    return verify_mldsa_signature(sender_public_key_hex, signature_hex, transaction_dict)


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
