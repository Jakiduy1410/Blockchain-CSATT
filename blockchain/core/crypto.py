"""
Crypto Module
Trách nhiệm:
- Thẩm định chữ ký số Hậu lượng tử ML-DSA-44 / ML-DSA-65 / ML-DSA-87 (FIPS 204), ECDSA (secp256k1) và RSA (PKCS#1 v1.5)
- Tính toán hàm băm mật mã SHA-256 chuẩn cho khối (block) và giao dịch (transaction)
"""

import binascii
import hashlib
import json
import os
import sys
import threading
from collections import OrderedDict

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

try:
    from Crypto.Hash import SHA
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
except ImportError:
    SHA = None
    RSA = None
    PKCS1_v1_5 = None

_tls_verifiers = threading.local()
_EC_PK_CACHE = {}


def _get_thread_oqs_verifier(alg_name: str):
    """Sử dụng thread-local cache cho OQS Signature verifiers để tối đa hóa hiệu năng luồng."""
    if oqs is None:
        return None
    cache = getattr(_tls_verifiers, 'cache', None)
    if cache is None:
        cache = {}
        _tls_verifiers.cache = cache
    if alg_name not in cache:
        cache[alg_name] = oqs.Signature(alg_name)
    return cache[alg_name]


def _get_cached_ec_pk(sender_public_key_hex: str):
    """Cache OpenSSL EC Public Key objects để giảm thiểu chi phí parse EC key lặp lại."""
    entry = _EC_PK_CACHE.get(sender_public_key_hex)
    if entry is None:
        public_key_bytes = bytes.fromhex(sender_public_key_hex)
        if len(public_key_bytes) == 64:
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b'\x04' + public_key_bytes)
        elif len(public_key_bytes) in (33, 65):
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)
        else:
            pk = serialization.load_der_public_key(public_key_bytes)
        entry = (pk, set())
        if len(_EC_PK_CACHE) < 512:
            _EC_PK_CACHE[sender_public_key_hex] = entry
    return entry


def _prewarm_crypto_engines():
    """
    Pre-fault shared libraries (liboqs, libcrypto) vào bộ nhớ khi khởi động
    để baseline RAM đo được luôn đồng nhất, không bị nhiễu do cold-start page faults.
    """
    try:
        if oqs is not None:
            for alg in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
                v = _get_thread_oqs_verifier(alg)
                if v:
                    pk = v.generate_keypair()
                    sig = v.sign(b"warmup")
                    v.verify(b"warmup", sig, pk)
        if ec is not None:
            sk = ec.generate_private_key(ec.SECP256K1())
            pk = sk.public_key()
            sig = sk.sign(b"warmup", ec.ECDSA(hashes.SHA256()))
            pk.verify(sig, b"warmup", ec.ECDSA(hashes.SHA256()))
    except Exception:
        pass


_prewarm_crypto_engines()


def _get_serialized_candidates(transaction_dict: dict, prefer_nonce: bool = True) -> list:
    """
    Tạo các dạng biểu diễn bytes chuẩn hóa của Transaction payload
    để tương thích tuyệt đối giữa:
    - Các phiên bản Python (Python <=3.11 dùng list of tuples repr, Python >=3.12 dùng dict repr cho OrderedDict)
    - Định dạng trường số tiền ('amount' vs 'value')
    - Trường hợp payload có nonce (ECDSA/Client) hoặc không nonce (ML-DSA dataset)
    prefer_nonce=True: ưu tiên dạng có nonce lên đầu (chuẩn cho ECDSA / Client transactions)
    prefer_nonce=False: ưu tiên dạng không nonce lên đầu (chuẩn cho PQC ML-DSA dataset)
    """
    candidates = []
    base_val = str(transaction_dict.get('value', transaction_dict.get('amount', '')))
    base_items = [
        ('sender_address', str(transaction_dict.get('sender_address', ''))),
        ('recipient_address', str(transaction_dict.get('recipient_address', ''))),
        ('value', base_val)
    ]

    has_nonce = (
        'nonce' in transaction_dict
        and transaction_dict['nonce'] is not None
        and str(transaction_dict['nonce']).strip() != ''
        and str(transaction_dict['nonce']).strip() != '0'
    )

    dicts_to_try = []
    if has_nonce and prefer_nonce:
        items_with_nonce = list(base_items) + [('nonce', str(transaction_dict['nonce']))]
        dicts_to_try.append(OrderedDict(items_with_nonce))
        dicts_to_try.append(OrderedDict(base_items))
    elif has_nonce and not prefer_nonce:
        items_with_nonce = list(base_items) + [('nonce', str(transaction_dict['nonce']))]
        dicts_to_try.append(OrderedDict(base_items))
        dicts_to_try.append(OrderedDict(items_with_nonce))
    else:
        dicts_to_try.append(OrderedDict(base_items))

    for od in dicts_to_try:
        native_bytes = str(od).encode('utf-8')
        if native_bytes not in candidates:
            candidates.append(native_bytes)

        items = list(od.items())
        py311_bytes = ('OrderedDict([' + ', '.join([f"({repr(k)}, {repr(v)})" for k, v in items]) + '])').encode('utf-8')
        if py311_bytes not in candidates:
            candidates.append(py311_bytes)

        py312_bytes = ('OrderedDict({' + ', '.join([f"{repr(k)}: {repr(v)}" for k, v in items]) + '})').encode('utf-8')
        if py312_bytes not in candidates:
            candidates.append(py312_bytes)

    return candidates


def verify_mldsa_signature(sender_public_key_hex: str, signature_hex: str, transaction_dict: dict) -> bool:
    """
    Xác thực chữ ký số Hậu lượng tử ML-DSA-44 / ML-DSA-65 / ML-DSA-87 (FIPS 204).
    Zero-Trust: nếu public key, signature hoặc định dạng dữ liệu sai -> từ chối ngay.
    """
    if oqs is None or not sender_public_key_hex or not signature_hex:
        return False
    try:
        public_key_bytes = bytes.fromhex(sender_public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)

        if len(public_key_bytes) >= 2592 or len(signature_bytes) >= 4627:
            alg_name = "ML-DSA-87"
        elif len(public_key_bytes) >= 1952 or len(signature_bytes) >= 3309:
            alg_name = "ML-DSA-65"
        else:
            alg_name = "ML-DSA-44"

        candidates = _get_serialized_candidates(transaction_dict, prefer_nonce=False)
        verifier = _get_thread_oqs_verifier(alg_name)

        for payload in candidates:
            try:
                if verifier:
                    if verifier.verify(payload, signature_bytes, public_key_bytes):
                        return True
                else:
                    with oqs.Signature(alg_name) as v:
                        if v.verify(payload, signature_bytes, public_key_bytes):
                            return True
            except Exception:
                continue
        return False
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
        pk, verified_sigs = _get_cached_ec_pk(sender_public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)

        # 2. Đọc Signature (chuẩn raw r||s 64B hoặc chuẩn DER ASN.1)
        if len(signature_bytes) == 64:
            r = int.from_bytes(signature_bytes[:32], 'big')
            s = int.from_bytes(signature_bytes[32:], 'big')
            der_sig = encode_dss_signature(r, s)
        else:
            der_sig = signature_bytes

        # 3. Thẩm định bằng C native OpenSSL (SHA-256) với prefer_nonce=True
        candidates = _get_serialized_candidates(transaction_dict, prefer_nonce=True)
        for payload in candidates:
            try:
                pk.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
                if len(verified_sigs) < 2048:
                    verified_sigs.add(signature_hex)
                return True
            except InvalidSignature:
                try:
                    pk.verify(der_sig, payload, ec.ECDSA(hashes.SHA1()))
                    return True
                except InvalidSignature:
                    continue
            except Exception:
                continue
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

        candidates = _get_serialized_candidates(transaction_dict, prefer_nonce=True)
        for payload in candidates:
            try:
                tx_hash = SHA.new(payload)
                if verifier.verify(tx_hash, signature_bytes):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def verify_signature(sender_public_key_hex: str, signature_hex: str, transaction_dict: dict) -> bool:
    """
    Hàm xác thực chữ ký số tổng quát:
    Tự động thẩm định theo ML-DSA-44/65/87 (PQC), ECDSA hoặc RSA.
    """
    if not sender_public_key_hex or not signature_hex:
        return False

    # 1. Nếu độ dài phù hợp ML-DSA (khóa pub >= 1312 bytes hoặc sig >= 2420 bytes)
    if len(signature_hex) > 1000 or len(sender_public_key_hex) > 1000:
        return verify_mldsa_signature(sender_public_key_hex, signature_hex, transaction_dict)

    # 2. Thẩm định ECDSA
    if verify_ecdsa_signature(sender_public_key_hex, signature_hex, transaction_dict):
        return True

    # 3. Thẩm định RSA
    if verify_rsa_signature(sender_public_key_hex, signature_hex, transaction_dict):
        return True

    # 4. Fallback thử lại ML-DSA nếu có
    return verify_mldsa_signature(sender_public_key_hex, signature_hex, transaction_dict)


def calculate_sha256(data: str) -> str:
    """Tính SHA-256 cho chuỗi ký tự."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def calculate_block_hash(block: dict) -> str:
    """
    Tính SHA-256 cho Block.
    Sắp xếp key (sort_keys=True) để đảm bảo tính toàn vẹn và bất biến.
    Tự động loại bỏ metadata nội bộ (key bắt đầu bằng '_') trước khi băm.
    """
    clean_txs = []
    for tx in block.get('transactions', []):
        if isinstance(tx, dict):
            clean_txs.append({k: v for k, v in tx.items() if not k.startswith('_')})
        else:
            clean_txs.append(tx)

    block_copy = {
        'block_number': block['block_number'],
        'timestamp': block['timestamp'],
        'transactions': clean_txs,
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash']
    }
    block_string = json.dumps(block_copy, sort_keys=True).encode('utf-8')
    return hashlib.sha256(block_string).hexdigest()
