"""
KEM Benchmark Suite: Classical ECDHE vs Post-Quantum KEM Mechanisms
Mechanisms:
1. secp256r1 (ECDHE NIST P-256)
2. X25519 (ECDHE Curve25519)
3. ML-KEM-768 (Kyber-768 / NIST FIPS 203)
4. FrodoKEM-640 (Unstructured LWE / NIST Round 3)
5. HQC-128 (Hamming Quasi-Cyclic / NIST Round 4)
"""

import hashlib
import time
import warnings
from typing import Dict, Tuple

# Suppress runtime warnings from FrodoKEM numpy uint16 scalar subtraction
warnings.filterwarnings('ignore', category=RuntimeWarning, module='FrodoKEM')

# 1. Classical ECDHE
try:
    from cryptography.hazmat.primitives.asymmetric import ec, x25519
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# 2. ML-KEM and HQC
try:
    import pqcrypto.kem.ml_kem_768 as mlkem768
    import pqcrypto.kem.hqc_128 as hqc128
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False

# 3. FrodoKEM
try:
    from FrodoKEM.frodo640.api_frodo640 import FrodoAPI640, CryptoKem
    FRODO_AVAILABLE = True
except ImportError:
    FRODO_AVAILABLE = False


KEM_CATALOG = {
    'secp256r1': {
        'name': 'ECDHE (secp256r1)',
        'category': 'Classical ECC',
        'subfamily': 'Weierstrass Curve (NIST P-256)',
        'nist_level': 'Classical 128-bit',
        'quantum_resistant': False,
        'pk_size': 65,
        'ct_size': 32,
        'shared_secret_size': 32
    },
    'x25519': {
        'name': 'ECDHE (X25519)',
        'category': 'Classical ECC',
        'subfamily': 'Montgomery Curve (Curve25519)',
        'nist_level': 'Classical 128-bit',
        'quantum_resistant': False,
        'pk_size': 32,
        'ct_size': 32,
        'shared_secret_size': 32
    },
    'mlkem768': {
        'name': 'ML-KEM-768',
        'category': 'Post-Quantum (Lattice)',
        'subfamily': 'Module-LWE (NIST FIPS 203 / Kyber)',
        'nist_level': 'Category 3 (192-bit)',
        'quantum_resistant': True,
        'pk_size': 1184,
        'ct_size': 1088,
        'shared_secret_size': 32
    },
    'hybrid_mlkem768': {
        'name': 'Hybrid (X25519 + ML-KEM-768)',
        'category': 'Hybrid Post-Quantum',
        'subfamily': 'IETF TLS 1.3 Draft (Dual Defense)',
        'nist_level': 'Classical 128-bit + PQC Category 3',
        'quantum_resistant': True,
        'pk_size': 1216,
        'ct_size': 1120,
        'shared_secret_size': 32
    },
    'frodokem640': {
        'name': 'FrodoKEM-640',
        'category': 'Post-Quantum (Lattice)',
        'subfamily': 'Unstructured LWE (Standard Lattice)',
        'nist_level': 'Category 1 (128-bit)',
        'quantum_resistant': True,
        'pk_size': 9616,
        'ct_size': 9720,
        'shared_secret_size': 16
    },
    'hqc128': {
        'name': 'HQC-128',
        'category': 'Post-Quantum (Code-based)',
        'subfamily': 'Hamming Quasi-Cyclic (NIST Round 4)',
        'nist_level': 'Category 1 (128-bit)',
        'quantum_resistant': True,
        'pk_size': 2241,
        'ct_size': 4433,
        'shared_secret_size': 32
    }
}


def perform_kem_handshake(kem_key: str) -> Tuple[float, int, int, int]:
    """
    Thực hiện đàm phán bắt tay KEM mô phỏng tầng trao đổi khóa TLS 1.3:
    - Client KeyGen / Ephemeral Key
    - Server Encapsulation
    - Client Decapsulation / Derivation
    Trả về: (thời gian tính toán ms, bytes khóa công khai, bytes bản mã KEM, tổng bytes gói tin trao đổi)
    """
    key = kem_key.lower().strip()
    if key not in KEM_CATALOG:
        raise ValueError(f"Khong ho tro KEM: '{kem_key}'. Danh sach ho tro: {list(KEM_CATALOG.keys())}")

    t0 = time.perf_counter()

    if key == 'secp256r1':
        client_sk = ec.generate_private_key(ec.SECP256R1())
        server_sk = ec.generate_private_key(ec.SECP256R1())
        ss = client_sk.exchange(ec.ECDH(), server_sk.public_key())
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return dt_ms, 65, 32, 97

    elif key == 'x25519':
        client_sk = x25519.X25519PrivateKey.generate()
        server_sk = x25519.X25519PrivateKey.generate()
        ss = client_sk.exchange(server_sk.public_key())
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return dt_ms, 32, 32, 64

    elif key == 'mlkem768':
        pk, sk = mlkem768.keygen()
        ct, ss1 = mlkem768.encaps(pk)
        ss2 = mlkem768.decaps(sk, ct)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return dt_ms, len(pk), len(ct), len(pk) + len(ct)

    elif key in ('hybrid_mlkem768', 'hybrid', 'x25519_mlkem768'):
        # 1. Client Ephemeral Keygen (X25519 + ML-KEM-768)
        client_sk_x = x25519.X25519PrivateKey.generate()
        client_pk_x = client_sk_x.public_key().public_bytes_raw()
        client_pk_m, client_sk_m = mlkem768.keygen()
        pk_hybrid = client_pk_x + client_pk_m

        # 2. Server Ephemeral Keygen & Encapsulation
        server_sk_x = x25519.X25519PrivateKey.generate()
        server_pk_x = server_sk_x.public_key().public_bytes_raw()
        ss_x_server = server_sk_x.exchange(x25519.X25519PublicKey.from_public_bytes(client_pk_x))
        ct_m, ss_m_server = mlkem768.encaps(client_pk_m)
        ct_hybrid = server_pk_x + ct_m

        # 3. Client Decapsulation & Dual Derivation
        ss_x_client = client_sk_x.exchange(x25519.X25519PublicKey.from_public_bytes(server_pk_x))
        ss_m_client = mlkem768.decaps(client_sk_m, ct_m)
        ss_hybrid_client = hashlib.sha256(ss_x_client + ss_m_client).digest()
        ss_hybrid_server = hashlib.sha256(ss_x_server + ss_m_server).digest()

        dt_ms = (time.perf_counter() - t0) * 1000.0
        return dt_ms, len(pk_hybrid), len(ct_hybrid), len(pk_hybrid) + len(ct_hybrid)

    elif key == 'hqc128':
        pk, sk = hqc128.keygen()
        ct, ss1 = hqc128.encaps(pk)
        ss2 = hqc128.decaps(sk, ct)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return dt_ms, len(pk), len(ct), len(pk) + len(ct)

    elif key == 'frodokem640':
        f_api = FrodoAPI640()
        pk, sk = f_api.crypto_kem_keypair_frodo640()
        ct, ss1 = f_api.crypto_kem_enc_frodo640()
        ss2 = CryptoKem.dec(f_api.kem, f_api.kem.ss_decap, ct, sk)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        pk_len = len(bytes(pk))
        ct_len = len(bytes(ct))
        return dt_ms, pk_len, ct_len, pk_len + ct_len

    raise ValueError(f"Unknown KEM key: {key}")
