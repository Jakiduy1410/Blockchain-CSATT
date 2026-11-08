"""
PERF-01: Load Dataset Generator (ML-DSA-44 L2, ML-DSA-65 L3, ML-DSA-87 L5 & ECDSA Baseline)
Sinh san tap du lieu giao dich da ky hop le:
- ECDSA (secp256k1): 500 txs (Baseline) va 2000 txs (Stress Test)
- ML-DSA-44 (NIST FIPS 204 Level 2 PQC): 500 txs (Baseline) va 2000 txs (Stress Test)
- ML-DSA-65 (NIST FIPS 204 Level 3 PQC - NIST Default): 500 txs (Baseline) va 2000 txs (Extreme OOM Hunt)
- ML-DSA-87 (NIST FIPS 204 Level 5 PQC): 500 txs (Baseline) va 2000 txs (Extreme OOM Hunt)
Toi uu: Chi sinh dung so luong can chay theo yeu cau, dung chung khoa de dam bao so du hop le.
"""

import json
import os
import sys
from collections import OrderedDict
from pathlib import Path

PERF_DIR = Path(__file__).resolve().parent
BASE_DIR = PERF_DIR.parent
sys.path.insert(0, str(BASE_DIR))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

try:
    if os.name == 'nt' and not (
        os.path.exists(os.path.expanduser('~/_oqs/bin/oqs.dll')) or os.path.exists('oqs.dll')
    ):
        OQS_AVAILABLE = False
    else:
        import oqs
        OQS_AVAILABLE = True
except (ImportError, Exception, SystemExit):
    OQS_AVAILABLE = False

RECIPIENT_HEX = "4d67538820a505b42abfa966b3c652ab041535045ab791dbc33711df832f428c453406314349fc98c4448c1e4b4ad85d049009bda5a29e66f7d26006403b6aae"


def generate_ecdsa_transactions(n: int = 2000) -> list:
    print(f"[*] Dang sinh {n} giao dich ECDSA (secp256k1) qua C OpenSSL...")
    sk = ec.generate_private_key(ec.SECP256K1())
    pub_num = sk.public_key().public_numbers()
    pub_hex = f"{pub_num.x:064x}{pub_num.y:064x}"

    txs = []
    for i in range(1, n + 1):
        tx_dict = OrderedDict([
            ('sender_address', pub_hex),
            ('recipient_address', RECIPIENT_HEX),
            ('value', "1.0"),
            ('nonce', str(i))
        ])
        der = sk.sign(str(tx_dict).encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        txs.append({
            'sender_address': pub_hex,
            'recipient_address': RECIPIENT_HEX,
            'amount': "1.0",
            'nonce': i,
            'signature': sig.hex(),
            'algorithm': 'ECDSA'
        })
    print(f"    -> Da sinh xong {len(txs)} txs ECDSA. Size: PK={len(pub_hex)//2}B, Sig={len(txs[0]['signature'])//2}B")
    return txs


def _generate_mldsa_by_level(alg_name: str, label: str, n: int = 2000) -> list:
    if not OQS_AVAILABLE:
        print(f"[!] Can chay qua Docker de co thu vien liboqs sinh {alg_name}")
        return []
    print(f"[*] Dang sinh {n} giao dich Hau luong tu {alg_name} ({label})...")

    txs = []
    with oqs.Signature(alg_name) as signer:
        pub_bytes = signer.generate_keypair()
        pub_hex = pub_bytes.hex()
        for i in range(1, n + 1):
            tx_dict = OrderedDict([
                ('sender_address', pub_hex),
                ('recipient_address', RECIPIENT_HEX),
                ('value', "1.0")
            ])
            sig_bytes = signer.sign(str(tx_dict).encode('utf-8'))
            txs.append({
                'sender_address': pub_hex,
                'recipient_address': RECIPIENT_HEX,
                'amount': "1.0",
                'nonce': i,
                'signature': sig_bytes.hex(),
                'algorithm': alg_name
            })
    print(f"    -> Da sinh xong {len(txs)} txs {alg_name}. Size: PK={len(pub_hex)//2}B, Sig={len(txs[0]['signature'])//2}B (Total Payload: {(len(pub_hex)+len(txs[0]['signature']))//2}B/tx)")
    return txs


def generate_mldsa44_transactions(n: int = 2000) -> list:
    return _generate_mldsa_by_level('ML-DSA-44', 'NIST FIPS 204 Level 2', n)


def generate_mldsa65_transactions(n: int = 2000) -> list:
    return _generate_mldsa_by_level('ML-DSA-65', 'NIST FIPS 204 Level 3 - Sweet Spot', n)


def generate_mldsa87_transactions(n: int = 2000) -> list:
    return _generate_mldsa_by_level('ML-DSA-87', 'NIST FIPS 204 Level 5', n)


def main():
    data_dir = PERF_DIR / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    # 1. Sinh 2000 ECDSA va chia lam 500 / 2000
    ecdsa_all = generate_ecdsa_transactions(2000)
    with open(data_dir / "txs_500_ecdsa.json", "w", encoding="utf-8") as f:
        json.dump(ecdsa_all[:500], f, indent=2)
    with open(data_dir / "txs_stress_ecdsa.json", "w", encoding="utf-8") as f:
        json.dump(ecdsa_all, f, indent=2)

    # 2. Sinh ML-DSA (44, 65, 87)
    mldsa44_all = []
    mldsa65_all = []
    mldsa87_all = []
    if OQS_AVAILABLE:
        # ML-DSA-44
        mldsa44_all = generate_mldsa44_transactions(2000)
        with open(data_dir / "txs_500_mldsa44.json", "w", encoding="utf-8") as f:
            json.dump(mldsa44_all[:500], f, indent=2)
        with open(data_dir / "txs_stress_mldsa44.json", "w", encoding="utf-8") as f:
            json.dump(mldsa44_all, f, indent=2)

        # ML-DSA-65
        mldsa65_all = generate_mldsa65_transactions(2000)
        with open(data_dir / "txs_500_mldsa65.json", "w", encoding="utf-8") as f:
            json.dump(mldsa65_all[:500], f, indent=2)
        with open(data_dir / "txs_stress_mldsa65.json", "w", encoding="utf-8") as f:
            json.dump(mldsa65_all, f, indent=2)

        # ML-DSA-87
        mldsa87_all = generate_mldsa87_transactions(2000)
        with open(data_dir / "txs_500_mldsa87.json", "w", encoding="utf-8") as f:
            json.dump(mldsa87_all[:500], f, indent=2)
        with open(data_dir / "txs_stress_mldsa87.json", "w", encoding="utf-8") as f:
            json.dump(mldsa87_all, f, indent=2)

    # 3. Cap nhat vi trong configs/wallets.json de dam bao so du hop le
    wallets_path = BASE_DIR / "configs" / "wallets.json"
    wallets = {}
    if wallets_path.exists():
        with open(wallets_path, "r", encoding="utf-8") as f:
            wallets = json.load(f)

    wallets["Perf_ECDSA"] = {
        "name": "Perf_ECDSA",
        "initial_balance": 5000000.0,
        "public_key": ecdsa_all[0]['sender_address'],
        "private_key": ""
    }
    if OQS_AVAILABLE and mldsa44_all:
        wallets["Perf_MLDSA44"] = {
            "name": "Perf_MLDSA44",
            "initial_balance": 5000000.0,
            "public_key": mldsa44_all[0]['sender_address'],
            "private_key": ""
        }
    if OQS_AVAILABLE and mldsa65_all:
        wallets["Perf_MLDSA65"] = {
            "name": "Perf_MLDSA65",
            "initial_balance": 5000000.0,
            "public_key": mldsa65_all[0]['sender_address'],
            "private_key": ""
        }
    if OQS_AVAILABLE and mldsa87_all:
        wallets["Perf_MLDSA87"] = {
            "name": "Perf_MLDSA87",
            "initial_balance": 5000000.0,
            "public_key": mldsa87_all[0]['sender_address'],
            "private_key": ""
        }

    with open(wallets_path, "w", encoding="utf-8") as f:
        json.dump(wallets, f, indent=2)

    print("\n[+] Hoan tat sinh du lieu toi uu: ECDSA + ML-DSA-(44, 65, 87) txs_500 (Baseline) va txs_stress (OOM Hunt)!")


if __name__ == '__main__':
    main()
