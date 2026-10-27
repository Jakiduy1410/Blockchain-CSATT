"""
PERF-01: Load Dataset Generator (ML-DSA-87 Level 5 & Baseline)
Sinh san tap du lieu giao dich da ky hop le:
- ECDSA (secp256k1): 500 txs (Baseline) va 2000 txs (Stress Test)
- RSA-2048 (PKCS#1 v1.5): 500 txs (Baseline)
- ML-DSA-87 (NIST FIPS 204 Level 5 PQC): 500 txs (Baseline) va 2000 txs (Extreme OOM Hunt)
Toi uu: Chi sinh dung so luong can chay theo yeu cau, dung chung khoa de dam bao so du hop le.
"""

import binascii
import json
import os
import sys
import time
from collections import OrderedDict
from pathlib import Path

PERF_DIR = Path(__file__).resolve().parent
BASE_DIR = PERF_DIR.parent
sys.path.insert(0, str(BASE_DIR))

import ecdsa
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False


def generate_ecdsa_transactions(n: int = 2000) -> list:
    print(f"[*] Dang sinh {n} giao dich ECDSA (secp256k1)...")
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pub_hex = vk.to_string().hex()
    recipient_hex = "4d67538820a505b42abfa966b3c652ab041535045ab791dbc33711df832f428c453406314349fc98c4448c1e4b4ad85d049009bda5a29e66f7d26006403b6aae"

    txs = []
    for i in range(1, n + 1):
        tx_dict = OrderedDict([
            ('sender_address', pub_hex),
            ('recipient_address', recipient_hex),
            ('value', "1.0"),
            ('nonce', str(i))
        ])
        sig = sk.sign(str(tx_dict).encode('utf-8'))
        txs.append({
            'sender_address': pub_hex,
            'recipient_address': recipient_hex,
            'amount': "1.0",
            'nonce': i,
            'signature': sig.hex(),
            'algorithm': 'ECDSA'
        })
    print(f"    -> Da sinh xong {len(txs)} txs ECDSA. Size: PK={len(pub_hex)//2}B, Sig={len(txs[0]['signature'])//2}B")
    return txs


def generate_rsa_transactions(n: int = 500) -> list:
    print(f"[*] Dang sinh {n} giao dich RSA-2048 (PKCS#1 v1.5)...")
    rsa_key = RSA.generate(2048)
    signer = PKCS1_v1_5.new(rsa_key)
    pub_der = rsa_key.publickey().export_key(format='DER')
    pub_hex = binascii.hexlify(pub_der).decode('ascii')
    recipient_hex = "4d67538820a505b42abfa966b3c652ab041535045ab791dbc33711df832f428c453406314349fc98c4448c1e4b4ad85d049009bda5a29e66f7d26006403b6aae"

    txs = []
    for i in range(1, n + 1):
        tx_dict = OrderedDict([
            ('sender_address', pub_hex),
            ('recipient_address', recipient_hex),
            ('value', "1.0")
        ])
        h = SHA.new(str(tx_dict).encode('utf-8'))
        sig = signer.sign(h)
        txs.append({
            'sender_address': pub_hex,
            'recipient_address': recipient_hex,
            'amount': "1.0",
            'nonce': i,
            'signature': binascii.hexlify(sig).decode('ascii'),
            'algorithm': 'RSA-2048'
        })
    print(f"    -> Da sinh xong {len(txs)} txs RSA-2048. Size: PK={len(pub_hex)//2}B, Sig={len(txs[0]['signature'])//2}B")
    return txs


def generate_mldsa87_transactions(n: int = 2000) -> list:
    if not OQS_AVAILABLE:
        print("[!] Can chay qua Docker de co thu vien liboqs sinh ML-DSA-87")
        return []
    print(f"[*] Dang sinh {n} giao dich Hau luong tu ML-DSA-87 (NIST FIPS 204 Level 5)...")
    recipient_hex = "4d67538820a505b42abfa966b3c652ab041535045ab791dbc33711df832f428c453406314349fc98c4448c1e4b4ad85d049009bda5a29e66f7d26006403b6aae"

    txs = []
    with oqs.Signature('ML-DSA-87') as signer:
        pub_bytes = signer.generate_keypair()
        pub_hex = pub_bytes.hex()
        for i in range(1, n + 1):
            tx_dict = OrderedDict([
                ('sender_address', pub_hex),
                ('recipient_address', recipient_hex),
                ('value', "1.0")
            ])
            sig_bytes = signer.sign(str(tx_dict).encode('utf-8'))
            txs.append({
                'sender_address': pub_hex,
                'recipient_address': recipient_hex,
                'amount': "1.0",
                'nonce': i,
                'signature': sig_bytes.hex(),
                'algorithm': 'ML-DSA-87'
            })
    print(f"    -> Da sinh xong {len(txs)} txs ML-DSA-87. Size: PK={len(pub_hex)//2}B, Sig={len(txs[0]['signature'])//2}B (Total Payload: {(len(pub_hex)+len(txs[0]['signature']))//2}B/tx)")
    return txs


def main():
    data_dir = PERF_DIR / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    # 1. Sinh 2000 ECDSA va chia lam 500 / 2000
    ecdsa_all = generate_ecdsa_transactions(2000)
    with open(data_dir / "txs_500_ecdsa.json", "w", encoding="utf-8") as f:
        json.dump(ecdsa_all[:500], f, indent=2)
    with open(data_dir / "txs_stress_ecdsa.json", "w", encoding="utf-8") as f:
        json.dump(ecdsa_all, f, indent=2)

    # 2. Sinh 500 RSA
    rsa_500 = generate_rsa_transactions(500)
    with open(data_dir / "txs_500_rsa.json", "w", encoding="utf-8") as f:
        json.dump(rsa_500, f, indent=2)

    # 3. Sinh 2000 ML-DSA-87 va chia lam 500 / 2000
    mldsa87_all = []
    if OQS_AVAILABLE:
        mldsa87_all = generate_mldsa87_transactions(2000)
        with open(data_dir / "txs_500_mldsa87.json", "w", encoding="utf-8") as f:
            json.dump(mldsa87_all[:500], f, indent=2)
        with open(data_dir / "txs_stress_mldsa87.json", "w", encoding="utf-8") as f:
            json.dump(mldsa87_all, f, indent=2)

    # 4. Cap nhat vi trong configs/wallets.json de dam bao so du hop le
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
    wallets["Perf_RSA"] = {
        "name": "Perf_RSA",
        "initial_balance": 5000000.0,
        "public_key": rsa_500[0]['sender_address'],
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

    print("\n[+] Hoan tat sinh du lieu toi uu: txs_500 (Baseline) va txs_stress (OOM Hunt)!")


if __name__ == '__main__':
    main()
