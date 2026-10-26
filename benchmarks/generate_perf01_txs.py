"""
PERF-01: Load Dataset Generator (Extended for Baseline & Stress Test)
Sinh san tap du lieu giao dich da ky hop le:
- ECDSA (secp256k1)
- RSA-2048 (PKCS#1 v1.5)
- ML-DSA-44 (NIST FIPS 204 Post-Quantum)
Ho tro so luong linh hoat: 500 txs (Baseline) va 3,000 txs (Stress Test & OOM Hunt)
"""

import binascii
import json
import os
import sys
import time
from collections import OrderedDict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
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


def generate_ecdsa_transactions(n: int = 3000) -> list:
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


def generate_rsa_transactions(n: int = 1000) -> list:
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
            ('value', "1.0"),
            ('nonce', str(i))
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


def generate_mldsa_transactions(n: int = 3000) -> list:
    if not OQS_AVAILABLE:
        print("[!] Can chay qua Docker de co thu vien liboqs sinh ML-DSA-44")
        return []
    print(f"[*] Dang sinh {n} giao dich Hau luong tu ML-DSA-44 (NIST FIPS 204)...")
    recipient_hex = "4d67538820a505b42abfa966b3c652ab041535045ab791dbc33711df832f428c453406314349fc98c4448c1e4b4ad85d049009bda5a29e66f7d26006403b6aae"

    txs = []
    with oqs.Signature('ML-DSA-44') as signer:
        pub_bytes = signer.generate_keypair()
        pub_hex = pub_bytes.hex()
        for i in range(1, n + 1):
            tx_dict = OrderedDict([
                ('sender_address', pub_hex),
                ('recipient_address', recipient_hex),
                ('value', "1.0"),
                ('nonce', str(i))
            ])
            sig_bytes = signer.sign(str(tx_dict).encode('utf-8'))
            txs.append({
                'sender_address': pub_hex,
                'recipient_address': recipient_hex,
                'amount': "1.0",
                'nonce': i,
                'signature': sig_bytes.hex(),
                'algorithm': 'ML-DSA-44'
            })
    print(f"    -> Da sinh xong {len(txs)} txs ML-DSA-44. Size: PK={len(pub_hex)//2}B, Sig={len(txs[0]['signature'])//2}B")
    return txs


def main():
    data_dir = BASE_DIR / "benchmarks" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    # 1. Dataset 500 txs cho Thi nghiem A (Baseline)
    ecdsa_all = generate_ecdsa_transactions(3000)
    with open(data_dir / "txs_500_ecdsa.json", "w", encoding="utf-8") as f:
        json.dump(ecdsa_all[:500], f, indent=2)
    with open(data_dir / "txs_3000_ecdsa.json", "w", encoding="utf-8") as f:
        json.dump(ecdsa_all, f, indent=2)

    rsa_all = generate_rsa_transactions(1000)
    with open(data_dir / "txs_500_rsa.json", "w", encoding="utf-8") as f:
        json.dump(rsa_all[:500], f, indent=2)

    if OQS_AVAILABLE:
        mldsa_all = generate_mldsa_transactions(3000)
        with open(data_dir / "txs_500_mldsa.json", "w", encoding="utf-8") as f:
            json.dump(mldsa_all[:500], f, indent=2)
        with open(data_dir / "txs_3000_mldsa.json", "w", encoding="utf-8") as f:
            json.dump(mldsa_all, f, indent=2)

    # Cap nhat wallets.json voi cac sender moi co so du 500,000 COIN
    wallets_path = BASE_DIR / "configs" / "wallets.json"
    wallets = {}
    if wallets_path.exists():
        with open(wallets_path, "r", encoding="utf-8") as f:
            wallets = json.load(f)

    wallets["Perf_ECDSA"] = {
        "name": "Perf_ECDSA",
        "initial_balance": 500000.0,
        "public_key": ecdsa_all[0]['sender_address'],
        "private_key": ""
    }
    wallets["Perf_RSA"] = {
        "name": "Perf_RSA",
        "initial_balance": 500000.0,
        "public_key": rsa_all[0]['sender_address'],
        "private_key": ""
    }
    if OQS_AVAILABLE and mldsa_all:
        wallets["Perf_MLDSA"] = {
            "name": "Perf_MLDSA",
            "initial_balance": 500000.0,
            "public_key": mldsa_all[0]['sender_address'],
            "private_key": ""
        }

    with open(wallets_path, "w", encoding="utf-8") as f:
        json.dump(wallets, f, indent=2)

    print("\n[+] Hoan tat tao du lieu mo rong cho Thi nghiem A (500 txs) va Thi nghiem B (Stress Test 3000 txs)!")


if __name__ == '__main__':
    main()
