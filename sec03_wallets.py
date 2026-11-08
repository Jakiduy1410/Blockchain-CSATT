#!/usr/bin/env python3
"""Provision funded, algorithm-matched sample wallets before SEC-03 nodes start.

The prototype ledger reads configs/wallets.json once at startup. Funding here
sets its test genesis balances; it does not expose an unauthenticated faucet.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import uuid
from pathlib import Path


PUBLIC_KEY_BYTES = {"ML-DSA-65": 1952, "ML-DSA-87": 2592}
DEFAULT_BALANCES = {"Alice": 100.0, "Bob": 50.0,
                    "Charlie": 30.0, "Dave": 10.0}
PAIR_PROBE = b"SEC-03 wallet key-pair validation v1"


def _generate_pair(oqs, algorithm):
    with oqs.Signature(algorithm) as signer:
        public_key = bytes(signer.generate_keypair())
        private_key = bytes(signer.export_secret_key())
    return public_key, private_key


def _matching_pair(oqs, algorithm, record, public_size, private_size):
    if not isinstance(record, dict):
        return False
    try:
        public_key = bytes.fromhex(record["public_key"])
        private_key = bytes.fromhex(record["private_key"])
        balance = float(record["initial_balance"])
        if (len(public_key) != public_size
                or len(private_key) != private_size
                or not math.isfinite(balance) or balance < 0):
            return False
        with oqs.Signature(algorithm, secret_key=private_key) as signer:
            signature = signer.sign(PAIR_PROBE)
        with oqs.Signature(algorithm) as verifier:
            return bool(verifier.verify(PAIR_PROBE, signature, public_key))
    except Exception:
        return False


def _atomic_json(path, data):
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _backup_once(path):
    if path.is_file():
        backup = path.with_name(path.name + ".sec03.bak")
        if not backup.exists():
            shutil.copy2(path, backup)


def fund_test_wallet(wallets, name="Alice", minimum=22.0):
    """Set the prototype ledger's startup balance for an existing test key."""
    current = float(wallets[name]["initial_balance"])
    if not math.isfinite(current) or current < minimum:
        wallets[name]["initial_balance"] = DEFAULT_BALANCES[name]
        return True
    return False


def provision_mldsa_wallets(project: Path, algorithm: str):
    """Reuse valid keys or generate the correct variant; fund before node boot."""
    if algorithm not in PUBLIC_KEY_BYTES:
        raise ValueError(f"Unsupported provisioning algorithm: {algorithm}")
    try:
        import oqs
    except ImportError as exc:
        raise RuntimeError("Cần oqs/liboqs để tạo ví ML-DSA") from exc

    project = Path(project)
    config_dir = project / "configs"
    wallet_path = config_dir / "wallets.json"
    mirror_path = config_dir / "wallets_mldsa.json"
    sample_public, sample_private = _generate_pair(oqs, algorithm)
    public_size, private_size = len(sample_public), len(sample_private)
    if public_size != PUBLIC_KEY_BYTES[algorithm]:
        raise RuntimeError(
            f"liboqs {algorithm} returned {public_size} public-key bytes; "
            f"expected {PUBLIC_KEY_BYTES[algorithm]}"
        )

    try:
        wallets = json.loads(wallet_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        wallets = None
    valid = (
        isinstance(wallets, dict)
        and all(
            _matching_pair(oqs, algorithm, wallets.get(name),
                           public_size, private_size)
            for name in DEFAULT_BALANCES
        )
        and len({wallets[name]["public_key"] for name in DEFAULT_BALANCES}) == 4
    )

    generated = not valid
    if generated:
        wallets = {}
        for index, (name, balance) in enumerate(DEFAULT_BALANCES.items()):
            public_key, private_key = (
                (sample_public, sample_private) if index == 0
                else _generate_pair(oqs, algorithm)
            )
            wallets[name] = {
                "name": name,
                "initial_balance": balance,
                "public_key": public_key.hex(),
                "private_key": private_key.hex(),
            }

    funded = fund_test_wallet(wallets)
    # Only the active config is read by the ledger. Keep the historical
    # wallets_mldsa.json mirror in sync for the sample-wallet tooling.
    if generated or funded:
        _backup_once(wallet_path)
        _atomic_json(wallet_path, wallets)
    try:
        mirror = json.loads(mirror_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        mirror = None
    if mirror != wallets:
        _backup_once(mirror_path)
        _atomic_json(mirror_path, wallets)

    sender_address = wallets["Alice"]["public_key"]
    return {
        "algorithm": algorithm,
        "generated": generated,
        "funded": generated or funded,
        "balance": float(wallets["Alice"]["initial_balance"]),
        "public_key_bytes": public_size,
        "private_key_bytes": private_size,
        "public_key_sha256": hashlib.sha256(
            bytes.fromhex(sender_address)
        ).hexdigest(),
        "sender_address": sender_address,
    }
