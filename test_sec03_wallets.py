"""Regression test for variant-specific wallet provisioning and funding."""

import hashlib
import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from sec03_wallets import provision_mldsa_wallets
import run_all_attacks


class FakeSignature:
    sizes = {"ML-DSA-65": (1952, 4032), "ML-DSA-87": (2592, 4896)}
    counter = 0

    def __init__(self, algorithm, secret_key=None):
        self.algorithm = algorithm
        self.secret_key = secret_key

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def generate_keypair(self):
        type(self).counter += 1
        token = type(self).counter.to_bytes(16, "big")
        public_size, private_size = self.sizes[self.algorithm]
        self.secret_key = token + bytes(private_size - len(token))
        return token + bytes(public_size - len(token))

    def export_secret_key(self):
        return self.secret_key

    def sign(self, message):
        return hashlib.sha256(self.secret_key[:16] + message).digest()

    def verify(self, message, signature, public_key):
        return signature == hashlib.sha256(
            public_key[:16] + message
        ).digest()


class WalletProvisioningTest(unittest.TestCase):
    def test_replaces_mldsa44_keys_and_reuses_valid_wallets(self):
        fake_oqs = types.SimpleNamespace(Signature=FakeSignature)
        for algorithm, public_bytes in (("ML-DSA-65", 1952),
                                        ("ML-DSA-87", 2592)):
            with self.subTest(algorithm=algorithm), \
                    tempfile.TemporaryDirectory() as directory, \
                    patch.dict(sys.modules, {"oqs": fake_oqs}):
                project = Path(directory)
                configs = project / "configs"
                configs.mkdir()
                wallets_path = configs / "wallets.json"
                wallets_path.write_text(json.dumps({
                    "Alice": {"name": "Alice", "initial_balance": 100,
                              "public_key": "ab" * 1312,
                              "private_key": "cd" * 2560}
                }), encoding="utf-8")

                first = provision_mldsa_wallets(project, algorithm)
                self.assertTrue(first["generated"])
                self.assertEqual(first["public_key_bytes"], public_bytes)
                self.assertGreaterEqual(first["balance"], 22)
                self.assertTrue(
                    (configs / "wallets.json.sec03.bak").is_file()
                )
                wallets = json.loads(wallets_path.read_text(encoding="utf-8"))
                self.assertEqual(len(wallets), 4)
                self.assertEqual(
                    wallets, json.loads(
                        (configs / "wallets_mldsa.json").read_text(encoding="utf-8")
                    )
                )

                second = provision_mldsa_wallets(project, algorithm)
                self.assertFalse(second["generated"])
                self.assertEqual(first["sender_address"],
                                 second["sender_address"])

                wallets["Alice"]["initial_balance"] = 1
                wallets_path.write_text(json.dumps(wallets), encoding="utf-8")
                third = provision_mldsa_wallets(project, algorithm)
                self.assertFalse(third["generated"])
                self.assertTrue(third["funded"])
                self.assertEqual(third["balance"], 100)
                self.assertEqual(first["sender_address"],
                                 third["sender_address"])

    def test_balance_check_uses_full_public_key_on_every_node(self):
        public_key = "ab" * 2592

        class FakeOpener:
            def open(self, url, timeout):
                body = json.dumps({"balances": [{
                    "address": public_key,
                    "available_balance": 100.0,
                }]}).encode("utf-8")
                return io.BytesIO(body)

        with patch.object(run_all_attacks, "OPENER", FakeOpener()):
            result = run_all_attacks.wait_funded(
                [5000, 5001, 5002], public_key, timeout=0.1
            )
        self.assertEqual(result, {5000: 100.0, 5001: 100.0,
                                  5002: 100.0})

        class TruncatedOpener:
            def open(self, url, timeout):
                body = json.dumps({"balances": [{
                    "address": public_key[:64],
                    "available_balance": 100.0,
                }]}).encode("utf-8")
                return io.BytesIO(body)

        with patch.object(run_all_attacks, "OPENER", TruncatedOpener()):
            with self.assertRaisesRegex(RuntimeError, "/accounts/balance"):
                run_all_attacks.wait_funded(
                    [5000], public_key, timeout=0.01
                )


if __name__ == "__main__":
    unittest.main()
