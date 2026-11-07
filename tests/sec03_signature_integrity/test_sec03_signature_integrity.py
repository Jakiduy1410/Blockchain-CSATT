"""
Unit & Integration Tests for SEC-03: Signature Integrity, Anti-Malleability & Replay Defense
Verifies bit-flipping rejection, payload tampering rejection, and nonce-based replay attack rejection.
"""

import copy
import random
import unittest
from collections import OrderedDict

import ecdsa
from blockchain.core.ledger import BlockchainLedger
from blockchain.core.transaction import Transaction
from blockchain.core.crypto import verify_ecdsa_signature, verify_mldsa_signature


class TestSec03SignatureIntegrity(unittest.TestCase):
    def setUp(self):
        self.ledger = BlockchainLedger(difficulty=1, mining_reward=1.0)
        self.sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.vk = self.sk.verifying_key
        self.sender_pub = self.vk.to_string().hex()
        self.recipient_pub = "0" * 128
        self.ledger.initial_balances[self.sender_pub] = 1000.0

    def _create_signed_tx(self, amount: str, nonce: int):
        ordered_tx = OrderedDict([
            ('sender_address', self.sender_pub),
            ('recipient_address', self.recipient_pub),
            ('value', str(amount)),
            ('nonce', str(nonce))
        ])
        sig = self.sk.sign(str(ordered_tx).encode('utf-8'))
        return {
            'sender_address': self.sender_pub,
            'recipient_address': self.recipient_pub,
            'value': str(amount),
            'nonce': nonce,
            'signature': sig.hex()
        }

    def test_bit_flipping_attack_rejection(self):
        """SEC-03: Bit-flipping on signature bytes must be rejected 100% of the time."""
        base_tx = self._create_signed_tx(amount="10.0", nonce=1)
        sig_bytes = bytearray(bytes.fromhex(base_tx['signature']))

        rng = random.Random(42)
        total_trials = 100
        rejected_count = 0

        for _ in range(total_trials):
            tampered_sig = bytearray(sig_bytes)
            # Flip a random bit in a random byte
            byte_idx = rng.randrange(len(tampered_sig))
            bit_idx = rng.randrange(8)
            tampered_sig[byte_idx] ^= (1 << bit_idx)

            tampered_tx = copy.deepcopy(base_tx)
            tampered_tx['signature'] = tampered_sig.hex()

            is_valid = verify_ecdsa_signature(
                tampered_tx['sender_address'],
                tampered_tx['signature'],
                tampered_tx
            )
            if not is_valid:
                rejected_count += 1

        self.assertEqual(rejected_count, total_trials, "Bit-flipping must be rejected in 100% of trials")

    def test_payload_mutation_attack_rejection(self):
        """SEC-03: Modifying recipient or amount while retaining signature must be rejected 100%."""
        base_tx = self._create_signed_tx(amount="10.0", nonce=1)

        # 1. Tamper amount
        tx_tampered_amount = copy.deepcopy(base_tx)
        tx_tampered_amount['value'] = "1000000.0"
        self.assertFalse(verify_ecdsa_signature(
            tx_tampered_amount['sender_address'],
            tx_tampered_amount['signature'],
            tx_tampered_amount
        ), "Tampered amount with original signature must be rejected")

        # 2. Tamper recipient
        tx_tampered_recipient = copy.deepcopy(base_tx)
        tx_tampered_recipient['recipient_address'] = "f" * 128
        self.assertFalse(verify_ecdsa_signature(
            tx_tampered_recipient['sender_address'],
            tx_tampered_recipient['signature'],
            tx_tampered_recipient
        ), "Tampered recipient with original signature must be rejected")

    def test_replay_attack_rejection(self):
        """SEC-03: Replaying the same transaction/nonce must be rejected 100% by the ledger."""
        tx_data = self._create_signed_tx(amount="5.0", nonce=1)
        tx_obj = Transaction(
            sender_address=tx_data['sender_address'],
            recipient_address=tx_data['recipient_address'],
            value=tx_data['value'],
            signature=tx_data['signature'],
            nonce=tx_data['nonce']
        )

        # 1. First submission succeeds into mempool
        first_success = self.ledger.submit_transaction(tx_obj)
        self.assertTrue(first_success, "First valid transaction submission must succeed")
        self.assertEqual(len(self.ledger.transactions), 1)

        # In mempool: replaying the same tx does not duplicate it
        for _ in range(5):
            self.ledger.submit_transaction(tx_obj)
            self.assertEqual(len(self.ledger.transactions), 1, "Mempool must not duplicate identical transactions")

        # 2. Mine the transaction into chain
        from blockchain.core.crypto import calculate_block_hash
        last_block = self.ledger.get_last_block()
        prev_hash = calculate_block_hash(last_block)
        self.ledger.create_block(nonce=12345, previous_hash=prev_hash)
        self.assertEqual(len(self.ledger.transactions), 0)

        # 3. Post-mining replay: must be rejected with False 100% of the time
        for i in range(10):
            replay_success = self.ledger.submit_transaction(tx_obj)
            self.assertFalse(replay_success, f"Replay attempt #{i + 1} must be rejected with False")


if __name__ == "__main__":
    unittest.main()
