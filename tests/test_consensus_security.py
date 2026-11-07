"""
Unit Tests: Kiểm thử Bảo mật Đồng thuận & Chống Replay Attack
"""

import unittest
import sys
import os
from collections import OrderedDict

# Thêm project root vào sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ecdsa
from blockchain.core.ledger import BlockchainLedger
from blockchain.core.transaction import Transaction
from blockchain.core.block import Block
from blockchain.core.crypto import calculate_block_hash


class TestConsensusSecurity(unittest.TestCase):
    def setUp(self):
        self.ledger = BlockchainLedger(difficulty=1, mining_reward=1.0)
        # Tạo cặp khóa ECDSA cho Alice và Bob
        self.alice_sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.alice_vk = self.alice_sk.verifying_key
        self.alice_pub = self.alice_vk.to_string().hex()
        self.alice_priv = self.alice_sk.to_string().hex()

        self.bob_sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.bob_vk = self.bob_sk.verifying_key
        self.bob_pub = self.bob_vk.to_string().hex()
        self.bob_priv = self.bob_sk.to_string().hex()

        # Nạp số dư khởi tạo cho Alice = 50.0 COIN
        self.ledger.initial_balances[self.alice_pub] = 50.0
        self.ledger.wallet_names[self.alice_pub] = "Alice"
        self.ledger.wallet_names[self.bob_pub] = "Bob"

    def _sign_tx(self, sk, sender, recipient, value, nonce):
        d = OrderedDict([
            ('sender_address', sender),
            ('recipient_address', recipient),
            ('value', str(value)),
            ('nonce', str(nonce))
        ])
        sig = sk.sign(str(d).encode('utf-8'))
        return Transaction(sender, recipient, str(value), sig.hex(), nonce=nonce)

    def test_valid_transaction_submission(self):
        """1. Gửi giao dịch hợp lệ kèm nonce -> Chấp nhận vào Mempool"""
        tx = self._sign_tx(self.alice_sk, self.alice_pub, self.bob_pub, 10.0, nonce=1)
        success = self.ledger.submit_transaction(tx)
        self.assertTrue(success)
        self.assertEqual(len(self.ledger.transactions), 1)

    def test_overspending_transaction(self):
        """2. Chi tiêu vượt quá số dư khả dụng (50 COIN) -> Từ chối"""
        tx = self._sign_tx(self.alice_sk, self.alice_pub, self.bob_pub, 100.0, nonce=1)
        success = self.ledger.submit_transaction(tx)
        self.assertFalse(success)
        self.assertEqual(len(self.ledger.transactions), 0)

    def test_replay_attack_prevention(self):
        """3. Tấn công phát lại (Replay Attack) sau khi block đã đào -> Từ chối ngay lập tức"""
        tx1 = self._sign_tx(self.alice_sk, self.alice_pub, self.bob_pub, 10.0, nonce=1)
        self.assertTrue(self.ledger.submit_transaction(tx1))

        # Đào block chứa tx1
        last_block = self.ledger.get_last_block()
        prev_hash = calculate_block_hash(last_block)
        block = self.ledger.create_block(nonce=123, previous_hash=prev_hash)
        self.assertEqual(len(self.ledger.chain), 2)
        self.assertEqual(len(self.ledger.transactions), 0)

        # Kẻ gian copy nguyên xi gói tin tx1 và gửi lại (Replay Attack)
        replay_success = self.ledger.submit_transaction(tx1)
        self.assertFalse(replay_success)

    def test_append_block_with_fake_signature_rejected(self):
        """4. Block chứa giao dịch có chữ ký giả mạo -> append_block từ chối"""
        fake_tx = {
            'sender_address': self.alice_pub,
            'recipient_address': self.bob_pub,
            'value': '10.0',
            'nonce': 1,
            'signature': 'deadbeef' * 16  # Chữ ký rác
        }
        last_block = self.ledger.get_last_block()
        prev_hash = calculate_block_hash(last_block)

        # Tìm nonce hợp lệ cho PoW
        nonce = 0
        while not Block.valid_proof([fake_tx], prev_hash, nonce, self.ledger.difficulty):
            nonce += 1

        bad_block = {
            'block_number': 2,
            'timestamp': 1000.0,
            'transactions': [fake_tx],
            'nonce': nonce,
            'previous_hash': prev_hash
        }
        appended = self.ledger.append_block(bad_block)
        self.assertFalse(appended)
        self.assertEqual(len(self.ledger.chain), 1)

    def test_append_block_with_excessive_coinbase_reward_rejected(self):
        """5. Block có phần thưởng Coinbase > 1.0 COIN -> append_block từ chối"""
        bad_coinbase_tx = {
            'sender_address': self.ledger.mining_sender,
            'recipient_address': self.bob_pub,
            'value': '100.0',  # Vượt quá mining_reward 1.0
            'nonce': 0,
            'signature': ''
        }
        last_block = self.ledger.get_last_block()
        prev_hash = calculate_block_hash(last_block)

        nonce = 0
        while not Block.valid_proof([], prev_hash, nonce, self.ledger.difficulty):
            nonce += 1

        bad_block = {
            'block_number': 2,
            'timestamp': 1000.0,
            'transactions': [bad_coinbase_tx],
            'nonce': nonce,
            'previous_hash': prev_hash
        }
        appended = self.ledger.append_block(bad_block)
        self.assertFalse(appended)
        self.assertEqual(len(self.ledger.chain), 1)

    def test_append_block_with_valid_tx_accepted(self):
        """6. Block có PoW, chữ ký ECDSA và Coinbase hợp lệ -> append_block chấp nhận"""
        tx = self._sign_tx(self.alice_sk, self.alice_pub, self.bob_pub, 5.0, nonce=1)
        coinbase_tx = {
            'sender_address': self.ledger.mining_sender,
            'recipient_address': self.bob_pub,
            'value': '1.0',
            'nonce': 0,
            'signature': ''
        }
        block_txs = [coinbase_tx, tx.to_full_dict()]

        last_block = self.ledger.get_last_block()
        prev_hash = calculate_block_hash(last_block)

        txs_for_pow = [t for t in block_txs if t.get('sender_address') != self.ledger.mining_sender]
        nonce = 0
        while not Block.valid_proof(txs_for_pow, prev_hash, nonce, self.ledger.difficulty):
            nonce += 1

        good_block = {
            'block_number': 2,
            'timestamp': 1000.0,
            'transactions': block_txs,
            'nonce': nonce,
            'previous_hash': prev_hash
        }
        appended = self.ledger.append_block(good_block)
        self.assertTrue(appended)
        self.assertEqual(len(self.ledger.chain), 2)


if __name__ == '__main__':
    unittest.main()
