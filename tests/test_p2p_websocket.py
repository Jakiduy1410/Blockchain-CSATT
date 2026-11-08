"""
Unit Tests: Kiểm thử Tầng Giao vận WebSocket P2P bọc TLS (ECDHE)
Xác thực Gossip giao dịch và Broadcast khối theo thời gian thực giữa 2 Node
"""

import os
import sys
import time
import unittest
from collections import OrderedDict

# Thêm project root vào sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from blockchain.core.ledger import BlockchainLedger
from blockchain.core.transaction import Transaction
from blockchain.network.p2p import P2PNetwork


class TestP2PWebSocket(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Tạo cặp khóa ECDSA cho Alice và Bob qua C OpenSSL
        cls.alice_sk = ec.generate_private_key(ec.SECP256K1())
        pub_a = cls.alice_sk.public_key().public_numbers()
        cls.alice_pub = f"{pub_a.x:064x}{pub_a.y:064x}"

        cls.bob_sk = ec.generate_private_key(ec.SECP256K1())
        pub_b = cls.bob_sk.public_key().public_numbers()
        cls.bob_pub = f"{pub_b.x:064x}{pub_b.y:064x}" 

    def setUp(self):
        # Node 1: HTTP 5080, WebSocket 6080
        self.ledger1 = BlockchainLedger(difficulty=1)
        self.ledger1.initial_balances[self.alice_pub] = 100.0
        self.net1 = P2PNetwork(ledger=self.ledger1, my_address="127.0.0.1:5080", ws_port=6080)

        # Node 2: HTTP 5081, WebSocket 6081
        self.ledger2 = BlockchainLedger(difficulty=1)
        self.ledger2.initial_balances[self.alice_pub] = 100.0
        self.net2 = P2PNetwork(ledger=self.ledger2, my_address="127.0.0.1:5081", ws_port=6081)

        # Đăng ký peer chéo giữa Node 1 và Node 2
        self.net1.register_peer("127.0.0.1:5081")
        self.net2.register_peer("127.0.0.1:5080")

        # Chờ 1.5 giây để đường ống WebSocket Persistent TLS kết nối thành công
        time.sleep(1.5)

    def tearDown(self):
        self.net1.stop()
        self.net2.stop()
        time.sleep(0.3)

    def _sign_tx(self, sk, sender, recipient, value, nonce):
        d = OrderedDict([
            ('sender_address', sender),
            ('recipient_address', recipient),
            ('value', str(value)),
            ('nonce', str(nonce))
        ])
        der = sk.sign(str(d).encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        return Transaction(sender, recipient, str(value), sig.hex(), nonce=nonce)

    def test_p2p_gossip_transaction_over_websocket(self):
        """1. Gửi giao dịch vào Node 1 -> Tự động Gossip qua WebSocket sang Mempool Node 2"""
        tx = self._sign_tx(self.alice_sk, self.alice_pub, self.bob_pub, 15.0, nonce=1)

        # Gửi vào Node 1
        gossiped = self.net1.gossip_transaction(tx)
        self.assertTrue(gossiped)
        self.assertEqual(len(self.ledger1.transactions), 1)

        # Chờ tối đa 2 giây để nhận gói tin qua WebSocket
        received = False
        for _ in range(20):
            time.sleep(0.1)
            if len(self.ledger2.transactions) >= 1:
                received = True
                break

        self.assertTrue(received, "Mempool Node 2 khong nhan duoc giao dich qua WebSocket!")
        self.assertEqual(self.ledger2.transactions[0]['value'], '15.0')
        self.assertEqual(self.ledger2.transactions[0]['nonce'], 1)

    def test_p2p_broadcast_block_over_websocket(self):
        """2. Node 2 đào Block mới -> Tự động Broadcast qua WebSocket sang chuỗi của Node 1"""
        # Node 2 tạo block
        last_block = self.ledger2.get_last_block()
        from blockchain.core.crypto import calculate_block_hash
        from blockchain.core.block import Block

        prev_hash = calculate_block_hash(last_block)
        coinbase = {
            'sender_address': self.ledger2.mining_sender,
            'recipient_address': self.bob_pub,
            'value': '1.0',
            'nonce': 0,
            'signature': ''
        }
        self.ledger2.submit_transaction(Transaction.from_dict(coinbase))
        nonce = 0
        while not Block.valid_proof([], prev_hash, nonce, self.ledger2.difficulty):
            nonce += 1

        new_block = self.ledger2.create_block(nonce=nonce, previous_hash=prev_hash)
        self.assertEqual(len(self.ledger2.chain), 2)

        # Node 2 broadcast qua WebSocket
        self.net2.broadcast_block(new_block)

        # Chờ Node 1 nhận block
        synced = False
        for _ in range(20):
            time.sleep(0.1)
            if len(self.ledger1.chain) >= 2:
                synced = True
                break

        self.assertTrue(synced, "Node 1 khong nhan duoc Block qua WebSocket Broadcast!")
        self.assertEqual(self.ledger1.chain[-1]['block_number'], 2)


if __name__ == '__main__':
    unittest.main()
