"""Regression coverage for tip/mempool changes while solving Proof of Work."""
import unittest
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock

import ecdsa

from blockchain.consensus.miner import Miner
from blockchain.core.block import Block
from blockchain.core.crypto import calculate_block_hash
from blockchain.core.ledger import BlockchainLedger
from blockchain.core.transaction import Transaction


class MiningRaceTests(unittest.TestCase):
    def setUp(self):
        self.ledger = BlockchainLedger(difficulty=1)
        self.network = SimpleNamespace(broadcast_block=Mock())
        self.miner = Miner(self.ledger, self.network)
        self.key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.pub = self.key.verifying_key.to_string().hex()
        self.ledger.initial_balances[self.pub] = 100

    def tx(self, nonce):
        data = OrderedDict([
            ('sender_address', self.pub), ('recipient_address', 'recipient'),
            ('value', '0.01'), ('nonce', str(nonce))
        ])
        return Transaction(self.pub, 'recipient', '0.01',
                           self.key.sign(str(data).encode()).hex(), nonce)

    def assert_valid(self, block):
        txs = [tx for tx in block['transactions']
               if tx['sender_address'] != self.ledger.mining_sender]
        self.assertTrue(Block.valid_proof(txs, block['previous_hash'],
                                         block['nonce'], self.ledger.difficulty))
        self.assertTrue(self.ledger.valid_chain(self.ledger.get_chain()))

    def test_new_transaction_during_pow_stays_pending(self):
        first, later = self.tx(1), self.tx(2)
        self.assertTrue(self.ledger.submit_transaction(first))
        solve = self.miner.proof_of_work

        def solve_and_receive(*args):
            nonce = solve(*args)
            self.assertTrue(self.ledger.submit_transaction(later))
            return nonce

        self.miner.proof_of_work = solve_and_receive
        block = self.miner.mine_block()
        self.assert_valid(block)
        self.assertIn(first.to_full_dict(), block['transactions'])
        self.assertNotIn(later.to_full_dict(), block['transactions'])
        self.assertEqual(self.ledger.transactions, [later.to_full_dict()])
        peer = BlockchainLedger(difficulty=1)
        peer.initial_balances[self.pub] = 100
        self.assertTrue(peer.append_block(block))

    def test_peer_block_during_pow_restarts_with_new_parent(self):
        self.ledger.submit_transaction(self.tx(1))
        peer = BlockchainLedger(difficulty=1)
        peer_block = Miner(peer, self.network).mine_block()
        solve = self.miner.proof_of_work
        attempts = []

        def solve_and_receive(*args):
            nonce = solve(*args)
            attempts.append(args[1])
            if len(attempts) == 1:
                self.assertTrue(self.ledger.append_block(peer_block))
            return nonce

        self.miner.proof_of_work = solve_and_receive
        block = self.miner.mine_block()
        self.assertEqual(len(attempts), 2)
        self.assertEqual(block['previous_hash'], calculate_block_hash(peer_block))
        self.assertEqual(block['block_number'], 3)
        self.assert_valid(block)

    def test_removed_pending_transaction_restarts_candidate(self):
        self.ledger.submit_transaction(self.tx(1))
        solve = self.miner.proof_of_work
        calls = []

        def solve_and_remove(*args):
            nonce = solve(*args)
            calls.append(1)
            if len(calls) == 1:
                with self.ledger.lock:
                    self.ledger.transactions.clear()
            return nonce

        self.miner.proof_of_work = solve_and_remove
        block = self.miner.mine_block()
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(block['transactions']), 1)
        self.assert_valid(block)

    def test_invalid_pow_does_not_change_chain_or_mempool(self):
        self.ledger.submit_transaction(self.tx(1))
        tip = calculate_block_hash(self.ledger.chain[-1])
        pending = self.ledger.get_mempool()
        nonce = 0
        while Block.valid_proof(pending, tip, nonce, self.ledger.difficulty):
            nonce += 1
        with self.assertRaises(ValueError):
            self.ledger.create_block(nonce, tip)
        self.assertEqual(len(self.ledger.chain), 1)
        self.assertEqual(self.ledger.get_mempool(), pending)

    def test_stale_parent_does_not_consume_pending(self):
        self.ledger.submit_transaction(self.tx(1))
        pending = self.ledger.get_mempool()
        self.assertIsNone(self.ledger.create_block(0, 'stale-parent'))
        self.assertEqual(self.ledger.get_mempool(), pending)
        self.assertEqual(len(self.ledger.chain), 1)

    def test_two_local_mining_calls_produce_valid_chain(self):
        self.ledger.submit_transaction(self.tx(1))
        with ThreadPoolExecutor(max_workers=2) as pool:
            blocks = list(pool.map(lambda _: self.miner.mine_block(), range(2)))
        self.assertEqual(sorted(b['block_number'] for b in blocks), [2, 3])
        for block in blocks:
            self.assert_valid(block)
            self.assertEqual(sum(tx['sender_address'] == self.ledger.mining_sender
                                 for tx in block['transactions']), 1)

    def test_real_mldsa_block_accepted_by_peer(self):
        import oqs
        with oqs.Signature('ML-DSA-44') as signer:
            pub = signer.generate_keypair().hex()
            data = OrderedDict([
                ('sender_address', pub), ('recipient_address', 'recipient'),
                ('value', '0.01')
            ])
            signature = signer.sign(str(data).encode()).hex()
        self.ledger.initial_balances[pub] = 100
        tx = Transaction(pub, 'recipient', '0.01', signature, 1)
        self.assertTrue(self.ledger.submit_transaction(tx))
        block = self.miner.mine_block()
        self.assert_valid(block)
        peer = BlockchainLedger(difficulty=1)
        peer.initial_balances[pub] = 100
        self.assertTrue(peer.append_block(block))


if __name__ == '__main__':
    unittest.main()
