"""
Block Model & Proof-of-Work Verification
"""

from collections import OrderedDict
from typing import List, Dict

try:
    from .crypto import calculate_block_hash, calculate_sha256
except ImportError:
    from crypto import calculate_block_hash, calculate_sha256


class Block:
    def __init__(self, block_number: int, timestamp: float, transactions: List[Dict], nonce: int, previous_hash: str):
        self.block_number = block_number
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.previous_hash = previous_hash

    def to_dict(self) -> dict:
        return {
            'block_number': self.block_number,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'nonce': self.nonce,
            'previous_hash': self.previous_hash
        }

    def hash(self) -> str:
        return calculate_block_hash(self.to_dict())

    @staticmethod
    def valid_proof(transactions: List[Dict], previous_hash: str, nonce: int, difficulty: int) -> bool:
        transaction_elements = ['sender_address', 'recipient_address', 'value']
        ordered_txs = []
        for tx in transactions:
            ordered_tx = OrderedDict((k, tx[k]) for k in transaction_elements if k in tx)
            ordered_txs.append(ordered_tx)

        guess = (str(ordered_txs) + str(previous_hash) + str(nonce)).encode('utf-8')
        guess_hash = calculate_sha256(guess.decode('utf-8', errors='ignore'))
        return guess_hash.startswith('0' * difficulty)
