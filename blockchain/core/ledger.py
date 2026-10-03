"""
Ledger & Blockchain State Manager
"""

import threading
from time import time
from typing import List, Dict, Optional
from uuid import uuid4

try:
    from .block import Block
    from .crypto import calculate_block_hash
    from .transaction import Transaction
    from .audit import AuditLogger
except ImportError:
    from block import Block
    from crypto import calculate_block_hash
    from transaction import Transaction
    from audit import AuditLogger


class BlockchainLedger:
    def __init__(self, difficulty: int = 2, mining_reward: float = 1.0, mining_sender: str = "THE BLOCKCHAIN", audit_logger: AuditLogger = None):
        self.chain: List[dict] = []
        self.transactions: List[dict] = []
        self.difficulty = difficulty
        self.mining_reward = mining_reward
        self.mining_sender = mining_sender
        self.audit = audit_logger or AuditLogger()

        self.node_id = str(uuid4()).replace('-', '')
        self.lock = threading.Lock()
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis = {
            'block_number': 1,
            'timestamp': time(),
            'transactions': [],
            'nonce': 0,
            'previous_hash': '00'
        }
        self.chain.append(genesis)
        self.audit.log(
            category="CONSENSUS",
            title="Khoi tao Genesis Block #1",
            details={'hash': '00', 'status': 'GENESIS_INITIALIZED'},
            status="SUCCESS"
        )

    def submit_transaction(self, tx: Transaction) -> bool:
        with self.lock:
            # 1. Thẩm định chữ ký số RSA PKCS#1 v1.5
            is_valid = tx.is_valid(self.mining_sender)
            if not is_valid:
                self.audit.log(
                    category="CRYPTO",
                    title="Tu choi giao dich: Chu ky RSA PKCS#1 v1.5 KHONG HOP LE",
                    details={
                        'sender': f"{tx.sender_address[:20]}...",
                        'amount': tx.value,
                        'signature_preview': f"{tx.signature[:24]}..." if tx.signature else "None"
                    },
                    status="FAILED"
                )
                return False

            # Ghi log kiểm toán mật mã thành công
            self.audit.log(
                category="CRYPTO",
                title="Xac thuc chu ky RSA PKCS#1 v1.5: THANH CONG (VERIFIED)",
                details={
                    'sender_pubkey': f"{tx.sender_address[:24]}...",
                    'recipient': f"{tx.recipient_address[:24]}...",
                    'amount': f"{tx.value} COIN",
                    'signature_algorithm': 'SHA1withRSA-PKCS1v15'
                },
                status="SUCCESS"
            )

            # 2. Kiểm tra trùng lặp trong Mempool
            for existing_tx in self.transactions:
                if existing_tx.get('sender_address') == tx.sender_address and \
                   existing_tx.get('recipient_address') == tx.recipient_address and \
                   existing_tx.get('value') == tx.value and \
                   existing_tx.get('signature') == tx.signature:
                    return True

            # 3. Đưa vào Mempool
            self.transactions.append(tx.to_full_dict())
            self.audit.log(
                category="MEMPOOL",
                title=f"Them giao dich vao Mempool (Tong: {len(self.transactions)} txs)",
                details={'tx_id': f"{tx.tx_id[:16]}...", 'amount': tx.value},
                status="INFO"
            )
            return True

    def create_block(self, nonce: int, previous_hash: str) -> dict:
        with self.lock:
            block = {
                'block_number': len(self.chain) + 1,
                'timestamp': time(),
                'transactions': list(self.transactions),
                'nonce': nonce,
                'previous_hash': previous_hash
            }

            self.transactions = []
            self.chain.append(block)

            self.audit.log(
                category="CONSENSUS",
                title=f"MERGE BLOCK #{block['block_number']} vao So cai (Local Chain)",
                details={
                    'block_hash': f"{calculate_block_hash(block)[:20]}...",
                    'nonce': nonce,
                    'tx_count': len(block['transactions'])
                },
                status="SUCCESS"
            )
            return block

    def append_block(self, block: dict) -> bool:
        with self.lock:
            last_block = self.chain[-1]

            # Kiểm tra thứ tự block
            if block['block_number'] != len(self.chain) + 1:
                self.audit.log(
                    category="CONSENSUS",
                    title=f"Tu choi Block #{block['block_number']}: Sai thu tu (Hien tai: #{len(self.chain)})",
                    status="FAILED"
                )
                return False

            # Kiểm tra previous_hash
            expected_prev_hash = calculate_block_hash(last_block)
            if block['previous_hash'] != expected_prev_hash:
                self.audit.log(
                    category="CONSENSUS",
                    title="Tu choi Block: previous_hash khong khop voi dinh chuoi!",
                    details={'expected': f"{expected_prev_hash[:16]}...", 'got': f"{block['previous_hash'][:16]}..."},
                    status="FAILED"
                )
                return False

            # Kiểm tra PoW
            txs_to_verify = [tx for tx in block['transactions'] if tx.get('sender_address') != self.mining_sender]
            if not Block.valid_proof(txs_to_verify, block['previous_hash'], block['nonce'], self.difficulty):
                self.audit.log(
                    category="CONSENSUS",
                    title="Tu choi Block: Proof-of-Work khong hop le (Nonce sai)!",
                    status="FAILED"
                )
                return False

            # Block hợp lệ -> MERGE BLOCK
            self.chain.append(block)

            # Dọn dẹp Mempool
            mined_signatures = {
                tx.get('signature') for tx in block['transactions'] if tx.get('signature')
            }
            before_len = len(self.transactions)
            self.transactions = [
                tx for tx in self.transactions if tx.get('signature') not in mined_signatures
            ]
            cleaned_count = before_len - len(self.transactions)

            self.audit.log(
                category="CONSENSUS",
                title=f"MERGE BLOCK #{block['block_number']} tu P2P thanh cong!",
                details={
                    'block_hash': f"{calculate_block_hash(block)[:20]}...",
                    'nonce': block['nonce'],
                    'tx_included': len(block['transactions']),
                    'mempool_cleaned': f"Da giai phong {cleaned_count} giao dich"
                },
                status="SUCCESS"
            )

            return True

    def get_last_block(self) -> dict:
        with self.lock:
            return self.chain[-1]

    def get_chain(self) -> List[dict]:
        with self.lock:
            return list(self.chain)

    def get_mempool(self) -> List[dict]:
        with self.lock:
            return list(self.transactions)

    def valid_chain(self, chain: List[dict]) -> bool:
        if not chain or len(chain) == 0:
            return False

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            if block['previous_hash'] != calculate_block_hash(last_block):
                return False

            txs_to_verify = [tx for tx in block['transactions'] if tx.get('sender_address') != self.mining_sender]
            if not Block.valid_proof(txs_to_verify, block['previous_hash'], block['nonce'], self.difficulty):
                return False

            last_block = block
            current_index += 1

        return True
