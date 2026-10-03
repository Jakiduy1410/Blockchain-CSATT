"""
Miner & Consensus Engine
"""

import threading
import time
from typing import Optional

try:
    from ..core.block import Block
    from ..core.crypto import calculate_block_hash
    from ..core.ledger import BlockchainLedger
    from ..core.transaction import Transaction
    from ..network.p2p import P2PNetwork
    from ..core.audit import AuditLogger
except ImportError:
    from core.block import Block
    from core.crypto import calculate_block_hash
    from core.ledger import BlockchainLedger
    from core.transaction import Transaction
    from network.p2p import P2PNetwork
    from core.audit import AuditLogger


class Miner:
    def __init__(self, ledger: BlockchainLedger, network: P2PNetwork, auto_mine: bool = False, check_interval: float = 3.0, audit_logger: AuditLogger = None):
        self.ledger = ledger
        self.network = network
        self.auto_mine = auto_mine
        self.check_interval = check_interval
        self.audit = audit_logger or (ledger.audit if hasattr(ledger, 'audit') else AuditLogger())
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def proof_of_work(self) -> int:
        last_block = self.ledger.get_last_block()
        last_hash = calculate_block_hash(last_block)
        current_txs = self.ledger.get_mempool()

        self.audit.log(
            category="MINER",
            title=f"Bat dau giai Proof-of-Work (Do kho: {self.ledger.difficulty} zeros)",
            details={'transactions_in_pool': len(current_txs), 'previous_hash': f"{last_hash[:16]}..."},
            status="INFO"
        )

        nonce = 0
        while not Block.valid_proof(current_txs, last_hash, nonce, self.ledger.difficulty):
            nonce += 1

        self.audit.log(
            category="MINER",
            title=f"Khai thac thanh cong! Tim thay Nonce hop le: {nonce}",
            details={'nonce': nonce, 'difficulty': self.ledger.difficulty},
            status="SUCCESS"
        )
        return nonce

    def mine_block(self) -> Optional[dict]:
        nonce = self.proof_of_work()

        reward_tx = Transaction(
            sender_address=self.ledger.mining_sender,
            recipient_address=self.ledger.node_id,
            value=str(self.ledger.mining_reward),
            signature=""
        )
        self.ledger.submit_transaction(reward_tx)

        last_block = self.ledger.get_last_block()
        previous_hash = calculate_block_hash(last_block)
        block = self.ledger.create_block(nonce, previous_hash)

        self.network.broadcast_block(block)
        return block

    def start_auto_miner(self):
        if not self.auto_mine or self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._miner_worker_loop, daemon=True)
        self._thread.start()

    def stop_auto_miner(self):
        self._running = False

    def _miner_worker_loop(self):
        while self._running:
            try:
                mempool = self.ledger.get_mempool()
                has_user_tx = any(tx.get('sender_address') != self.ledger.mining_sender for tx in mempool)
                if has_user_tx:
                    self.mine_block()
            except Exception:
                pass

            time.sleep(self.check_interval)
