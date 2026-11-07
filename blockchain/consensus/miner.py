"""
Miner & Consensus Engine
Trách nhiệm:
- Quản lý cơ chế đồng thuận Proof-of-Work (PoW)
- Hỗ trợ Auto-Mining tự động gom khối (Batching: 10 hoặc 20 giao dịch / block)
- Hỗ trợ cơ chế Flush vét Mempool khi mạng dừng nhận giao dịch mới
- Đóng gói Block và phát sóng Block qua mạng P2P WebSocket
"""

import os
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
    def __init__(
        self,
        ledger: BlockchainLedger,
        network: P2PNetwork,
        auto_mine: bool = False,
        check_interval: float = 2.0,
        audit_logger: AuditLogger = None,
        batch_size: int = 10
    ):
        self.ledger = ledger
        self.network = network
        self.auto_mine = auto_mine
        self.check_interval = check_interval
        try:
            self.batch_size = int(os.environ.get("BLOCKCHAIN_BATCH_SIZE", batch_size))
        except (ValueError, TypeError):
            self.batch_size = batch_size
        self.audit = audit_logger or (ledger.audit if hasattr(ledger, 'audit') else AuditLogger())
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def proof_of_work(self, candidate_txs: list) -> int:
        last_block = self.ledger.get_last_block()
        last_hash = calculate_block_hash(last_block)

        self.audit.log(
            category="MINER",
            title=f"Bat dau giai Proof-of-Work (Do kho: {self.ledger.difficulty} zeros)",
            details={'transactions_in_block': len(candidate_txs), 'previous_hash': f"{last_hash[:16]}..."},
            status="INFO"
        )

        nonce = 0
        while not Block.valid_proof(candidate_txs, last_hash, nonce, self.ledger.difficulty):
            nonce += 1

        self.audit.log(
            category="MINER",
            title=f"Khai thac thanh cong! Tim thay Nonce hop le: {nonce}",
            details={'nonce': nonce, 'difficulty': self.ledger.difficulty},
            status="SUCCESS"
        )
        return nonce

    def mine_block(self, max_txs: int = None) -> Optional[dict]:
        if max_txs is None:
            max_txs = self.batch_size

        reward_tx = Transaction(
            sender_address=self.ledger.mining_sender,
            recipient_address=self.ledger.node_id,
            value=str(self.ledger.mining_reward),
            signature=""
        )
        self.ledger.submit_transaction(reward_tx)

        with self.ledger.lock:
            txs_to_mine = list(self.ledger.transactions[:max_txs])

        txs_for_pow = [tx for tx in txs_to_mine if tx.get('sender_address') != self.ledger.mining_sender]
        nonce = self.proof_of_work(txs_for_pow)

        last_block = self.ledger.get_last_block()
        previous_hash = calculate_block_hash(last_block)
        block = self.ledger.create_block(nonce, previous_hash, max_txs=max_txs)

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
        """
        Luồng ngầm tự động đào gom giao dịch:
        - Gom block khi Mempool đạt đủ batch_size (ví dụ 10 hoặc 20 giao dịch).
        - Tự động flush vét các giao dịch còn lại sau 4 giây idle.
        """
        last_mempool_change = time.time()
        prev_count = 0

        while self._running:
            try:
                mempool = self.ledger.get_mempool()
                user_txs = [tx for tx in mempool if tx.get('sender_address') != self.ledger.mining_sender]
                curr_count = len(user_txs)

                if curr_count != prev_count:
                    last_mempool_change = time.time()
                    prev_count = curr_count

                should_mine = False
                reason = ""
                if curr_count >= self.batch_size:
                    should_mine = True
                    reason = f"Mempool dat nguong gom khoi ({curr_count}/{self.batch_size} txs)"
                elif curr_count > 0 and (time.time() - last_mempool_change) >= 4.0:
                    should_mine = True
                    reason = f"Flush vet Mempool ({curr_count} txs sau 4s idle)"

                if should_mine:
                    self.audit.log(
                        category="MINER",
                        title=f"Kich hoat dong Block tu dong: {reason}",
                        details={'user_tx_count': curr_count, 'batch_size': self.batch_size},
                        status="INFO"
                    )
                    self.mine_block(max_txs=self.batch_size)
                    last_mempool_change = time.time()
                    prev_count = len([tx for tx in self.ledger.get_mempool() if tx.get('sender_address') != self.ledger.mining_sender])
            except Exception:
                pass

            time.sleep(self.check_interval)
