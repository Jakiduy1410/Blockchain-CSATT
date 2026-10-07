"""
P2P Network Engine
"""

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Set, List
from urllib.parse import urlparse
import requests
import urllib3

# Vô hiệu hóa cảnh báo chứng chỉ tự ký khi chạy mạng nội bộ thử nghiệm
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from ..core.crypto import calculate_block_hash
    from ..core.ledger import BlockchainLedger
    from ..core.transaction import Transaction
    from ..core.audit import AuditLogger
except ImportError:
    from core.crypto import calculate_block_hash
    from core.ledger import BlockchainLedger
    from core.transaction import Transaction
    from core.audit import AuditLogger

logger = logging.getLogger("P2PNetwork")


class P2PNetwork:
    def __init__(self, ledger: BlockchainLedger, my_address: str = "127.0.0.1:5000", audit_logger: AuditLogger = None, use_tls: bool = False):
        self.ledger = ledger
        self.my_address = my_address
        self.use_tls = use_tls
        self.protocol = "https" if use_tls else "http"
        self.peers: Set[str] = set()
        self.audit = audit_logger or (ledger.audit if hasattr(ledger, 'audit') else AuditLogger())

        self.seen_tx_hashes: Set[str] = set()
        self.seen_block_hashes: Set[str] = set()
        self.executor = ThreadPoolExecutor(max_workers=10)

    def register_peer(self, peer_url: str):
        if not peer_url:
            return

        parsed = urlparse(peer_url)
        peer_netloc = parsed.netloc if parsed.netloc else parsed.path
        peer_netloc = peer_netloc.strip().replace("http://", "").replace("https://", "")

        if peer_netloc and peer_netloc != self.my_address:
            self.peers.add(peer_netloc)
            self.audit.log(
                category="P2P",
                title=f"Ket noi thanh cong Peer: {peer_netloc} ({self.protocol.upper()})",
                details={'total_peers': len(self.peers), 'protocol': self.protocol},
                status="INFO"
            )

    def register_peers_bulk(self, peer_list: List[str]):
        for p in peer_list:
            self.register_peer(p)

    def _send_post(self, url: str, data: dict):
        try:
            requests.post(url, json=data, timeout=1.5, verify=False)
        except Exception:
            pass

    def gossip_transaction(self, tx: Transaction) -> bool:
        # 1. Chống bão lặp DoS: Nếu đã thấy giao dịch này rồi -> Bỏ qua ngay
        if tx.tx_id in self.seen_tx_hashes:
            return True

        self.seen_tx_hashes.add(tx.tx_id)

        # 2. Thẩm định mật mã và số dư ví
        success = self.ledger.submit_transaction(tx)
        if not success:
            return False

        # 3. Lan truyền sang các peer
        payload = tx.to_full_dict()
        peer_count = len(self.peers)
        if peer_count > 0:
            for peer in list(self.peers):
                url = f"{self.protocol}://{peer}/p2p/transactions/receive"
                self.executor.submit(self._send_post, url, payload)

            self.audit.log(
                category="P2P",
                title=f"Gossip P2P: Phat song giao dich toi {peer_count} peers",
                details={'tx_id': f"{tx.tx_id[:16]}...", 'peers': list(self.peers)},
                status="SUCCESS"
            )

        return True

    def broadcast_block(self, block: dict):
        block_hash = calculate_block_hash(block)
        if block_hash in self.seen_block_hashes:
            return

        self.seen_block_hashes.add(block_hash)

        payload = {'block': block}
        peer_count = len(self.peers)
        for peer in list(self.peers):
            url = f"{self.protocol}://{peer}/p2p/blocks/receive"
            self.executor.submit(self._send_post, url, payload)

        self.audit.log(
            category="P2P",
            title=f"Block Broadcast: Phat song Block #{block['block_number']} toi toan bo {peer_count} peers",
            details={'block_hash': f"{block_hash[:20]}...", 'nonce': block['nonce']},
            status="SUCCESS"
        )

    def handle_incoming_block(self, block: dict) -> bool:
        block_hash = calculate_block_hash(block)
        if block_hash in self.seen_block_hashes:
            return True

        self.seen_block_hashes.add(block_hash)

        self.audit.log(
            category="P2P",
            title=f"Nhan goi tin Block #{block['block_number']} tu mang P2P",
            details={'block_hash': f"{block_hash[:20]}...", 'nonce': block['nonce']},
            status="INFO"
        )

        appended = self.ledger.append_block(block)
        if appended:
            self.broadcast_block(block)
            return True
        else:
            self.resolve_conflicts()
            return False

    def resolve_conflicts(self) -> bool:
        max_length = len(self.ledger.chain)
        new_chain = None

        for peer in list(self.peers):
            try:
                response = requests.get(f"{self.protocol}://{peer}/chain", timeout=2.0, verify=False)
                if response.status_code == 200:
                    data = response.json()
                    length = data.get('length', 0)
                    chain = data.get('chain', [])

                    if length > max_length and self.ledger.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except Exception:
                continue

        if new_chain:
            with self.ledger.lock:
                self.ledger.chain = new_chain
                all_chain_signatures = {
                    tx.get('signature')
                    for blk in new_chain
                    for tx in blk.get('transactions', [])
                    if tx.get('signature')
                }
                self.ledger.transactions = [
                    tx for tx in self.ledger.transactions
                    if tx.get('signature') not in all_chain_signatures
                ]

            self.audit.log(
                category="CONSENSUS",
                title=f"Longest Chain Consensus: Chuoi da duoc thay the bang chuoi dai hon ({max_length} blocks)",
                status="SUCCESS"
            )
            return True

        return False
