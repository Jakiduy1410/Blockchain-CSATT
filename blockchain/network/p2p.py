"""
P2P Network Engine - Persistent WebSocket bọc TLS 1.3 / ECDHE
Thay thế hoàn toàn cơ chế HTTP POST rời rạc bằng kết nối WebSocket liên tục (wss://)
"""

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import requests
from websockets.sync.client import connect as ws_connect
from websockets.sync.server import serve as ws_serve

try:
    from .tls_helper import TLSManager
    from ..core.crypto import calculate_block_hash
    from ..core.ledger import BlockchainLedger
    from ..core.transaction import Transaction
    from ..core.audit import AuditLogger
except ImportError:
    from network.tls_helper import TLSManager
    from core.crypto import calculate_block_hash
    from core.ledger import BlockchainLedger
    from core.transaction import Transaction
    from core.audit import AuditLogger

logger = logging.getLogger("P2PNetwork")


class P2PNetwork:
    def __init__(self, ledger: BlockchainLedger, my_address: str = "127.0.0.1:5000", audit_logger: AuditLogger = None, ws_port: int = None):
        self.ledger = ledger
        self.my_address = my_address
        self.audit = audit_logger or (ledger.audit if hasattr(ledger, 'audit') else AuditLogger())

        # Tính toán cổng HTTP và cổng WebSocket P2P riêng biệt (mặc định HTTP port + 1000)
        try:
            self.my_http_port = int(self.my_address.split(':')[1])
        except Exception:
            self.my_http_port = 5000

        self.ws_port = ws_port if ws_port else (self.my_http_port + 1000)
        self.peers: Set[str] = set()

        # Quản lý kết nối WebSocket
        self.outgoing_sockets: Dict[str, object] = {}
        self.incoming_sockets: Set[object] = set()
        self.conn_lock = threading.Lock()

        # Bộ lọc chống lặp và DoS
        self.seen_tx_hashes: Set[str] = set()
        self.seen_block_hashes: Set[str] = set()
        self.executor = ThreadPoolExecutor(max_workers=15)
        self._running = True

        # Thiết lập SSL Context (TLS 1.3 / ECDHE)
        self.server_ssl_ctx = TLSManager.create_server_ssl_context()
        self.client_ssl_ctx = TLSManager.create_client_ssl_context()

        # 1. Khởi chạy WebSocket Server P2P trên cổng ws_port
        self._ws_server = None
        self._start_ws_server()

        # 2. Khởi chạy luồng tự động duy trì kết nối WebSocket tới các Peers
        self._connector_thread = threading.Thread(target=self._maintain_peer_connections_loop, daemon=True)
        self._connector_thread.start()

    def _start_ws_server(self):
        def run_server():
            try:
                self._ws_server = ws_serve(
                    self._handle_incoming_connection,
                    host="127.0.0.1",
                    port=self.ws_port,
                    ssl=self.server_ssl_ctx
                )
                self.audit.log(
                    category="P2P",
                    title=f"Khoi chay WebSocket P2P Server (wss://127.0.0.1:{self.ws_port})",
                    details={'tls': 'TLS 1.3 / ECDHE', 'ws_port': self.ws_port},
                    status="SUCCESS"
                )
                self._ws_server.serve_forever()
            except Exception as e:
                logger.error(f"Lỗi khởi chạy WebSocket Server port {self.ws_port}: {e}")

        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()

    def _handle_incoming_connection(self, websocket):
        """Xử lý kết nối WebSocket đến từ các Peer"""
        with self.conn_lock:
            self.incoming_sockets.add(websocket)

        try:
            for message in websocket:
                self._process_ws_message(message)
        except Exception:
            pass
        finally:
            with self.conn_lock:
                self.incoming_sockets.discard(websocket)

    def _peer_to_ws_url(self, peer: str) -> str:
        """Chuyển đổi peer address (127.0.0.1:5001) thành URL wss:// (wss://127.0.0.1:6001)"""
        host = "127.0.0.1"
        port = 5001
        if ":" in peer:
            parts = peer.split(":")
            host = parts[0]
            try:
                p = int(parts[1])
                port = p + 1000 if p < 6000 else p
            except ValueError:
                port = 6001
        return f"wss://{host}:{port}"

    def register_peer(self, peer_url: str):
        if not peer_url:
            return

        parsed = urlparse(peer_url)
        peer_netloc = parsed.netloc if parsed.netloc else parsed.path
        peer_netloc = peer_netloc.strip().replace("http://", "").replace("https://", "").replace("ws://", "").replace("wss://", "")

        if peer_netloc and peer_netloc != self.my_address:
            self.peers.add(peer_netloc)
            self.audit.log(
                category="P2P",
                title=f"Dang ky Peer: {peer_netloc}",
                details={'ws_endpoint': self._peer_to_ws_url(peer_netloc), 'total_peers': len(self.peers)},
                status="INFO"
            )

    def register_peers_bulk(self, peer_list: List[str]):
        for p in peer_list:
            self.register_peer(p)

    def _maintain_peer_connections_loop(self):
        """Luồng ngầm duy trì Persistent WebSocket tới toàn bộ Peers"""
        time.sleep(1.0)  # Chờ các node khác khởi động
        while self._running:
            for peer in list(self.peers):
                with self.conn_lock:
                    has_conn = peer in self.outgoing_sockets

                if not has_conn:
                    ws_url = self._peer_to_ws_url(peer)
                    try:
                        sock = ws_connect(ws_url, ssl=self.client_ssl_ctx, open_timeout=1.5)
                        with self.conn_lock:
                            self.outgoing_sockets[peer] = sock

                        self.audit.log(
                            category="P2P",
                            title=f"Thiet lap Persistent WebSocket toi Peer: {peer}",
                            details={'ws_url': ws_url, 'cipher': 'TLS 1.3 / ECDHE'},
                            status="SUCCESS"
                        )

                        # Mở luồng lắng nghe tin nhắn từ peer này
                        threading.Thread(target=self._listen_outgoing_socket, args=(peer, sock), daemon=True).start()
                    except Exception:
                        pass
            time.sleep(3.0)

    def _listen_outgoing_socket(self, peer: str, sock):
        try:
            for message in sock:
                self._process_ws_message(message)
        except Exception:
            pass
        finally:
            with self.conn_lock:
                if peer in self.outgoing_sockets:
                    del self.outgoing_sockets[peer]

    def _process_ws_message(self, raw_message: str):
        try:
            msg = json.loads(raw_message)
            msg_type = msg.get("type")
            data = msg.get("data")

            if msg_type == "TRANSACTION" and data:
                tx = Transaction.from_dict(data)
                self.gossip_transaction(tx)
            elif msg_type == "BLOCK" and data:
                self.handle_incoming_block(data)
        except Exception as e:
            logger.debug(f"Lỗi xử lý gói tin P2P: {e}")

    def _send_ws_payload(self, payload: dict):
        """Gửi gói tin qua toàn bộ các kết nối WebSocket đang mở (Outgoing + Incoming)"""
        msg_str = json.dumps(payload)
        dead_outgoing = []

        # 1. Gửi qua Outgoing Sockets
        with self.conn_lock:
            out_targets = list(self.outgoing_sockets.items())
            in_targets = list(self.incoming_sockets)

        for peer, sock in out_targets:
            try:
                sock.send(msg_str)
            except Exception:
                dead_outgoing.append(peer)

        if dead_outgoing:
            with self.conn_lock:
                for peer in dead_outgoing:
                    if peer in self.outgoing_sockets:
                        del self.outgoing_sockets[peer]

        # 2. Gửi qua Incoming Sockets
        dead_incoming = []
        for sock in in_targets:
            try:
                sock.send(msg_str)
            except Exception:
                dead_incoming.append(sock)

        if dead_incoming:
            with self.conn_lock:
                for sock in dead_incoming:
                    self.incoming_sockets.discard(sock)

    def gossip_transaction(self, tx: Transaction) -> bool:
        # 0. Kiểm tra chống Replay Attack: nếu giao dịch đã có trong Blockchain -> Từ chối ngay
        with self.ledger.lock:
            for blk in self.ledger.chain:
                for past_tx in blk.get('transactions', []):
                    if past_tx.get('signature') and past_tx.get('signature') == tx.signature:
                        return False
                    if tx.sender_address != self.ledger.mining_sender and \
                       past_tx.get('sender_address') == tx.sender_address and \
                       past_tx.get('nonce') is not None and \
                       int(past_tx.get('nonce', 0)) == int(getattr(tx, 'nonce', 0)) and \
                       int(getattr(tx, 'nonce', 0)) > 0:
                        return False

        # 1. Chống bão lặp DoS trong Mempool: nếu đang chờ xử lý -> Bỏ qua
        if tx.tx_id in self.seen_tx_hashes:
            return True

        self.seen_tx_hashes.add(tx.tx_id)

        # 2. Thẩm định mật mã và số dư ví
        success = self.ledger.submit_transaction(tx)
        if not success:
            return False

        # 3. Lan truyền sang các peer qua Persistent WebSocket pipeline
        payload = {
            'type': 'TRANSACTION',
            'data': tx.to_full_dict(),
            'origin': self.my_address
        }
        self.executor.submit(self._send_ws_payload, payload)

        active_conn_count = len(self.outgoing_sockets) + len(self.incoming_sockets)
        self.audit.log(
            category="P2P",
            title=f"Gossip P2P (WebSocket TLS ECDHE): Phat song giao dich qua {active_conn_count} ket noi wss://",
            details={'tx_id': f"{tx.tx_id[:16]}...", 'nonce': getattr(tx, 'nonce', 0)},
            status="SUCCESS"
        )
        return True

    def broadcast_block(self, block: dict):
        block_hash = calculate_block_hash(block)
        if block_hash in self.seen_block_hashes:
            return

        self.seen_block_hashes.add(block_hash)

        payload = {
            'type': 'BLOCK',
            'data': block,
            'origin': self.my_address
        }
        self.executor.submit(self._send_ws_payload, payload)

        active_conn_count = len(self.outgoing_sockets) + len(self.incoming_sockets)
        self.audit.log(
            category="P2P",
            title=f"Block Broadcast (WebSocket TLS ECDHE): Phat song Block #{block['block_number']} qua {active_conn_count} ket noi wss://",
            details={'block_hash': f"{block_hash[:20]}...", 'nonce': block['nonce'], 'tx_count': len(block.get('transactions', []))},
            status="SUCCESS"
        )

    def handle_incoming_block(self, block: dict) -> bool:
        block_hash = calculate_block_hash(block)
        if block_hash in self.seen_block_hashes:
            return True

        self.seen_block_hashes.add(block_hash)

        self.audit.log(
            category="P2P",
            title=f"Nhan goi tin Block #{block['block_number']} tu WebSocket P2P",
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
                response = requests.get(f"http://{peer}/chain", timeout=2.0)
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

    def stop(self):
        self._running = False
        with self.conn_lock:
            for sock in list(self.outgoing_sockets.values()):
                try:
                    sock.close()
                except Exception:
                    pass
            self.outgoing_sockets.clear()
            for sock in list(self.incoming_sockets):
                try:
                    sock.close()
                except Exception:
                    pass
            self.incoming_sockets.clear()
        if self._ws_server:
            try:
                self._ws_server.shutdown()
            except Exception:
                pass
