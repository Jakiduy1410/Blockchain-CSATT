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
    def __init__(
        self,
        ledger: BlockchainLedger,
        my_address: str = "127.0.0.1:5000",
        audit_logger: AuditLogger = None,
        ws_port: int = None
    ):
        self.ledger = ledger
        self.my_address = my_address
        self.audit = audit_logger or (
            ledger.audit if hasattr(ledger, 'audit') else AuditLogger()
        )

        # HTTP port và WebSocket P2P port.
        try:
            self.my_http_port = int(self.my_address.split(':')[1])
        except Exception:
            self.my_http_port = 5000

        self.ws_port = ws_port if ws_port else (self.my_http_port + 1000)
        self.peers: Set[str] = set()

        # Quản lý kết nối WebSocket.
        self.outgoing_sockets: Dict[str, object] = {}
        self.incoming_sockets: Set[object] = set()
        self.conn_lock = threading.Lock()

        # Bộ lọc chống lặp và DoS.
        self.seen_tx_hashes: Set[str] = set()
        self.seen_block_hashes: Set[str] = set()

        self.executor = ThreadPoolExecutor(max_workers=15)
        self._running = True

        # ==========================================================
        # NET-01 / NET-02 EXPERIMENT METRICS
        # ==========================================================
        # Số lần resolve_conflicts() thực sự được gọi.
        self.resolve_conflicts_count = 0

        # Số block cạnh tranh/xung đột nhận được.
        self.conflict_count = 0

        # Số fork candidate: block khác hash nhưng cùng height
        # với tip hiện tại.
        self.fork_count = 0

        # Số block local bị loại bỏ sau khi chuyển sang longest chain.
        self.orphan_blocks_count = 0

        # Độ trễ từ thời điểm peer broadcast block đến khi node này nhận.
        self.block_propagation_delays_ms = []
        self.last_block_propagation_ms = 0.0

        # Bảo vệ metric khi nhiều WebSocket thread cập nhật đồng thời.
        self.metrics_lock = threading.Lock()

        # Thiết lập SSL Context (TLS 1.3 / ECDHE).
        self.server_ssl_ctx = TLSManager.create_server_ssl_context()
        self.client_ssl_ctx = TLSManager.create_client_ssl_context()

        # Khởi chạy WebSocket Server P2P.
        self._ws_server = None
        self._start_ws_server()

        # Luồng tự động duy trì kết nối tới peers.
        self._connector_thread = threading.Thread(
            target=self._maintain_peer_connections_loop,
            daemon=True
        )
        self._connector_thread.start()

    # ==============================================================
    # NET-01 / NET-02 METRIC HELPERS
    # ==============================================================

    def get_net_metrics(self) -> dict:
        """
        Trả về metric dùng cho kịch bản NET-01 / NET-02.
        """
        with self.metrics_lock:
            delays = list(self.block_propagation_delays_ms)

            avg_delay = (
                sum(delays) / len(delays)
                if delays
                else 0.0
            )

            min_delay = min(delays) if delays else 0.0
            max_delay = max(delays) if delays else 0.0

            return {
                "resolve_conflicts_count": self.resolve_conflicts_count,
                "conflict_count": self.conflict_count,
                "fork_count": self.fork_count,
                "orphan_blocks_count": self.orphan_blocks_count,

                "propagation_samples": len(delays),
                "last_block_propagation_ms": round(
                    self.last_block_propagation_ms, 6
                ),
                "avg_block_propagation_ms": round(avg_delay, 6),
                "min_block_propagation_ms": round(min_delay, 6),
                "max_block_propagation_ms": round(max_delay, 6),

                # Giữ raw samples để benchmark ghi CSV.
                "block_propagation_delays_ms": [
                    round(x, 6) for x in delays
                ]
            }

    def reset_net_metrics(self):
        """
        Reset metric giữa các case:
        ECDSA / ML-DSA, loss 5% / 15%, MTU 576 / 1500.
        """
        with self.metrics_lock:
            self.resolve_conflicts_count = 0
            self.conflict_count = 0
            self.fork_count = 0
            self.orphan_blocks_count = 0

            self.block_propagation_delays_ms.clear()
            self.last_block_propagation_ms = 0.0

    def _record_propagation_delay(self, sent_at_ns):
        """
        sent_at_ns nằm trong WebSocket envelope, KHÔNG nằm trong block.
        Vì vậy việc đo không làm thay đổi block hash.
        """
        if sent_at_ns is None:
            return

        try:
            sent_at_ns = int(sent_at_ns)
            received_at_ns = time.time_ns()

            delay_ms = (
                received_at_ns - sent_at_ns
            ) / 1_000_000.0

            # Clock lỗi hoặc dữ liệu bất thường thì bỏ.
            if delay_ms < 0:
                return

            with self.metrics_lock:
                self.last_block_propagation_ms = delay_ms
                self.block_propagation_delays_ms.append(delay_ms)

                # Tránh giữ vô hạn nếu test lâu.
                if len(self.block_propagation_delays_ms) > 5000:
                    self.block_propagation_delays_ms = \
                        self.block_propagation_delays_ms[-5000:]

        except (TypeError, ValueError, OverflowError):
            pass

    def _detect_competing_block(self, block: dict, block_hash: str):
        """
        Một fork candidate được ghi nhận khi node đã có block tip
        ở cùng block_number nhưng nhận một block khác hash.

        Đây chính là tình huống thường xảy ra khi hai miner đào
        cạnh tranh ở cùng height.
        """
        try:
            with self.ledger.lock:
                if not self.ledger.chain:
                    return

                local_tip = self.ledger.chain[-1]

                incoming_height = int(
                    block.get("block_number", -1)
                )
                local_height = int(
                    local_tip.get("block_number", -2)
                )

                if incoming_height != local_height:
                    return

                local_hash = calculate_block_hash(local_tip)

                if local_hash != block_hash:
                    with self.metrics_lock:
                        self.fork_count += 1

                    self.audit.log(
                        category="CONSENSUS",
                        title=(
                            f"NET-02 Fork Candidate: "
                            f"phat hien hai Block #{incoming_height} "
                            f"canh tranh"
                        ),
                        details={
                            "local_hash": local_hash[:20],
                            "incoming_hash": block_hash[:20],
                            "height": incoming_height
                        },
                        status="WARNING"
                    )

        except Exception:
            pass

    # ==============================================================
    # WEBSOCKET SERVER / CONNECTION MANAGEMENT
    # ==============================================================

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
                    title=(
                        f"Khoi chay WebSocket P2P Server "
                        f"(wss://127.0.0.1:{self.ws_port})"
                    ),
                    details={
                        'tls': 'TLS 1.3 / ECDHE',
                        'ws_port': self.ws_port
                    },
                    status="SUCCESS"
                )

                self._ws_server.serve_forever()

            except Exception as e:
                logger.error(
                    f"Lỗi khởi chạy WebSocket Server "
                    f"port {self.ws_port}: {e}"
                )

        server_thread = threading.Thread(
            target=run_server,
            daemon=True
        )
        server_thread.start()

    def _handle_incoming_connection(self, websocket):
        """Xử lý kết nối WebSocket đến từ các Peer."""

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
        """
        Chuyển:
        127.0.0.1:5001
        thành:
        wss://127.0.0.1:6001
        """

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

        peer_netloc = (
            parsed.netloc
            if parsed.netloc
            else parsed.path
        )

        peer_netloc = (
            peer_netloc
            .strip()
            .replace("http://", "")
            .replace("https://", "")
            .replace("ws://", "")
            .replace("wss://", "")
        )

        # Config hi?n t?i c? th? ch? truy?n port: "5001".
        # Chu?n h?a th?nh "127.0.0.1:5001" ?? c? HTTP consensus
        # v? WebSocket P2P ??u d?ng ??ng ??a ch?.
        if peer_netloc.isdigit():
            peer_netloc = f"127.0.0.1:{peer_netloc}"

        if (
            peer_netloc
            and peer_netloc != self.my_address
        ):
            self.peers.add(peer_netloc)

            self.audit.log(
                category="P2P",
                title=f"Dang ky Peer: {peer_netloc}",
                details={
                    'ws_endpoint':
                        self._peer_to_ws_url(peer_netloc),

                    'total_peers':
                        len(self.peers)
                },
                status="INFO"
            )

    def register_peers_bulk(self, peer_list: List[str]):
        for p in peer_list:
            self.register_peer(p)

    def _maintain_peer_connections_loop(self):
        """
        Luồng ngầm duy trì Persistent WebSocket
        tới toàn bộ Peers.
        """

        time.sleep(1.0)

        while self._running:

            for peer in list(self.peers):

                with self.conn_lock:
                    has_conn = (
                        peer in self.outgoing_sockets
                    )

                if not has_conn:

                    ws_url = self._peer_to_ws_url(peer)

                    try:
                        sock = ws_connect(
                            ws_url,
                            ssl=self.client_ssl_ctx,
                            open_timeout=1.5
                        )

                        with self.conn_lock:
                            self.outgoing_sockets[peer] = sock

                        self.audit.log(
                            category="P2P",
                            title=(
                                f"Thiet lap Persistent "
                                f"WebSocket toi Peer: {peer}"
                            ),
                            details={
                                'ws_url': ws_url,
                                'cipher': 'TLS 1.3 / ECDHE'
                            },
                            status="SUCCESS"
                        )

                        threading.Thread(
                            target=self._listen_outgoing_socket,
                            args=(peer, sock),
                            daemon=True
                        ).start()

                    except Exception:
                        pass

            time.sleep(3.0)

    def _listen_outgoing_socket(
        self,
        peer: str,
        sock
    ):
        try:
            for message in sock:
                self._process_ws_message(message)

        except Exception:
            pass

        finally:
            with self.conn_lock:
                if peer in self.outgoing_sockets:
                    del self.outgoing_sockets[peer]

    # ==============================================================
    # P2P MESSAGE PROCESSING
    # ==============================================================

    def _process_ws_message(self, raw_message: str):
        try:
            msg = json.loads(raw_message)

            msg_type = msg.get("type")
            data = msg.get("data")

            if msg_type == "TRANSACTION" and data:

                tx = Transaction.from_dict(data)
                self.gossip_transaction(tx)

            elif msg_type == "BLOCK" and data:

                # Timestamp nằm ngoài block để không ảnh hưởng hash.
                sent_at_ns = msg.get("sent_at_ns")
                origin = msg.get("origin")

                self.handle_incoming_block(
                    data,
                    sent_at_ns=sent_at_ns,
                    origin=origin
                )

        except Exception as e:
            logger.debug(
                f"Lỗi xử lý gói tin P2P: {e}"
            )

    def _send_ws_payload(self, payload: dict):
        """
        Gửi payload qua toàn bộ kết nối
        WebSocket đang mở.
        """

        msg_str = json.dumps(payload)

        dead_outgoing = []

        with self.conn_lock:

            out_targets = list(
                self.outgoing_sockets.items()
            )

            in_targets = list(
                self.incoming_sockets
            )

        # Outgoing sockets.
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

        # Incoming sockets.
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

    # ==============================================================
    # TRANSACTION GOSSIP
    # ==============================================================

    def gossip_transaction(
        self,
        tx: Transaction
    ) -> bool:

        # Chống replay đối với transaction
        # đã nằm trong blockchain.
        with self.ledger.lock:

            for blk in self.ledger.chain:

                for past_tx in blk.get(
                    'transactions',
                    []
                ):

                    if (
                        past_tx.get('signature')
                        and
                        past_tx.get('signature')
                        == tx.signature
                    ):
                        return False

                    if (
                        tx.sender_address
                        != self.ledger.mining_sender
                        and
                        past_tx.get('sender_address')
                        == tx.sender_address
                        and
                        past_tx.get('nonce')
                        is not None
                        and
                        int(
                            past_tx.get(
                                'nonce',
                                0
                            )
                        )
                        ==
                        int(
                            getattr(
                                tx,
                                'nonce',
                                0
                            )
                        )
                        and
                        int(
                            getattr(
                                tx,
                                'nonce',
                                0
                            )
                        ) > 0
                    ):
                        return False

        # Chống transaction lặp trong mempool.
        if tx.tx_id in self.seen_tx_hashes:
            return True

        self.seen_tx_hashes.add(
            tx.tx_id
        )

        # Thẩm định chữ ký + balance.
        success = (
            self.ledger.submit_transaction(tx)
        )

        if not success:
            return False

        # Gossip transaction.
        payload = {
            'type': 'TRANSACTION',
            'data': tx.to_full_dict(),
            'origin': self.my_address
        }

        self.executor.submit(
            self._send_ws_payload,
            payload
        )

        active_conn_count = (
            len(self.outgoing_sockets)
            +
            len(self.incoming_sockets)
        )

        self.audit.log(
            category="P2P",
            title=(
                "Gossip P2P "
                "(WebSocket TLS ECDHE): "
                f"Phat song giao dich qua "
                f"{active_conn_count} ket noi wss://"
            ),
            details={
                'tx_id':
                    f"{tx.tx_id[:16]}...",

                'nonce':
                    getattr(tx, 'nonce', 0)
            },
            status="SUCCESS"
        )

        return True

    # ==============================================================
    # BLOCK BROADCAST / PROPAGATION / FORK
    # ==============================================================

    def broadcast_block(
        self,
        block: dict
    ):
        block_hash = calculate_block_hash(block)

        if block_hash in self.seen_block_hashes:
            return

        self.seen_block_hashes.add(block_hash)

        # NET-02:
        # Timestamp được thêm vào WebSocket envelope.
        # Không thêm vào block -> không làm thay đổi block hash.
        sent_at_ns = time.time_ns()

        payload = {
            'type': 'BLOCK',
            'data': block,
            'origin': self.my_address,
            'sent_at_ns': sent_at_ns
        }

        self.executor.submit(
            self._send_ws_payload,
            payload
        )

        active_conn_count = (
            len(self.outgoing_sockets)
            +
            len(self.incoming_sockets)
        )

        self.audit.log(
            category="P2P",
            title=(
                f"Block Broadcast "
                f"(WebSocket TLS ECDHE): "
                f"Phat song Block "
                f"#{block['block_number']} "
                f"qua {active_conn_count} "
                f"ket noi wss://"
            ),
            details={
                'block_hash':
                    f"{block_hash[:20]}...",

                'nonce':
                    block['nonce'],

                'tx_count':
                    len(
                        block.get(
                            'transactions',
                            []
                        )
                    ),

                'net02_sent_at_ns':
                    sent_at_ns
            },
            status="SUCCESS"
        )

    def handle_incoming_block(
        self,
        block: dict,
        sent_at_ns=None,
        origin=None
    ) -> bool:

        block_hash = calculate_block_hash(block)

        if block_hash in self.seen_block_hashes:
            return True

        # Đo propagation trước khi xử lý block.
        self._record_propagation_delay(
            sent_at_ns
        )

        # Kiểm tra competing block/fork candidate
        # trước khi append.
        self._detect_competing_block(
            block,
            block_hash
        )

        self.seen_block_hashes.add(
            block_hash
        )

        self.audit.log(
            category="P2P",
            title=(
                f"Nhan goi tin "
                f"Block #{block['block_number']} "
                f"tu WebSocket P2P"
            ),
            details={
                'block_hash':
                    f"{block_hash[:20]}...",

                'nonce':
                    block['nonce'],

                'origin':
                    origin,

                'propagation_ms':
                    round(
                        self.last_block_propagation_ms,
                        6
                    )
            },
            status="INFO"
        )

        appended = (
            self.ledger.append_block(block)
        )

        if appended:

            # Giữ nguyên hành vi cũ.
            self.broadcast_block(block)

            return True

        # append_block thất bại:
        # có block cạnh tranh hoặc conflict cần consensus.
        with self.metrics_lock:
            self.conflict_count += 1

        self.resolve_conflicts()

        return False

    # ==============================================================
    # CONSENSUS / CONFLICT RESOLUTION
    # ==============================================================

    def resolve_conflicts(self) -> bool:

        # NET-02:
        # Mỗi lần hàm này được gọi đều được thống kê.
        with self.metrics_lock:
            self.resolve_conflicts_count += 1

        max_length = len(
            self.ledger.chain
        )

        new_chain = None

        for peer in list(self.peers):

            try:
                response = requests.get(
                    f"http://{peer}/chain",
                    timeout=2.0
                )

                if response.status_code == 200:

                    data = response.json()

                    length = data.get(
                        'length',
                        0
                    )

                    chain = data.get(
                        'chain',
                        []
                    )

                    if (
                        length > max_length
                        and
                        self.ledger.valid_chain(chain)
                    ):
                        max_length = length
                        new_chain = chain

            except Exception:
                continue

        if new_chain:

            with self.ledger.lock:

                # Chain hiện tại trước khi reorg.
                old_chain = list(
                    self.ledger.chain
                )

                # Những block local không còn tồn tại
                # trong winning chain => orphan.
                try:
                    old_hashes = {
                        calculate_block_hash(block)
                        for block in old_chain[1:]
                    }

                    new_hashes = {
                        calculate_block_hash(block)
                        for block in new_chain[1:]
                    }

                    orphaned_hashes = (
                        old_hashes - new_hashes
                    )

                    orphaned_count = len(
                        orphaned_hashes
                    )

                except Exception:
                    orphaned_count = 0

                self.ledger.chain = new_chain

                all_chain_signatures = {
                    tx.get('signature')
                    for blk in new_chain
                    for tx in blk.get(
                        'transactions',
                        []
                    )
                    if tx.get('signature')
                }

                self.ledger.transactions = [
                    tx
                    for tx in self.ledger.transactions
                    if tx.get('signature')
                    not in all_chain_signatures
                ]

            if orphaned_count:

                with self.metrics_lock:
                    self.orphan_blocks_count += (
                        orphaned_count
                    )

            self.audit.log(
                category="CONSENSUS",
                title=(
                    "Longest Chain Consensus: "
                    "Chuoi da duoc thay the "
                    f"bang chuoi dai hon "
                    f"({max_length} blocks)"
                ),
                details={
                    "net02_orphaned_blocks":
                        orphaned_count,

                    "net02_resolve_conflicts_count":
                        self.resolve_conflicts_count
                },
                status="SUCCESS"
            )

            return True

        return False

    # ==============================================================
    # SHUTDOWN
    # ==============================================================

    def stop(self):

        self._running = False

        with self.conn_lock:

            for sock in list(
                self.outgoing_sockets.values()
            ):

                try:
                    sock.close()

                except Exception:
                    pass

            self.outgoing_sockets.clear()

            for sock in list(
                self.incoming_sockets
            ):

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