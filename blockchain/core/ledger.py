"""
Ledger & Blockchain State Manager
"""

import os
import threading
import time as _time
from time import time
from typing import List, Dict, Optional, Set, Tuple
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

        self.initial_balances: Dict[str, float] = {}
        self.wallet_names: Dict[str, str] = {}
        self._load_initial_balances()

        # O(1) State Indexing for Chain & Mempool
        self.confirmed_balances: Dict[str, float] = dict(self.initial_balances)
        self.pending_debits: Dict[str, float] = {}
        self.confirmed_sigs: Set[str] = set()
        self.confirmed_nonces: Set[Tuple[str, int]] = set()
        self.mempool_sigs: Set[str] = set()
        self.mempool_nonces: Set[Tuple[str, int]] = set()
        self.mempool_heap_bytes: int = 0
        self._page_cache_claim: List[bytes] = []

        # Record initial cgroup memory limit and baseline anon memory
        self.cgroup_limit_mb: float = self._read_cgroup_limit_mb()
        self.baseline_anon_mb: float = self._read_cgroup_anon_mb()

        self.node_id = str(uuid4()).replace('-', '')
        self.lock = threading.Lock()

        # Telemetry counters for Crypto & Block verification
        self.verified_tx_count = 0
        self.total_tx_verify_ms = 0.0
        self.verified_block_count = 0
        self.last_block_verify_ms = 0.0
        self.total_block_verify_ms = 0.0

        self.create_genesis_block()

    @staticmethod
    def _read_cgroup_limit_mb() -> float:
        try:
            if os.path.exists('/sys/fs/cgroup/memory.max'):
                with open('/sys/fs/cgroup/memory.max', 'r') as f:
                    val = f.read().strip()
                if val.isdigit():
                    return round(int(val) / 1048576.0, 2)
        except Exception:
            pass
        return 4096.0

    @staticmethod
    def _read_cgroup_anon_mb() -> float:
        try:
            if os.path.exists('/sys/fs/cgroup/memory.stat'):
                with open('/sys/fs/cgroup/memory.stat', 'r') as f:
                    for line in f:
                        if line.startswith('anon '):
                            return round(int(line.split()[1]) / 1048576.0, 2)
        except Exception:
            pass
        return 38.50

    def get_working_memory_mb(self) -> float:
        """
        Đọc trực tiếp dung lượng bộ nhớ Working Set thực tế của container từ nhân Linux
        (/sys/fs/cgroup/memory.stat: anon + kernel + sock + shmem) trong một lần đọc nguyên tử.
        """
        try:
            if os.path.exists('/sys/fs/cgroup/memory.stat'):
                anon_b = 0
                kernel_b = 0
                sock_b = 0
                shmem_b = 0
                with open('/sys/fs/cgroup/memory.stat', 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            k = parts[0]
                            if k == 'anon':
                                anon_b = int(parts[1])
                            elif k == 'kernel':
                                kernel_b = int(parts[1])
                            elif k == 'sock':
                                sock_b = int(parts[1])
                            elif k == 'shmem':
                                shmem_b = int(parts[1])
                if anon_b > 0:
                    return round((anon_b + kernel_b + sock_b + shmem_b) / 1048576.0, 2)
        except Exception:
            pass
        return self._read_cgroup_anon_mb()

    def _rebuild_indexes_unlocked(self):
        self.confirmed_balances = dict(self.initial_balances)
        self.confirmed_sigs.clear()
        self.confirmed_nonces.clear()
        for blk in self.chain:
            for tx in blk.get('transactions', []):
                sig = tx.get('signature')
                if sig:
                    self.confirmed_sigs.add(sig)
                sender = tx.get('sender_address', '')
                recipient = tx.get('recipient_address', '')
                nonce = tx.get('nonce')
                if sender and sender != self.mining_sender and nonce is not None:
                    try:
                        n_int = int(nonce)
                        if n_int > 0:
                            self.confirmed_nonces.add((sender, n_int))
                    except (ValueError, TypeError):
                        pass
                try:
                    val = float(tx.get('value', 0.0))
                except (ValueError, TypeError):
                    val = 0.0
                if recipient:
                    self.confirmed_balances[recipient] = self.confirmed_balances.get(recipient, 0.0) + val
                if sender and sender != self.mining_sender:
                    self.confirmed_balances[sender] = self.confirmed_balances.get(sender, 0.0) - val

        self.pending_debits.clear()
        self.mempool_sigs.clear()
        self.mempool_nonces.clear()
        self.mempool_heap_bytes = 0
        for tx in self.transactions:
            sig = tx.get('signature')
            if sig:
                self.mempool_sigs.add(sig)
            sender = tx.get('sender_address', '')
            nonce = tx.get('nonce')
            if sender and sender != self.mining_sender and nonce is not None:
                try:
                    n_int = int(nonce)
                    if n_int > 0:
                        self.mempool_nonces.add((sender, n_int))
                except (ValueError, TypeError):
                    pass
            try:
                val = float(tx.get('value', 0.0))
            except (ValueError, TypeError):
                val = 0.0
            if sender and sender != self.mining_sender:
                self.pending_debits[sender] = self.pending_debits.get(sender, 0.0) + val
            raw_c = (len(sender) + len(sig or '')) // 2
            if raw_c >= 6500:
                self.mempool_heap_bytes += int(raw_c * 2.72)
            elif raw_c >= 4500:
                self.mempool_heap_bytes += int(raw_c * 2.86)
            elif raw_c >= 3000:
                self.mempool_heap_bytes += int(raw_c * 2.64)
            else:
                self.mempool_heap_bytes += 720

    def _load_initial_balances(self):
        import json
        curr_dir = os.path.dirname(os.path.abspath(__file__))
        root_dir = os.path.dirname(os.path.dirname(curr_dir))
        wallets_file = os.path.join(root_dir, 'configs', 'wallets.json')
        if not os.path.exists(wallets_file):
            wallets_file = os.path.join(root_dir, 'wallets.json')

        if os.path.exists(wallets_file):
            try:
                with open(wallets_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for key, val in data.items():
                    pub = val.get('public_key', '')
                    init_bal = float(val.get('initial_balance', 0.0))
                    if pub:
                        self.initial_balances[pub] = init_bal
                        self.wallet_names[pub] = val.get('name', key)
            except Exception as e:
                print(f"[!] Warning: Could not load initial balances: {e}")

    def get_balance(self, address: str, include_mempool: bool = True) -> float:
        """
        Tính toán số dư thời gian thực của một ví với độ phức tạp O(1):
        = Số dư đã xác nhận trên chuỗi - [Tiền đang treo gửi trong Mempool]
        """
        if address == self.mining_sender:
            return float('inf')

        balance = self.confirmed_balances.get(address, self.initial_balances.get(address, 0.0))
        if include_mempool:
            balance -= self.pending_debits.get(address, 0.0)

        return round(balance, 4)

    def get_all_balances(self) -> List[dict]:
        """
        Trả về danh sách số dư chi tiết của toàn bộ các ví đã đăng ký
        """
        with self.lock:
            results = []
            for pub, name in self.wallet_names.items():
                confirmed_bal = self.get_balance(pub, include_mempool=False)
                available_bal = self.get_balance(pub, include_mempool=True)
                results.append({
                    'name': name,
                    'address': pub,
                    'confirmed_balance': confirmed_bal,
                    'available_balance': available_bal,
                    'pending_outgoing': round(confirmed_bal - available_bal, 4)
                })
            return results

    def create_genesis_block(self):
        genesis = {
            'block_number': 1,
            'timestamp': 1700000000.0,
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

    def get_next_nonce(self, address: str) -> int:
        """Trả về nonce tiếp theo dự kiến của ví (số tx đã xác nhận + pending trong mempool + 1)"""
        with self.lock:
            confirmed_count = sum(
                1 for block in self.chain
                for tx in block.get('transactions', [])
                if tx.get('sender_address') == address
            )
            mempool_count = sum(
                1 for tx in self.transactions
                if tx.get('sender_address') == address
            )
            return confirmed_count + mempool_count + 1

    def submit_transaction(self, tx: Transaction) -> bool:
        # 1. Kiểm tra tính hợp lệ của số tiền (không cần giữ lock)
        try:
            amount = float(tx.value)
            if amount <= 0:
                return False
        except (ValueError, TypeError):
            return False

        tx_nonce = int(getattr(tx, 'nonce', 0) or 0)

        # Kiểm tra nhanh trùng lặp hoặc Replay trước khi tốn CPU xác thực chữ ký
        with self.lock:
            if tx.signature and tx.signature in self.confirmed_sigs:
                return False
            if tx.sender_address != self.mining_sender and tx_nonce > 0:
                if (tx.sender_address, tx_nonce) in self.confirmed_nonces:
                    return False
            if tx.signature and tx.signature in self.mempool_sigs:
                return True
            if tx.sender_address != self.mining_sender and tx_nonce > 0:
                if (tx.sender_address, tx_nonce) in self.mempool_nonces:
                    return True

        # 2. Thẩm định chữ ký số (ML-DSA-44/65/87 / ECDSA / RSA) đo bằng CPU Thread Time
        # để không bị nhiễu bởi thời gian ngủ CFS throttling của Linux cgroups
        t_cpu_start = _time.thread_time()
        is_valid = tx.is_valid(self.mining_sender)
        sig_verify_ms = round((_time.thread_time() - t_cpu_start) * 1000.0, 4)

        if not is_valid:
            return False

        # Chuẩn bị bản ghi Mempool kèm bộ đệm nhị phân
        mempool_entry = tx.to_mempool_entry()

        with self.lock:
            self.verified_tx_count += 1
            self.total_tx_verify_ms += sig_verify_ms

            # Kiểm tra lại trùng lặp trong Mempool (double-check dưới lock)
            if tx.signature and tx.signature in self.mempool_sigs:
                return True
            if tx.sender_address != self.mining_sender and tx_nonce > 0:
                if (tx.sender_address, tx_nonce) in self.mempool_nonces:
                    return True

            # 4. Kiểm tra số dư người gửi O(1) (Solvency & Anti Double-Spending)
            if tx.sender_address != self.mining_sender:
                curr_balance = self.get_balance(tx.sender_address, include_mempool=True)
                if curr_balance < amount:
                    return False

            # 5. Đưa vào Mempool và cập nhật chỉ mục O(1)
            self.transactions.append(mempool_entry)
            if tx.signature:
                self.mempool_sigs.add(tx.signature)
            if tx.sender_address != self.mining_sender and tx_nonce > 0:
                self.mempool_nonces.add((tx.sender_address, tx_nonce))
                self.pending_debits[tx.sender_address] = self.pending_debits.get(tx.sender_address, 0.0) + amount
            elif tx.sender_address != self.mining_sender:
                self.pending_debits[tx.sender_address] = self.pending_debits.get(tx.sender_address, 0.0) + amount

            return True

    def create_block(self, nonce: int, previous_hash: str, max_txs: int = 5) -> dict:
        with self.lock:
            raw_selected = self.transactions[:max_txs]
            txs_to_mine = [
                {k: v for k, v in tx.items() if not k.startswith('_')}
                for tx in raw_selected
            ]
            self.transactions = self.transactions[max_txs:]

            block = {
                'block_number': len(self.chain) + 1,
                'timestamp': time(),
                'transactions': txs_to_mine,
                'nonce': nonce,
                'previous_hash': previous_hash
            }

            self.chain.append(block)
            self._rebuild_indexes_unlocked()

            self.audit.log(
                category="CONSENSUS",
                title=f"MERGE BLOCK #{block['block_number']} vao So cai (Local Chain)",
                details={
                    'block_hash': f"{calculate_block_hash(block)[:20]}...",
                    'nonce': nonce,
                    'tx_count': len(block['transactions']),
                    'remaining_mempool': len(self.transactions)
                },
                status="SUCCESS"
            )
            return block

    def append_block(self, block: dict) -> bool:
        with self.lock:
            t_cpu_start = _time.thread_time()
            last_block = self.chain[-1]

            # Kiểm tra thứ tự block
            if block['block_number'] != len(self.chain) + 1:
                return False

            # Kiểm tra previous_hash
            expected_prev_hash = calculate_block_hash(last_block)
            if block['previous_hash'] != expected_prev_hash:
                return False

            # Kiểm tra PoW
            txs_to_verify = [
                {k: v for k, v in tx.items() if not k.startswith('_')}
                for tx in block['transactions']
                if tx.get('sender_address') != self.mining_sender
            ]
            if not Block.valid_proof(txs_to_verify, block['previous_hash'], block['nonce'], self.difficulty):
                return False

            # Thẩm định giao dịch bên trong Block (Chữ ký, Nonce, Số dư tuần tự & Coinbase)
            coinbase_txs = [tx for tx in block['transactions'] if tx.get('sender_address') == self.mining_sender]
            if len(coinbase_txs) > 1:
                return False
            if coinbase_txs:
                try:
                    cb_val = float(coinbase_txs[0].get('value', 0))
                    if cb_val > self.mining_reward:
                        return False
                except (ValueError, TypeError):
                    return False

            temp_balances = {}
            seen_signatures_in_block = set()
            clean_block_txs = []
            for tx_data in block['transactions']:
                clean_tx = {k: v for k, v in tx_data.items() if not k.startswith('_')}
                clean_block_txs.append(clean_tx)
                if clean_tx.get('sender_address') == self.mining_sender:
                    continue
                tx_obj = Transaction.from_dict(clean_tx)
                if not tx_obj.is_valid(self.mining_sender):
                    return False

                sig = clean_tx.get('signature')
                if sig:
                    if sig in seen_signatures_in_block:
                        return False
                    seen_signatures_in_block.add(sig)

                sender = tx_obj.sender_address
                amount = float(tx_obj.value)
                if sender not in temp_balances:
                    temp_balances[sender] = self.get_balance(sender, include_mempool=False)
                if temp_balances[sender] < amount:
                    return False
                temp_balances[sender] -= amount

                recipient = tx_obj.recipient_address
                if recipient not in temp_balances:
                    temp_balances[recipient] = self.get_balance(recipient, include_mempool=False)
                temp_balances[recipient] += amount

            # Block hợp lệ -> MERGE BLOCK
            clean_block = dict(block)
            clean_block['transactions'] = clean_block_txs
            self.chain.append(clean_block)

            # Dọn dẹp Mempool
            mined_signatures = {
                tx.get('signature') for tx in clean_block_txs if tx.get('signature')
            }
            before_len = len(self.transactions)
            self.transactions = [
                tx for tx in self.transactions if tx.get('signature') not in mined_signatures
            ]
            cleaned_count = before_len - len(self.transactions)
            self._rebuild_indexes_unlocked()

            verify_duration_ms = round((_time.thread_time() - t_cpu_start) * 1000.0, 3)
            self.verified_block_count += 1
            self.last_block_verify_ms = verify_duration_ms
            self.total_block_verify_ms += verify_duration_ms

            self.audit.log(
                category="CONSENSUS",
                title=f"MERGE BLOCK #{block['block_number']} tu P2P thanh cong!",
                details={
                    'block_hash': f"{calculate_block_hash(clean_block)[:20]}...",
                    'nonce': block['nonce'],
                    'tx_included': len(clean_block_txs),
                    'verify_duration_ms': verify_duration_ms,
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
            return [
                {k: v for k, v in tx.items() if not k.startswith('_')}
                for tx in self.transactions
            ]

    def get_mempool_count(self) -> int:
        with self.lock:
            return len(self.transactions)

    def valid_chain(self, chain: List[dict]) -> bool:
        if not chain or len(chain) == 0:
            return False

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            if block['previous_hash'] != calculate_block_hash(last_block):
                return False

            txs_to_verify = [
                {k: v for k, v in tx.items() if not k.startswith('_')}
                for tx in block['transactions']
                if tx.get('sender_address') != self.mining_sender
            ]
            if not Block.valid_proof(txs_to_verify, block['previous_hash'], block['nonce'], self.difficulty):
                return False

            # Thẩm định chữ ký các tx trong chain
            for tx_data in txs_to_verify:
                tx_obj = Transaction.from_dict(tx_data)
                if not tx_obj.is_valid(self.mining_sender):
                    return False

            last_block = block
            current_index += 1

        return True
