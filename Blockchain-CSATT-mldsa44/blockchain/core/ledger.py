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

        self.initial_balances: Dict[str, float] = {}
        self.wallet_names: Dict[str, str] = {}
        self._load_initial_balances()

        self.node_id = str(uuid4()).replace('-', '')
        self.lock = threading.Lock()
        self.create_genesis_block()

    def _load_initial_balances(self):
        import json
        import os
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
        Tính toán số dư thời gian thực của một ví:
        = Số dư khởi tạo + Tổng nhận - Tổng gửi [- Tiền đang treo gửi trong Mempool]
        """
        if address == self.mining_sender:
            return float('inf')

        balance = self.initial_balances.get(address, 0.0)

        # 1. Duyệt chuỗi các block đã xác nhận
        for block in self.chain:
            for tx in block.get('transactions', []):
                try:
                    val = float(tx.get('value', 0.0))
                except (ValueError, TypeError):
                    val = 0.0

                if tx.get('recipient_address') == address:
                    balance += val
                if tx.get('sender_address') == address:
                    balance -= val

        # 2. Trừ các khoản đang nằm trong Mempool nếu include_mempool=True (chống double-spending)
        if include_mempool:
            for tx in self.transactions:
                try:
                    val = float(tx.get('value', 0.0))
                except (ValueError, TypeError):
                    val = 0.0

                if tx.get('sender_address') == address:
                    balance -= val

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
            # 1. Kiểm tra tính hợp lệ của số tiền
            try:
                amount = float(tx.value)
                if amount <= 0:
                    self.audit.log(
                        category="BALANCE",
                        title="Tu choi giao dich: So tien gui phai lon hon 0",
                        details={'amount': tx.value, 'sender': f"{tx.sender_address[:20]}..."},
                        status="FAILED"
                    )
                    return False
            except (ValueError, TypeError):
                self.audit.log(
                    category="BALANCE",
                    title="Tu choi giao dich: So tien khong hop le",
                    details={'amount': tx.value},
                    status="FAILED"
                )
                return False

            # 2. Thẩm định chữ ký số (ML-DSA-44 / ECDSA / RSA)
            is_valid = tx.is_valid(self.mining_sender)
            if len(tx.signature) > 1000 or len(tx.sender_address) > 1000:
                algo = "ML-DSA-44 (PQC)"
            elif len(tx.signature) <= 140:
                algo = "ECDSA-secp256k1"
            else:
                algo = "RSA-PKCS1v15"

            if not is_valid:
                self.audit.log(
                    category="CRYPTO",
                    title=f"Tu choi giao dich: Chu ky so {algo} KHONG HOP LE",
                    details={
                        'sender': f"{tx.sender_address[:20]}...",
                        'amount': tx.value,
                        'signature_preview': f"{tx.signature[:24]}..." if tx.signature else "None"
                    },
                    status="FAILED"
                )
                return False

            # 3. Kiểm tra trùng lặp trong Mempool
            for existing_tx in self.transactions:
                if existing_tx.get('sender_address') == tx.sender_address and \
                   existing_tx.get('recipient_address') == tx.recipient_address and \
                   existing_tx.get('value') == tx.value and \
                   existing_tx.get('signature') == tx.signature:
                    return True

            # 4. Kiểm tra số dư người gửi (Solvency & Anti Double-Spending)
            if tx.sender_address != self.mining_sender:
                curr_balance = self.get_balance(tx.sender_address, include_mempool=True)
                sender_name = self.wallet_names.get(tx.sender_address, f"{tx.sender_address[:16]}...")
                if curr_balance < amount:
                    self.audit.log(
                        category="BALANCE",
                        title=f"Tu choi giao dich: So du vi [{sender_name}] khong du (Insufficient Balance)",
                        details={
                            'sender': sender_name,
                            'available_balance': f"{curr_balance} COIN",
                            'attempted_amount': f"{amount} COIN",
                            'deficit': f"{round(amount - curr_balance, 4)} COIN"
                        },
                        status="FAILED"
                    )
                    return False

            # Ghi log kiểm toán mật mã thành công
            self.audit.log(
                category="CRYPTO",
                title=f"Xac thuc chu ky so {algo}: THANH CONG (VERIFIED)",
                details={
                    'sender_pubkey': f"{tx.sender_address[:24]}...",
                    'recipient': f"{tx.recipient_address[:24]}...",
                    'amount': f"{tx.value} COIN",
                    'signature_algorithm': algo
                },
                status="SUCCESS"
            )

            # 5. Đưa vào Mempool
            self.transactions.append(tx.to_full_dict())
            sender_name = self.wallet_names.get(tx.sender_address, f"{tx.sender_address[:16]}...")
            recipient_name = self.wallet_names.get(tx.recipient_address, f"{tx.recipient_address[:16]}...")
            new_avail_balance = self.get_balance(tx.sender_address, include_mempool=True)

            self.audit.log(
                category="MEMPOOL",
                title=f"Them giao dich vao Mempool (Queue: {len(self.transactions)} txs)",
                details={
                    'from': sender_name,
                    'to': recipient_name,
                    'amount': f"{amount} COIN",
                    'sender_remaining_balance': f"{new_avail_balance} COIN"
                },
                status="INFO"
            )
            return True

    def create_block(self, nonce: int, previous_hash: str, max_txs: int = 5) -> dict:
        with self.lock:
            # Lấy tối đa max_txs giao dịch vào block
            txs_to_mine = self.transactions[:max_txs]
            # Giữ lại các giao dịch còn lại trong Mempool cho các block sau
            self.transactions = self.transactions[max_txs:]

            block = {
                'block_number': len(self.chain) + 1,
                'timestamp': time(),
                'transactions': txs_to_mine,
                'nonce': nonce,
                'previous_hash': previous_hash
            }

            self.chain.append(block)

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
