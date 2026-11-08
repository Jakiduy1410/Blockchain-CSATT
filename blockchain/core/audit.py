"""
Audit Logger Module
Trách nhiệm An ninh mạng:
- Ghi nhận lịch sử kiểm toán an ninh (Security Audit Trail) theo thời gian thực
- Chi tiết hóa quá trình thẩm định chữ ký số ML-DSA / ECDSA / RSA
- Chi tiết hóa quá trình thẩm định PoW, Consensus và Merge Block
"""

from collections import deque
from datetime import datetime
import threading
import time
from typing import List, Dict


class AuditLogger:
    def __init__(self, max_entries: int = 200):
        self.max_entries = max_entries
        self.logs = deque(maxlen=max_entries)
        self.lock = threading.Lock()

    def log(self, category: str, title: str, details: dict = None, status: str = "INFO"):
        """
        Ghi một bản ghi kiểm toán mới:
        - category: P2P, CRYPTO, CONSENSUS, MEMPOOL, MINER
        - status: SUCCESS, FAILED, INFO, WARNING
        """
        now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        epoch_ms = round(time.time() * 1000.0, 3)
        entry = {
            'timestamp': now,
            'epoch_ms': epoch_ms,
            'category': category.upper(),
            'title': title,
            'status': status.upper(),
            'details': details or {}
        }
        with self.lock:
            self.logs.appendleft(entry)

    def get_logs(self, limit: int = 50) -> List[Dict]:
        with self.lock:
            return list(self.logs)[:limit]
