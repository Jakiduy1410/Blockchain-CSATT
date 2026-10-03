"""
Audit Logger Module
Trách nhiệm An ninh mạng:
- Ghi nhận lịch sử kiểm toán an ninh (Security Audit Trail) theo thời gian thực
- Chi tiết hóa quá trình thẩm định chữ ký số RSA PKCS#1 v1.5
- Chi tiết hóa quá trình thẩm định PoW, Consensus và Merge Block
"""

from datetime import datetime
import threading
from typing import List, Dict


class AuditLogger:
    def __init__(self, max_entries: int = 100):
        self.max_entries = max_entries
        self.logs: List[Dict] = []
        self.lock = threading.Lock()

    def log(self, category: str, title: str, details: dict = None, status: str = "INFO"):
        """
        Ghi một bản ghi kiểm toán mới:
        - category: P2P, CRYPTO, CONSENSUS, MEMPOOL, MINER
        - status: SUCCESS, FAILED, INFO, WARNING
        """
        now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        entry = {
            'timestamp': now,
            'category': category.upper(),
            'title': title,
            'status': status.upper(),
            'details': details or {}
        }
        with self.lock:
            self.logs.insert(0, entry)  # Mới nhất ở trên cùng
            if len(self.logs) > self.max_entries:
                self.logs.pop()

    def get_logs(self, limit: int = 50) -> List[Dict]:
        with self.lock:
            return list(self.logs[:limit])
