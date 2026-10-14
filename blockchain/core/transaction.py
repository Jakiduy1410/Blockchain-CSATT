"""
Transaction Model
"""

from collections import OrderedDict

try:
    from .crypto import calculate_sha256, verify_signature
except ImportError:
    from crypto import calculate_sha256, verify_signature


class Transaction:
    def __init__(self, sender_address: str, recipient_address: str, value: str, signature: str = "", nonce: int = 0):
        self.sender_address = str(sender_address)
        self.recipient_address = str(recipient_address)
        self.value = str(value)
        self.signature = str(signature)
        try:
            self.nonce = int(nonce) if nonce is not None and str(nonce).strip() != '' else 0
        except (ValueError, TypeError):
            self.nonce = 0
        self.tx_id = self.calculate_hash()

    def to_dict(self) -> OrderedDict:
        d = OrderedDict([
            ('sender_address', self.sender_address),
            ('recipient_address', self.recipient_address),
            ('value', self.value)
        ])
        if self.nonce is not None:
            d['nonce'] = str(self.nonce)
        return d

    def to_full_dict(self) -> dict:
        return {
            'tx_id': self.tx_id,
            'sender_address': self.sender_address,
            'recipient_address': self.recipient_address,
            'value': self.value,
            'nonce': self.nonce,
            'signature': self.signature
        }

    def calculate_hash(self) -> str:
        data = f"{self.sender_address}:{self.recipient_address}:{self.value}:{self.nonce}:{self.signature}"
        return calculate_sha256(data)

    def is_valid(self, mining_sender: str = "THE BLOCKCHAIN") -> bool:
        if self.sender_address == mining_sender:
            return True

        if not self.signature:
            return False

        return verify_signature(self.sender_address, self.signature, self.to_dict())

    @staticmethod
    def from_dict(data: dict) -> 'Transaction':
        return Transaction(
            sender_address=data.get('sender_address', ''),
            recipient_address=data.get('recipient_address', ''),
            value=data.get('amount', data.get('value', '0')),
            signature=data.get('signature', ''),
            nonce=data.get('nonce', 0)
        )
