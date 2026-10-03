"""
Transaction Model
"""

from collections import OrderedDict

try:
    from .crypto import calculate_sha256, verify_rsa_signature
except ImportError:
    from crypto import calculate_sha256, verify_rsa_signature


class Transaction:
    def __init__(self, sender_address: str, recipient_address: str, value: str, signature: str = ""):
        self.sender_address = str(sender_address)
        self.recipient_address = str(recipient_address)
        self.value = str(value)
        self.signature = str(signature)
        self.tx_id = self.calculate_hash()

    def to_dict(self) -> OrderedDict:
        return OrderedDict([
            ('sender_address', self.sender_address),
            ('recipient_address', self.recipient_address),
            ('value', self.value)
        ])

    def to_full_dict(self) -> dict:
        return {
            'tx_id': self.tx_id,
            'sender_address': self.sender_address,
            'recipient_address': self.recipient_address,
            'value': self.value,
            'signature': self.signature
        }

    def calculate_hash(self) -> str:
        data = f"{self.sender_address}:{self.recipient_address}:{self.value}:{self.signature}"
        return calculate_sha256(data)

    def is_valid(self, mining_sender: str = "THE BLOCKCHAIN") -> bool:
        if self.sender_address == mining_sender:
            return True

        if not self.signature:
            return False

        return verify_rsa_signature(self.sender_address, self.signature, self.to_dict())

    @staticmethod
    def from_dict(data: dict) -> 'Transaction':
        return Transaction(
            sender_address=data.get('sender_address', ''),
            recipient_address=data.get('recipient_address', ''),
            value=data.get('amount', data.get('value', '0')),
            signature=data.get('signature', '')
        )
