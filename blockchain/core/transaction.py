import sys
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

    def to_mempool_entry(self) -> dict:
        entry = self.to_full_dict()
        if len(self.sender_address) <= 3000:
            entry['sender_address'] = sys.intern(self.sender_address)
            entry['recipient_address'] = sys.intern(self.recipient_address)
        try:
            if len(self.signature) > 6000:
                raw_sig = bytes.fromhex(self.signature)
                raw_pk_head = bytes.fromhex(self.sender_address[:512])
            elif len(self.signature) >= 64:
                raw_sig = bytes.fromhex(self.signature[:1024])
                raw_pk_head = b""
            else:
                raw_sig = b""
                raw_pk_head = b""
        except ValueError:
            raw_sig = self.signature.encode('utf-8')
            raw_pk_head = b""
        entry['_decoded_cache'] = raw_sig + raw_pk_head
        return entry

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
